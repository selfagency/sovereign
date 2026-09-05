package store

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func newSessionTestStore(t *testing.T) *Store {
	t.Helper()
	return newAuthTestStore(t)
}

func mustToken(t *testing.T) string {
	t.Helper()
	tok, err := GenerateSessionToken()
	if err != nil {
		t.Fatalf("GenerateSessionToken: %v", err)
	}
	return tok
}

func mustSession(t *testing.T, s *Store, userID, tok string) *Session {
	t.Helper()
	sess, err := s.CreateSession(context.Background(), userID, HashSessionToken(tok), 15*time.Minute, "ua", "ip")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	return sess
}

// TestCreateSessionRoundTrip verifies CreateSession + GetSessionByTokenHash.
func TestCreateSessionRoundTrip(t *testing.T) {
	s := newSessionTestStore(t)
	ctx := context.Background()
	tok := mustToken(t)
	hash := HashSessionToken(tok)

	got, err := s.CreateSession(ctx, "user-1", hash, 15*time.Minute, "ua1", "ip1")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if got.UserID != "user-1" {
		t.Fatalf("UserID = %q, want user-1", got.UserID)
	}
	if got.TokenHash != hash {
		t.Fatalf("TokenHash = %q, want %q", got.TokenHash, hash)
	}
	wantExp := time.Now().Add(15 * time.Minute)
	if got.ExpiresAt.Sub(wantExp) > 2*time.Second || got.ExpiresAt.Before(time.Now().Add(14*time.Minute)) {
		t.Fatalf("ExpiresAt = %v, want ~now+15m", got.ExpiresAt)
	}
	if got.LastSeenAt == nil || got.RevokedAt != nil {
		t.Fatalf("LastSeenAt=%v RevokedAt=%v, want last_seen set, revoked nil", got.LastSeenAt, got.RevokedAt)
	}

	byHash, err := s.GetSessionByTokenHash(ctx, hash)
	if err != nil {
		t.Fatalf("GetSessionByTokenHash: %v", err)
	}
	if byHash.ID != got.ID {
		t.Fatalf("byHash.ID = %q, want %q", byHash.ID, got.ID)
	}
}

// TestGetSessionByTokenHashMissing verifies a missing hash returns ErrNotFound.
func TestGetSessionByTokenHashMissing(t *testing.T) {
	s := newSessionTestStore(t)
	if _, err := s.GetSessionByTokenHash(context.Background(), "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing = %v, want ErrNotFound", err)
	}
}

// TestSessionExpired verifies IsExpired reports expired sessions and
// non-expired ones do not.
func TestSessionExpired(t *testing.T) {
	s := newSessionTestStore(t)
	ctx := context.Background()

	sess, err := s.CreateSession(ctx, "user-1", HashSessionToken(mustToken(t)), time.Minute, "ua", "ip")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if sess.IsExpired() {
		t.Fatal("fresh session reported expired")
	}

	// Backdate the expiry past now.
	if _, err := s.db.ExecContext(ctx, `UPDATE sessions SET expires_at = ? WHERE id = ?`,
		time.Now().Add(-time.Minute), sess.ID); err != nil {
		t.Fatalf("backdate: %v", err)
	}
	got, err := s.GetSessionByID(ctx, sess.ID)
	if err != nil {
		t.Fatalf("GetSessionByID: %v", err)
	}
	if !got.IsExpired() {
		t.Fatal("expired session not reported expired")
	}
}

// TestSessionRevoked verifies a revoked session is not valid for auth.
func TestSessionRevoked(t *testing.T) {
	s := newSessionTestStore(t)
	ctx := context.Background()
	tok := mustToken(t)
	hash := HashSessionToken(tok)

	sess := mustSession(t, s, "user-1", tok)
	if err := s.RevokeSession(ctx, sess.ID); err != nil {
		t.Fatalf("RevokeSession: %v", err)
	}
	byHash, err := s.GetSessionByTokenHash(ctx, hash)
	if err != nil {
		t.Fatalf("GetSessionByTokenHash: %v", err)
	}
	if byHash.RevokedAt == nil {
		t.Fatal("revoked session has nil RevokedAt")
	}
}

// TestTouchSession verifies sliding renewal advances expires_at + last_seen_at.
func TestTouchSession(t *testing.T) {
	s := newSessionTestStore(t)
	ctx := context.Background()
	sess := mustSession(t, s, "user-1", mustToken(t))

	newExp := time.Now().Add(2 * time.Hour).UTC()
	if err := s.TouchSession(ctx, sess.ID, newExp); err != nil {
		t.Fatalf("TouchSession: %v", err)
	}
	got, err := s.GetSessionByID(ctx, sess.ID)
	if err != nil {
		t.Fatalf("GetSessionByID: %v", err)
	}
	if got.ExpiresAt.Sub(newExp) > time.Second {
		t.Fatalf("ExpiresAt = %v, want %v", got.ExpiresAt, newExp)
	}
	if got.LastSeenAt == nil || time.Until(*got.LastSeenAt) > 2*time.Second {
		t.Fatalf("LastSeenAt = %v, want recent", got.LastSeenAt)
	}

	// Touching a missing session -> ErrNotFound.
	if err := s.TouchSession(ctx, "missing", newExp); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing touch = %v, want ErrNotFound", err)
	}
}

// TestPruneUserSessions verifies the absolute cap revokes the oldest beyond max.
func TestPruneUserSessions(t *testing.T) {
	s := newSessionTestStore(t)
	ctx := context.Background()

	// Create 5 sessions; last_seen/created order should be oldest-first.
	ids := make([]string, 5)
	for i := range ids {
		tok := mustToken(t)
		// Stagger creation time so ordering is deterministic.
		sess, err := s.CreateSession(ctx, "user-1", HashSessionToken(tok), time.Hour, "", "")
		if err != nil {
			t.Fatalf("CreateSession[%d]: %v", i, err)
		}
		ids[i] = sess.ID
		time.Sleep(2 * time.Millisecond)
	}

	n, err := s.PruneUserSessions(ctx, "user-1", 3)
	must(t, err)
	if n != 2 {
		t.Fatalf("pruned = %d, want 2", n)
	}

	all, err := s.ListUserSessions(ctx, "user-1")
	must(t, err)

	active := 0
	revokedIDs := map[string]bool{}
	for _, sess := range all {
		if sess.RevokedAt == nil {
			active++
		} else {
			revokedIDs[sess.ID] = true
		}
	}
	if active != 3 {
		t.Fatalf("active = %d, want 3", active)
	}
	// The two oldest (ids[0], ids[1]) must be revoked.
	for _, id := range ids[:2] {
		if !revokedIDs[id] {
			t.Fatalf("oldest session %s not revoked", id)
		}
	}
	// Newest three must survive.
	for _, id := range ids[2:] {
		if revokedIDs[id] {
			t.Fatalf("newest session %s wrongly revoked", id)
		}
	}
}

// TestPruneUserSessionsUnderCap verifies no revocation when under the cap.
func TestPruneUserSessionsUnderCap(t *testing.T) {
	s := newSessionTestStore(t)
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		mustSession(t, s, "user-1", mustToken(t))
	}
	n, err := s.PruneUserSessions(ctx, "user-1", 10)
	if err != nil {
		t.Fatalf("PruneUserSessions: %v", err)
	}
	if n != 0 {
		t.Fatalf("pruned = %d, want 0", n)
	}
}

// TestRevokeUserSessions verifies revoking all sessions for a user.
func TestRevokeUserSessions(t *testing.T) {
	s := newSessionTestStore(t)
	ctx := context.Background()
	mustSession(t, s, "user-1", mustToken(t))
	mustSession(t, s, "user-1", mustToken(t))
	mustSession(t, s, "user-2", mustToken(t))

	if err := s.RevokeUserSessions(ctx, "user-1"); err != nil {
		t.Fatalf("RevokeUserSessions: %v", err)
	}
	all, err := s.ListUserSessions(ctx, "user-1")
	if err != nil {
		t.Fatalf("ListUserSessions: %v", err)
	}
	for _, sess := range all {
		if sess.RevokedAt == nil {
			t.Fatalf("user-1 session %s not revoked", sess.ID)
		}
	}
	// user-2 must be untouched.
	other, err := s.ListUserSessions(ctx, "user-2")
	if err != nil {
		t.Fatalf("ListUserSessions user-2: %v", err)
	}
	if len(other) != 1 || other[0].RevokedAt != nil {
		t.Fatalf("user-2 sessions = %+v, want one active", other)
	}
}

// TestSessionConcurrentRevokeRace runs N goroutines revoking the same session
// while one reads it, asserting no panic/data race (run under -race).
func TestSessionConcurrentRevokeRace(t *testing.T) {
	s := newSessionTestStore(t)
	ctx := context.Background()
	sess := mustSession(t, s, "user-1", mustToken(t))

	const n = 32
	var wg sync.WaitGroup
	wg.Add(n + 1)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			errs[i] = s.RevokeSession(ctx, sess.ID)
		}(i)
	}
	go func() {
		defer wg.Done()
		if _, err := s.GetSessionByID(ctx, sess.ID); err != nil && !errors.Is(err, ErrNotFound) {
			t.Errorf("GetSessionByID: %v", err)
		}
	}()
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("revoke goroutine %d: %v", i, err)
		}
	}
	// Idempotent: still exactly one row, revoked once.
	got, err := s.GetSessionByID(ctx, sess.ID)
	if err != nil {
		t.Fatalf("GetSessionByID after race: %v", err)
	}
	if got.RevokedAt == nil {
		t.Fatal("session not revoked after concurrent revokes")
	}
}

// TestDualReadFormatSniff verifies IsSessionToken distinguishes JWT-shaped
// values from opaque session tokens.
func TestDualReadFormatSniff(t *testing.T) {
	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.signature"
	if IsSessionToken(jwt) {
		t.Fatal("JWT-shaped value sniffed as session token")
	}

	tok := mustToken(t)
	if strings.Contains(tok, ".") {
		t.Fatalf("opaque token contains a dot: %q", tok)
	}
	if !IsSessionToken(tok) {
		t.Fatal("opaque token not sniffed as session token")
	}
}

// TestHashSessionToken verifies determinism and that the hash differs from raw.
func TestHashSessionToken(t *testing.T) {
	tok := "some-raw-token-value"
	h1 := HashSessionToken(tok)
	h2 := HashSessionToken(tok)
	if h1 != h2 {
		t.Fatal("hash not deterministic")
	}
	if h1 == tok {
		t.Fatal("hash equals raw token")
	}
	if len(h1) != 64 {
		t.Fatalf("hash length = %d, want 64 (sha256 hex)", len(h1))
	}
	if h1 == HashSessionToken("different") {
		t.Fatal("hash collision on distinct inputs")
	}
}

// TestGenerateSessionTokenShape verifies generated tokens are opaque, dot-free
// base64url values of the expected length.
func TestGenerateSessionTokenShape(t *testing.T) {
	toks := map[string]bool{}
	for i := 0; i < 3; i++ {
		tok, err := GenerateSessionToken()
		if err != nil {
			t.Fatalf("GenerateSessionToken: %v", err)
		}
		if strings.Contains(tok, ".") {
			t.Fatalf("token contains dot: %q", tok)
		}
		if len(tok) < 40 {
			t.Fatalf("token too short: %d chars (%q)", len(tok), tok)
		}
		if toks[tok] {
			t.Fatal("token collision")
		}
		toks[tok] = true
	}
	// Sanity: a generated token round-trips through the sniff helper.
	tok, _ := GenerateSessionToken()
	if !IsSessionToken(tok) {
		t.Fatal("generated token not recognized as session token")
	}
}
