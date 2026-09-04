package middleware

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/selfagency/sovereign/internal/auth"
	"github.com/selfagency/sovereign/internal/store"
)

const (
	testIssuer  = "https://id.example.test"
	testKeyBits = 2048
)

// testSigningKey returns a fresh RSA key for JWT minting.
func testSigningKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, testKeyBits)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// mintAPIJWT mints an access token with the given scopes and audience.
func mintAPIJWT(t *testing.T, key *rsa.PrivateKey, sub string, scopes []string, aud string) string {
	t.Helper()
	tok, err := auth.MintAccessToken(key, sub, scopes, time.Minute, testIssuer, aud)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// newTestStore opens an in-memory store for authn tests.
func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// userSeq is a package-level counter so test users get unique IDs even when a
// single store creates several in one test.
var userSeq struct {
	sync.Mutex
	n int
}

// createTestUser inserts a tenant + user and returns the user. The store's
// first user auto-becomes admin, so for a requested non-admin we first seed a
// placeholder admin to consume that slot, ensuring IsAdmin is honored.
func createTestUser(t *testing.T, s *store.Store, isAdmin bool) *store.User {
	t.Helper()
	if err := s.CreateTenant(context.Background(), &store.Tenant{ID: "tenant-1", Handle: "alice.example.com", DIDMethod: "web"}); err != nil && !errors.Is(err, store.ErrDuplicateTenant) {
		t.Fatal(err)
	}
	if !isAdmin {
		seedPlaceholderAdmin(t, s)
	}
	userSeq.Lock()
	userSeq.n++
	id := fmt.Sprintf("user-%d", userSeq.n)
	userSeq.Unlock()
	u := &store.User{
		ID:       id,
		TenantID: "tenant-1",
		Handle:   "alice",
		Email:    "alice@example.com",
		IsAdmin:  isAdmin,
	}
	if err := s.CreateUser(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	return u
}

// seedPlaceholderAdmin inserts a user into an empty store so the auto-admin
// slot is consumed, leaving the next user to honor its explicit IsAdmin.
func seedPlaceholderAdmin(t *testing.T, s *store.Store) {
	t.Helper()
	userSeq.Lock()
	userSeq.n++
	id := fmt.Sprintf("user-%d", userSeq.n)
	userSeq.Unlock()
	if err := s.CreateUser(context.Background(), &store.User{
		ID:       id,
		TenantID: "tenant-1",
		Handle:   "placeholder",
		Email:    "ph@example.com",
		IsAdmin:  true,
	}); err != nil {
		t.Fatal(err)
	}
}

// newAuthN builds an AuthN wired to a real store.
func newAuthN(t *testing.T, s *store.Store, key *rsa.PrivateKey, dualRead bool) *AuthN {
	t.Helper()
	return &AuthN{
		Key:           key,
		Issuer:        testIssuer,
		SessionCookie: "session",
		Sessions:      s,
		Users:         s,
		DualRead:      dualRead,
	}
}

// TestAuthNBearerPasses verifies a valid bearer token with the API audience
// authenticates and sets a principal.
func TestAuthNBearerPasses(t *testing.T) {
	key := testSigningKey(t)
	s := newTestStore(t)
	u := createTestUser(t, s, false)
	tok := mintAPIJWT(t, key, u.ID, []string{"self:read"}, apiAudience)

	var p *Principal
	h := newAuthN(t, s, key, true).Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p = PrincipalFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/x", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if p == nil || p.UserID != u.ID {
		t.Fatalf("principal = %+v, want user %s", p, u.ID)
	}
	if p.IsCookie {
		t.Fatal("bearer principal should not be a cookie principal")
	}
}

// TestAuthNBearerAndCookieRejected verifies bearer + cookie together is 400.
func TestAuthNBearerAndCookieRejected(t *testing.T) {
	key := testSigningKey(t)
	s := newTestStore(t)
	u := createTestUser(t, s, false)
	tok := mintAPIJWT(t, key, u.ID, []string{"self"}, apiAudience)

	h := newAuthN(t, s, key, true).Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/x", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+tok)
	req.AddCookie(&http.Cookie{Name: "session", Value: "opaque-session-token"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

// TestAuthNWrongAudienceRejected verifies a valid JWT with a non-API audience
// is 401 on the control plane.
func TestAuthNWrongAudienceRejected(t *testing.T) {
	key := testSigningKey(t)
	s := newTestStore(t)
	tok := mintAPIJWT(t, key, "some-sub", []string{"rs"}, "sovereign-rs")

	h := newAuthN(t, s, key, true).Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/x", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

// TestAuthNNoCredential verifies a request with no credential is 401.
func TestAuthNNoCredential(t *testing.T) {
	key := testSigningKey(t)
	s := newTestStore(t)
	h := newAuthN(t, s, key, true).Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", http.NoBody))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

// TestAuthNJWTCookieDualRead verifies a legacy JWT cookie authenticates when
// DualRead is true.
func TestAuthNJWTCookieDualRead(t *testing.T) {
	key := testSigningKey(t)
	s := newTestStore(t)
	u := createTestUser(t, s, false)
	tok := mintAPIJWT(t, key, u.ID, []string{"self"}, apiAudience)

	var p *Principal
	h := newAuthN(t, s, key, true).Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p = PrincipalFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/x", http.NoBody)
	req.AddCookie(&http.Cookie{Name: "session", Value: tok})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if p == nil || p.UserID != u.ID || !p.IsCookie {
		t.Fatalf("principal = %+v, want cookie user %s", p, u.ID)
	}
}

// TestAuthNJWTCookieDualReadDisabled verifies legacy JWT cookies are rejected
// when DualRead is false.
func TestAuthNJWTCookieDualReadDisabled(t *testing.T) {
	key := testSigningKey(t)
	s := newTestStore(t)
	u := createTestUser(t, s, false)
	tok := mintAPIJWT(t, key, u.ID, []string{"self"}, apiAudience)

	h := newAuthN(t, s, key, false).Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/x", http.NoBody)
	req.AddCookie(&http.Cookie{Name: "session", Value: tok})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

// TestAuthNOpaqueSession verifies an opaque session cookie authenticates via a
// session row.
func TestAuthNOpaqueSession(t *testing.T) {
	key := testSigningKey(t)
	s := newTestStore(t)
	u := createTestUser(t, s, false)
	tok, err := store.GenerateSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateSession(context.Background(), u.ID, store.HashSessionToken(tok), time.Hour, "", ""); err != nil {
		t.Fatal(err)
	}

	var p *Principal
	h := newAuthN(t, s, key, true).Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p = PrincipalFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/x", http.NoBody)
	req.AddCookie(&http.Cookie{Name: "session", Value: tok})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if p == nil || p.UserID != u.ID || !p.IsCookie {
		t.Fatalf("principal = %+v, want cookie user %s", p, u.ID)
	}
}

// TestAuthNOpaqueSessionExpired verifies an expired session row is rejected.
func TestAuthNOpaqueSessionExpired(t *testing.T) {
	key := testSigningKey(t)
	s := newTestStore(t)
	u := createTestUser(t, s, false)
	tok, err := store.GenerateSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateSession(context.Background(), u.ID, store.HashSessionToken(tok), -time.Hour, "", ""); err != nil {
		t.Fatal(err)
	}

	h := newAuthN(t, s, key, true).Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/x", http.NoBody)
	req.AddCookie(&http.Cookie{Name: "session", Value: tok})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

// TestAuthNAmbiguousCookie verifies a cookie carrying both the JWT and opaque
// shapes is rejected (400), never guessed.
func TestAuthNAmbiguousCookie(t *testing.T) {
	key := testSigningKey(t)
	s := newTestStore(t)
	u := createTestUser(t, s, false)
	tok := mintAPIJWT(t, key, u.ID, []string{"self"}, apiAudience)

	h := newAuthN(t, s, key, true).Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	// Two cookies, same name: one JWT-shaped, one opaque-shaped.
	req := httptest.NewRequest(http.MethodGet, "/x", http.NoBody)
	req.AddCookie(&http.Cookie{Name: "session", Value: tok})
	req.AddCookie(&http.Cookie{Name: "session", Value: "opaque-token"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

// TestAuthNAdminFlag verifies the principal carries the user's admin flag.
func TestAuthNAdminFlag(t *testing.T) {
	key := testSigningKey(t)
	s := newTestStore(t)
	u := createTestUser(t, s, true)
	tok := mintAPIJWT(t, key, u.ID, []string{"admin:users"}, apiAudience)

	var p *Principal
	h := newAuthN(t, s, key, true).Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p = PrincipalFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/x", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if p == nil || !p.IsAdmin {
		t.Fatalf("principal = %+v, want admin=true", p)
	}
}
