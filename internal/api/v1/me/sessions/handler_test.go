package sessions_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/selfagency/sovereign/internal/api/dto"
	"github.com/selfagency/sovereign/internal/api/middleware"
	v1sessions "github.com/selfagency/sovereign/internal/api/v1/me/sessions"
	"github.com/selfagency/sovereign/internal/store"
)

func testStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func seedTenantUser(t *testing.T, s *store.Store, tenantID, handle string) *store.User {
	t.Helper()
	ctx := context.Background()
	if err := s.CreateTenant(ctx, &store.Tenant{ID: tenantID, Handle: handle + ".example.com", DIDMethod: "web"}); err != nil && !errors.Is(err, store.ErrDuplicateTenant) {
		t.Fatal(err)
	}
	u := &store.User{ID: "user-" + tenantID + "-" + handle, TenantID: tenantID, Handle: handle, DisplayName: handle}
	if err := s.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	return u
}

// seedSession creates a session row for a user and returns it.
func seedSession(t *testing.T, s *store.Store, userID string) *store.Session {
	t.Helper()
	tok, err := store.GenerateSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	sess, err := s.CreateSession(context.Background(), userID, store.HashSessionToken(tok), 15*time.Minute, "ua-hash", "ip-hash")
	if err != nil {
		t.Fatal(err)
	}
	return sess
}

// req builds an httptest request carrying the given principal in context.
func req(method, path string, p *middleware.Principal) *http.Request {
	r := httptest.NewRequest(method, path, http.NoBody)
	if p != nil {
		r = r.WithContext(middleware.WithPrincipal(r.Context(), p))
	}
	return r
}

// reqCookie builds a request carrying a principal plus a session cookie value.
func reqCookie(method, path string, p *middleware.Principal, cookieVal string) *http.Request {
	r := req(method, path, p)
	if cookieVal != "" {
		r.AddCookie(&http.Cookie{Name: "session", Value: cookieVal})
	}
	return r
}

func do(h http.HandlerFunc, r *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func decode[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode %T: %v (body %s)", v, err, rec.Body.String())
	}
	return v
}

func newHandler(s *store.Store) *v1sessions.Handler {
	return v1sessions.New(s, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func principal(userID, tenantID string) *middleware.Principal {
	return &middleware.Principal{UserID: userID, TenantID: tenantID, Scopes: []string{"self", "sessions"}}
}

func TestListSessions(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	u := seedTenantUser(t, s, "tenant-a", "alice")
	a := seedSession(t, s, u.ID)
	b := seedSession(t, s, u.ID)

	rec := do(h.List, req(http.MethodGet, "/api/v1/me/sessions", principal(u.ID, u.TenantID)))
	if rec.Code != http.StatusOK {
		t.Fatalf("list = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	got := decode[[]dto.Session](t, rec)
	if len(got) != 2 {
		t.Fatalf("list = %d sessions, want 2", len(got))
	}
	// Oldest first.
	if got[0].ID != a.ID || got[1].ID != b.ID {
		t.Fatalf("session order = %s,%s want %s,%s", got[0].ID, got[1].ID, a.ID, b.ID)
	}
	if got[0].UserID != u.ID {
		t.Fatalf("session user_id = %q, want %q", got[0].UserID, u.ID)
	}
}

func TestListSessionsEmpty(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	u := seedTenantUser(t, s, "tenant-a", "alice")

	rec := do(h.List, req(http.MethodGet, "/api/v1/me/sessions", principal(u.ID, u.TenantID)))
	if rec.Code != http.StatusOK {
		t.Fatalf("list = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	got := decode[[]dto.Session](t, rec)
	if len(got) != 0 {
		t.Fatalf("fresh user sessions = %d, want 0", len(got))
	}
}

func TestListSessionsUnauthenticated(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	rec := do(h.List, req(http.MethodGet, "/api/v1/me/sessions", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated = %d, want 401", rec.Code)
	}
}

func TestListSessionsNeverLeaksTokenOrIPHash(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	u := seedTenantUser(t, s, "tenant-a", "alice")
	seedSession(t, s, u.ID)

	rec := do(h.List, req(http.MethodGet, "/api/v1/me/sessions", principal(u.ID, u.TenantID)))
	if rec.Code != http.StatusOK {
		t.Fatalf("list = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if strings.Contains(body, "token_hash") || strings.Contains(body, "ip_hash") {
		t.Fatalf("response leaks token_hash or ip_hash: %s", body)
	}
	// The DTO must not even carry the fields.
	got := decode[[]dto.Session](t, rec)
	if got[0].IPHash != "" {
		t.Fatalf("session ip_hash leaked: %q", got[0].IPHash)
	}
}

func TestRevokeSession(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	u := seedTenantUser(t, s, "tenant-a", "alice")
	a := seedSession(t, s, u.ID)
	b := seedSession(t, s, u.ID)

	rec := do(h.Revoke, req(http.MethodDelete, "/api/v1/me/sessions/"+a.ID, principal(u.ID, u.TenantID)))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("revoke = %d, want 204 (body %s)", rec.Code, rec.Body.String())
	}
	// a revoked, b still active.
	gotA, err := s.GetSessionByID(context.Background(), a.ID)
	if err != nil || gotA.RevokedAt == nil {
		t.Fatalf("session a not revoked: err=%v revoked=%v", err, gotA.RevokedAt)
	}
	gotB, err := s.GetSessionByID(context.Background(), b.ID)
	if err != nil || gotB.RevokedAt != nil {
		t.Fatalf("session b should remain active: err=%v revoked=%v", err, gotB.RevokedAt)
	}
}

func TestRevokeSessionNotFound(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	u := seedTenantUser(t, s, "tenant-a", "alice")

	rec := do(h.Revoke, req(http.MethodDelete, "/api/v1/me/sessions/missing-id", principal(u.ID, u.TenantID)))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("revoke missing = %d, want 404 (body %s)", rec.Code, rec.Body.String())
	}
}

func TestRevokeSessionUnauthenticated(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	rec := do(h.Revoke, req(http.MethodDelete, "/api/v1/me/sessions/any-id", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated = %d, want 401", rec.Code)
	}
}

func TestRevokeAnotherUsersSessionIsNotFound(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	a := seedTenantUser(t, s, "tenant-a", "alice")
	b := seedTenantUser(t, s, "tenant-b", "bob")
	bSess := seedSession(t, s, b.ID)

	// Alice attempts to revoke Bob's session: must be 404 (existence safety),
	// never 403, and Bob's session must remain active.
	rec := do(h.Revoke, req(http.MethodDelete, "/api/v1/me/sessions/"+bSess.ID, principal(a.ID, a.TenantID)))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("cross-user revoke = %d, want 404 (body %s)", rec.Code, rec.Body.String())
	}
	got, err := s.GetSessionByID(context.Background(), bSess.ID)
	if err != nil || got.RevokedAt != nil {
		t.Fatalf("bob's session was revoked: err=%v revoked=%v", err, got.RevokedAt)
	}
}

func TestRevokeAllKeepsCurrentSession(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	u := seedTenantUser(t, s, "tenant-a", "alice")
	// Current session: create a real token so the cookie resolves to a row.
	curTok, err := store.GenerateSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	cur, err := s.CreateSession(context.Background(), u.ID, store.HashSessionToken(curTok), 15*time.Minute, "ua", "ip")
	if err != nil {
		t.Fatal(err)
	}
	other := seedSession(t, s, u.ID)

	rec := do(h.RevokeAll, reqCookie(http.MethodDelete, "/api/v1/me/sessions", principal(u.ID, u.TenantID), curTok))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("revoke all = %d, want 204 (body %s)", rec.Code, rec.Body.String())
	}
	gotCur, err := s.GetSessionByID(context.Background(), cur.ID)
	if err != nil || gotCur.RevokedAt != nil {
		t.Fatalf("current session revoked: err=%v revoked=%v", err, gotCur.RevokedAt)
	}
	gotOther, err := s.GetSessionByID(context.Background(), other.ID)
	if err != nil || gotOther.RevokedAt == nil {
		t.Fatalf("other session not revoked: err=%v revoked=%v", err, gotOther.RevokedAt)
	}
}

func TestRevokeAllWithoutCookieRevokesAll(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	u := seedTenantUser(t, s, "tenant-a", "alice")
	a := seedSession(t, s, u.ID)
	b := seedSession(t, s, u.ID)

	// Bearer principal: no session cookie, so every session is revoked.
	rec := do(h.RevokeAll, req(http.MethodDelete, "/api/v1/me/sessions", principal(u.ID, u.TenantID)))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("revoke all = %d, want 204 (body %s)", rec.Code, rec.Body.String())
	}
	for _, id := range []string{a.ID, b.ID} {
		got, err := s.GetSessionByID(context.Background(), id)
		if err != nil || got.RevokedAt == nil {
			t.Fatalf("session %s not revoked: err=%v revoked=%v", id, err, got.RevokedAt)
		}
	}
}

func TestRevokeAllUnauthenticated(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	rec := do(h.RevokeAll, req(http.MethodDelete, "/api/v1/me/sessions", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated = %d, want 401", rec.Code)
	}
}
