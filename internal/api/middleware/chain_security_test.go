package middleware

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/selfagency/sovereign/internal/store"
)

// TestNewHandlerPathMismatchNoBypass verifies the authn/scope decision is bound
// to the handler, not a path lookup: a request ServeMux would route to a
// protected handler can never skip authn+scope authz. Trailing-slash, subtree,
// and double-slash variants of a protected route must be 401/403/404, never
// silently authenticated.
func TestNewHandlerPathMismatchNoBypass(t *testing.T) {
	key := testSigningKey(t)
	s := newTestStore(t)
	reached := false
	cfg := chainTestConfig(t, s, key)
	cfg.Routes[1].Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	})
	life := NewHandler(cfg)
	defer life.Close()

	// The protected route is /api/v1/me (Scope self:read). ServeMux normalizes
	// trailing slashes and path-cleaning, so these all resolve to the same
	// handler. None may reach it without a credential.
	for _, path := range []string{
		"/api/v1/me/",      // trailing slash
		"//api/v1/me",      // double slash (path cleaning)
		"/api/v1/me/extra", // subtree under a trailing-slash registration
	} {
		reached = false
		rec := httptest.NewRecorder()
		life.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, http.NoBody))
		if rec.Code != http.StatusUnauthorized && rec.Code != http.StatusForbidden && rec.Code != http.StatusNotFound && rec.Code != http.StatusTemporaryRedirect {
			t.Fatalf("path %q: status = %d, want 401/403/404/307 (bypass closed)", path, rec.Code)
		}
		if reached {
			t.Fatalf("path %q: protected handler reached without authn (bypass)", path)
		}
	}
}

// TestNewHandlerCookieAdminScope verifies a cookie-authenticated admin can reach
// an admin:* route (the cookie principal is granted the admin scopes from the
// user record), while a cookie non-admin is still 403.
func TestNewHandlerCookieAdminScope(t *testing.T) {
	key := testSigningKey(t)
	s := newTestStore(t)

	// Create an admin and a non-admin with distinct handles (createTestUser
	// hardcodes "alice", so create them directly).
	if err := s.CreateTenant(t.Context(), &store.Tenant{ID: "tenant-1", Handle: "alice.example.com", DIDMethod: "web"}); err != nil && !errors.Is(err, store.ErrDuplicateTenant) {
		t.Fatal(err)
	}
	admin := &store.User{ID: "admin-1", TenantID: "tenant-1", Handle: "admin", Email: "admin@example.com", IsAdmin: true}
	if err := s.CreateUser(t.Context(), admin); err != nil {
		t.Fatal(err)
	}
	nonAdmin := &store.User{ID: "user-1", TenantID: "tenant-1", Handle: "user", Email: "user@example.com", IsAdmin: false}
	if err := s.CreateUser(t.Context(), nonAdmin); err != nil {
		t.Fatal(err)
	}

	adminTok, err := store.GenerateSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateSession(t.Context(), admin.ID, store.HashSessionToken(adminTok), time.Hour, "", ""); err != nil {
		t.Fatal(err)
	}

	nonAdminTok, err := store.GenerateSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateSession(t.Context(), nonAdmin.ID, store.HashSessionToken(nonAdminTok), time.Hour, "", ""); err != nil {
		t.Fatal(err)
	}

	cfg := chainTestConfig(t, s, key)
	cfg.Routes = append(cfg.Routes, RouteInfo{
		Method: http.MethodGet, Path: "/api/v1/admin/users", Scope: "admin:users", Timeout: 5 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }),
	})
	life := NewHandler(cfg)
	defer life.Close()

	// Cookie admin reaches the admin route (200, not 403 InsufficientScope).
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/users", http.NoBody)
	req.AddCookie(&http.Cookie{Name: "session", Value: adminTok})
	rec := httptest.NewRecorder()
	life.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("cookie admin status = %d, want 200 (not 403)", rec.Code)
	}

	// Cookie non-admin is 403.
	req = httptest.NewRequest(http.MethodGet, "/api/v1/admin/users", http.NoBody)
	req.AddCookie(&http.Cookie{Name: "session", Value: nonAdminTok})
	rec = httptest.NewRecorder()
	life.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("cookie non-admin status = %d, want 403", rec.Code)
	}
}

// TestNewHandlerRouteWithoutScopePanics verifies NewHandler rejects a route
// with Anonymous:false and Scope:"" (a forgotten declaration that would pass
// authn but skip scope authz).
func TestNewHandlerRouteWithoutScopePanics(t *testing.T) {
	key := testSigningKey(t)
	s := newTestStore(t)
	cfg := chainTestConfig(t, s, key)
	cfg.Routes = append(cfg.Routes, RouteInfo{
		Method: http.MethodGet, Path: "/api/v1/forgotten", Timeout: 5 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }),
	})

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("NewHandler did not panic on a route with no scope and no anonymous marker")
		}
	}()
	NewHandler(cfg)
}

// TestAuthNBearerEmptyCookie verifies a valid bearer token with an empty
// session cookie authenticates (the empty cookie is treated as absent, not a
// conflicting credential).
func TestAuthNBearerEmptyCookie(t *testing.T) {
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
	req.Header.Set("Authorization", "Bearer "+tok)
	req.AddCookie(&http.Cookie{Name: "session", Value: ""})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (empty cookie must not conflict)", rec.Code)
	}
	if p == nil || p.UserID != u.ID {
		t.Fatalf("principal = %+v, want user %s", p, u.ID)
	}
}
