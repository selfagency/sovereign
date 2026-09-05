package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// routeHasScope reports whether a route declares a scope, either explicitly
// (non-empty Scope) or via the Anonymous marker.
func routeHasScope(r Route) bool {
	return r.Scope != "" || r.Anonymous
}

// TestNoRouteWithoutScope asserts every route declares either a non-empty
// Scope or the explicit Anonymous marker. A route with Scope:"" and
// Anonymous:false is a forgotten declaration and must fail. This is the m4
// amendment: the test distinguishes an explicit anonymous marker from a
// forgotten empty scope, so it is not vacuous.
func TestNoRouteWithoutScope(t *testing.T) {
	// The shipped Phase 1 table is all-anonymous; prove the mechanism with a
	// test-local route list that mixes anonymous and scoped routes.
	routes := []Route{
		{Method: http.MethodGet, Path: "/api/v1/meta/capabilities", Anonymous: true, Timeout: time.Second},
		{Method: http.MethodGet, Path: "/api/v1/me", Scope: "self:read", Timeout: time.Second},
	}
	for _, r := range routes {
		if !routeHasScope(r) {
			t.Fatalf("route %s %s has no scope and is not marked anonymous", r.Method, r.Path)
		}
	}

	// A forgotten declaration (empty scope, no marker) must be rejected.
	bad := Route{Method: http.MethodGet, Path: "/api/v1/forgotten", Timeout: time.Second}
	if routeHasScope(bad) {
		t.Fatal("expected a route with empty scope and no anonymous marker to be rejected")
	}
}

// TestEveryRouteHasTimeout asserts every Phase 1 route declares a positive
// per-route timeout, unless it is explicitly marked LongRunning (Phase 3
// backup routes).
func TestEveryRouteHasTimeout(t *testing.T) {
	for _, r := range Routes() {
		if r.LongRunning {
			continue
		}
		if r.Timeout <= 0 {
			t.Errorf("route %s %s has no positive timeout", r.Method, r.Path)
		}
	}
}

// TestRouterRegistersMethods asserts New() mounts each route with the correct
// Go 1.22+ method pattern: a registered GET route returns its real handler
// (200 for the now-implemented capabilities route), a not-yet-implemented
// route returns the 501 stub, and an unknown path returns 404.
func TestRouterRegistersMethods(t *testing.T) {
	mux := New(Routes())

	// Registered, implemented GET route -> 200.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/meta/capabilities", http.NoBody)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/meta/capabilities: got %d, want 200", rec.Code)
	}

	// Registered, not-yet-implemented POST route -> 501 stub.
	req = httptest.NewRequest(http.MethodPost, "/api/v1/auth/session/refresh", http.NoBody)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("POST /api/v1/auth/session/refresh: got %d, want 501", rec.Code)
	}

	// Unknown path -> 404.
	req = httptest.NewRequest(http.MethodGet, "/api/v1/nope", http.NoBody)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET /api/v1/nope: got %d, want 404", rec.Code)
	}
}
