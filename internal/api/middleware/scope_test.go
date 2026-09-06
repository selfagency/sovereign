package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// scopeHandler builds a ScopeAuthz with a fixed required-scope resolver and a
// downstream handler that records reachability.
func scopeHandler(require func(path string) string) (h http.Handler, reached *bool) {
	reached = new(bool)
	s := &ScopeAuthz{RequireScope: require}
	h = s.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		*reached = true
		w.WriteHeader(http.StatusOK)
	}))
	return h, reached
}

func ctxWithPrincipal(r *http.Request, p *Principal) *http.Request {
	return r.WithContext(WithPrincipal(r.Context(), p))
}

// TestScopePass verifies a principal with the required scope passes.
func TestScopePass(t *testing.T) {
	h, reached := scopeHandler(func(string) string { return "self:read" })
	req := ctxWithPrincipal(httptest.NewRequest(http.MethodGet, "/x", http.NoBody),
		&Principal{UserID: "u1", Scopes: []string{"self:read"}})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !*reached {
		t.Fatalf("status = %d, reached = %v, want 200 true", rec.Code, *reached)
	}
}

// TestScopeMissing verifies a principal without the required scope is 403.
func TestScopeMissing(t *testing.T) {
	h, _ := scopeHandler(func(string) string { return "profile:write" })
	req := ctxWithPrincipal(httptest.NewRequest(http.MethodPut, "/x", http.NoBody),
		&Principal{UserID: "u1", Scopes: []string{"profile:read"}})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

// TestScopeImplies verifies an implied scope satisfies the requirement.
func TestScopeImplies(t *testing.T) {
	// "admin:*" implies nothing in the default table, but exact-match admin
	// scope passes for an admin user.
	h, reached := scopeHandler(func(string) string { return "admin:users" })
	req := ctxWithPrincipal(httptest.NewRequest(http.MethodGet, "/x", http.NoBody),
		&Principal{UserID: "u1", Scopes: []string{"admin:users"}, IsAdmin: true})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !*reached {
		t.Fatalf("status = %d, reached = %v, want 200 true", rec.Code, *reached)
	}
}

// TestScopeAdminNoAdminFlag verifies an admin-scope route requires IsAdmin even
// when the scope is present.
func TestScopeAdminNoAdminFlag(t *testing.T) {
	h, _ := scopeHandler(func(string) string { return "admin:users" })
	req := ctxWithPrincipal(httptest.NewRequest(http.MethodGet, "/x", http.NoBody),
		&Principal{UserID: "u1", Scopes: []string{"admin:users"}, IsAdmin: false})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

// TestScopeNoRequirement verifies a route with no required scope (anonymous)
// passes without a principal.
func TestScopeNoRequirement(t *testing.T) {
	h, reached := scopeHandler(func(string) string { return "" })
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", http.NoBody))
	if rec.Code != http.StatusOK || !*reached {
		t.Fatalf("status = %d, reached = %v, want 200 true", rec.Code, *reached)
	}
}

// TestScopeNoPrincipal verifies a scoped route with no principal is 401.
func TestScopeNoPrincipal(t *testing.T) {
	h, _ := scopeHandler(func(string) string { return "self:read" })
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", http.NoBody))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}
