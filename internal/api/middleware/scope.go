package middleware

import (
	"net/http"
	"strings"

	"github.com/selfagency/sovereign/internal/api/problem"
	"github.com/selfagency/sovereign/internal/wiring"
)

// ScopeAuthz is table-driven, coarse scope authorization. The route declares
// its required scope (Route.Scope); the principal's granted scopes (from the
// authn context) are checked via wiring.ScopesContains (exact match plus the
// scopeImplies table). Admin routes declare a coarse scope under "admin:*" and
// additionally require IsAdmin (belt and braces). Anonymous routes carry no
// principal and are skipped.
//
// requireScope returns the route's required scope for the request path, or ""
// for routes that require no scope (anonymous).
type ScopeAuthz struct {
	RequireScope func(path string) string
}

// Middleware returns the scope-authorization handler.
func (s *ScopeAuthz) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		want := ""
		if s.RequireScope != nil {
			want = s.RequireScope(r.URL.Path)
		}
		if want == "" {
			// Anonymous or no declared scope: nothing to enforce.
			next.ServeHTTP(w, r)
			return
		}
		p := PrincipalFromContext(r.Context())
		if p == nil {
			problem.Unauthenticated().Write(w)
			return
		}
		if !wiring.ScopesContains(p.Scopes, want) {
			problem.InsufficientScope().Write(w)
			return
		}
		// Admin routes (coarse scope admin:*) need the scope AND the admin flag.
		if isAdminScope(want) && !p.IsAdmin {
			problem.Forbidden().Write(w)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// isAdminScope reports whether a coarse scope is an admin scope (admin:*).
func isAdminScope(scope string) bool {
	return strings.HasPrefix(scope, "admin:")
}
