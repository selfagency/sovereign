// Package api provides the versioned JSON REST API surface (/api/v1).
//
// The route table in this file is the single source of truth for which
// endpoints exist, what scope each requires, and its per-route timeout.
// The OpenAPI drift test (openapi_drift_test.go) asserts this table stays
// in parity with openapi/sovereign.v1.yaml in both directions.
package api

import (
	"net/http"
	"time"

	"github.com/selfagency/sovereign/internal/api/problem"
)

// Route describes one HTTP endpoint on the /api/v1 surface.
type Route struct {
	Method  string        // "GET", "POST", ...
	Path    string        // "/api/v1/meta/capabilities"
	Scope   string        // required scope, or "" when Anonymous is set
	Timeout time.Duration // per-route timeout
	Handler http.HandlerFunc

	// Anonymous marks a route that requires no authentication. A route must
	// declare either a non-empty Scope or Anonymous=true; an empty Scope with
	// Anonymous=false is a forgotten declaration and fails the route table
	// validation test.
	Anonymous bool

	// LongRunning marks a route exempt from the per-route timeout column
	// (e.g. Phase 3 backup run/restore). Phase 1 routes must have Timeout > 0.
	LongRunning bool

	// Idempotent marks a POST route that must be protected by the idempotency
	// middleware: it reads an Idempotency-Key header and replays the original
	// response on retry. Only /auth/invite/redeem declares this in Phase 1.
	Idempotent bool
}

// notImplemented returns a 501 stub handler for routes whose real handler
// lands in a later task (T1.6 meta, T1.7 auth).
func notImplemented() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		problem.NotImplemented().Write(w)
	}
}

// New builds a *http.ServeMux from the route table using Go 1.22+ method
// patterns ("GET /api/v1/meta/capabilities"). Each route is wired to its
// handler (a 501 stub until the real handler lands). The returned mux is what
// the middleware chain (T1.4) wraps.
func New(routes []Route) *http.ServeMux {
	mux := http.NewServeMux()
	for _, r := range routes {
		r := r
		mux.HandleFunc(r.Method+" "+r.Path, r.Handler)
	}
	return mux
}

// Routes returns the current route set. Phase 1 endpoints only; later
// phases (T1.6 meta, T1.7 auth) replace the 501 stubs with real handlers.
func Routes() []Route {
	return []Route{
		// Meta / health / ready (anonymous).
		{Method: http.MethodGet, Path: "/api/v1/meta/capabilities", Anonymous: true, Timeout: 5 * time.Second, Handler: notImplemented()},
		{Method: http.MethodGet, Path: "/api/v1/meta/version", Anonymous: true, Timeout: 5 * time.Second, Handler: notImplemented()},
		{Method: http.MethodGet, Path: "/api/v1/health", Anonymous: true, Timeout: 5 * time.Second, Handler: notImplemented()},
		{Method: http.MethodGet, Path: "/api/v1/ready", Anonymous: true, Timeout: 5 * time.Second, Handler: notImplemented()},
		{Method: http.MethodGet, Path: "/api/v1/openapi.json", Anonymous: true, Timeout: 5 * time.Second, Handler: notImplemented()},

		// Auth & session.
		{Method: http.MethodPost, Path: "/api/v1/auth/invite/redeem", Anonymous: true, Idempotent: true, Timeout: 10 * time.Second, Handler: notImplemented()},
		{Method: http.MethodGet, Path: "/api/v1/auth/session", Anonymous: true, Timeout: 5 * time.Second, Handler: notImplemented()},
		{Method: http.MethodDelete, Path: "/api/v1/auth/session", Anonymous: true, Timeout: 5 * time.Second, Handler: notImplemented()},
		{Method: http.MethodPost, Path: "/api/v1/auth/session/refresh", Anonymous: true, Timeout: 5 * time.Second, Handler: notImplemented()},
		{Method: http.MethodPost, Path: "/api/v1/auth/webauthn/register/begin", Anonymous: true, Timeout: 10 * time.Second, Handler: notImplemented()},
		{Method: http.MethodPost, Path: "/api/v1/auth/webauthn/register/finish", Anonymous: true, Timeout: 10 * time.Second, Handler: notImplemented()},
		{Method: http.MethodPost, Path: "/api/v1/auth/webauthn/login/begin", Anonymous: true, Timeout: 10 * time.Second, Handler: notImplemented()},
		{Method: http.MethodPost, Path: "/api/v1/auth/webauthn/login/finish", Anonymous: true, Timeout: 10 * time.Second, Handler: notImplemented()},
	}
}
