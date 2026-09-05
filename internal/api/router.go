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

	"github.com/selfagency/sovereign/internal/api/dto"
	"github.com/selfagency/sovereign/internal/api/middleware"
	"github.com/selfagency/sovereign/internal/api/problem"
	v1auth "github.com/selfagency/sovereign/internal/api/v1/auth"
	"github.com/selfagency/sovereign/internal/api/v1/meta"
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

// phase1Meta is the meta/health/ready handler used by the Phase 1 route
// table. It reports only the features actually wired for Phase 1 (the API
// itself, plus web_authn/oidc plumbing); data-plane features are reported
// false until their wiring lands in Phase 3/4. Production wiring (T1.10)
// should construct a meta.Handler with the real dependencies and pass the
// resulting routes in place of these defaults.
var phase1Meta = meta.New(
	meta.WithCapabilities(dto.Capabilities{
		WebAuthn: true,
		OIDC:     true,
	}),
	meta.WithVersion(meta.VersionInfo{}),
)

// RoutesFor returns the current route set with the given meta handler wired
// to the /meta, /health, /ready, and /openapi.json routes, and the auth routes
// as 501 stubs. Routes() uses the Phase-1 default handler; the server passes a
// handler wired to the real capabilities/version/ping when it assembles the
// control plane (T1.10). The route table is the single source of truth for
// both entry points.
func RoutesFor(h *meta.Handler) []Route {
	return routesFor(h, nil)
}

// RoutesForAPI returns the current route set with both the given meta handler
// and the auth handler wired to the /api/v1/auth/* and /invite/{token} routes.
// Pass nil for the auth handler to keep those routes as 501 stubs (the drift
// test checks parity only).
func RoutesForAPI(h *meta.Handler, ah *v1auth.Handler) []Route {
	return routesFor(h, ah)
}

// Routes returns the current route set with the Phase-1 default meta handler
// (capabilities web_authn+oidc, empty version) and 501 auth stubs. Production
// wiring uses RoutesForAPI with a fully-wired auth handler.
func Routes() []Route {
	return RoutesFor(phase1Meta)
}

// routesFor is the shared route-table constructor. When ah is nil, the auth
// routes are 501 stubs; otherwise they delegate to the auth handler.
func routesFor(h *meta.Handler, ah *v1auth.Handler) []Route {
	return append([]Route{
		// Meta / health / ready (anonymous).
		{Method: http.MethodGet, Path: "/api/v1/meta/capabilities", Anonymous: true, Timeout: 5 * time.Second, Handler: h.Capabilities},
		{Method: http.MethodGet, Path: "/api/v1/meta/version", Anonymous: true, Timeout: 5 * time.Second, Handler: h.Version},
		{Method: http.MethodGet, Path: "/api/v1/health", Anonymous: true, Timeout: 5 * time.Second, Handler: h.Health},
		{Method: http.MethodGet, Path: "/api/v1/ready", Anonymous: true, Timeout: 5 * time.Second, Handler: h.Ready},
		{Method: http.MethodGet, Path: "/api/v1/openapi.json", Anonymous: true, Timeout: 5 * time.Second, Handler: h.OpenAPI},
	}, authRoutes(ah)...)
}

// authRoutes builds the auth/session/webauthn route set. When ah is nil the
// handlers are 501 stubs; otherwise they delegate to the auth handler.
func authRoutes(ah *v1auth.Handler) []Route {
	// Resolve the handlers once; referencing a method value on a nil receiver
	// panics, so only bind when ah is non-nil.
	redeem, getSess, delSess, refresh, regBegin, regFinish, loginBegin, loginFinish, inviteGet := stub(), stub(), stub(), stub(), stub(), stub(), stub(), stub(), stub()
	if ah != nil {
		redeem, getSess, delSess, refresh = ah.RedeemInvite, ah.GetSession, ah.DeleteSession, ah.RefreshSession
		regBegin, regFinish = ah.RegisterBegin, ah.RegisterFinish
		loginBegin, loginFinish = ah.LoginBegin, ah.LoginFinish
		inviteGet = ah.InviteGet
	}
	return []Route{
		{Method: http.MethodPost, Path: "/api/v1/auth/invite/redeem", Anonymous: true, Idempotent: true, Timeout: 10 * time.Second, Handler: redeem},
		{Method: http.MethodGet, Path: "/api/v1/auth/session", Scope: "self", Timeout: 5 * time.Second, Handler: getSess},
		{Method: http.MethodDelete, Path: "/api/v1/auth/session", Scope: "self", Timeout: 5 * time.Second, Handler: delSess},
		{Method: http.MethodPost, Path: "/api/v1/auth/session/refresh", Scope: "self", Timeout: 5 * time.Second, Handler: refresh},
		{Method: http.MethodPost, Path: "/api/v1/auth/webauthn/register/begin", Scope: "self", Timeout: 10 * time.Second, Handler: regBegin},
		{Method: http.MethodPost, Path: "/api/v1/auth/webauthn/register/finish", Scope: "self", Timeout: 10 * time.Second, Handler: regFinish},
		{Method: http.MethodPost, Path: "/api/v1/auth/webauthn/login/begin", Anonymous: true, Timeout: 10 * time.Second, Handler: loginBegin},
		{Method: http.MethodPost, Path: "/api/v1/auth/webauthn/login/finish", Anonymous: true, Timeout: 10 * time.Second, Handler: loginFinish},
		// Anonymous browser entry point (M1): redeem a magic link into a session
		// cookie and redirect to /panel. Token-in-URL leaks are acknowledged.
		{Method: http.MethodGet, Path: "/invite/{token}", Anonymous: true, Timeout: 10 * time.Second, Handler: inviteGet},
	}
}

// stub returns a 501 stub handler.
func stub() http.HandlerFunc { return notImplemented() }

// ToRouteInfo adapts the api.Route table to the middleware.RouteInfo slice
// that NewHandler consumes, attaching the real handler from each Route.Handler.
// Deriving the middleware table from api.Routes() guarantees the authn/scope
// decisions use the exact same route set the mux registers: they can never
// diverge.
func ToRouteInfo(routes []Route) []middleware.RouteInfo {
	infos := make([]middleware.RouteInfo, len(routes))
	for i, r := range routes {
		infos[i] = middleware.RouteInfo{
			Method:      r.Method,
			Path:        r.Path,
			Scope:       r.Scope,
			Timeout:     r.Timeout,
			Anonymous:   r.Anonymous,
			LongRunning: r.LongRunning,
			Idempotent:  r.Idempotent,
			Handler:     r.Handler,
		}
	}
	return infos
}
