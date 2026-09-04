package middleware

import (
	"crypto/rsa"
	"log/slog"
	"net/http"
	"time"
)

// Chain composes middlewares in the order given: the first argument is the
// outermost middleware (runs first on the request path). NewHandler calls it
// with the documented fixed order.
func Chain(middlewares ...func(http.Handler) http.Handler) func(http.Handler) http.Handler {
	return func(handler http.Handler) http.Handler {
		for i := len(middlewares) - 1; i >= 0; i-- {
			handler = middlewares[i](handler)
		}
		return handler
	}
}

// RouteInfo is the per-route metadata the chain needs. It mirrors the fields
// of api.Route that drive middleware behavior; the server package adapts
// api.Route here (avoiding an import cycle, since api imports middleware).
type RouteInfo struct {
	Method      string
	Path        string
	Scope       string
	Timeout     time.Duration
	Anonymous   bool
	LongRunning bool
	Idempotent  bool
}

// ChainConfig carries the dependencies NewHandler needs to build the chain.
type ChainConfig struct {
	Routes        []RouteInfo
	Logger        *slog.Logger
	SigningKey    *rsa.PrivateKey
	Issuer        string
	SessionCookie string
	Sessions      SessionStore
	Users         UserStore
	DualRead      bool
	CORSOrigins   []string
	RateLimit     *RateLimiter
	BodyLimit     int64
}

// NewHandler applies the full middleware chain in the documented fixed order
// around the given API mux. Middleware order (outermost first):
//
//	request-id -> panic-recover -> body-limit -> per-route timeout -> CORS ->
//	rate-limit -> authn -> CSRF -> scope authz -> conditional-request ->
//	idempotency -> problem+json mapper -> access log -> [mux handler]
//
// T1.10 mounts the returned handler into the server.
func NewHandler(mux *http.ServeMux, cfg *ChainConfig) *lifecycle {
	routeByPath := indexRoutes(cfg.Routes)
	timeoutByRoute := indexRoutesByMethodPath(cfg.Routes)

	authn := &AuthN{
		Key:           cfg.SigningKey,
		Issuer:        cfg.Issuer,
		SessionCookie: cfg.SessionCookie,
		Sessions:      cfg.Sessions,
		Users:         cfg.Users,
		DualRead:      cfg.DualRead,
		RequireAuth: func(path string) bool {
			r, ok := routeByPath[path]
			return ok && !r.Anonymous
		},
	}
	scopeAuthz := &ScopeAuthz{
		RequireScope: func(path string) string {
			if r, ok := routeByPath[path]; ok {
				return r.Scope
			}
			return ""
		},
	}
	csrf := &CSRF{IsCookiePrincipal: func(r *http.Request) bool {
		// A cookie principal is either authenticated-by-cookie OR simply carries
		// the session cookie. Enforcing CSRF whenever the session cookie is
		// present (even on anonymous routes) is the safe default: it prevents a
		// cross-site unsafe request that would otherwise be sent with the cookie.
		if p := PrincipalFromContext(r.Context()); p != nil && p.IsCookie {
			return true
		}
		return cfg.SessionCookie != "" && hasCookie(r, cfg.SessionCookie)
	}}
	idem := NewIdempotency(func(path string) bool {
		if r, ok := routeByPath[path]; ok {
			return r.Idempotent
		}
		return false
	})

	h := Chain(
		RequestID, // 1. request-id
		func(next http.Handler) http.Handler { return Recover(cfg.Logger, next) }, // 2. panic-recover
		BodyLimit(cfg.BodyLimit),              // 3. body-limit
		Timeout(routeTimeout(timeoutByRoute)), // 4. per-route timeout
		CORS(cfg.CORSOrigins),                 // 5. CORS
		rateLimiterMiddleware(cfg.RateLimit),  // 6. rate-limit
		authn.Middleware,                      // 7. authn
		csrf.Middleware,                       // 8. CSRF
		scopeAuthz.Middleware,                 // 9. scope authz
		(&Conditional{}).Middleware,           // 10. conditional-request
		idem.Middleware,                       // 11. idempotency
		ProblemMapper,                         // 12. problem+json mapper
		func(next http.Handler) http.Handler { return AccessLog(cfg.Logger, next) }, // 13. access log (innermost)
	)(mux)

	return &lifecycle{chain: h, idem: idem}
}

// lifecycle wraps the composed handler and exposes Close so callers (server
// teardown) can stop the chain's owned background goroutines.
type lifecycle struct {
	chain http.Handler
	idem  *Idempotency
}

func (l *lifecycle) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	l.chain.ServeHTTP(w, r)
}

// Close stops the middleware chain's background goroutines (idempotency pruner).
func (l *lifecycle) Close() {
	if l.idem != nil {
		l.idem.Close()
	}
}

// indexRoutes maps a route path to its RouteInfo. Paths are unique in the
// route table; the middleware callbacks (authn, scope, idempotency) key on
// path alone. The timeout middleware keys on method+path via routeKey.
func indexRoutes(routes []RouteInfo) map[string]RouteInfo {
	m := make(map[string]RouteInfo, len(routes))
	for _, r := range routes {
		m[r.Path] = r
	}
	return m
}

// indexRoutesByMethodPath maps "METHOD path" to its RouteInfo for the timeout
// middleware, which must distinguish methods on the same path.
func indexRoutesByMethodPath(routes []RouteInfo) map[string]RouteInfo {
	m := make(map[string]RouteInfo, len(routes))
	for _, r := range routes {
		m[r.Method+" "+r.Path] = r
	}
	return m
}

// routeKey returns the "METHOD path" route key for a request.
func routeKey(r *http.Request) string { return r.Method + " " + r.URL.Path }

// routeTimeout returns the per-route timeout budget: 0 disables the timeout
// (unregistered or LongRunning routes). The timeout middleware treats <= 0 as
// "no timeout".
func routeTimeout(routes map[string]RouteInfo) func(*http.Request) time.Duration {
	return func(r *http.Request) time.Duration {
		ri, ok := routes[routeKey(r)]
		if !ok || ri.LongRunning {
			return 0
		}
		return ri.Timeout
	}
}

// rateLimiterMiddleware adapts a RateLimiter to the middleware signature.
func rateLimiterMiddleware(rl *RateLimiter) func(http.Handler) http.Handler {
	if rl == nil {
		return func(next http.Handler) http.Handler { return next }
	}
	return rl.Middleware
}
