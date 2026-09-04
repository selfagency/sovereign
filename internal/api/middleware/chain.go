package middleware

import (
	"crypto/rsa"
	"fmt"
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
// Handler is the route's HTTP handler; NewHandler wraps it with the per-route
// authn/scope/timeout/idempotency middleware at registration time, so the
// authn and scope decisions are bound to the exact handler ServeMux would
// invoke (never a path lookup).
type RouteInfo struct {
	Method      string
	Path        string
	Scope       string
	Timeout     time.Duration
	Anonymous   bool
	LongRunning bool
	Idempotent  bool
	Handler     http.Handler
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

// NewHandler builds the API mux from cfg.Routes, wrapping each route's handler
// with its per-route middleware (timeout, authn, scope authz, idempotency,
// access log) at registration time, then wraps the whole mux with the shared
// chain. Binding authn/scope to the handler (rather than a path lookup) closes
// the path-mismatch bypass: a request ServeMux routes to a protected handler
// can never skip authn or scope authz, regardless of trailing slashes, subtree
// matches, or path cleaning.
//
// Middleware order (outermost first):
//
//	request-id -> panic-recover -> body-limit -> CORS -> rate-limit -> CSRF ->
//	conditional-request -> problem+json mapper -> [mux]
//	  per-route (innermost, closest to handler): timeout -> authn -> scope ->
//	  idempotency -> access log -> [handler]
//
// T1.10 mounts the returned handler into the server.
func NewHandler(cfg *ChainConfig) *lifecycle {
	// Validate the route table: every non-anonymous route must declare a
	// scope. A route with Anonymous:false and Scope:"" is a forgotten
	// declaration that would otherwise pass authn but skip scope authz,
	// letting any authenticated user through.
	for _, r := range cfg.Routes {
		if !r.Anonymous && r.Scope == "" {
			panic(fmt.Sprintf("middleware: route %s %s has no scope and is not marked anonymous", r.Method, r.Path))
		}
	}

	authn := &AuthN{
		Key:           cfg.SigningKey,
		Issuer:        cfg.Issuer,
		SessionCookie: cfg.SessionCookie,
		Sessions:      cfg.Sessions,
		Users:         cfg.Users,
		DualRead:      cfg.DualRead,
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
	// Idempotency is applied only to routes marked Idempotent, so RequireKey
	// always returns true for the handlers it wraps.
	idem := NewIdempotency(func(string) bool { return true })

	mux := http.NewServeMux()
	for _, r := range cfg.Routes {
		r := r
		h := r.Handler
		// Per-route middleware, innermost first so the request flows
		// timeout -> authn -> scope -> idempotency -> access log -> handler.
		h = func(next http.Handler) http.Handler { return AccessLog(cfg.Logger, next) }(h)
		if r.Idempotent {
			h = idem.Middleware(h)
		}
		if r.Scope != "" {
			s := &ScopeAuthz{RequireScope: func(string) string { return r.Scope }}
			h = s.Middleware(h)
		}
		if !r.Anonymous {
			h = authn.Middleware(h)
		}
		if !r.LongRunning && r.Timeout > 0 {
			h = Timeout(func(*http.Request) time.Duration { return r.Timeout })(h)
		}
		mux.Handle(r.Method+" "+r.Path, h)
	}

	h := Chain(
		RequestID, // 1. request-id
		func(next http.Handler) http.Handler { return Recover(cfg.Logger, next) }, // 2. panic-recover
		BodyLimit(cfg.BodyLimit),             // 3. body-limit
		CORS(cfg.CORSOrigins),                // 4. CORS
		rateLimiterMiddleware(cfg.RateLimit), // 5. rate-limit
		csrf.Middleware,                      // 6. CSRF
		(&Conditional{}).Middleware,          // 7. conditional-request
		ProblemMapper,                        // 8. problem+json mapper
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

// rateLimiterMiddleware adapts a RateLimiter to the middleware signature.
func rateLimiterMiddleware(rl *RateLimiter) func(http.Handler) http.Handler {
	if rl == nil {
		return func(next http.Handler) http.Handler { return next }
	}
	return rl.Middleware
}
