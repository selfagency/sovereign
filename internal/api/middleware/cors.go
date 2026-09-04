package middleware

import (
	"net/http"
)

// CORS implements deny-by-default cross-origin resource sharing against an
// explicit allowlist. When api.cors_origins is empty (default) no CORS headers
// are set, so browsers block every cross-origin read. When origins are set,
// matching origins are allowed with credentials (Access-Control-Allow-
// Credentials: true). '*' is never combined with credentials. The Origin
// header is always listed in Vary so caches distinguish same-origin from
// allowed cross-origin responses.
//
// Preflight OPTIONS requests to allowed origins are answered with the CORS
// headers and a 204; disallowed preflights fall through to the normal handler
// with no CORS headers (the browser blocks).
func CORS(allowedOrigins []string) func(http.Handler) http.Handler {
	allowed := make(map[string]bool, len(allowedOrigins))
	for _, o := range allowedOrigins {
		allowed[o] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Add("Vary", "Origin")

			origin := r.Header.Get("Origin")
			if origin == "" || !allowed[origin] {
				// Disallowed or absent origin: set no CORS headers. The browser
				// blocks the response, which is the deny-by-default behavior.
				next.ServeHTTP(w, r)
				return
			}

			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")

			if r.Method == http.MethodOptions {
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Request-Id, X-CSRF-Token, Idempotency-Key, If-None-Match")
				w.Header().Set("Access-Control-Max-Age", "600")
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
