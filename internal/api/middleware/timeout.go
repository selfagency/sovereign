package middleware

import (
	"net/http"
	"time"
)

// Timeout enforces a per-route deadline. getTimeout returns the timeout budget
// for the current request (0 or negative disables the timeout). It uses
// http.TimeoutHandler so a handler that exceeds its budget is aborted with a
// timeout response while the server keeps serving other requests.
//
// The route table drives this: NewHandler supplies a getTimeout that returns
// the route's Timeout column, or 0 for routes marked LongRunning (Phase 3
// backup run/restore), so slow long-running handlers are never killed by the
// default timeout.
func Timeout(getTimeout func(*http.Request) time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			d := getTimeout(r)
			if d <= 0 {
				next.ServeHTTP(w, r)
				return
			}
			// http.TimeoutHandler serves a 503 text body on timeout and closes
			// the request body; it never crashes the server.
			http.TimeoutHandler(next, d, "request timed out").ServeHTTP(w, r)
		})
	}
}
