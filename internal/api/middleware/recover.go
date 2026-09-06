package middleware

import (
	"log/slog"
	"net/http"
	"runtime/debug"

	"github.com/selfagency/sovereign/internal/api/problem"
)

// Recover converts a handler panic into a 500 problem+json response instead of
// crashing the process. The stack trace is logged at error level, tagged with
// the request ID for correlation; the client only ever sees a generic internal
// error (never the stack or internal state).
func Recover(logger *slog.Logger, next http.Handler) http.Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				logger.Error("panic recovered",
					"request_id", ctxRequestID(r.Context()),
					"method", r.Method,
					"path", r.URL.Path,
					"panic", rec,
					"stack", string(debug.Stack()),
				)
				problem.Internal().Write(w)
			}
		}()
		next.ServeHTTP(w, r)
	})
}
