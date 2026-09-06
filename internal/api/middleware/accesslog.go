package middleware

import (
	"log/slog"
	"net/http"
	"time"
)

// AccessLog emits a structured slog access-log entry per request: request ID,
// principal ID, method, path, status, duration, and response bytes. It is the
// outermost middleware so it always wraps the chain.
func AccessLog(logger *slog.Logger, next http.Handler) http.Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := newResponseRecorder(w)
		next.ServeHTTP(rec, r)

		// PII discipline: log the principal ID (a UUID), never email or token.
		principalID := ""
		if p := PrincipalFromContext(r.Context()); p != nil {
			principalID = p.UserID
		}
		logger.Info("request",
			"request_id", ctxRequestID(r.Context()),
			"principal", principalID,
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.status,
			"duration_ms", time.Since(start).Milliseconds(),
			"bytes", rec.bytes,
		)
	})
}
