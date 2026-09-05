package middleware

import (
	"context"
	"net/http"

	"github.com/google/uuid"
)

// requestIDHeader is the standard request-correlation header. RequestID reads
// it to honor upstream-issued IDs (proxies, load balancers) and echoes it back
// so the caller can correlate the response with the access-log entry.
const requestIDHeader = "X-Request-Id"

// RequestID assigns every request a stable ID: it reuses a client-supplied
// X-Request-Id when present, otherwise generates a fresh UUID. The ID is
// stored in the request context (consumed by Recover, ProblemMapper, and the
// access log) and echoed back in the response header.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get(requestIDHeader)
		if id == "" {
			id = uuid.NewString()
		}
		w.Header().Set(requestIDHeader, id)
		next.ServeHTTP(w, r.WithContext(withRequestID(r.Context(), id)))
	})
}

// withRequestID returns a copy of ctx carrying the request ID under the
// private key. Access via ctxRequestID / RequestIDFromContext.
func withRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey{}, id)
}
