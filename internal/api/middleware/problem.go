package middleware

import (
	"net/http"

	"github.com/selfagency/sovereign/internal/api/problem"
)

// ProblemMapper guarantees error responses carry an RFC 9457 problem+json
// body. Middleware and handlers that already write a problem via
// problem.Problem.Write are left untouched. When the inner handler returns an
// error status (>= 400) without writing a body or content type, ProblemMapper
// synthesizes a problem+json document matching the status so no bare or empty
// error response leaks to clients.
func ProblemMapper(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := newResponseRecorder(w)
		next.ServeHTTP(rec, r)
		if rec.status >= 400 && rec.bytes == 0 && rec.Header().Get("Content-Type") == "" {
			problemFromStatus(rec.status).Write(rec)
		}
	})
}

// problemFromStatus maps a status code to its problem+json representation.
func problemFromStatus(status int) *problem.Problem {
	switch status {
	case http.StatusUnauthorized:
		return problem.Unauthenticated()
	case http.StatusForbidden:
		return problem.Forbidden()
	case http.StatusNotFound:
		return problem.NotFound()
	case http.StatusConflict:
		return problem.Conflict()
	case http.StatusRequestEntityTooLarge:
		return problem.PayloadTooLarge()
	case http.StatusTooManyRequests:
		return problem.RateLimited(0)
	case http.StatusInternalServerError:
		return problem.Internal()
	case http.StatusNotImplemented:
		return problem.NotImplemented()
	default:
		return &problem.Problem{Status: status}
	}
}
