// Package problem implements RFC 9457 Problem Details
// (application/problem+json), the error contract for the Sovereign REST API.
package problem

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// baseURI is the stable prefix for problem type URIs. The domain is
// substituted at deployment; the path segment is fixed by the registry.
const baseURI = "https://sovereign.example/problems/"

// Problem is an RFC 9457 problem details document.
type Problem struct {
	Type     string       `json:"type"`
	Title    string       `json:"title"`
	Status   int          `json:"status"`
	Detail   string       `json:"detail,omitempty"`
	Instance string       `json:"instance,omitempty"`
	Errors   []FieldError `json:"errors,omitempty"`

	// retryAfter is the Retry-After duration for rate-limited problems. It is
	// not serialized; Write emits it as a header.
	retryAfter time.Duration
}

// FieldError is a single validation error within a validation-failed problem.
type FieldError struct {
	Field  string `json:"field"`
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

// newProblem builds a Problem with the given type slug, title, and status.
func newProblem(slug, title string, status int) *Problem {
	return &Problem{
		Type:   baseURI + slug,
		Title:  title,
		Status: status,
	}
}

// InvalidRequest reports a malformed or unparseable request (400).
func InvalidRequest(detail string) *Problem {
	return &Problem{
		Type:   baseURI + "invalid-request",
		Title:  "Invalid Request",
		Status: http.StatusBadRequest,
		Detail: detail,
	}
}

// ValidationFailed reports one or more field-level validation errors (422).
func ValidationFailed(errs []FieldError) *Problem {
	return &Problem{
		Type:   baseURI + "validation-failed",
		Title:  "Validation Failed",
		Status: http.StatusUnprocessableEntity,
		Errors: errs,
	}
}

// Unauthenticated reports a missing or invalid credential (401).
func Unauthenticated() *Problem {
	return newProblem("unauthenticated", "Unauthenticated", http.StatusUnauthorized)
}

// InsufficientScope reports a valid credential lacking the required scope (403).
func InsufficientScope() *Problem {
	return newProblem("insufficient-scope", "Insufficient Scope", http.StatusForbidden)
}

// Forbidden reports an authenticated principal denied access (403).
func Forbidden() *Problem {
	return newProblem("forbidden", "Forbidden", http.StatusForbidden)
}

// NotFound reports a missing resource (404).
func NotFound() *Problem {
	return newProblem("not-found", "Not Found", http.StatusNotFound)
}

// Conflict reports a state conflict, e.g. a duplicate resource (409).
func Conflict() *Problem {
	return newProblem("conflict", "Conflict", http.StatusConflict)
}

// PreconditionRequired reports a missing required precondition, e.g. an
// If-Match header (428).
func PreconditionRequired() *Problem {
	return newProblem("precondition-required", "Precondition Required", http.StatusPreconditionRequired)
}

// PreconditionFailed reports a failed precondition, e.g. a stale If-Match (412).
func PreconditionFailed() *Problem {
	return newProblem("precondition-failed", "Precondition Failed", http.StatusPreconditionFailed)
}

// PayloadTooLarge reports a request body exceeding the server limit (413).
func PayloadTooLarge() *Problem {
	return newProblem("payload-too-large", "Payload Too Large", http.StatusRequestEntityTooLarge)
}

// RateLimited reports the client has exceeded a rate limit (429). The
// Retry-After header is set from retryAfter when the problem is written.
func RateLimited(retryAfter time.Duration) *Problem {
	return &Problem{
		Type:       baseURI + "rate-limited",
		Title:      "Rate Limited",
		Status:     http.StatusTooManyRequests,
		retryAfter: retryAfter,
	}
}

// NotImplemented reports an endpoint that is recognized but not yet
// implemented (501).
func NotImplemented() *Problem {
	return newProblem("not-implemented", "Not Implemented", http.StatusNotImplemented)
}

// ServiceUnavailable reports a dependency failure during readiness (503).
func ServiceUnavailable() *Problem {
	return newProblem("service-unavailable", "Service Unavailable", http.StatusServiceUnavailable)
}

// Internal reports an unexpected server failure (500).
func Internal() *Problem {
	return newProblem("internal", "Internal Server Error", http.StatusInternalServerError)
}

// Write serializes the problem to w with the correct content type, nosniff
// header, and status code. For rate-limited problems it also sets Retry-After.
func (p *Problem) Write(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if p.retryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(int(p.retryAfter.Seconds())))
	}
	w.WriteHeader(p.Status)
	_ = json.NewEncoder(w).Encode(p)
}

// Error returns a human-readable string so Problem satisfies error.
func (p *Problem) Error() string {
	return fmt.Sprintf("%s: %s", p.Title, p.Detail)
}
