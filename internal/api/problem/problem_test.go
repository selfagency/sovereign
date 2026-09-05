// Package problem implements RFC 9457 Problem Details (application/problem+json),
// the error contract for the Sovereign REST API.
package problem

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// goldenJSON is the exact expected serialization for each problem type.
// The type URI is stable under https://<domain>/problems/.
var goldenJSON = map[string]string{
	"invalid-request":       `{"type":"https://sovereign.example/problems/invalid-request","title":"Invalid Request","status":400,"detail":"bad body"}`,
	"validation-failed":     `{"type":"https://sovereign.example/problems/validation-failed","title":"Validation Failed","status":422,"errors":[{"field":"email","code":"required","detail":"email is required"},{"field":"age","code":"min","detail":"age must be at least 18"}]}`,
	"unauthenticated":       `{"type":"https://sovereign.example/problems/unauthenticated","title":"Unauthenticated","status":401}`,
	"insufficient-scope":    `{"type":"https://sovereign.example/problems/insufficient-scope","title":"Insufficient Scope","status":403}`,
	"forbidden":             `{"type":"https://sovereign.example/problems/forbidden","title":"Forbidden","status":403}`,
	"not-found":             `{"type":"https://sovereign.example/problems/not-found","title":"Not Found","status":404}`,
	"conflict":              `{"type":"https://sovereign.example/problems/conflict","title":"Conflict","status":409}`,
	"precondition-required": `{"type":"https://sovereign.example/problems/precondition-required","title":"Precondition Required","status":428}`,
	"precondition-failed":   `{"type":"https://sovereign.example/problems/precondition-failed","title":"Precondition Failed","status":412}`,
	"payload-too-large":     `{"type":"https://sovereign.example/problems/payload-too-large","title":"Payload Too Large","status":413}`,
	"rate-limited":          `{"type":"https://sovereign.example/problems/rate-limited","title":"Rate Limited","status":429}`,
	"not-implemented":       `{"type":"https://sovereign.example/problems/not-implemented","title":"Not Implemented","status":501}`,
	"service-unavailable":   `{"type":"https://sovereign.example/problems/service-unavailable","title":"Service Unavailable","status":503}`,
	"internal":              `{"type":"https://sovereign.example/problems/internal","title":"Internal Server Error","status":500}`,
}

// statusFor maps each problem type to its expected HTTP status code.
var statusFor = map[string]int{
	"invalid-request":       http.StatusBadRequest,
	"validation-failed":     http.StatusUnprocessableEntity,
	"unauthenticated":       http.StatusUnauthorized,
	"insufficient-scope":    http.StatusForbidden,
	"forbidden":             http.StatusForbidden,
	"not-found":             http.StatusNotFound,
	"conflict":              http.StatusConflict,
	"precondition-required": http.StatusPreconditionRequired,
	"precondition-failed":   http.StatusPreconditionFailed,
	"payload-too-large":     http.StatusRequestEntityTooLarge,
	"rate-limited":          http.StatusTooManyRequests,
	"not-implemented":       http.StatusNotImplemented,
	"service-unavailable":   http.StatusServiceUnavailable,
	"internal":              http.StatusInternalServerError,
}

// constructors builds a *Problem for each type. ValidationFailed and
// InvalidRequest take arguments; the rest are argument-free.
func constructors() map[string]*Problem {
	return map[string]*Problem{
		"invalid-request":       InvalidRequest("bad body"),
		"validation-failed":     ValidationFailed([]FieldError{{Field: "email", Code: "required", Detail: "email is required"}, {Field: "age", Code: "min", Detail: "age must be at least 18"}}),
		"unauthenticated":       Unauthenticated(),
		"insufficient-scope":    InsufficientScope(),
		"forbidden":             Forbidden(),
		"not-found":             NotFound(),
		"conflict":              Conflict(),
		"precondition-required": PreconditionRequired(),
		"precondition-failed":   PreconditionFailed(),
		"payload-too-large":     PayloadTooLarge(),
		"rate-limited":          RateLimited(30 * time.Second),
		"not-implemented":       NotImplemented(),
		"service-unavailable":   ServiceUnavailable(),
		"internal":              Internal(),
	}
}

// TestGoldenJSON verifies each problem type serializes to the exact expected
// JSON: type URI, title, status, detail, instance, and errors[].
func TestGoldenJSON(t *testing.T) {
	for name, want := range goldenJSON {
		t.Run(name, func(t *testing.T) {
			p := constructors()[name]
			got, err := json.Marshal(p)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if string(got) != want {
				t.Errorf("json mismatch\n got: %s\nwant: %s", got, want)
			}
		})
	}
}

// TestStatusCodes verifies each problem type carries the correct status code.
func TestStatusCodes(t *testing.T) {
	for name, want := range statusFor {
		t.Run(name, func(t *testing.T) {
			if got := constructors()[name].Status; got != want {
				t.Errorf("status = %d, want %d", got, want)
			}
		})
	}
}

// TestWrite verifies Write sets Content-Type, X-Content-Type-Options, the
// status code, and writes the JSON body.
func TestWrite(t *testing.T) {
	for name := range goldenJSON {
		t.Run(name, func(t *testing.T) {
			p := constructors()[name]
			rec := httptest.NewRecorder()
			p.Write(rec)

			if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
				t.Errorf("Content-Type = %q, want application/problem+json", ct)
			}
			if nosniff := rec.Header().Get("X-Content-Type-Options"); nosniff != "nosniff" {
				t.Errorf("X-Content-Type-Options = %q, want nosniff", nosniff)
			}
			if rec.Code != p.Status {
				t.Errorf("status = %d, want %d", rec.Code, p.Status)
			}
			if got := strings.TrimSpace(rec.Body.String()); got != goldenJSON[name] {
				t.Errorf("body mismatch\n got: %s\nwant: %s", got, goldenJSON[name])
			}
		})
	}
}

// TestRateLimitedRetryAfter verifies RateLimited sets the Retry-After header.
func TestRateLimitedRetryAfter(t *testing.T) {
	p := RateLimited(90 * time.Second)
	rec := httptest.NewRecorder()
	p.Write(rec)

	if ra := rec.Header().Get("Retry-After"); ra != "90" {
		t.Errorf("Retry-After = %q, want 90", ra)
	}
}

// TestError verifies Problem satisfies the error interface.
func TestError(t *testing.T) {
	p := NotFound()
	if got := p.Error(); got == "" {
		t.Error("Error() returned empty string")
	}
	if !strings.Contains(p.Error(), "Not Found") {
		t.Errorf("Error() = %q, want it to contain title", p.Error())
	}
}

// TestInstanceRoundTrip verifies Instance (request ID) is serialized when set.
func TestInstanceRoundTrip(t *testing.T) {
	p := NotFound()
	p.Instance = "req-abc123"
	got, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := `{"type":"https://sovereign.example/problems/not-found","title":"Not Found","status":404,"instance":"req-abc123"}`
	if string(got) != want {
		t.Errorf("json mismatch\n got: %s\nwant: %s", got, want)
	}
}
