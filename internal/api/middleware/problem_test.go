package middleware

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestProblemMapperEmptyError verifies a bare error status with no body gets a
// problem+json document.
func TestProblemMapperEmptyError(t *testing.T) {
	h := ProblemMapper(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", http.NoBody))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	body, _ := io.ReadAll(rec.Body)
	if !strings.Contains(string(body), "internal") {
		t.Fatalf("body = %q, want internal problem", body)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/problem+json") {
		t.Fatalf("content-type = %q, want problem+json", ct)
	}
}

// TestProblemMapperPassthrough verifies a successful response is untouched.
func TestProblemMapperPassthrough(t *testing.T) {
	h := ProblemMapper(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", http.NoBody))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if rec.Body.String() != `{"ok":true}` {
		t.Fatalf("body = %q, want untouched", rec.Body.String())
	}
}

// TestProblemMapperExistingProblem verifies an existing problem body is left
// as-is (not double-wrapped).
func TestProblemMapperExistingProblem(t *testing.T) {
	h := ProblemMapper(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"type":"rate-limited"}`))
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", http.NoBody))
	if rec.Body.String() != `{"type":"rate-limited"}` {
		t.Fatalf("body = %q, want existing problem untouched", rec.Body.String())
	}
}

// TestProblemFromStatus verifies every status mapping in problemFromStatus.
func TestProblemFromStatus(t *testing.T) {
	cases := []struct {
		name   string
		status int
		title  string // expected problem title, or "" to just assert the status round-trips
	}{
		{"unauthorized", http.StatusUnauthorized, "Unauthenticated"},
		{"forbidden", http.StatusForbidden, "Forbidden"},
		{"not-found", http.StatusNotFound, "Not Found"},
		{"conflict", http.StatusConflict, "Conflict"},
		{"payload-too-large", http.StatusRequestEntityTooLarge, "Payload Too Large"},
		{"too-many-requests", http.StatusTooManyRequests, "Rate Limited"},
		{"internal", http.StatusInternalServerError, "Internal Server Error"},
		{"not-implemented", http.StatusNotImplemented, "Not Implemented"},
		{"default", http.StatusBadGateway, ""}, // unmapped -> bare Problem with just Status
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := problemFromStatus(tc.status)
			if p == nil {
				t.Fatalf("problemFromStatus(%d) = nil", tc.status)
			}
			if p.Status != tc.status {
				t.Fatalf("problem.Status = %d, want %d", p.Status, tc.status)
			}
			if tc.title != "" && p.Title != tc.title {
				t.Fatalf("problem.Title = %q, want %q", p.Title, tc.title)
			}
		})
	}
}

// TestProblemMapperSynthesizesStatus verifies ProblemMapper synthesizes a
// problem body for each status a bare (empty, no content-type) error handler
// might return.
func TestProblemMapperSynthesizesStatus(t *testing.T) {
	for _, status := range []int{
		http.StatusUnauthorized,
		http.StatusForbidden,
		http.StatusNotFound,
		http.StatusConflict,
		http.StatusRequestEntityTooLarge,
		http.StatusTooManyRequests,
		http.StatusInternalServerError,
		http.StatusNotImplemented,
		http.StatusBadGateway,
	} {
		h := ProblemMapper(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
		}))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", http.NoBody))
		if rec.Code != status {
			t.Fatalf("status %d: got %d", status, rec.Code)
		}
		if rec.Body.Len() == 0 {
			t.Fatalf("status %d: no body synthesized", status)
		}
		if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/problem+json") {
			t.Fatalf("status %d: content-type = %q", status, ct)
		}
	}
}
