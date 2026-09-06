package middleware

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestBodyLimitOversized verifies a POST body exceeding the limit is 413.
func TestBodyLimitOversized(t *testing.T) {
	h := BodyLimit(8)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Read the body; the read fails with MaxBytesError. A well-behaved
		// handler returns without writing so the middleware writes the 413.
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader("1234567890"))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", rec.Code)
	}
	body, _ := io.ReadAll(rec.Body)
	if !strings.Contains(string(body), "payload-too-large") {
		t.Fatalf("body = %q, want payload-too-large problem", body)
	}
}

// TestBodyLimitWithin verifies a body under the limit passes.
func TestBodyLimitWithin(t *testing.T) {
	var read []byte
	h := BodyLimit(64)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		read = b
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader("hello"))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if string(read) != "hello" {
		t.Fatalf("body read = %q, want hello", read)
	}
}

// TestBodyLimitDisabled verifies a zero limit disables the check.
func TestBodyLimitDisabled(t *testing.T) {
	h := BodyLimit(0)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader("large-body"))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}
