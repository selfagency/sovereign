package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestRequestIDGenerates verifies a request without X-Request-Id gets a fresh
// UUID echoed back and stored in context.
func TestRequestIDGenerates(t *testing.T) {
	var got string
	h := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = RequestIDFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/x", http.NoBody)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Header().Get(requestIDHeader) == "" {
		t.Fatal("response missing X-Request-Id")
	}
	if rec.Header().Get(requestIDHeader) != got {
		t.Fatalf("context id %q != response header %q", got, rec.Header().Get(requestIDHeader))
	}
}

// TestRequestIDEchoes verifies a client-supplied X-Request-Id is honored.
func TestRequestIDEchoes(t *testing.T) {
	h := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if id := RequestIDFromContext(r.Context()); id != "client-id" {
			t.Fatalf("context id = %q, want client-id", id)
		}
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/x", http.NoBody)
	req.Header.Set(requestIDHeader, "client-id")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Header().Get(requestIDHeader) != "client-id" {
		t.Fatalf("response header = %q, want client-id", rec.Header().Get(requestIDHeader))
	}
}
