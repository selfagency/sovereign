package middleware

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestRecoverPanic verifies a panicking handler returns 500 problem.Internal
// and does not crash the server.
func TestRecoverPanic(t *testing.T) {
	panicHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		panic("boom")
	})
	var logBuf strings.Builder
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))

	h := RequestID(Recover(logger, panicHandler))
	req := httptest.NewRequest(http.MethodGet, "/x", http.NoBody)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/problem+json") {
		t.Fatalf("content-type = %q, want problem+json", ct)
	}
	body, _ := io.ReadAll(rec.Body)
	if !strings.Contains(string(body), "internal") {
		t.Fatalf("body = %q, want internal problem", body)
	}
	// The stack must be logged at error level.
	if !strings.Contains(logBuf.String(), "panic recovered") {
		t.Fatalf("log = %q, want panic logged", logBuf.String())
	}
	if !strings.Contains(logBuf.String(), "goroutine") {
		t.Fatalf("log = %q, want stack trace logged", logBuf.String())
	}
}

// TestRecoverNormalPasses verifies Recover forwards a healthy handler unchanged.
func TestRecoverNormalPasses(t *testing.T) {
	h := Recover(nil, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", http.NoBody))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}
