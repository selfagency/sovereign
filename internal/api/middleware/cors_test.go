package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestCORSAllowed verifies an allowlisted origin gets credentials headers.
func TestCORSAllowed(t *testing.T) {
	h := CORS([]string{"https://app.example"})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/x", http.NoBody)
	req.Header.Set("Origin", "https://app.example")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Header().Get("Access-Control-Allow-Origin") != "https://app.example" {
		t.Fatalf("allow-origin = %q", rec.Header().Get("Access-Control-Allow-Origin"))
	}
	if rec.Header().Get("Access-Control-Allow-Credentials") != "true" {
		t.Fatalf("allow-credentials = %q, want true", rec.Header().Get("Access-Control-Allow-Credentials"))
	}
}

// TestCORSDisallowed verifies a non-allowlisted origin gets no CORS headers.
func TestCORSDisallowed(t *testing.T) {
	h := CORS([]string{"https://app.example"})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/x", http.NoBody)
	req.Header.Set("Origin", "https://evil.example")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("allow-origin = %q, want none", rec.Header().Get("Access-Control-Allow-Origin"))
	}
}

// TestCORSNoOrigin verifies a request with no Origin gets no CORS headers.
func TestCORSNoOrigin(t *testing.T) {
	h := CORS([]string{"https://app.example"})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", http.NoBody))
	if rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("allow-origin = %q, want none", rec.Header().Get("Access-Control-Allow-Origin"))
	}
}

// TestCORSPreflight verifies an allowed-origin preflight OPTIONS gets headers
// and a 204 without invoking the handler.
func TestCORSPreflight(t *testing.T) {
	called := false
	h := CORS([]string{"https://app.example"})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodOptions, "/x", http.NoBody)
	req.Header.Set("Origin", "https://app.example")
	req.Header.Set("Access-Control-Request-Method", "POST")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
	if called {
		t.Fatal("handler should not run for preflight")
	}
	if rec.Header().Get("Access-Control-Allow-Methods") == "" {
		t.Fatal("preflight missing Allow-Methods")
	}
}

// TestCORSVaryOrigin verifies Vary: Origin is set.
func TestCORSVaryOrigin(t *testing.T) {
	h := CORS([]string{"https://app.example"})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/x", http.NoBody)
	req.Header.Set("Origin", "https://app.example")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	found := false
	for _, v := range rec.Header().Values("Vary") {
		if v == "Origin" {
			found = true
		}
	}
	if !found {
		t.Fatalf("Vary = %v, want Origin", rec.Header().Values("Vary"))
	}
}
