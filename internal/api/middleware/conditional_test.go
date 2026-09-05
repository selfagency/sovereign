package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestConditionalSetsETagOnGET verifies a GET response gets an ETag.
func TestConditionalSetsETagOnGET(t *testing.T) {
	c := &Conditional{}
	h := c.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("hello"))
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", http.NoBody))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if rec.Header().Get("ETag") == "" {
		t.Fatal("missing ETag on GET")
	}
	if rec.Body.String() != "hello" {
		t.Fatalf("body = %q, want hello", rec.Body.String())
	}
}

// TestConditional304 verifies a matching If-None-Match returns 304 with no body.
func TestConditional304(t *testing.T) {
	c := &Conditional{}
	h := c.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("hello"))
	}))
	// First request to learn the ETag.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", http.NoBody))
	tag := rec.Header().Get("ETag")

	req := httptest.NewRequest(http.MethodGet, "/x", http.NoBody)
	req.Header.Set("If-None-Match", tag)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req)
	if rec2.Code != http.StatusNotModified {
		t.Fatalf("status = %d, want 304", rec2.Code)
	}
	if body := rec2.Body.String(); body != "" {
		t.Fatalf("body = %q, want empty on 304", body)
	}
}

// TestConditionalNonMatching verifies a non-matching If-None-Match serves the
// full response.
func TestConditionalNonMatching(t *testing.T) {
	c := &Conditional{}
	h := c.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("hello"))
	}))
	req := httptest.NewRequest(http.MethodGet, "/x", http.NoBody)
	req.Header.Set("If-None-Match", `"nope"`)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if rec.Body.String() != "hello" {
		t.Fatalf("body = %q, want hello", rec.Body.String())
	}
}

// TestConditionalNonGETUntouched verifies non-GET methods are passed through
// without an ETag.
func TestConditionalNonGETUntouched(t *testing.T) {
	c := &Conditional{}
	h := c.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/x", http.NoBody))
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201", rec.Code)
	}
	if rec.Header().Get("ETag") != "" {
		t.Fatalf("non-GET got ETag %q, want none", rec.Header().Get("ETag"))
	}
}

// TestETagDeterministic verifies identical responses yield identical ETags.
func TestETagDeterministic(t *testing.T) {
	c := &Conditional{}
	h := c.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("same-body"))
	}))
	a := httptest.NewRecorder()
	h.ServeHTTP(a, httptest.NewRequest(http.MethodGet, "/x", http.NoBody))
	b := httptest.NewRecorder()
	h.ServeHTTP(b, httptest.NewRequest(http.MethodGet, "/x", http.NoBody))
	if a.Header().Get("ETag") != b.Header().Get("ETag") {
		t.Fatalf("etags differ: %q vs %q", a.Header().Get("ETag"), b.Header().Get("ETag"))
	}
}
