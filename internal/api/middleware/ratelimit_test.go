package middleware

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

// TestRateLimit429 verifies a burst-exhausting caller gets 429 with Retry-After
// and RateLimit-* headers.
func TestRateLimit429(t *testing.T) {
	rl := NewRateLimiter(1, 2) // burst of 2, refill 1/s
	rl.now = func() time.Time { return time.Unix(1000, 0) }
	defer rl.Close()
	h := rl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// First two consume the burst.
	for i := 0; i < 2; i++ {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", http.NoBody))
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d status = %d, want 200", i, rec.Code)
		}
	}
	// Third exceeds the burst -> 429.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", http.NoBody))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("missing Retry-After header")
	}
	if rec.Header().Get("RateLimit-Limit") == "" || rec.Header().Get("RateLimit-Remaining") != "0" {
		t.Fatalf("RateLimit headers wrong: %v", rec.Header())
	}
}

// TestRateLimitPerIP verifies different source IPs have independent buckets.
func TestRateLimitPerIP(t *testing.T) {
	rl := NewRateLimiter(1, 1) // burst of 1
	rl.now = func() time.Time { return time.Unix(1000, 0) }
	defer rl.Close()
	h := rl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	reqA := httptest.NewRequest(http.MethodGet, "/x", http.NoBody)
	reqA.RemoteAddr = "1.1.1.1:1234"
	reqB := httptest.NewRequest(http.MethodGet, "/x", http.NoBody)
	reqB.RemoteAddr = "2.2.2.2:5678"

	recA := httptest.NewRecorder()
	h.ServeHTTP(recA, reqA)
	if recA.Code != http.StatusOK {
		t.Fatalf("A first status = %d, want 200", recA.Code)
	}
	// B still has its own token.
	recB := httptest.NewRecorder()
	h.ServeHTTP(recB, reqB)
	if recB.Code != http.StatusOK {
		t.Fatalf("B status = %d, want 200", recB.Code)
	}
	// A is exhausted -> 429.
	recA2 := httptest.NewRecorder()
	h.ServeHTTP(recA2, reqA)
	if recA2.Code != http.StatusTooManyRequests {
		t.Fatalf("A second status = %d, want 429", recA2.Code)
	}
}

// TestRateLimitRefill verifies a bucket refills over time.
func TestRateLimitRefill(t *testing.T) {
	rl := NewRateLimiter(1, 1)
	now := time.Unix(1000, 0)
	rl.now = func() time.Time { return now }
	defer rl.Close()
	h := rl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/x", http.NoBody)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("first status = %d, want 200", rec.Code)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("second status = %d, want 429", rec.Code)
	}

	now = now.Add(2 * time.Second) // refills >= 1 token
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("post-refill status = %d, want 200", rec.Code)
	}
}

// TestClientIP ensures the port is stripped from RemoteAddr.
func TestClientIP(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/x", http.NoBody)
	r.RemoteAddr = "203.0.113.7:8080"
	if got := clientIP(r); got != "203.0.113.7" {
		t.Fatalf("clientIP = %q, want 203.0.113.7", got)
	}
}

// TestRateLimitResetHeader verifies the Reset value is a valid epoch seconds.
func TestRateLimitResetHeader(t *testing.T) {
	rl := NewRateLimiter(1, 1)
	rl.now = func() time.Time { return time.Unix(1000, 0) }
	defer rl.Close()
	h := rl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/x", http.NoBody)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rec.Code)
	}
	if _, err := strconv.ParseInt(rec.Header().Get("RateLimit-Reset"), 10, 64); err != nil {
		t.Fatalf("RateLimit-Reset = %q not a valid epoch: %v", rec.Header().Get("RateLimit-Reset"), err)
	}
}
