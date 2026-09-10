package middleware

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestChainRateLimitLoadAuth hammers an /auth/* endpoint through the full
// middleware chain (real store + signing key, no mocks) with more requests
// than the burst and verifies the wired per-IP limiter rejects the excess with
// 429 + Retry-After + RateLimit-* headers, then recovers after the retry
// window. The limiter is constructed with the tuned auth values (rate 2/s,
// burst 10) and wired exactly as server.go wires it.
func TestChainRateLimitLoadAuth(t *testing.T) {
	key := testSigningKey(t)
	s := newTestStore(t)
	cfg := chainTestConfig(t, s, key)

	rl := NewRateLimiter(2, 10) // tuned per-IP values for auth routes
	now := time.Unix(1000, 0)
	rl.now = func() time.Time { return now }
	cfg.RateLimit = rl

	life := NewHandler(cfg)
	defer life.Close()
	defer rl.Close()

	do := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/invite/redeem", strings.NewReader(`{"code":"x"}`))
		req.Header.Set(idempotencyKeyHeader, "load")
		rec := httptest.NewRecorder()
		life.ServeHTTP(rec, req)
		return rec
	}

	// A burst of exactly `burst` requests passes the limiter.
	for i := 0; i < 10; i++ {
		if rec := do(); rec.Code != http.StatusOK {
			t.Fatalf("request %d status = %d, want 200", i, rec.Code)
		}
	}

	// The next request exceeds the burst -> 429 with the standard headers.
	rec := do()
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("over-burst status = %d, want 429", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("missing Retry-After header on 429")
	}
	if got := rec.Header().Get("RateLimit-Limit"); got != "10" {
		t.Fatalf("RateLimit-Limit = %q, want 10", got)
	}
	if got := rec.Header().Get("RateLimit-Remaining"); got != "0" {
		t.Fatalf("RateLimit-Remaining = %q, want 0", got)
	}
	if _, err := strconv.ParseInt(rec.Header().Get("RateLimit-Reset"), 10, 64); err != nil {
		t.Fatalf("RateLimit-Reset = %q not a valid epoch: %v", rec.Header().Get("RateLimit-Reset"), err)
	}

	// Advance past the retry window (rate 2/s refills one token in 500ms) and
	// the limiter recovers.
	now = now.Add(2 * time.Second)
	if rec := do(); rec.Code != http.StatusOK {
		t.Fatalf("post-recovery status = %d, want 200", rec.Code)
	}
}

// TestChainRateLimitDisabledNoop verifies a nil RateLimit in the chain config
// leaves the middleware a no-op (the pre-T8.1 behavior preserved for
// rate: 0).
func TestChainRateLimitDisabledNoop(t *testing.T) {
	key := testSigningKey(t)
	s := newTestStore(t)
	life := NewHandler(chainTestConfig(t, s, key)) // RateLimit nil
	defer life.Close()

	for i := 0; i < 100; i++ {
		rec := httptest.NewRecorder()
		life.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/health", http.NoBody))
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d status = %d, want 200 (limiter disabled)", i, rec.Code)
		}
	}
}
