package middleware

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestIdempotencyReplay verifies a replay with the same key returns the
// original response without re-executing the handler.
func TestIdempotencyReplay(t *testing.T) {
	calls := 0
	id := NewIdempotency(func(string) bool { return true })
	defer id.Close()
	h := id.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.Header().Set("X-Run", "yes")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("created"))
	}))

	do := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/redeem", strings.NewReader(`{"code":"abc"}`))
		req.Header.Set(idempotencyKeyHeader, "key-1")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	first := do()
	if first.Code != http.StatusCreated || calls != 1 {
		t.Fatalf("first: code=%d calls=%d, want 201 1", first.Code, calls)
	}
	second := do()
	if second.Code != http.StatusCreated {
		t.Fatalf("second code = %d, want 201", second.Code)
	}
	if calls != 1 {
		t.Fatalf("calls = %d, want 1 (replay must not re-execute)", calls)
	}
	if b, _ := io.ReadAll(second.Body); string(b) != "created" {
		t.Fatalf("replay body = %q, want created", b)
	}
	if second.Header().Get("X-Run") != "yes" {
		t.Fatalf("replay missing X-Run header: %v", second.Header())
	}
}

// TestIdempotencyMissingKey verifies a declared route without a key is 400.
func TestIdempotencyMissingKey(t *testing.T) {
	id := NewIdempotency(func(string) bool { return true })
	defer id.Close()
	h := id.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodPost, "/redeem", http.NoBody)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

// TestIdempotencyNonDeclared verifies undeclared routes pass through.
func TestIdempotencyNonDeclared(t *testing.T) {
	id := NewIdempotency(func(path string) bool { return path == "/redeem" })
	defer id.Close()
	called := false
	h := id.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodPost, "/other", http.NoBody) // no key, undeclared
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !called {
		t.Fatalf("status = %d, called = %v, want 200 true", rec.Code, called)
	}
}

// TestIdempotencyDistinctKeys verifies different keys execute independently.
func TestIdempotencyDistinctKeys(t *testing.T) {
	calls := 0
	id := NewIdempotency(func(string) bool { return true })
	defer id.Close()
	h := id.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	}))
	run := func(key string) {
		req := httptest.NewRequest(http.MethodPost, "/redeem", http.NoBody)
		req.Header.Set(idempotencyKeyHeader, key)
		h.ServeHTTP(httptest.NewRecorder(), req)
	}
	run("k1")
	run("k2")
	if calls != 2 {
		t.Fatalf("calls = %d, want 2", calls)
	}
}

// TestIdempotencyRetention verifies an entry expires after the retention
// window and the handler runs again.
func TestIdempotencyRetention(t *testing.T) {
	calls := 0
	id := NewIdempotency(func(string) bool { return true })
	defer id.Close()
	now := time.Now()
	id.now = func() time.Time { return now }
	h := id.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	}))
	run := func() {
		req := httptest.NewRequest(http.MethodPost, "/redeem", http.NoBody)
		req.Header.Set(idempotencyKeyHeader, "k")
		h.ServeHTTP(httptest.NewRecorder(), req)
	}
	run() // call 1
	now = now.Add(idempotencyRetention + time.Second)
	id.prune(now)
	run() // call 2 after expiry
	if calls != 2 {
		t.Fatalf("calls = %d, want 2 after expiry", calls)
	}
}

// TestIdempotencyConcurrentSameKey verifies concurrent requests with the same
// key execute the side effect exactly once: the loser waits for the winner and
// replays its stored response (security audit C1 — the lookup/execute/record
// sequence must be atomic under concurrency).
func TestIdempotencyConcurrentSameKey(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	id := NewIdempotency(func(string) bool { return true })
	defer id.Close()
	h := id.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		calls++
		mu.Unlock()
		// Slow the handler so concurrent requests overlap the window.
		time.Sleep(50 * time.Millisecond)
		w.Header().Set("X-Run", "yes")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("created"))
	}))

	const n = 8
	var wg sync.WaitGroup
	codes := make([]int, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodPost, "/redeem", strings.NewReader(`{"code":"abc"}`))
			req.Header.Set(idempotencyKeyHeader, "key-1")
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			codes[i] = rec.Code
		}(i)
	}
	wg.Wait()

	if calls != 1 {
		t.Fatalf("calls = %d, want 1 (side effect must run once)", calls)
	}
	for i, c := range codes {
		if c != http.StatusCreated {
			t.Fatalf("request %d = %d, want 201", i, c)
		}
	}
}

// TestIdempotencyNoDuplicateHeaders verifies the first execution does not
// duplicate response headers (audit C1 — bufferWriter forwards headers to the
// real writer, so the post-handler copy must not re-add them).
func TestIdempotencyNoDuplicateHeaders(t *testing.T) {
	id := NewIdempotency(func(string) bool { return true })
	defer id.Close()
	h := id.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Run", "yes")
		w.WriteHeader(http.StatusCreated)
	}))
	req := httptest.NewRequest(http.MethodPost, "/redeem", http.NoBody)
	req.Header.Set(idempotencyKeyHeader, "k")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if got := rec.Header().Values("X-Run"); len(got) != 1 {
		t.Fatalf("X-Run values = %v, want exactly 1", got)
	}
}
