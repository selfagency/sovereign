package middleware

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// TestTimeoutNormalKills verifies a slow handler on a normal (non-long-running)
// route is killed by the timeout.
func TestTimeoutNormalKills(t *testing.T) {
	start := time.Now()
	release := make(chan struct{})
	var once sync.Once
	slow := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-release // block until timeout or release
		once.Do(func() { close(release) })
		w.WriteHeader(http.StatusOK)
	})

	h := Timeout(func(*http.Request) time.Duration { return 30 * time.Millisecond })(slow)
	rec := httptest.NewRecorder()
	// ServeHTTP returns once TimeoutHandler gives up; the handler goroutine is
	// abandoned. Give it a deadline so the test cannot hang.
	done := make(chan struct{})
	go func() {
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", http.NoBody))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout handler did not return")
	}
	once.Do(func() { close(release) })

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if time.Since(start) > time.Second {
		t.Fatal("slow handler was not killed promptly")
	}
}

// TestTimeoutLongRunningNotKilled verifies a slow handler on a long-running
// route (timeout disabled) completes.
func TestTimeoutLongRunningNotKilled(t *testing.T) {
	slow := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(40 * time.Millisecond) // longer than any normal budget
		w.WriteHeader(http.StatusOK)
	})
	// LongRunning routes resolve to 0 timeout => disabled.
	h := Timeout(func(*http.Request) time.Duration { return 0 })(slow)
	rec := httptest.NewRecorder()
	start := time.Now()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", http.NoBody))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if time.Since(start) < 40*time.Millisecond {
		t.Fatal("handler finished too fast; timeout may have been applied")
	}
}

// TestTimeoutImmediatePasses verifies a fast handler is unaffected.
func TestTimeoutImmediatePasses(t *testing.T) {
	h := Timeout(func(*http.Request) time.Duration { return time.Second })(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", http.NoBody))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}
