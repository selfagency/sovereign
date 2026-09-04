package middleware

import (
	"bytes"
	"crypto/rsa"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/selfagency/sovereign/internal/store"
)

// chainTestConfig builds a ChainConfig wired to a real store and a fresh key.
// Each route carries a handler that writes 200.
func chainTestConfig(t *testing.T, s *store.Store, key *rsa.PrivateKey) *ChainConfig {
	t.Helper()
	ok := func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }
	return &ChainConfig{
		Routes: []RouteInfo{
			{Method: http.MethodGet, Path: "/api/v1/health", Anonymous: true, Timeout: 5 * time.Second, Handler: http.HandlerFunc(ok)},
			{Method: http.MethodGet, Path: "/api/v1/me", Scope: "self:read", Timeout: 5 * time.Second, Handler: http.HandlerFunc(ok)},
			{Method: http.MethodPost, Path: "/api/v1/auth/invite/redeem", Anonymous: true, Idempotent: true, Timeout: 5 * time.Second, Handler: http.HandlerFunc(ok)},
			{Method: http.MethodPost, Path: "/api/v1/backups/restore", Scope: "admin:backup", LongRunning: true, Timeout: 0, Handler: http.HandlerFunc(ok)},
		},
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		SigningKey:    key,
		Issuer:        testIssuer,
		SessionCookie: "session",
		Sessions:      s,
		Users:         s,
		DualRead:      true,
		BodyLimit:     DefaultMaxBodyBytes,
	}
}

// TestNewHandlerAnonymousRoute verifies an anonymous route passes the chain.
func TestNewHandlerAnonymousRoute(t *testing.T) {
	key := testSigningKey(t)
	s := newTestStore(t)
	life := NewHandler(chainTestConfig(t, s, key))
	defer life.Close()

	rec := httptest.NewRecorder()
	life.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/health", http.NoBody))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if rec.Header().Get(requestIDHeader) == "" {
		t.Fatal("chain missing request-id header")
	}
}

// TestNewHandlerAuthRequiredRoute verifies a scoped route rejects an
// unauthenticated request before reaching the handler.
func TestNewHandlerAuthRequiredRoute(t *testing.T) {
	key := testSigningKey(t)
	s := newTestStore(t)
	life := NewHandler(chainTestConfig(t, s, key))
	defer life.Close()

	rec := httptest.NewRecorder()
	life.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/me", http.NoBody))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	body, _ := io.ReadAll(rec.Body)
	if !strings.Contains(string(body), "problem+json") && rec.Header().Get("Content-Type") != "application/problem+json" {
		t.Fatalf("content-type = %q, want problem+json", rec.Header().Get("Content-Type"))
	}
}

// TestNewHandlerScopedPass verifies a principal with the required scope passes.
func TestNewHandlerScopedPass(t *testing.T) {
	key := testSigningKey(t)
	s := newTestStore(t)
	u := createTestUser(t, s, false)
	tok := mintAPIJWT(t, key, u.ID, []string{"self:read"}, apiAudience)

	reached := false
	cfg := chainTestConfig(t, s, key)
	cfg.Routes[1].Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	})
	life := NewHandler(cfg)
	defer life.Close()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/me", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	life.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !reached {
		t.Fatalf("status = %d, reached = %v, want 200 true", rec.Code, reached)
	}
}

// TestNewHandlerCSRFFormEncodedNoJS verifies a cookie-principal form POST with a
// hidden csrf_token field passes the CSRF middleware in the chain.
func TestNewHandlerCSRFFormEncodedNoJS(t *testing.T) {
	key := testSigningKey(t)
	s := newTestStore(t)
	u := createTestUser(t, s, false)
	tok := mintAPIJWT(t, key, u.ID, []string{"self"}, apiAudience)

	reached := false
	cfg := chainTestConfig(t, s, key)
	cfg.Routes = append(cfg.Routes, RouteInfo{Method: http.MethodPost, Path: "/api/v1/session/refresh", Anonymous: true, Timeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	})})
	life := NewHandler(cfg)
	defer life.Close()

	// Set a CSRF token cookie + a matching session cookie.
	csrfTok, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{csrfFieldName: {csrfTok}}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/session/refresh", bytes.NewBufferString(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: csrfTok})
	req.AddCookie(&http.Cookie{Name: "session", Value: tok})

	rec := httptest.NewRecorder()
	life.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !reached {
		t.Fatalf("status = %d, reached = %v, want 200 true", rec.Code, reached)
	}
}

// TestNewHandlerCrossOriginUnsafeCSRFRejected verifies a cookie-principal
// cross-origin unsafe request is rejected by CSRF (403).
func TestNewHandlerCrossOriginUnsafeCSRFRejected(t *testing.T) {
	key := testSigningKey(t)
	s := newTestStore(t)
	u := createTestUser(t, s, false)
	tok := mintAPIJWT(t, key, u.ID, []string{"self"}, apiAudience)

	cfg := chainTestConfig(t, s, key)
	cfg.Routes = append(cfg.Routes, RouteInfo{Method: http.MethodPost, Path: "/api/v1/session/refresh", Anonymous: true, Timeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})})
	life := NewHandler(cfg)
	defer life.Close()

	csrfTok, _ := NewToken()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/session/refresh", http.NoBody)
	req.Header.Set(csrfHeaderName, csrfTok)
	req.Header.Set("Origin", "https://evil.example")
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: csrfTok})
	req.AddCookie(&http.Cookie{Name: "session", Value: tok})

	rec := httptest.NewRecorder()
	life.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

// TestNewHandlerSlowRestoreNotKilled verifies a long-running route (backup
// restore) with a slow handler completes, while a normal route's slow handler
// is killed.
func TestNewHandlerSlowRestoreNotKilled(t *testing.T) {
	key := testSigningKey(t)
	s := newTestStore(t)
	u := createTestUser(t, s, true)
	tok := mintAPIJWT(t, key, u.ID, []string{"admin:backup"}, apiAudience)

	cfg := chainTestConfig(t, s, key)
	cfg.Routes = []RouteInfo{
		{Method: http.MethodPost, Path: "/api/v1/backups/restore", Scope: "admin:backup", LongRunning: true, Timeout: 0, Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			time.Sleep(120 * time.Millisecond) // long-running: must not be killed
			w.WriteHeader(http.StatusOK)
		})},
		{Method: http.MethodPost, Path: "/api/v1/backups/run", Scope: "admin:backup", Timeout: 50 * time.Millisecond, Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			time.Sleep(200 * time.Millisecond) // exceeds the 50ms normal budget: must be killed
			w.WriteHeader(http.StatusOK)
		})},
	}
	life := NewHandler(cfg)
	defer life.Close()

	// Long-running route: slow handler completes.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/backups/restore", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set(idempotencyKeyHeader, "r1")
	rec := httptest.NewRecorder()
	life.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("long-running restore status = %d, want 200 (must not be killed)", rec.Code)
	}

	// Normal route with a slow handler: killed.
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/backups/run", http.NoBody)
	req2.Header.Set("Authorization", "Bearer "+tok)
	req2.Header.Set(idempotencyKeyHeader, "r2")
	rec2 := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		life.ServeHTTP(rec2, req2)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("normal route timeout handler did not return")
	}
	if rec2.Code != http.StatusServiceUnavailable {
		t.Fatalf("normal slow route status = %d, want 503 (must be killed)", rec2.Code)
	}
}

// TestNewHandlerIdempotencyReplay verifies the chain replays an idempotent
// POST response on retry.
func TestNewHandlerIdempotencyReplay(t *testing.T) {
	key := testSigningKey(t)
	s := newTestStore(t)
	calls := 0
	cfg := chainTestConfig(t, s, key)
	cfg.Routes[2].Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("redeemed"))
	})
	life := NewHandler(cfg)
	defer life.Close()

	do := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/invite/redeem", strings.NewReader(`{"code":"x"}`))
		req.Header.Set(idempotencyKeyHeader, "k")
		rec := httptest.NewRecorder()
		life.ServeHTTP(rec, req)
		return rec
	}
	first := do()
	second := do()
	if first.Code != http.StatusOK || second.Code != http.StatusOK {
		t.Fatalf("codes = %d, %d; want 200 200", first.Code, second.Code)
	}
	if calls != 1 {
		t.Fatalf("calls = %d, want 1 (replay)", calls)
	}
	if b, _ := io.ReadAll(second.Body); string(b) != "redeemed" {
		t.Fatalf("replay body = %q, want redeemed", b)
	}
}
