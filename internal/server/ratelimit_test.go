package server

import (
	"net/http"
	"testing"
	"time"
)

// TestConfigRateLimitDefault verifies an absent api.rate_limit defaults to the
// tuned per-IP values (rate 10/s, burst 50).
func TestConfigRateLimitDefault(t *testing.T) {
	cfg, err := LoadConfig(writeConfig(t, "domain: example.com\ndata_dir: /tmp/data\n"))
	if err != nil {
		t.Fatalf("LoadConfig = %v, want nil", err)
	}
	if cfg.API.RateLimit.Rate != 10 || cfg.API.RateLimit.Burst != 50 {
		t.Fatalf("default rate_limit = %+v, want {10 50}", cfg.API.RateLimit)
	}
}

// TestConfigRateLimitAbsentWithinAPIDefaults verifies the default applies when
// the api block is present but rate_limit is omitted.
func TestConfigRateLimitAbsentWithinAPIDefaults(t *testing.T) {
	cfg, err := LoadConfig(writeConfig(t, "domain: example.com\ndata_dir: /tmp/data\napi:\n  cors_origins:\n    - https://app.example.com\n"))
	if err != nil {
		t.Fatalf("LoadConfig = %v, want nil", err)
	}
	if cfg.API.RateLimit.Rate != 10 || cfg.API.RateLimit.Burst != 50 {
		t.Fatalf("default rate_limit = %+v, want {10 50}", cfg.API.RateLimit)
	}
}

// TestConfigRateLimitParsed verifies explicit api.rate_limit values are used
// as-is (not overridden by the default).
func TestConfigRateLimitParsed(t *testing.T) {
	cfg, err := LoadConfig(writeConfig(t, "domain: example.com\ndata_dir: /tmp/data\napi:\n  rate_limit:\n    rate: 2\n    burst: 10\n"))
	if err != nil {
		t.Fatalf("LoadConfig = %v, want nil", err)
	}
	if cfg.API.RateLimit.Rate != 2 || cfg.API.RateLimit.Burst != 10 {
		t.Fatalf("rate_limit = %+v, want {2 10}", cfg.API.RateLimit)
	}
}

// TestConfigRateLimitExplicitZeroPreserved verifies an explicit rate: 0 (the
// disable switch) survives the absent-key default.
func TestConfigRateLimitExplicitZeroPreserved(t *testing.T) {
	cfg, err := LoadConfig(writeConfig(t, "domain: example.com\ndata_dir: /tmp/data\napi:\n  rate_limit:\n    rate: 0\n    burst: 0\n"))
	if err != nil {
		t.Fatalf("LoadConfig = %v, want nil", err)
	}
	if cfg.API.RateLimit.Rate != 0 || cfg.API.RateLimit.Burst != 0 {
		t.Fatalf("explicit zero rate_limit = %+v, want {0 0}", cfg.API.RateLimit)
	}
}

// TestServerRateLimitWired verifies the api.rate_limit config flows through to
// the middleware chain: a burst-exceeding client gets 429 with the standard
// headers, and the limiter recovers after the retry window.
func TestServerRateLimitWired(t *testing.T) {
	cfg := &Config{
		Domain:  "example.com",
		DataDir: t.TempDir(),
		Storage: StorageConfig{Backend: "fs"},
		Log:     LogConfig{Level: "info", Format: "text"},
		API:     APIConfig{RateLimit: RateLimitConfig{Rate: 1, Burst: 2}},
	}
	srv, err := New(cfg, "dev")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = srv.Close() }()

	// A burst of exactly `burst` requests passes.
	for i := 0; i < 2; i++ {
		if rec := apiGet(t, srv, "/api/v1/health"); rec.Code != http.StatusOK {
			t.Fatalf("request %d = %d, want 200", i, rec.Code)
		}
	}
	// The next request exceeds the burst -> 429 + headers.
	rec := apiGet(t, srv, "/api/v1/health")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("over-burst status = %d, want 429", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("missing Retry-After header on 429")
	}
	if got := rec.Header().Get("RateLimit-Limit"); got != "2" {
		t.Fatalf("RateLimit-Limit = %q, want 2", got)
	}
	if got := rec.Header().Get("RateLimit-Remaining"); got != "0" {
		t.Fatalf("RateLimit-Remaining = %q, want 0", got)
	}
	// After the retry window (rate 1/s refills one token in 1s), recovery.
	time.Sleep(1100 * time.Millisecond)
	if rec := apiGet(t, srv, "/api/v1/health"); rec.Code != http.StatusOK {
		t.Fatalf("post-recovery status = %d, want 200", rec.Code)
	}
}

// TestServerRateLimitDisabled verifies an explicit zero rate_limit leaves the
// limiter a no-op (no 429 however many requests arrive).
func TestServerRateLimitDisabled(t *testing.T) {
	cfg := &Config{
		Domain:  "example.com",
		DataDir: t.TempDir(),
		Storage: StorageConfig{Backend: "fs"},
		Log:     LogConfig{Level: "info", Format: "text"},
		API:     APIConfig{RateLimit: RateLimitConfig{Rate: 0, Burst: 0}},
	}
	srv, err := New(cfg, "dev")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = srv.Close() }()

	for i := 0; i < 25; i++ {
		if rec := apiGet(t, srv, "/api/v1/health"); rec.Code != http.StatusOK {
			t.Fatalf("request %d = %d, want 200 (limiter disabled)", i, rec.Code)
		}
	}
}
