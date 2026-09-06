package server

import (
	"strings"
	"testing"
)

// TestConfigRejectsUnknownKeys verifies LoadConfig rejects a config containing
// a key that is not declared on the Config struct (yaml.KnownFields strictness).
func TestConfigRejectsUnknownKeys(t *testing.T) {
	path := writeConfig(t, "domain: example.com\ndata_dir: /tmp/data\nbogus_key: true\n")
	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("LoadConfig with unknown key = nil, want error")
	}
	if !strings.Contains(err.Error(), "bogus_key") {
		t.Fatalf("error %q does not name the unknown key", err)
	}
}

// TestConfigRejectsRemovedKeys verifies LoadConfig rejects each key in the
// canonical removed-key list. The fields have been removed from the Config
// struct so strict parsing reports them as not found.
func TestConfigRejectsRemovedKeys(t *testing.T) {
	base := "domain: example.com\ndata_dir: /tmp/data\n"
	cases := map[string]string{
		"identity_host": base + "identity_host: id.example.com\n",
		"sqlite.mode":   base + "sqlite:\n  mode: single\n",
		"sqlite.single": base + "sqlite:\n  single:\n    path: /tmp/s.db\n",
		"tls.enabled":   base + "tls:\n  enabled: true\n",
		"tls.email":     base + "tls:\n  email: admin@example.com\n",
		"atproto.did":   base + "atproto:\n  did_method: web\n",
		"backup.cron":   base + "backup:\n  cron_expr: 0 0 * * *\n",
	}
	for name, yaml := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := LoadConfig(writeConfig(t, yaml))
			if err == nil {
				t.Fatalf("LoadConfig with removed key %q = nil, want error", name)
			}
		})
	}
}

// TestConfigRejectsUnknownStorageS3Secure verifies storage.s3.secure is not
// silently accepted (it is not a declared S3Config field).
func TestConfigRejectsUnknownStorageS3Secure(t *testing.T) {
	yaml := "domain: example.com\ndata_dir: /tmp/data\nstorage:\n  backend: s3\n  s3:\n    endpoint: https://s3.example.com\n    bucket: b\n    access_key: a\n    secret_key: s\n    region: us-east-1\n    secure: true\n"
	_, err := LoadConfig(writeConfig(t, yaml))
	if err == nil {
		t.Fatal("LoadConfig with storage.s3.secure = nil, want error")
	}
	if !strings.Contains(err.Error(), "secure") {
		t.Fatalf("error %q does not name storage.s3.secure", err)
	}
}

// TestConfigNoSQLiteMode verifies sqlite.mode is neither accepted nor
// validated (the field and its validation block were removed).
func TestConfigNoSQLiteMode(t *testing.T) {
	_, err := LoadConfig(writeConfig(t, "domain: example.com\ndata_dir: /tmp/data\nsqlite:\n  mode: per_tenant\n"))
	if err == nil {
		t.Fatal("LoadConfig with sqlite.mode = nil, want error")
	}
}

// TestConfigDualReadDefault verifies absent auth.session.dual_read defaults to
// true (fail-safe against lockout during the migration window).
func TestConfigDualReadDefault(t *testing.T) {
	cfg, err := LoadConfig(writeConfig(t, "domain: example.com\ndata_dir: /tmp/data\n"))
	if err != nil {
		t.Fatalf("LoadConfig = %v, want nil", err)
	}
	if !cfg.Auth.Session.DualRead {
		t.Fatal("absent auth.session.dual_read = false, want true (default)")
	}
}

// TestConfigDualReadExplicitFalse verifies an explicitly-set
// auth.session.dual_read: false is preserved (not overridden by the default).
func TestConfigDualReadExplicitFalse(t *testing.T) {
	cfg, err := LoadConfig(writeConfig(t, "domain: example.com\ndata_dir: /tmp/data\nauth:\n  session:\n    dual_read: false\n"))
	if err != nil {
		t.Fatalf("LoadConfig = %v, want nil", err)
	}
	if cfg.Auth.Session.DualRead {
		t.Fatal("explicit auth.session.dual_read: false = true, want false")
	}
}

// TestConfigCORSOriginsParsed verifies api.cors_origins parses into the
// APIConfig.CORSOrigins slice.
func TestConfigCORSOriginsParsed(t *testing.T) {
	cfg, err := LoadConfig(writeConfig(t, "domain: example.com\ndata_dir: /tmp/data\napi:\n  cors_origins:\n    - https://app.example.com\n"))
	if err != nil {
		t.Fatalf("LoadConfig = %v, want nil", err)
	}
	if len(cfg.API.CORSOrigins) != 1 || cfg.API.CORSOrigins[0] != "https://app.example.com" {
		t.Fatalf("cors_origins = %v, want [https://app.example.com]", cfg.API.CORSOrigins)
	}
}

// TestConfigCORSOriginsAbsent verifies an absent api.cors_origins yields an
// empty (deny-by-default) slice.
func TestConfigCORSOriginsAbsent(t *testing.T) {
	cfg, err := LoadConfig(writeConfig(t, "domain: example.com\ndata_dir: /tmp/data\n"))
	if err != nil {
		t.Fatalf("LoadConfig = %v, want nil", err)
	}
	if len(cfg.API.CORSOrigins) != 0 {
		t.Fatalf("absent cors_origins = %v, want empty slice", cfg.API.CORSOrigins)
	}
}

// TestConfigExampleRoundTrip verifies config.example.yml parses under strict
// validation (KnownFields) and yields the dual_read default of true.
func TestConfigExampleRoundTrip(t *testing.T) {
	cfg, err := LoadConfig("../../config.example.yml")
	if err != nil {
		t.Fatalf("LoadConfig(example.yml) = %v, want nil", err)
	}
	if !cfg.Auth.Session.DualRead {
		t.Fatal("example.yml dual_read = false, want true")
	}
}

// TestConfigValidMinimal verifies a minimal valid config still loads and
// defaults are applied.
func TestConfigValidMinimal(t *testing.T) {
	dir := t.TempDir()
	cfg, err := LoadConfig(writeConfig(t, "domain: example.com\ndata_dir: "+dir+"\n"))
	if err != nil {
		t.Fatalf("LoadConfig minimal = %v, want nil", err)
	}
	if cfg.Domain != "example.com" {
		t.Fatalf("domain = %q, want example.com", cfg.Domain)
	}
	if cfg.DataDir != dir {
		t.Fatalf("data_dir = %q, want %q", cfg.DataDir, dir)
	}
	if cfg.Storage.Backend != "fs" {
		t.Fatalf("storage.backend default = %q, want fs", cfg.Storage.Backend)
	}
	if cfg.Log.Level != "info" {
		t.Fatalf("log.level default = %q, want info", cfg.Log.Level)
	}
	if cfg.Log.Format != "text" {
		t.Fatalf("log.format default = %q, want text", cfg.Log.Format)
	}
}
