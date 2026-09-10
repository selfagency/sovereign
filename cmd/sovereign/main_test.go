package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/viper"

	"github.com/selfagency/sovereign/internal/server"
	"github.com/selfagency/sovereign/internal/store"
)

// TestRunHelp verifies the root command succeeds with --help.
func TestRunHelp(t *testing.T) {
	if err := runFn([]string{"--help"}); err != nil {
		t.Fatalf("runFn(--help) = %v, want nil", err)
	}
}

// TestRunVersion verifies the version subcommand prints the version.
func TestRunVersion(t *testing.T) {
	if err := runFn([]string{"version"}); err != nil {
		t.Fatalf("runFn(version) = %v, want nil", err)
	}
}

// TestRunServeMissingConfig verifies serve errors when the config file is
// missing (Validate fails on empty config).
func TestRunServeMissingConfig(t *testing.T) {
	if err := runFn([]string{"serve", "--config", "/nonexistent/config.yml"}); err == nil {
		t.Fatal("expected error for missing config")
	}
}

// TestRunServeValidConfig verifies the Viper integration loads a valid config
// file into server.Config (the journey's PersistentPreRunE + Unmarshal path).
func TestRunServeValidConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yml")
	cfg := "domain: example.com\ndata_dir: " + dir + "\n"
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	// Simulate the serve command: set the config flag value (as a parsed flag
	// would flow into Viper via BindPFlag), run initConfig (PersistentPreRunE),
	// then loadServerConfig (Unmarshal + Validate).
	v := viper.New()
	v.Set("config", cfgPath)
	if err := initConfig(rootCmd, v); err != nil {
		t.Fatalf("initConfig: %v", err)
	}
	got, err := loadServerConfig(v)
	if err != nil {
		t.Fatalf("loadServerConfig: %v", err)
	}
	if got.Domain != "example.com" {
		t.Fatalf("domain = %q, want example.com", got.Domain)
	}
	if got.DataDir != dir {
		t.Fatalf("data_dir = %q, want %q", got.DataDir, dir)
	}
}

// TestLoadServerConfigRateLimitDefault verifies the Viper path applies the
// tuned per-IP rate-limit default when api.rate_limit is absent (mirroring
// LoadConfig), so the production CLI path is rate-limited by default.
func TestLoadServerConfigRateLimitDefault(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(cfgPath, []byte("domain: example.com\ndata_dir: "+dir+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	v := viper.New()
	v.Set("config", cfgPath)
	if err := initConfig(rootCmd, v); err != nil {
		t.Fatalf("initConfig: %v", err)
	}
	got, err := loadServerConfig(v)
	if err != nil {
		t.Fatalf("loadServerConfig: %v", err)
	}
	if got.API.RateLimit.Rate != 10 || got.API.RateLimit.Burst != 50 {
		t.Fatalf("default rate_limit = %+v, want {10 50}", got.API.RateLimit)
	}
}

// TestConfigRejectsUnknownKeysViper verifies the Viper path (loadServerConfig)
// rejects an unknown config key via the ErrorUnused decoder option.
func TestConfigRejectsUnknownKeysViper(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yml")
	cfg := "domain: example.com\ndata_dir: " + dir + "\nbogus_key: true\n"
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	v := viper.New()
	v.SetConfigFile(cfgPath)
	if err := v.ReadInConfig(); err != nil {
		t.Fatalf("ReadInConfig: %v", err)
	}
	_, err := loadServerConfig(v)
	if err == nil {
		t.Fatal("loadServerConfig with unknown key = nil, want error")
	}
	if !strings.Contains(err.Error(), "bogus_key") {
		t.Fatalf("error %q does not name the unknown key", err)
	}
}

// TestInitConfigMissingFile verifies a missing default config file is not
// fatal (defaults and env vars still apply).
func TestInitConfigMissingFile(t *testing.T) {
	// Reset the --config flag's changed state: an earlier test (via runFn)
	// may have set it, which would make initConfig treat the missing default
	// as an explicit (fatal) path.
	rootCmd.PersistentFlags().Lookup("config").Changed = false

	// No --config flag: the default config.yml is missing, which is non-fatal.
	v := viper.New()
	if err := initConfig(rootCmd, v); err != nil {
		t.Fatalf("initConfig with missing default = %v, want nil", err)
	}
}

// TestConfigPrecedence verifies the 12-factor precedence order:
// flag > env > config > default. It exercises the full initConfig path.
func TestConfigPrecedence(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yml")
	// Config file sets addr to :9000.
	if err := os.WriteFile(cfgPath, []byte("domain: example.com\ndata_dir: "+dir+"\naddr: :9000\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Case 1: config file only -> :9000 (config beats default :8080).
	v := viper.New()
	v.Set("config", cfgPath)
	if err := initConfig(rootCmd, v); err != nil {
		t.Fatalf("initConfig: %v", err)
	}
	if got := v.GetString("addr"); got != ":9000" {
		t.Fatalf("config-only addr = %q, want :9000", got)
	}

	// Case 2: env var beats config file.
	t.Setenv("SOVEREIGN_ADDR", ":7000")
	v2 := viper.New()
	v2.Set("config", cfgPath)
	if err := initConfig(rootCmd, v2); err != nil {
		t.Fatalf("initConfig: %v", err)
	}
	if got := v2.GetString("addr"); got != ":7000" {
		t.Fatalf("env addr = %q, want :7000", got)
	}

	// Case 3: flag beats env. Simulate a parsed --addr flag.
	v3 := viper.New()
	v3.Set("config", cfgPath)
	rootCmd.PersistentFlags().Set("addr", ":5000")
	if err := initConfig(rootCmd, v3); err != nil {
		t.Fatalf("initConfig: %v", err)
	}
	if got := v3.GetString("addr"); got != ":5000" {
		t.Fatalf("flag addr = %q, want :5000", got)
	}
	rootCmd.PersistentFlags().Lookup("addr").Changed = false
}

// TestRunMainHelp verifies runMain returns 0 with --help.
func TestRunMainHelp(t *testing.T) {
	if code := runMain([]string{"--help"}); code != 0 {
		t.Fatalf("runMain(--help) = %d, want 0", code)
	}
}

// TestRunMainError verifies runMain returns 1 when run() errors.
func TestRunMainError(t *testing.T) {
	orig := runFn
	runFn = func([]string) error { return errors.New("boom") }
	defer func() { runFn = orig }()

	if code := runMain([]string{"x"}); code != 1 {
		t.Fatalf("runMain with error = %d, want 1", code)
	}
}

// TestRunServer verifies runServer starts the server and shuts down cleanly
// when the context is cancelled. A pre-cancelled context exercises the full
// listen -> graceful-shutdown path without blocking.
func TestRunServer(t *testing.T) {
	dir := t.TempDir()
	cfg := &server.Config{
		Domain:  "example.com",
		DataDir: dir,
		Storage: server.StorageConfig{Backend: "fs"},
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel so Run returns immediately after graceful shutdown

	if err := runServer(ctx, cfg, "127.0.0.1:0"); err != nil {
		t.Fatalf("runServer = %v, want nil", err)
	}
}

// TestRunServerInvalidConfig verifies runServer propagates a server.New error
// (here an invalid storage backend) rather than panicking.
func TestRunServerInvalidConfig(t *testing.T) {
	cfg := &server.Config{
		Domain:  "example.com",
		DataDir: t.TempDir(),
		Storage: server.StorageConfig{Backend: "bogus"},
	}
	if err := runServer(context.Background(), cfg, "127.0.0.1:0"); err == nil {
		t.Fatal("runServer with invalid backend = nil, want error")
	}
}

// TestSetSecretCmd verifies the clients set-secret subcommand re-registers a
// client secret and prints the new secret once.
func TestSetSecretCmd(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(cfgPath, []byte("domain: example.com\ndata_dir: "+dir+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Pre-create a client in the store the command will open.
	st, err := store.Open(filepath.Join(dir, "identity.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateClient(context.Background(), &store.Client{
		ID:     "client1",
		Secret: "old-secret",
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	if err := runFn([]string{"clients", "set-secret", "client1", "--config", cfgPath}); err != nil {
		t.Fatalf("set-secret = %v, want nil", err)
	}

	// Reopen and verify the secret was re-registered (non-empty hash).
	st2, err := store.Open(filepath.Join(dir, "identity.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st2.Close() }()
	c, err := st2.ClientByID(context.Background(), "client1")
	if err != nil {
		t.Fatal(err)
	}
	if c.Secret == "" || c.Secret == "old-secret" {
		t.Fatalf("client secret not re-registered: %q", c.Secret)
	}
}

// TestSetSecretCmdUnknownClient verifies set-secret errors for a client that
// does not exist.
func TestSetSecretCmdUnknownClient(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(cfgPath, []byte("domain: example.com\ndata_dir: "+dir+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := runFn([]string{"clients", "set-secret", "nope", "--config", cfgPath}); err == nil {
		t.Fatal("set-secret for unknown client = nil, want error")
	}
}

// TestSetSecretCmdWrongArgs verifies set-secret rejects a missing client ID.
func TestSetSecretCmdWrongArgs(t *testing.T) {
	if err := runFn([]string{"clients", "set-secret"}); err == nil {
		t.Fatal("set-secret with no args = nil, want error")
	}
}
