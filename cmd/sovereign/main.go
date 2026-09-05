// Command sovereign is the Sovereign identity and data server.
//
// A single multi-tenant binary serving Solid Pod, remoteStorage, atproto PDS,
// IPFS pinning, WebFinger, OIDC/OAuth2 + IndieAuth, and an ActivityPub actor.
//
// The CLI is built on Cobra (command structure) + Viper (configuration),
// following the integration pattern from the Cobra & Viper learning journey:
// Viper is initialized in PersistentPreRunE, flags are bound in init(), and
// all values are read through Viper getters (never the flag variables).
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/go-viper/mapstructure/v2"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/selfagency/sovereign/internal/server"
	"github.com/selfagency/sovereign/internal/store"
)

// version is the build version, overridable at link time.
var version = "dev"

// v is the Viper configuration instance. Per Viper's documented best practice,
// a dedicated instance is preferred over the global singleton (which leaks
// state between tests). It is created in main() and threaded through the
// config functions.
var v *viper.Viper

// rootCmd is the CLI root. It owns Viper configuration via PersistentPreRunE.
var rootCmd = &cobra.Command{
	Use:   "sovereign",
	Short: "Sovereign identity and data server",
	Long: `Sovereign is a single multi-tenant binary serving Solid Pod, remoteStorage,
atproto PDS, IPFS pinning, WebFinger, OIDC/OAuth2 + IndieAuth, and an
ActivityPub actor.`,
	// PersistentPreRunE initializes Viper before any subcommand runs. This is
	// the journey's integration pattern: config is loaded here, flags are
	// bound in init(), and commands read values via Viper getters.
	PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
		return initConfig(cmd, v)
	},
	// SilenceUsage avoids dumping usage on runtime errors (only on flag errors).
	SilenceUsage: true,
	// SilenceErrors lets runMain own error output (avoids a double print).
	SilenceErrors: true,
}

// serveCmd runs the HTTP server.
var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Run the identity server",
	RunE: func(cmd *cobra.Command, _ []string) error {
		// Read config through Viper (the single source of truth).
		cfg, err := loadServerConfig(v)
		if err != nil {
			return err
		}
		return runServer(cmd.Context(), cfg, v.GetString("addr"))
	},
}

// versionCmd prints the build version.
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version",
	Run: func(_ *cobra.Command, _ []string) {
		fmt.Println(version)
	},
}

// clientsCmd groups client administration subcommands.
var clientsCmd = &cobra.Command{
	Use:   "clients",
	Short: "Manage OIDC clients",
}

// setSecretCmd re-registers a client secret after migration v5 invalidates
// plaintext secrets. It generates a fresh secret, hashes it with argon2id, and
// updates the row in place (sidestepping CreateClient's unique constraint).
// The new secret is printed once to stdout.
var setSecretCmd = &cobra.Command{
	Use:   "set-secret <id>",
	Short: "Re-register a client secret (prints the new secret once)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadServerConfig(v)
		if err != nil {
			return err
		}
		st, err := store.Open(filepath.Join(cfg.DataDir, "identity.db"))
		if err != nil {
			return fmt.Errorf("open store: %w", err)
		}
		defer func() { _ = st.Close() }()

		// Generate a 32-byte base64url secret.
		raw := make([]byte, 32)
		if _, err := rand.Read(raw); err != nil {
			return fmt.Errorf("generate secret: %w", err)
		}
		secret := base64.RawURLEncoding.EncodeToString(raw)
		if err := st.SetClientSecret(cmd.Context(), args[0], secret); err != nil {
			return err
		}
		// Print the new secret once so the operator can store it.
		fmt.Println(secret)
		return nil
	},
}

func main() {
	v = viper.New()
	os.Exit(runMain(os.Args[1:]))
}

// runFn is a package-level hook so tests can exercise runMain's error path.
// It initializes the Viper instance (as main() does) so both the real binary
// and tests get a fresh, non-nil instance.
var runFn = func(args []string) error {
	v = viper.New()
	rootCmd.SetArgs(args)
	return rootCmd.Execute()
}

// runMain runs the CLI and returns a process exit code.
func runMain(args []string) int {
	if err := runFn(args); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	return 0
}

// init registers flags and binds them to Viper. This runs at package init,
// before any command executes.
func init() {
	// Persistent flags available to every subcommand.
	rootCmd.PersistentFlags().String("config", "config.yml", "path to config file")
	rootCmd.PersistentFlags().String("addr", ":8080", "listen address (host:port)")

	rootCmd.AddCommand(serveCmd)
	rootCmd.AddCommand(versionCmd)
	clientsCmd.AddCommand(setSecretCmd)
	rootCmd.AddCommand(clientsCmd)
}

// initConfig loads configuration into Viper. It is the PersistentPreRunE hook,
// following the 12-factor integration pattern: env vars are configured first,
// flags are bound, then the config file is read. Flags take top precedence
// (flag > env > config > default).
func initConfig(cmd *cobra.Command, v *viper.Viper) error {
	// Environment variables: SOVEREIGN_<KEY> (e.g. SOVEREIGN_ADDR). The key
	// replacer maps nested config keys (e.g. storage.backend) to env vars
	// (SOVEREIGN_STORAGE_BACKEND).
	v.SetEnvPrefix("SOVEREIGN")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	v.AutomaticEnv()

	// Bind the command's full flag set to Viper. cmd.Flags() covers local
	// flags; InheritedFlags() covers persistent flags from ancestors (where
	// --config/--addr live); PersistentFlags() covers this command's own
	// persistent flags. Binding here (after parsing) means the flags reflect
	// the actual invocation.
	if err := v.BindPFlags(cmd.Flags()); err != nil {
		return fmt.Errorf("bind flags: %w", err)
	}
	if err := v.BindPFlags(cmd.InheritedFlags()); err != nil {
		return fmt.Errorf("bind inherited flags: %w", err)
	}
	if err := v.BindPFlags(cmd.PersistentFlags()); err != nil {
		return fmt.Errorf("bind persistent flags: %w", err)
	}

	// Config file: --config flag (now in viper), then SOVEREIGN_CONFIG, then
	// the default config.yml.
	configPath := v.GetString("config")
	if configPath != "" {
		v.SetConfigFile(configPath)
	} else {
		v.SetConfigName("config")
		v.AddConfigPath(".")
	}

	// Read the config file if present. A missing file is not fatal (defaults
	// and env vars still apply) UNLESS the user explicitly passed --config,
	// in which case a missing file is an error.
	if err := v.ReadInConfig(); err != nil {
		explicit := cmd.Flags().Changed("config")
		if !explicit && os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read config: %w", err)
	}
	return nil
}

// loadServerConfig unmarshals Viper into a server.Config and validates it.
func loadServerConfig(v *viper.Viper) (*server.Config, error) {
	// CLI-only flags (config, addr, help) are operational, not config-schema
	// keys. Decode a copy without them so ErrorUnused rejects genuinely
	// unknown config keys (e.g. typos, removed keys) without tripping on the
	// bound flags that initConfig merges into viper.
	strict := viper.New()
	for k, val := range v.AllSettings() {
		switch k {
		case "config", "addr", "help":
			continue
		}
		strict.Set(k, val)
	}
	var cfg server.Config
	if err := strict.Unmarshal(&cfg, viper.DecoderConfigOption(func(dc *mapstructure.DecoderConfig) {
		dc.ErrorUnused = true
	})); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	// DualRead defaults to true (fail-safe against lockout). Only the absent
	// key defaults; an explicit `auth.session.dual_read: false` stays false.
	if !strict.IsSet("auth.session.dual_read") {
		cfg.Auth.Session.DualRead = true
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// runServer starts the HTTP server with graceful shutdown.
func runServer(ctx context.Context, cfg *server.Config, addr string) error {
	srv, err := server.New(cfg, version)
	if err != nil {
		return err
	}
	defer func() { _ = srv.Close() }()

	// Graceful shutdown on SIGINT/SIGTERM.
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	return srv.Run(ctx, addr)
}
