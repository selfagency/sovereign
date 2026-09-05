// Package server wires the identity server's protocol handlers, storage,
// and middleware into a runnable HTTP server. It is the integration layer
// that turns the packages into a deployable single binary.
package server

import (
	"bytes"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config is the server configuration, loaded from config.yml.
// Both yaml and mapstructure tags are present: yaml for the file loader,
// mapstructure for Viper's Unmarshal (the CLI path).
type Config struct {
	Domain            string        `yaml:"domain" mapstructure:"domain"`
	Audience          string        `yaml:"audience" mapstructure:"audience"`
	DataDir           string        `yaml:"data_dir" mapstructure:"data_dir"`
	Storage           StorageConfig `yaml:"storage" mapstructure:"storage"`
	IPFS              IPFSConfig    `yaml:"ipfs" mapstructure:"ipfs"`
	SMTP              SMTPConfig    `yaml:"smtp" mapstructure:"smtp"`
	Log               LogConfig     `yaml:"log" mapstructure:"log"`
	OpenRegistrations bool          `yaml:"open_registrations" mapstructure:"open_registrations"`
	Auth              AuthConfig    `yaml:"auth" mapstructure:"auth"`
	API               APIConfig     `yaml:"api" mapstructure:"api"`
}

// StorageConfig configures the protocol blob backend.
type StorageConfig struct {
	Backend string    `yaml:"backend" mapstructure:"backend"` // "fs" | "s3"
	S3      *S3Config `yaml:"s3" mapstructure:"s3"`
}

// S3Config configures an S3-compatible blob backend.
type S3Config struct {
	Endpoint  string `yaml:"endpoint" mapstructure:"endpoint"`
	Bucket    string `yaml:"bucket" mapstructure:"bucket"`
	AccessKey string `yaml:"access_key" mapstructure:"access_key"`
	SecretKey string `yaml:"secret_key" mapstructure:"secret_key"`
	Region    string `yaml:"region" mapstructure:"region"`
}

// IPFSConfig configures the IPFS pinning broker.
type IPFSConfig struct {
	Enabled bool `yaml:"enabled" mapstructure:"enabled"`
}

// SMTPConfig configures outbound email via stdlib net/smtp.
type SMTPConfig struct {
	Host     string `yaml:"host" mapstructure:"host"`
	Port     int    `yaml:"port" mapstructure:"port"`
	Username string `yaml:"username" mapstructure:"username"`
	Password string `yaml:"password" mapstructure:"password"`
	From     string `yaml:"from" mapstructure:"from"`
	TLS      bool   `yaml:"tls" mapstructure:"tls"` // STARTTLS
}

// Enabled reports whether SMTP is configured for sending.
func (s *SMTPConfig) Enabled() bool {
	return s.Host != "" && s.Port != 0
}

// LogConfig configures logging.
type LogConfig struct {
	Level  string `yaml:"level" mapstructure:"level"`
	Format string `yaml:"format" mapstructure:"format"`
}

// AuthConfig configures the identity/auth subsystem.
type AuthConfig struct {
	Session SessionConfig `yaml:"session" mapstructure:"session"`
}

// SessionConfig configures browser sessions.
type SessionConfig struct {
	// DualRead, when true (default), accepts BOTH legacy JWT session cookies
	// AND new server-side session rows during the migration window.
	// Operators flip this to false after the transition release to drop
	// legacy JWT cookies. Fail-safe default: true.
	DualRead bool `yaml:"dual_read" mapstructure:"dual_read"`
}

// APIConfig configures the control-plane REST API.
type APIConfig struct {
	// CORSOrigins is the allowlist for cross-origin browser access.
	// Deny-by-default (empty). Never '*' alongside credentials.
	CORSOrigins []string `yaml:"cors_origins" mapstructure:"cors_origins"`
}

// LoadConfig reads and parses a YAML config file.
func LoadConfig(path string) (*Config, error) {
	// #nosec G304 -- path is a caller-provided config path (CLI flag), not user input.
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	// DualRead defaults to true (fail-safe against lockout during the
	// migration window). Only the ABSENT key defaults; an explicit
	// `auth.session.dual_read: false` is preserved as-is. This must be done
	// here (not in Validate) because the yaml.v3 plain-bool decode cannot
	// distinguish an absent key from an explicit false.
	if !yamlKeyPresent(data, "auth", "session", "dual_read") {
		cfg.Auth.Session.DualRead = true
	}
	return &cfg, nil
}

// yamlKeyPresent reports whether the given dot-path key exists in the YAML
// document. It is used to apply absent-key defaults that must not override an
// explicit value (e.g. a bool whose default is true but whose zero value is
// false).
func yamlKeyPresent(data []byte, path ...string) bool {
	var m map[string]any
	if err := yaml.Unmarshal(data, &m); err != nil {
		return false
	}
	for i, key := range path {
		v, ok := m[key]
		if !ok {
			return false
		}
		if i == len(path)-1 {
			return true
		}
		nm, ok := v.(map[string]any)
		if !ok {
			return false
		}
		m = nm
	}
	return true
}

// Validate checks required config fields.
func (c *Config) Validate() error {
	if c.Domain == "" {
		return fmt.Errorf("config: domain is required")
	}
	if c.Audience == "" {
		c.Audience = c.Domain
	}
	if c.DataDir == "" {
		return fmt.Errorf("config: data_dir is required")
	}
	if c.Storage.Backend == "" {
		c.Storage.Backend = "fs"
	}
	if c.Storage.Backend != "fs" && c.Storage.Backend != "s3" {
		return fmt.Errorf("config: storage.backend must be fs or s3, got %q", c.Storage.Backend)
	}
	if c.Log.Level == "" {
		c.Log.Level = "info"
	}
	if c.Log.Format == "" {
		c.Log.Format = "text"
	}
	return nil
}
