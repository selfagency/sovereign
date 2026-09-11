package server

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/selfagency/sovereign/internal/auth"
	"github.com/selfagency/sovereign/internal/protocols/atproto"
	"github.com/selfagency/sovereign/internal/protocols/nodeinfo"
	"github.com/selfagency/sovereign/internal/storage"
	"github.com/selfagency/sovereign/internal/store"
	"github.com/selfagency/sovereign/internal/tenant"
)

// writeConfig writes a test config file.
func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestLoadConfig verifies config parsing + defaults.
func TestLoadConfig(t *testing.T) {
	path := writeConfig(t, `domain: example.com
data_dir: ./data
`)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Domain != "example.com" {
		t.Fatalf("domain = %q", cfg.Domain)
	}
	// Defaults applied.
	if cfg.Storage.Backend != "fs" {
		t.Fatalf("storage.backend = %q, want fs", cfg.Storage.Backend)
	}
	if cfg.Log.Level != "info" {
		t.Fatalf("log.level = %q, want info", cfg.Log.Level)
	}
}

// TestLoadConfigMissingFile verifies a missing config errors.
func TestLoadConfigMissingFile(t *testing.T) {
	if _, err := LoadConfig("/nonexistent/config.yml"); err == nil {
		t.Fatal("expected error for missing config")
	}
}

// TestLoadConfigInvalid verifies an invalid config errors.
func TestLoadConfigInvalid(t *testing.T) {
	path := writeConfig(t, `domain: ""`)
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("expected error for empty domain")
	}
}

// TestLoadConfigInvalidBackend verifies an invalid backend errors.
func TestLoadConfigInvalidBackend(t *testing.T) {
	path := writeConfig(t, `domain: example.com
data_dir: ./data
storage:
  backend: gcs
`)
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("expected error for invalid backend")
	}
}

// TestNewServer verifies server assembly.
func TestNewServer(t *testing.T) {
	cfg := &Config{
		Domain:  "example.com",
		DataDir: t.TempDir(),
		Storage: StorageConfig{Backend: "fs"},
		Log:     LogConfig{Level: "info", Format: "text"},
	}
	srv, err := New(cfg, "dev")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = srv.Close() }()
	if srv == nil {
		t.Fatal("nil server")
	}
}

// nodeInfoDoc fetches the NodeInfo document from the assembled router.
func nodeInfoDoc(t *testing.T, srv *Server) nodeinfo.NodeInfo {
	t.Helper()
	req := httptest.NewRequest("GET", "/.well-known/nodeinfo", http.NoBody)
	req.Host = "alice.example.com"
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("nodeinfo status = %d, want 200", rec.Code)
	}
	var doc nodeinfo.NodeInfo
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("invalid NodeInfo JSON: %v", err)
	}
	return doc
}

// TestNodeInfoVersionFromBuild verifies NodeInfo SoftwareVersion matches the
// build version passed to New(cfg, version), not a Config field.
func TestNodeInfoVersionFromBuild(t *testing.T) {
	cfg := &Config{
		Domain:  "example.com",
		DataDir: t.TempDir(),
		Storage: StorageConfig{Backend: "fs"},
		Log:     LogConfig{Level: "info", Format: "text"},
	}
	srv, err := New(cfg, "1.2.3-test")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = srv.Close() }()
	_ = srv.store.CreateTenant(context.Background(), &store.Tenant{ID: "t1", Handle: "alice.example.com", DIDMethod: "web"})

	if got := nodeInfoDoc(t, srv).Software.Version; got != "1.2.3-test" {
		t.Fatalf("software version = %q, want %q", got, "1.2.3-test")
	}
}

// TestNodeInfoProtocolsWired verifies NodeInfo Protocols lists the wired set,
// including activitypub (ServeActor is served at /profile/).
func TestNodeInfoProtocolsWired(t *testing.T) {
	cfg := &Config{
		Domain:  "example.com",
		DataDir: t.TempDir(),
		Storage: StorageConfig{Backend: "fs"},
		Log:     LogConfig{Level: "info", Format: "text"},
	}
	srv, err := New(cfg, "dev")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = srv.Close() }()
	_ = srv.store.CreateTenant(context.Background(), &store.Tenant{ID: "t1", Handle: "alice.example.com", DIDMethod: "web"})

	got := nodeInfoDoc(t, srv).Protocols
	want := []string{"solid", "remotestorage", "atproto", "activitypub", "webfinger"}
	if len(got) != len(want) {
		t.Fatalf("protocols = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("protocols = %v, want %v", got, want)
		}
	}
}

// TestNodeInfoOpenRegistrationsFromConfig verifies NodeInfo OpenRegistrations
// derives from the config field.
func TestNodeInfoOpenRegistrationsFromConfig(t *testing.T) {
	cfg := &Config{
		Domain:            "example.com",
		DataDir:           t.TempDir(),
		Storage:           StorageConfig{Backend: "fs"},
		Log:               LogConfig{Level: "info", Format: "text"},
		OpenRegistrations: true,
	}
	srv, err := New(cfg, "dev")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = srv.Close() }()
	_ = srv.store.CreateTenant(context.Background(), &store.Tenant{ID: "t1", Handle: "alice.example.com", DIDMethod: "web"})

	if !nodeInfoDoc(t, srv).OpenRegistrations {
		t.Fatal("open registrations should be true from config")
	}
}

// TestServerRoutes verifies the assembled router serves known endpoints.
func TestServerRoutes(t *testing.T) {
	cfg := &Config{
		Domain:  "example.com",
		DataDir: t.TempDir(),
		Storage: StorageConfig{Backend: "fs"},
		Log:     LogConfig{Level: "info", Format: "text"},
	}
	srv, err := New(cfg, "dev")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = srv.Close() }()

	// Seed a tenant so the tenant middleware resolves the host.
	_ = srv.store.CreateTenant(context.Background(), &store.Tenant{ID: "t1", Handle: "alice.example.com", DIDMethod: "web"})
	// Seed a published profile so /profile/ renders.
	_ = srv.store.UpsertProfilePage(context.Background(), &store.ProfilePage{
		ID:          "p1",
		TenantID:    "t1",
		AccountID:   "acct1",
		DisplayName: "Alice A.",
		IsPublished: true,
	})

	cases := []struct {
		path string
		host string
		want int
	}{
		{"/.well-known/webfinger?resource=acct:alice@example.com", "alice.example.com", http.StatusOK},
		{"/.well-known/nodeinfo", "alice.example.com", http.StatusOK},
		{"/.well-known/proofs", "alice.example.com", http.StatusOK},
		{"/keys", "alice.example.com", http.StatusOK},
		{"/profile/", "alice.example.com", http.StatusOK},
		{"/rs/docs/x", "alice.example.com", http.StatusUnauthorized}, // no token
		{"/unknown", "alice.example.com", http.StatusNotFound},
	}
	for _, c := range cases {
		req := httptest.NewRequest("GET", c.path, http.NoBody)
		req.Host = c.host
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		if rec.Code != c.want {
			t.Fatalf("GET %s (host %s) = %d, want %d", c.path, c.host, rec.Code, c.want)
		}
	}
}

// TestServerUnknownTenant verifies an unknown host is a 404.
func TestServerUnknownTenant(t *testing.T) {
	cfg := &Config{
		Domain:  "example.com",
		DataDir: t.TempDir(),
		Storage: StorageConfig{Backend: "fs"},
		Log:     LogConfig{Level: "info", Format: "text"},
	}
	srv, err := New(cfg, "dev")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Close() }()

	req := httptest.NewRequest("GET", "/.well-known/webfinger?resource=acct:x@evil.com", http.NoBody)
	req.Host = "evil.com"
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown host = %d, want 404", rec.Code)
	}
}

// TestSQLiteTenantStore verifies tenant resolution from the SQLite store.
func TestSQLiteTenantStore(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	ctx := context.Background()
	_ = st.CreateTenant(ctx, &store.Tenant{ID: "t1", Handle: "alice.example.com", DIDMethod: "web"})

	ts := sqliteTenantStore{store: st}
	t1, err := ts.FindByHost(ctx, "alice.example.com")
	if err != nil || t1.Handle != "alice.example.com" {
		t.Fatalf("tenant = %+v, %v", t1, err)
	}
	// Unknown host.
	if _, err := ts.FindByHost(ctx, "evil.com"); err == nil {
		t.Fatal("expected error for unknown host")
	}
}

// TestBuildBlobBackendS3 verifies S3 backend construction (stubbed — the
// real constructor does a live bucket probe).
func TestBuildBlobBackendS3(t *testing.T) {
	orig := newS3Backend
	newS3Backend = func(ctx context.Context, cfg *Config) (storage.Backend, error) {
		return &storage.FS{Root: t.TempDir()}, nil
	}
	defer func() { newS3Backend = orig }()

	cfg := &Config{
		Storage: StorageConfig{
			Backend: "s3",
			S3: &S3Config{
				Endpoint: "s3.example.com", Bucket: "blobs",
				AccessKey: "ak", SecretKey: "sk", Region: "us-east-1",
			},
		},
	}
	b, err := buildBlobBackend(cfg, newLogger(LogConfig{Level: "info"}))
	if err != nil {
		t.Fatalf("buildBlobBackend s3: %v", err)
	}
	if b == nil {
		t.Fatal("nil backend")
	}
}

// TestBuildBlobBackendS3MissingConfig verifies S3 without config errors.
func TestBuildBlobBackendS3MissingConfig(t *testing.T) {
	cfg := &Config{Storage: StorageConfig{Backend: "s3"}}
	if _, err := buildBlobBackend(cfg, slog.New(slog.NewTextHandler(os.Stderr, nil))); err == nil {
		t.Fatal("expected error for s3 without config")
	}
}

// TestBuildBlobBackendUnknown verifies an unknown backend errors.
func TestBuildBlobBackendUnknown(t *testing.T) {
	cfg := &Config{Storage: StorageConfig{Backend: "gcs"}}
	if _, err := buildBlobBackend(cfg, slog.New(slog.NewTextHandler(os.Stderr, nil))); err == nil {
		t.Fatal("expected error for unknown backend")
	}
}

// TestNewFailsOnOIDCInitError verifies that an OIDC provider init failure
// is fatal: New returns an error instead of booting with auth disabled.
func TestNewFailsOnOIDCInitError(t *testing.T) {
	orig := newAuthProvider
	newAuthProvider = func(string, op.Storage) (*auth.Provider, error) {
		return nil, errors.New("injected oidc failure")
	}
	defer func() { newAuthProvider = orig }()

	cfg := &Config{
		Domain:  "example.com",
		DataDir: t.TempDir(),
		Storage: StorageConfig{Backend: "fs"},
		Log:     LogConfig{Level: "info", Format: "text"},
	}
	if _, err := New(cfg, "dev"); err == nil {
		t.Fatal("expected New to fail on OIDC provider init error")
	}
}

// TestNewFailsOnWebAuthnInitError verifies that a WebAuthn handler init
// failure is fatal: New returns an error instead of booting with auth
// disabled.
func TestNewFailsOnWebAuthnInitError(t *testing.T) {
	orig := newWebAuthnHandler
	newWebAuthnHandler = func(string, string, string, *store.Store) (*auth.WebAuthnHandler, error) {
		return nil, errors.New("injected webauthn failure")
	}
	defer func() { newWebAuthnHandler = orig }()

	cfg := &Config{
		Domain:  "example.com",
		DataDir: t.TempDir(),
		Storage: StorageConfig{Backend: "fs"},
		Log:     LogConfig{Level: "info", Format: "text"},
	}
	if _, err := New(cfg, "dev"); err == nil {
		t.Fatal("expected New to fail on WebAuthn handler init error")
	}
}

// TestDidDocHandler verifies the DID doc endpoint.
func TestDidDocHandler(t *testing.T) {
	cfg := &Config{
		Domain:  "example.com",
		DataDir: t.TempDir(),
		Storage: StorageConfig{Backend: "fs"},
		Log:     LogConfig{Level: "info", Format: "text"},
	}
	srv, err := New(cfg, "dev")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = srv.Close() }()
	_ = srv.store.CreateTenant(context.Background(), &store.Tenant{ID: "t1", Handle: "alice.example.com", DIDMethod: "web"})

	req := httptest.NewRequest("GET", "/profile/", http.NoBody)
	req.Host = "alice.example.com"
	req.Header.Set("Accept", "application/did+json")
	req = req.WithContext(tenant.WithTenant(req.Context(), &tenant.Tenant{ID: "t1", Handle: "alice.example.com"}))
	rec := httptest.NewRecorder()
	srv.didDocHandler()(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "did:web:alice.example.com") {
		t.Fatalf("body = %q", rec.Body.String())
	}
}

// TestDIDDocUsesTenantHandle verifies the DID doc derives did:web: and
// alsoKnownAs from the resolved tenant.Handle (never r.Host) and that a
// stored DID takes precedence over the fallback.
func TestDIDDocUsesTenantHandle(t *testing.T) {
	cfg := &Config{
		Domain:  "example.com",
		DataDir: t.TempDir(),
		Storage: StorageConfig{Backend: "fs"},
		Log:     LogConfig{Level: "info", Format: "text"},
	}
	srv, err := New(cfg, "dev")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = srv.Close() }()

	// Request host differs from tenant handle to prove r.Host is not used.
	const handle = "alice.example.com"
	const reqHost = "evil.example.com"

	cases := []struct {
		name      string
		id        string
		handle    string
		did       string
		wantID    string
		wantKnown string
	}{
		{
			name:      "no stored DID uses normalized handle",
			id:        "t1",
			handle:    handle,
			wantID:    "did:web:" + handle,
			wantKnown: "https://" + handle + "/profile/",
		},
		{
			name:      "stored DID takes precedence",
			id:        "t2",
			handle:    "bob.example.com",
			did:       "did:example:abc123",
			wantID:    "did:example:abc123",
			wantKnown: "https://bob.example.com/profile/",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_ = srv.store.CreateTenant(context.Background(), &store.Tenant{
				ID: tc.id, Handle: tc.handle, DIDMethod: "web", DID: tc.did,
			})

			req := httptest.NewRequest("GET", "/profile/", http.NoBody)
			req.Host = reqHost
			req.Header.Set("Accept", "application/did+json")
			req = req.WithContext(tenant.WithTenant(req.Context(), &tenant.Tenant{ID: tc.id, Handle: tc.handle}))
			rec := httptest.NewRecorder()
			srv.didDocHandler()(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", rec.Code)
			}
			body := rec.Body.String()
			if !strings.Contains(body, tc.wantID) {
				t.Fatalf("body missing id %q: %s", tc.wantID, body)
			}
			if !strings.Contains(body, tc.wantKnown) {
				t.Fatalf("body missing alsoKnownAs %q: %s", tc.wantKnown, body)
			}
			if strings.Contains(body, reqHost) {
				t.Fatalf("body leaks request host %q: %s", reqHost, body)
			}
		})
	}
}

// TestAtprotoHandler verifies the atproto XRPC server.
func TestAtprotoHandler(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	_ = st.CreateTenant(context.Background(), &store.Tenant{ID: "t1", Handle: "alice.example.com", DIDMethod: "web"})

	xrpc := &atproto.XRPCServer{Store: st}
	req := httptest.NewRequest("GET", "/xrpc/com.atproto.identity.resolveHandle?handle=alice.example.com", http.NoBody)
	rec := httptest.NewRecorder()
	xrpc.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "did:web:alice.example.com") {
		t.Fatalf("body = %q", rec.Body.String())
	}
}

// TestNewLogger verifies logger level selection.
func TestNewLogger(t *testing.T) {
	for _, lvl := range []string{"debug", "warn", "error", "info"} {
		lg := newLogger(LogConfig{Level: lvl})
		if lg == nil {
			t.Fatalf("nil logger for level %q", lvl)
		}
	}
}
