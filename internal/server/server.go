package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/selfagency/sovereign/internal/admin"
	"github.com/selfagency/sovereign/internal/api"
	"github.com/selfagency/sovereign/internal/api/dto"
	"github.com/selfagency/sovereign/internal/api/middleware"
	v1auth "github.com/selfagency/sovereign/internal/api/v1/auth"
	"github.com/selfagency/sovereign/internal/api/v1/meta"
	"github.com/selfagency/sovereign/internal/auth"
	"github.com/selfagency/sovereign/internal/endpoints"
	"github.com/selfagency/sovereign/internal/mail"
	"github.com/selfagency/sovereign/internal/moderation"
	"github.com/selfagency/sovereign/internal/protocols/activitypub"
	"github.com/selfagency/sovereign/internal/protocols/atproto"
	"github.com/selfagency/sovereign/internal/protocols/hyperlink"
	"github.com/selfagency/sovereign/internal/protocols/indieauth"
	"github.com/selfagency/sovereign/internal/protocols/ipfspin"
	"github.com/selfagency/sovereign/internal/protocols/nodeinfo"
	"github.com/selfagency/sovereign/internal/protocols/remotestorage"
	"github.com/selfagency/sovereign/internal/protocols/solid"
	"github.com/selfagency/sovereign/internal/protocols/webfinger"
	"github.com/selfagency/sovereign/internal/protocols/wellknown"
	"github.com/selfagency/sovereign/internal/storage"
	"github.com/selfagency/sovereign/internal/store"
	"github.com/selfagency/sovereign/internal/tenant"
	"github.com/selfagency/sovereign/internal/wiring"
)

// Server is the assembled identity server.
type Server struct {
	cfg       *Config
	version   string
	store     *store.Store
	authStore *auth.SQLStore
	blobs     storage.Backend
	mailer    mail.Sender
	mux       http.Handler
	logger    *slog.Logger
	// apiClose stops the control-plane middleware chain's background goroutines
	// (idempotency pruner) on Close.
	apiClose func()
}

// New assembles the server from config: opens the SQLite store, builds the
// blob backend, and wires every protocol handler into a router. version is
// the build-time version constant (e.g. from cmd/sovereign's var version),
// surfaced in NodeInfo; it is deliberately NOT a Config field.
func New(cfg *Config, version string) (*Server, error) {
	logger := newLogger(cfg.Log)

	// Ensure the data directory exists.
	if err := os.MkdirAll(cfg.DataDir, 0o750); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}

	// Open the account-data SQLite store.
	storePath := filepath.Join(cfg.DataDir, "identity.db")
	st, err := store.Open(storePath)
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}

	// Seed the identity host as a tenant so the tenant middleware resolves
	// it and the OIDC provider can be mounted there.
	identityHost := "id." + cfg.Domain
	if err := seedIdentityTenant(context.Background(), st, identityHost); err != nil {
		return nil, fmt.Errorf("seed identity tenant: %w", err)
	}

	// Build the SQLite-backed OIDC storage (users, clients, signing key,
	// refresh tokens).
	authStore, err := auth.NewSQLStore(context.Background(), st)
	if err != nil {
		return nil, fmt.Errorf("open auth store: %w", err)
	}

	// Build the blob backend.
	blobs, err := buildBlobBackend(cfg, logger)
	if err != nil {
		return nil, err
	}

	s := &Server{cfg: cfg, version: version, store: st, authStore: authStore, blobs: blobs, logger: logger}
	// Build the mail sender: SMTP when configured, else the dev logging
	// fallback so magic links remain testable without a mail server.
	if cfg.SMTP.Enabled() {
		s.mailer = mail.NewSMTP(&mail.SMTPConfig{
			Host: cfg.SMTP.Host, Port: cfg.SMTP.Port, Username: cfg.SMTP.Username,
			Password: cfg.SMTP.Password, From: cfg.SMTP.From, TLS: cfg.SMTP.TLS,
		})
	} else {
		s.mailer = mail.NewLogSender(logger)
	}
	if err := s.buildRouter(); err != nil {
		return nil, err
	}
	return s, nil
}

// seedIdentityTenant ensures the identity host (id.<domain>) exists as a
// tenant row so the tenant middleware resolves it. It is idempotent.
func seedIdentityTenant(ctx context.Context, st *store.Store, host string) error {
	_, err := st.GetTenantByHandle(ctx, host)
	if err == nil {
		return nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return err
	}
	return st.CreateTenant(ctx, &store.Tenant{
		ID:        "identity",
		Handle:    host,
		DIDMethod: "web",
		DID:       "did:web:" + host,
	})
}

// Close releases the store and stops the control-plane middleware chain's
// background goroutines.
func (s *Server) Close() error {
	if s.apiClose != nil {
		s.apiClose()
	}
	return s.store.Close()
}

// newS3Backend is a package-level hook so tests can stub the S3 constructor
// (which does a live bucket probe).
var newS3Backend = func(cfg *Config) (storage.Backend, error) {
	s3 := cfg.Storage.S3
	return storage.NewS3(&storage.S3Config{
		Endpoint:  s3.Endpoint,
		Bucket:    s3.Bucket,
		AccessKey: s3.AccessKey,
		SecretKey: s3.SecretKey,
		Region:    s3.Region,
	})
}

// newAuthProvider is a package-level hook so tests can inject OIDC provider
// init failures.
var newAuthProvider = auth.NewProvider

// newWebAuthnHandler is a package-level hook so tests can inject WebAuthn
// handler init failures.
var newWebAuthnHandler = auth.NewWebAuthnHandler

// buildBlobBackend constructs the FS or S3 storage backend.
func buildBlobBackend(cfg *Config, logger *slog.Logger) (storage.Backend, error) {
	switch cfg.Storage.Backend {
	case "fs":
		return &storage.FS{Root: filepath.Join(cfg.DataDir, "blobs")}, nil
	case "s3":
		if cfg.Storage.S3 == nil {
			return nil, fmt.Errorf("config: storage.s3 is required when backend=s3")
		}
		return newS3Backend(cfg)
	default:
		return nil, fmt.Errorf("config: unknown storage backend %q", cfg.Storage.Backend)
	}
}

// buildRouter wires all protocol handlers onto the mux. The OIDC provider is
// served only on the identity host (id.<domain>); all other hosts serve the
// protocol mux.
func (s *Server) buildRouter() error {
	mux := http.NewServeMux()

	// Tenant-scoped blob backend resolver. Each tenant's keys are prefixed
	// with the tenant ID on the shared backend, so tenants cannot read or
	// write each other's data (IDOR boundary). Works for both FS and S3.
	backendFor := func(tenantID string) storage.Backend {
		return &storage.Prefixed{Backend: s.blobs, Prefix: tenantID}
	}

	// The OIDC issuer is the identity host (https://id.<domain>); access tokens
	// are minted and validated against it.
	identityHost := "id." + s.cfg.Domain
	issuer := "https://" + identityHost

	// remoteStorage.
	rs := &remotestorage.Server{
		Backend: backendFor,
		Tokens:  &wiring.TokenValidator{Key: s.authStore.SigningKeyMaterial(), Issuer: issuer, Audience: s.cfg.Audience},
	}
	mux.Handle("/rs/", rs)

	// Solid LDP.
	solidSrv := &solid.Server{
		Backend: backendFor,
		ACL:     &wiring.ACLChecker{Store: s.store},
		Tokens:  &wiring.SubjectValidator{Key: s.authStore.SigningKeyMaterial(), Issuer: issuer, Audience: s.cfg.Audience},
	}
	mux.Handle("/solid/", solidSrv)

	// WebFinger.
	wf := webfinger.Handler(webfinger.Config{
		IdentityHost: identityHost,
		StorageRoot:  "https://" + s.cfg.Domain + "/rs/",
		ActorURL:     "https://" + s.cfg.Domain + "/profile/",
	})
	mux.Handle("/.well-known/webfinger", wf)

	// NodeInfo.
	ni := nodeinfo.Handler(nodeinfo.Config{
		SoftwareName:      "sovereign",
		SoftwareVersion:   s.version,
		Protocols:         []string{"solid", "remotestorage", "atproto", "activitypub"},
		OpenRegistrations: s.cfg.OpenRegistrations,
	})
	mux.Handle("/.well-known/nodeinfo", ni)

	// Content-negotiated profile (h-card / actor / DID doc).
	profile := wellknown.ProfileHandler(wellknown.Handlers{
		HCard:  s.hcardHandler(),
		Actor:  activitypub.ServeActor(activitypub.ActorConfig{Handle: s.cfg.Domain}),
		DIDDoc: s.didDocHandler(),
	})
	mux.Handle("/profile/", profile)

	// Public key + proofs endpoints.
	keys := &endpoints.KeysHandler{Store: s.store}
	mux.Handle("/keys", keys)
	mux.Handle("/.well-known/openpgpkey/", keys)
	proofs := &endpoints.ProofsHandler{Store: s.store}
	mux.Handle("/.well-known/proofs", proofs)

	// IPFS pinning broker — a client injected into backup/export flows and
	// exposed as an admin-guarded HTTP surface.
	var ipfsBackend ipfspin.Backend
	if s.cfg.IPFS.Enabled {
		ipfsBackend = ipfspin.NewKuboRPC("http://127.0.0.1:5001")
	}
	ipfsBroker := newIPFSBroker(s.store, ipfsBackend)

	// atproto PDS.
	xrpc := &atproto.XRPCServer{Store: s.store, Issuer: issuer, Audience: s.cfg.Audience}
	mux.Handle("/xrpc/", xrpc)

	// OIDC provider, served only on the identity host.
	provider, err := newAuthProvider(issuer, s.authStore)
	if err != nil {
		return fmt.Errorf("oidc provider init: %w", err)
	}

	// WebAuthn passkey endpoints, served on the identity host.
	waHandler, err := newWebAuthnHandler(identityHost, "Sovereign", "https://"+identityHost, s.store)
	if err != nil {
		return fmt.Errorf("webauthn init: %w", err)
	}

	// Admin guard: validates a bearer access token and requires the subject
	// to be an instance admin. Protects the admin backup + moderation routes.
	adminGuard := &wiring.AdminGuard{Key: s.authStore.SigningKeyMaterial(), Store: s.store, Issuer: issuer, Audience: s.cfg.Audience}

	// Admin backup config (GET form / POST apply).
	backupHandler := &admin.BackupHandler{
		Apply: func(cfg admin.BackupConfig) error {
			if err := admin.ValidateBackupConfig(cfg); err != nil {
				return err
			}
			s.logger.Info("backup config applied", "schedule", cfg.Schedule, "destination", cfg.Destination, "prefix", cfg.Prefix)
			return nil
		},
	}

	// Admin moderation takedown with a persistent audit log.
	takedown := &moderation.TakedownHandler{
		Backend: backendFor,
		Log:     moderation.NewStoreAuditLog(s.store),
		AdminAuthorizer: func(r *http.Request) bool {
			return adminGuard.Authorize(r)
		},
	}

	// IndieAuth bridge, served on the identity host. It mints tokens for an
	// IndieAuth identity URL via the shared OIDC signing key.
	iaBridge := indieauth.NewBridge(true, &indieauthIssuer{key: s.authStore.SigningKeyMaterial(), issuer: issuer, audience: s.cfg.Audience})

	// Host-based dispatch: the identity host serves the OIDC provider and
	// WebAuthn endpoints; every other host serves the protocol mux.
	var root http.Handler = mux
	if provider != nil || waHandler != nil {
		identity := http.NewServeMux()
		if provider != nil {
			identity.Handle("/", provider.Handler())
		}
		if waHandler != nil {
			identity.Handle("/webauthn/register/begin", http.HandlerFunc(waHandler.RegisterBegin))
			identity.Handle("/webauthn/register/finish", http.HandlerFunc(waHandler.RegisterFinish))
			identity.Handle("/webauthn/login/begin", http.HandlerFunc(waHandler.LoginBegin))
			identity.Handle("/webauthn/login/finish", http.HandlerFunc(waHandler.LoginFinish))
		}
		// IndieAuth endpoints.
		iaSessions := newIndieAuthSessionStore()
		identity.Handle("/indieauth/auth", http.HandlerFunc(indieAuthAuthorize(iaBridge, iaSessions)))
		identity.Handle("/indieauth/token", http.HandlerFunc(indieAuthToken(iaBridge, iaSessions)))
		// Admin routes on the identity host, behind the admin guard.
		identity.Handle("/admin/backup", adminGuard.Middleware(backupHandler))
		identity.Handle("/admin/moderation/takedown", adminGuard.Middleware(takedown))
		// Admin user creation + magic-link invite.
		userHandler := &admin.UserHandler{Store: s.store, Sender: s.mailer, BaseURL: "https://" + identityHost}
		identity.Handle("/admin/users", adminGuard.Middleware(userHandler))
		// Magic-link redemption (public, no admin guard).
		identity.Handle("/invite/", inviteHandler(s.store, s.authStore.SigningKeyMaterial(), issuer, s.cfg.Audience))
		// User panel (first-login ToS + passkey + profile).
		identity.Handle("/panel", panelHandler(s.store, s.authStore.SigningKeyMaterial(), issuer, s.cfg.Audience))
		identity.Handle("/panel/", panelHandler(s.store, s.authStore.SigningKeyMaterial(), issuer, s.cfg.Audience))
		// IPFS pinning broker, behind the admin guard.
		identity.Handle("/ipfs/pin", adminGuard.Middleware(http.HandlerFunc(ipfsBroker.pin)))
		identity.Handle("/ipfs/pin/", adminGuard.Middleware(http.HandlerFunc(ipfsBroker.status)))
		// Control-plane REST API (/api/v1), mounted on the identity host. It
		// shares the host with the OIDC provider at "/"; the distinct /api/v1
		// prefix keeps the two surfaces from colliding.
		apiHandler, err := s.apiHandler(waHandler)
		if err != nil {
			return fmt.Errorf("api handler: %w", err)
		}
		identity.Handle("/api/v1/", apiHandler)
		root = hostRouter{
			identityHost: identityHost,
			identity:     identity,
			other:        mux,
		}
	}

	// Tenant middleware wraps the whole mux.
	s.mux = tenant.Middleware(s.tenantStore())(root)
	return nil
}

// hostRouter dispatches to the identity handler on the identity host and the
// protocol mux on every other host.
type hostRouter struct {
	identityHost string
	identity     http.Handler
	other        http.Handler
}

func (h hostRouter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := tenant.NormalizeHost(r.Host)
	if host == h.identityHost {
		h.identity.ServeHTTP(w, r)
		return
	}
	h.other.ServeHTTP(w, r)
}

// apiHandler builds the /api/v1 control-plane handler with the real meta
// dependencies (capabilities, version, ping) and wires the middleware chain
// config from the server config. The returned lifecycle is stored so Close
// stops its background goroutines.
func (s *Server) apiHandler(waHandler *auth.WebAuthnHandler) (http.Handler, error) {
	// The honest wired-feature list: authn/identity plumbing is live; data-plane
	// features stay false until their wiring lands in Phase 3/4.
	capabilities := dto.Capabilities{
		Backup:   false,
		Atproto:  false,
		Solid:    false,
		IPFS:     false,
		Proofs:   false,
		WebAuthn: true,
		OIDC:     true,
	}

	// /ready pings the SQLite store; unreachable store fails closed with 503.
	ping := func(ctx context.Context) error { return s.store.DB().PingContext(ctx) }

	h := meta.New(
		meta.WithCapabilities(capabilities),
		meta.WithVersion(meta.VersionInfo{Version: s.version}),
		meta.WithPing(ping),
	)

	ah := v1auth.New(s.store, s.authStore.SigningKeyMaterial(), "https://id."+s.cfg.Domain, waHandler, s.logger)

	routes := api.ToRouteInfo(api.RoutesForAPI(h, ah))
	life := middleware.NewHandler(&middleware.ChainConfig{
		Routes:        routes,
		Logger:        s.logger,
		SigningKey:    s.authStore.SigningKeyMaterial(),
		Issuer:        "https://id." + s.cfg.Domain,
		SessionCookie: "session",
		Sessions:      s.store,
		Users:         s.store,
		DualRead:      s.cfg.Auth.Session.DualRead,
		CORSOrigins:   s.cfg.API.CORSOrigins,
		BodyLimit:     middleware.DefaultMaxBodyBytes,
	})
	s.apiClose = life.Close
	return life, nil
}

// tenantStore resolves a host to a tenant from the SQLite store.
func (s *Server) tenantStore() tenant.Store {
	return sqliteTenantStore{store: s.store}
}

// sqliteTenantStore resolves hosts to tenants via the SQLite store.
type sqliteTenantStore struct {
	store *store.Store
}

func (t sqliteTenantStore) FindByHost(ctx context.Context, host string) (*tenant.Tenant, error) {
	tn, err := t.store.GetTenantByHandle(ctx, host)
	if err != nil {
		return nil, tenant.ErrNotFound
	}
	return &tenant.Tenant{
		ID:        tn.ID,
		Handle:    tn.Handle,
		DIDMethod: tn.DIDMethod,
		DID:       tn.DID,
	}, nil
}

// hcardHandler serves the HTML h-card profile from the store. It renders a
// uniform 404 for unpublished/unknown profiles (no tenant-enumeration signal).
func (s *Server) hcardHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		t, ok := tenant.FromContext(r.Context())
		if !ok {
			http.NotFound(w, r)
			return
		}
		page, err := s.store.GetProfilePage(r.Context(), t.ID)
		if err != nil || !page.IsPublished {
			http.NotFound(w, r)
			return
		}
		links, _ := s.store.ListProfileLinks(r.Context(), page.ID)
		p := &hyperlink.Profile{
			Handle:      t.Handle,
			DisplayName: page.DisplayName,
			Bio:         page.Bio,
			Published:   true,
		}
		for i := range links {
			if !links[i].IsVisible {
				continue
			}
			p.Links = append(p.Links, hyperlink.Link{
				Label:   links[i].Label,
				URL:     links[i].URL,
				Visible: true,
			})
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=60")
		_ = hyperlink.RenderHTML(w, p)
	}
}

// didDocHandler serves the DID document. It uses the tenant's real DID when
// set, falling back to did:web:<host>.
func (s *Server) didDocHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		t, ok := tenant.FromContext(r.Context())
		if !ok {
			http.NotFound(w, r)
			return
		}
		tn, err := s.store.GetTenantByHandle(r.Context(), t.Handle)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		// Normalize the resolved handle so the fallback never reflects the
		// raw request host (B15).
		th := tenant.NormalizeHost(tn.Handle)
		did := tn.DID
		if did == "" {
			did = "did:web:" + th
		}
		w.Header().Set("Content-Type", "application/did+json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"@context":    []string{"https://www.w3.org/ns/did/v1"},
			"id":          did,
			"alsoKnownAs": []string{"https://" + th + "/profile/"},
		})
	}
}

// ServeHTTP serves the assembled server.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

// Run starts the HTTP server on addr with graceful shutdown. It blocks until
// the server exits or ctx is cancelled (SIGINT/SIGTERM), then shuts down.
func (s *Server) Run(ctx context.Context, addr string) error {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	return s.Serve(ctx, ln)
}

// Serve serves on an existing listener with graceful shutdown. It blocks
// until the server exits or ctx is cancelled, then shuts down cleanly.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	srv := &http.Server{
		Handler:      s,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
	}
	s.logger.Info("server listening", "addr", ln.Addr().String())

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Serve(ln)
	}()

	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
		// Graceful shutdown with a timeout.
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown: %w", err)
		}
	}
	return nil
}

// newLogger builds a slog logger from config.
func newLogger(cfg LogConfig) *slog.Logger {
	level := slog.LevelInfo
	switch cfg.Level {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
}
