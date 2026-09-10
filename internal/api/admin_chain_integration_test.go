package api

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/selfagency/sovereign/internal/api/middleware"
	"github.com/selfagency/sovereign/internal/api/v1/admin"
	"github.com/selfagency/sovereign/internal/api/v1/admin/system"
	"github.com/selfagency/sovereign/internal/api/v1/meta"
	"github.com/selfagency/sovereign/internal/auth"
	"github.com/selfagency/sovereign/internal/backup"
	"github.com/selfagency/sovereign/internal/mail"
	"github.com/selfagency/sovereign/internal/storage"
	"github.com/selfagency/sovereign/internal/store"
)

// buildAdminChain assembles the real middleware chain over the admin route set
// (RoutesForAdmin with a wired admin handler), backed by a real store + key.
// It returns the handler plus a mint helper for bearer tokens.
func buildAdminChain(t *testing.T) (chain http.Handler, mint func(sub string, isAdmin bool, scopes []string) string) {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	// Seed a tenant + a placeholder admin so the auto-admin slot is consumed,
	// leaving subsequent users to honor their explicit IsAdmin.
	if err := s.CreateTenant(t.Context(), &store.Tenant{ID: "tenant-1", Handle: "alice.example.com", DIDMethod: "web"}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateUser(t.Context(), &store.User{
		ID: "placeholder-admin", TenantID: "tenant-1", Handle: "placeholder", Email: "ph@x.test", IsAdmin: true,
	}); err != nil {
		t.Fatal(err)
	}

	// Backup handler needs a scheduler whose BackupFn writes a blob; give it a
	// real FS backend so TriggerRun/Restore work end to end.
	fs := &storage.FS{Root: t.TempDir()}
	sched := backup.NewScheduler(backup.Config{
		Schedule:    "0 0 2 * * *",
		Destination: &backup.FSDestination{Backend: fs, Prefix: "backups"},
	}, func(ctx context.Context) (io.Reader, error) {
		return strings.NewReader("backup-data"), nil
	})
	if err := sched.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sched.Stop)

	m := meta.New()
	adm := admin.New(s, slog.New(slog.NewTextHandler(io.Discard, nil)), sched, sched.BackupFn, fs, nil, &system.Info{}, mail.NewLogSender(slog.New(slog.NewTextHandler(io.Discard, nil))), "https://id.example.test", nil)
	routes := RoutesForAdmin(m, nil, nil, adm)
	infos := ToRouteInfo(routes)

	life := middleware.NewHandler(&middleware.ChainConfig{
		Routes:        infos,
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		SigningKey:    key,
		Issuer:        "https://id.example.test",
		SessionCookie: "session",
		Sessions:      s,
		Users:         s,
		DualRead:      true,
		BodyLimit:     middleware.DefaultMaxBodyBytes,
	})
	t.Cleanup(life.Close)

	mint = func(sub string, isAdmin bool, scopes []string) string {
		t.Helper()
		if err := s.CreateUser(t.Context(), &store.User{
			ID: sub, TenantID: "tenant-1", Handle: sub, Email: sub + "@x.test", IsAdmin: isAdmin,
		}); err != nil {
			t.Fatal(err)
		}
		tok, err := auth.MintAccessToken(key, sub, scopes, time.Minute, "https://id.example.test", "sovereign-api")
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}

	return life, mint
}

// TestAdminRoutesNonAdminForbidden drives EVERY admin route through the real
// middleware chain with a non-admin bearer token carrying the route's coarse
// admin scope. The scope middleware must reject it with 403 (admin:* scope +
// IsAdmin both required), never reaching the handler.
func TestAdminRoutesNonAdminForbidden(t *testing.T) {
	life, mint := buildAdminChain(t)

	// A non-admin bearer carrying the full coarse admin scope set.
	tok := mint("nonadmin", false, []string{
		"admin:tenants", "admin:clients", "admin:moderation", "admin:backup",
		"admin:audit", "admin:users", "admin:system",
	})

	for _, r := range adminRoutes(nil) {
		if r.Anonymous {
			continue
		}
		req := httptest.NewRequest(r.Method, r.Path, http.NoBody)
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		life.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("non-admin %s %s = %d, want 403 (body %s)", r.Method, r.Path, rec.Code, rec.Body.String())
		}
	}
}

// allAdminGranularScopes is the union of every granular scope the admin route
// table declares, so an admin bearer with this set can reach any admin route.
var allAdminGranularScopes = []string{
	"admin:tenants:read", "admin:tenants:write",
	"admin:clients:read", "admin:clients:write",
	"admin:moderation:read", "admin:moderation:write",
	"admin:backup:read", "admin:backup:write",
	"admin:audit:read",
	"admin:users:read", "admin:users:write",
	"admin:system:read",
}

// TestAdminRoutesAdminReaches verifies an admin bearer with the granular admin
// scopes passes the scope middleware on a representative admin route (a GET
// that needs no body), returning 200 rather than 403/401.
func TestAdminRoutesAdminReaches(t *testing.T) {
	life, mint := buildAdminChain(t)
	tok := mint("admin", true, allAdminGranularScopes)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/system/info", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	life.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin GET /admin/system/info = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
}

// TestAdminBackupRunIdempotencyReplay proves a backup run POST with the same
// Idempotency-Key replays the original response and does not double-run. The
// handler writes a backup_runs row each execution; a replay must not add a
// second row.
func TestAdminBackupRunIdempotencyReplay(t *testing.T) {
	life, mint := buildAdminChain(t)
	tok := mint("admin", true, []string{"admin:backup:write", "admin:backup:read"})

	do := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/backup/runs", http.NoBody)
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Idempotency-Key", "run-key-1")
		rec := httptest.NewRecorder()
		life.ServeHTTP(rec, req)
		return rec
	}
	first := do()
	second := do()

	if first.Code != http.StatusCreated || second.Code != http.StatusCreated {
		t.Fatalf("codes = %d, %d; want 201 201 (body %s)", first.Code, second.Code, first.Body.String())
	}
	if first.Body.String() != second.Body.String() {
		t.Fatalf("replay body differs:\n first=%s\nsecond=%s", first.Body.String(), second.Body.String())
	}

	// A replay must not double-run: only one backup_runs row exists.
	// Count via the store used by buildAdminChain is not accessible, so assert
	// the scheduler's run recorded exactly once by listing through the API.
	list := httptest.NewRequest(http.MethodGet, "/api/v1/admin/backup/runs", http.NoBody)
	list.Header.Set("Authorization", "Bearer "+tok)
	lrec := httptest.NewRecorder()
	life.ServeHTTP(lrec, list)
	if !strings.Contains(lrec.Body.String(), `"total":1`) {
		t.Fatalf("expected exactly 1 backup run after replay, got %s", lrec.Body.String())
	}
}
