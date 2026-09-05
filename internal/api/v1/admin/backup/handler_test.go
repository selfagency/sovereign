package backup_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/selfagency/sovereign/internal/api/dto"
	"github.com/selfagency/sovereign/internal/api/middleware"
	v1backup "github.com/selfagency/sovereign/internal/api/v1/admin/backup"
	"github.com/selfagency/sovereign/internal/backup"
	"github.com/selfagency/sovereign/internal/storage"
	"github.com/selfagency/sovereign/internal/store"
)

func testStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func adminPrincipal() *middleware.Principal {
	return &middleware.Principal{UserID: "admin", TenantID: "identity", Scopes: []string{"admin:backup"}, IsAdmin: true}
}

func nonAdminPrincipal() *middleware.Principal {
	return &middleware.Principal{UserID: "user", TenantID: "tenant-a", Scopes: []string{"self"}, IsAdmin: false}
}

func req(method, path string, p *middleware.Principal) *http.Request {
	r := httptest.NewRequest(method, path, http.NoBody)
	if p != nil {
		r = r.WithContext(middleware.WithPrincipal(r.Context(), p))
	}
	return r
}

func do(h http.HandlerFunc, r *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func decode[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode %T: %v (body %s)", v, err, rec.Body.String())
	}
	return v
}

// newHandler builds a backup Handler with a real FS backend and a scheduler
// whose BackupFn produces fixed bytes. The scheduler is started so a config
// PUT can restart it.
func newHandler(t *testing.T, s *store.Store) *v1backup.Handler {
	t.Helper()
	fs := &storage.FS{Root: t.TempDir()}
	dest := &backup.FSDestination{Backend: fs, Prefix: "backups"}
	sched := backup.NewScheduler(backup.Config{Schedule: "0 0 2 * * *", Destination: dest}, func(ctx context.Context) (io.Reader, error) {
		return strings.NewReader("backup-data"), nil
	})
	if err := sched.Start(); err != nil {
		t.Fatalf("scheduler start: %v", err)
	}
	t.Cleanup(sched.Stop)
	return v1backup.New(s, slog.New(slog.NewTextHandler(io.Discard, nil)), sched, sched.BackupFn, fs)
}

func TestGetConfigNotFound(t *testing.T) {
	s := testStore(t)
	h := newHandler(t, s)
	rec := do(h.GetConfig, req(http.MethodGet, "/api/v1/admin/backup/config", adminPrincipal()))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("get = %d, want 404 (body %s)", rec.Code, rec.Body.String())
	}
}

func TestPutConfigPersistsAndDrivesScheduler(t *testing.T) {
	s := testStore(t)
	h := newHandler(t, s)

	body := `{"schedule":"0 0 3 * * *","destination":"fs","prefix":"new-prefix"}`
	r := req(http.MethodPut, "/api/v1/admin/backup/config", adminPrincipal())
	r.Body = io.NopCloser(strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	rec := do(h.PutConfig, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("put = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	got := decode[dto.BackupConfig](t, rec)
	if got.Schedule != "0 0 3 * * *" || got.Destination != "fs" || got.Prefix != "new-prefix" {
		t.Fatalf("config = %+v", got)
	}

	// Persisted in the store.
	cfg, err := s.GetBackupConfig(context.Background())
	if err != nil {
		t.Fatalf("GetBackupConfig: %v", err)
	}
	if cfg.Schedule != "0 0 3 * * *" || cfg.Prefix != "new-prefix" {
		t.Fatalf("persisted = %+v", cfg)
	}

	// The scheduler was restarted with the new config: a manual run writes to
	// the new prefix.
	runRec := do(h.TriggerRun, req(http.MethodPost, "/api/v1/admin/backup/runs", adminPrincipal()))
	if runRec.Code != http.StatusCreated {
		t.Fatalf("trigger = %d, want 201 (body %s)", runRec.Code, runRec.Body.String())
	}
	run := decode[dto.BackupRun](t, runRec)
	if run.Status != "succeeded" {
		t.Fatalf("run status = %q, want succeeded (body %s)", run.Status, runRec.Body.String())
	}
	if !strings.HasPrefix(run.DestinationKey, "new-prefix/") {
		t.Fatalf("destination_key = %q, want new-prefix/ prefix", run.DestinationKey)
	}
}

func TestPutConfigValidation(t *testing.T) {
	s := testStore(t)
	h := newHandler(t, s)
	for _, body := range []string{
		`{"schedule":"","destination":"fs","prefix":"p"}`,
		`{"schedule":"0 0 2 * * *","destination":"gcs","prefix":"p"}`,
		`{"schedule":"0 0 2 * * *","destination":"fs","prefix":""}`,
		`{`,
	} {
		r := req(http.MethodPut, "/api/v1/admin/backup/config", adminPrincipal())
		r.Body = io.NopCloser(strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		rec := do(h.PutConfig, r)
		if rec.Code != http.StatusUnprocessableEntity && rec.Code != http.StatusBadRequest {
			t.Fatalf("body %q = %d, want 4xx (body %s)", body, rec.Code, rec.Body.String())
		}
	}
}

func TestTriggerRunRecordsRun(t *testing.T) {
	s := testStore(t)
	h := newHandler(t, s)

	rec := do(h.TriggerRun, req(http.MethodPost, "/api/v1/admin/backup/runs", adminPrincipal()))
	if rec.Code != http.StatusCreated {
		t.Fatalf("trigger = %d, want 201 (body %s)", rec.Code, rec.Body.String())
	}
	run := decode[dto.BackupRun](t, rec)
	if run.Status != "succeeded" || run.DestinationKey == "" {
		t.Fatalf("run = %+v", run)
	}

	// Persisted and listable.
	listRec := do(h.ListRuns, req(http.MethodGet, "/api/v1/admin/backup/runs", adminPrincipal()))
	if listRec.Code != http.StatusOK {
		t.Fatalf("list = %d, want 200", listRec.Code)
	}
	list := decode[dto.List[dto.BackupRun]](t, listRec)
	if list.Total != 1 || len(list.Data) != 1 || list.Data[0].ID != run.ID {
		t.Fatalf("list = %+v", list)
	}

	// Fetch by id.
	byID := do(h.RunByID, req(http.MethodGet, "/api/v1/admin/backup/runs/"+run.ID, adminPrincipal()))
	if byID.Code != http.StatusOK {
		t.Fatalf("by id = %d, want 200 (body %s)", byID.Code, byID.Body.String())
	}
	got := decode[dto.BackupRun](t, byID)
	if got.ID != run.ID || got.Status != "succeeded" {
		t.Fatalf("by id = %+v", got)
	}
}

func TestRunByIDNotFound(t *testing.T) {
	s := testStore(t)
	h := newHandler(t, s)
	rec := do(h.RunByID, req(http.MethodGet, "/api/v1/admin/backup/runs/missing", adminPrincipal()))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("missing = %d, want 404", rec.Code)
	}
}

func TestRestoreRequiresConfirm(t *testing.T) {
	s := testStore(t)
	h := newHandler(t, s)

	// Missing confirm -> 422.
	r := req(http.MethodPost, "/api/v1/admin/backup/restores", adminPrincipal())
	r.Body = io.NopCloser(strings.NewReader(`{"source_key":"backups/x.tar.gz"}`))
	r.Header.Set("Content-Type", "application/json")
	rec := do(h.Restore, r)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("no confirm = %d, want 422 (body %s)", rec.Code, rec.Body.String())
	}

	// confirm:false -> 422.
	r = req(http.MethodPost, "/api/v1/admin/backup/restores", adminPrincipal())
	r.Body = io.NopCloser(strings.NewReader(`{"source_key":"backups/x.tar.gz","confirm":false}`))
	r.Header.Set("Content-Type", "application/json")
	rec = do(h.Restore, r)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("confirm false = %d, want 422 (body %s)", rec.Code, rec.Body.String())
	}

	// Missing source_key -> 422.
	r = req(http.MethodPost, "/api/v1/admin/backup/restores", adminPrincipal())
	r.Body = io.NopCloser(strings.NewReader(`{"confirm":true}`))
	r.Header.Set("Content-Type", "application/json")
	rec = do(h.Restore, r)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("no source_key = %d, want 422 (body %s)", rec.Code, rec.Body.String())
	}
}

func TestRestoreRecordsRestore(t *testing.T) {
	s := testStore(t)

	// Seed a backup so the restore has a source to read.
	fs := &storage.FS{Root: t.TempDir()}
	dest := &backup.FSDestination{Backend: fs, Prefix: "backups"}
	key, err := dest.WriteBackup(context.Background(), "b1.tar.gz", strings.NewReader("data"))
	if err != nil {
		t.Fatalf("write backup: %v", err)
	}

	// Rebuild the handler with a scheduler whose RestoreFn consumes the bytes.
	sched := backup.NewScheduler(backup.Config{Destination: dest}, nil)
	sched.RestoreFn = func(ctx context.Context, r io.Reader) error {
		_, _ = io.ReadAll(r)
		return nil
	}
	h := v1backup.New(s, slog.New(slog.NewTextHandler(io.Discard, nil)), sched, nil, fs)

	r := req(http.MethodPost, "/api/v1/admin/backup/restores", adminPrincipal())
	r.Body = io.NopCloser(strings.NewReader(`{"source_key":"` + key + `","confirm":true}`))
	r.Header.Set("Content-Type", "application/json")
	rec := do(h.Restore, r)
	if rec.Code != http.StatusCreated {
		t.Fatalf("restore = %d, want 201 (body %s)", rec.Code, rec.Body.String())
	}
	rest := decode[dto.BackupRestore](t, rec)
	if rest.Status != "succeeded" || rest.SourceKey != key || rest.RequestedBy != "admin" {
		t.Fatalf("restore = %+v", rest)
	}

	// Persisted and listable.
	listRec := do(h.ListRestores, req(http.MethodGet, "/api/v1/admin/backup/restores", adminPrincipal()))
	if listRec.Code != http.StatusOK {
		t.Fatalf("list = %d, want 200", listRec.Code)
	}
	list := decode[dto.List[dto.BackupRestore]](t, listRec)
	if list.Total != 1 || len(list.Data) != 1 || list.Data[0].ID != rest.ID {
		t.Fatalf("list = %+v", list)
	}

	byID := do(h.RestoreByID, req(http.MethodGet, "/api/v1/admin/backup/restores/"+rest.ID, adminPrincipal()))
	if byID.Code != http.StatusOK {
		t.Fatalf("by id = %d, want 200 (body %s)", byID.Code, byID.Body.String())
	}
}

// TestSlowRestoreNotKilled proves a restore that takes longer than the default
// per-route timeout completes when the route is declared long-running (Timeout
// resolves to 0, disabling the kill). It exercises the Timeout middleware the
// chain applies to long-running routes.
func TestSlowRestoreNotKilled(t *testing.T) {
	s := testStore(t)
	fs := &storage.FS{Root: t.TempDir()}
	dest := &backup.FSDestination{Backend: fs, Prefix: "backups"}
	key, err := dest.WriteBackup(context.Background(), "b1.tar.gz", strings.NewReader("data"))
	if err != nil {
		t.Fatalf("write backup: %v", err)
	}

	// A RestoreFn that blocks well past any normal timeout budget.
	release := make(chan struct{})
	sched := backup.NewScheduler(backup.Config{Destination: dest}, nil)
	sched.RestoreFn = func(ctx context.Context, r io.Reader) error {
		select {
		case <-release:
		case <-ctx.Done():
			return ctx.Err()
		}
		_, _ = io.ReadAll(r)
		return nil
	}
	h := v1backup.New(s, slog.New(slog.NewTextHandler(io.Discard, nil)), sched, nil, fs)

	// Long-running routes resolve to 0 timeout => the Timeout middleware is a
	// no-op and the slow restore is never killed.
	wrapped := middleware.Timeout(func(*http.Request) time.Duration { return 0 })(http.HandlerFunc(h.Restore))

	body := `{"source_key":"` + key + `","confirm":true}`
	r := req(http.MethodPost, "/api/v1/admin/backup/restores", adminPrincipal())
	r.Body = io.NopCloser(strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		wrapped.ServeHTTP(rec, r)
		close(done)
	}()
	// Release the restore after a delay longer than any normal timeout budget.
	time.Sleep(120 * time.Millisecond)
	close(release)
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("slow restore did not complete")
	}
	if rec.Code != http.StatusCreated {
		t.Fatalf("slow restore = %d, want 201 (must not be killed; body %s)", rec.Code, rec.Body.String())
	}
}

func TestNonAdminPrincipalForbidden(t *testing.T) {
	s := testStore(t)
	h := newHandler(t, s)

	cases := []struct {
		name string
		do   func() *httptest.ResponseRecorder
	}{
		{"get config", func() *httptest.ResponseRecorder {
			return do(h.GetConfig, req(http.MethodGet, "/api/v1/admin/backup/config", nonAdminPrincipal()))
		}},
		{"put config", func() *httptest.ResponseRecorder {
			r := req(http.MethodPut, "/api/v1/admin/backup/config", nonAdminPrincipal())
			r.Body = io.NopCloser(strings.NewReader(`{"schedule":"0 2 * * *","destination":"fs","prefix":"p"}`))
			return do(h.PutConfig, r)
		}},
		{"list runs", func() *httptest.ResponseRecorder {
			return do(h.ListRuns, req(http.MethodGet, "/api/v1/admin/backup/runs", nonAdminPrincipal()))
		}},
		{"trigger run", func() *httptest.ResponseRecorder {
			return do(h.TriggerRun, req(http.MethodPost, "/api/v1/admin/backup/runs", nonAdminPrincipal()))
		}},
		{"run by id", func() *httptest.ResponseRecorder {
			return do(h.RunByID, req(http.MethodGet, "/api/v1/admin/backup/runs/x", nonAdminPrincipal()))
		}},
		{"restore", func() *httptest.ResponseRecorder {
			r := req(http.MethodPost, "/api/v1/admin/backup/restores", nonAdminPrincipal())
			r.Body = io.NopCloser(strings.NewReader(`{"source_key":"k","confirm":true}`))
			return do(h.Restore, r)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := tc.do()
			if rec.Code != http.StatusForbidden {
				t.Fatalf("%s = %d, want 403 (body %s)", tc.name, rec.Code, rec.Body.String())
			}
		})
	}
}

func TestUnauthenticated(t *testing.T) {
	s := testStore(t)
	h := newHandler(t, s)
	rec := do(h.GetConfig, req(http.MethodGet, "/api/v1/admin/backup/config", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated = %d, want 401", rec.Code)
	}
}

// TestTriggerRunFailure verifies a failing backup is recorded as a failed run.
func TestTriggerRunFailure(t *testing.T) {
	s := testStore(t)
	fs := &storage.FS{Root: t.TempDir()}
	dest := &backup.FSDestination{Backend: fs, Prefix: "backups"}
	sched := backup.NewScheduler(backup.Config{Destination: dest}, func(ctx context.Context) (io.Reader, error) {
		return nil, errors.New("disk full")
	})
	h := v1backup.New(s, slog.New(slog.NewTextHandler(io.Discard, nil)), sched, sched.BackupFn, fs)

	rec := do(h.TriggerRun, req(http.MethodPost, "/api/v1/admin/backup/runs", adminPrincipal()))
	if rec.Code != http.StatusCreated {
		t.Fatalf("trigger = %d, want 201 (body %s)", rec.Code, rec.Body.String())
	}
	run := decode[dto.BackupRun](t, rec)
	if run.Status != "failed" || run.Error == nil || !strings.Contains(*run.Error, "disk full") {
		t.Fatalf("run = %+v", run)
	}
}

// TestRestoreFailure verifies a failing restore is recorded as failed.
func TestRestoreFailure(t *testing.T) {
	s := testStore(t)
	fs := &storage.FS{Root: t.TempDir()}
	dest := &backup.FSDestination{Backend: fs, Prefix: "backups"}
	key, err := dest.WriteBackup(context.Background(), "b1.tar.gz", strings.NewReader("data"))
	if err != nil {
		t.Fatalf("write backup: %v", err)
	}
	sched := backup.NewScheduler(backup.Config{Destination: dest}, nil)
	sched.RestoreFn = func(ctx context.Context, r io.Reader) error {
		return errors.New("corrupt backup")
	}
	h := v1backup.New(s, slog.New(slog.NewTextHandler(io.Discard, nil)), sched, nil, fs)

	r := req(http.MethodPost, "/api/v1/admin/backup/restores", adminPrincipal())
	r.Body = io.NopCloser(strings.NewReader(`{"source_key":"` + key + `","confirm":true}`))
	r.Header.Set("Content-Type", "application/json")
	rec := do(h.Restore, r)
	if rec.Code != http.StatusCreated {
		t.Fatalf("restore = %d, want 201 (body %s)", rec.Code, rec.Body.String())
	}
	rest := decode[dto.BackupRestore](t, rec)
	if rest.Status != "failed" || rest.Error == nil || !strings.Contains(*rest.Error, "corrupt backup") {
		t.Fatalf("restore = %+v", rest)
	}
}

// TestRestoreByIDNotFound verifies a missing restore returns 404.
func TestRestoreByIDNotFound(t *testing.T) {
	s := testStore(t)
	h := newHandler(t, s)
	rec := do(h.RestoreByID, req(http.MethodGet, "/api/v1/admin/backup/restores/missing", adminPrincipal()))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("missing = %d, want 404", rec.Code)
	}
}

// TestListPagination verifies limit/offset query params and invalid values.
func TestListPagination(t *testing.T) {
	s := testStore(t)
	h := newHandler(t, s)

	// Invalid limit -> 422.
	rec := do(h.ListRuns, req(http.MethodGet, "/api/v1/admin/backup/runs?limit=abc", adminPrincipal()))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("bad limit = %d, want 422", rec.Code)
	}
	rec = do(h.ListRuns, req(http.MethodGet, "/api/v1/admin/backup/runs?offset=-1", adminPrincipal()))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("bad offset = %d, want 422", rec.Code)
	}

	// Valid pagination returns an empty page.
	rec = do(h.ListRuns, req(http.MethodGet, "/api/v1/admin/backup/runs?limit=5&offset=0", adminPrincipal()))
	if rec.Code != http.StatusOK {
		t.Fatalf("paged = %d, want 200", rec.Code)
	}
	list := decode[dto.List[dto.BackupRun]](t, rec)
	if list.Limit != 5 || list.Offset != 0 {
		t.Fatalf("list = %+v", list)
	}
}

// TestClosedStoreInternal verifies handlers degrade to 500, never panic, when
// the store fails.
func TestClosedStoreInternal(t *testing.T) {
	s := testStore(t)
	if err := s.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}
	fs := &storage.FS{Root: t.TempDir()}
	sched := backup.NewScheduler(backup.Config{Destination: &backup.FSDestination{Backend: fs, Prefix: "backups"}}, nil)
	h := v1backup.New(s, slog.New(slog.NewTextHandler(io.Discard, nil)), sched, nil, fs)

	cases := []struct {
		name string
		do   func() *httptest.ResponseRecorder
	}{
		{"get config", func() *httptest.ResponseRecorder {
			return do(h.GetConfig, req(http.MethodGet, "/api/v1/admin/backup/config", adminPrincipal()))
		}},
		{"put config", func() *httptest.ResponseRecorder {
			r := req(http.MethodPut, "/api/v1/admin/backup/config", adminPrincipal())
			r.Body = io.NopCloser(strings.NewReader(`{"schedule":"0 0 2 * * *","destination":"fs","prefix":"p"}`))
			return do(h.PutConfig, r)
		}},
		{"list runs", func() *httptest.ResponseRecorder {
			return do(h.ListRuns, req(http.MethodGet, "/api/v1/admin/backup/runs", adminPrincipal()))
		}},
		{"run by id", func() *httptest.ResponseRecorder {
			return do(h.RunByID, req(http.MethodGet, "/api/v1/admin/backup/runs/x", adminPrincipal()))
		}},
		{"list restores", func() *httptest.ResponseRecorder {
			return do(h.ListRestores, req(http.MethodGet, "/api/v1/admin/backup/restores", adminPrincipal()))
		}},
		{"restore by id", func() *httptest.ResponseRecorder {
			return do(h.RestoreByID, req(http.MethodGet, "/api/v1/admin/backup/restores/x", adminPrincipal()))
		}},
		{"trigger run", func() *httptest.ResponseRecorder {
			return do(h.TriggerRun, req(http.MethodPost, "/api/v1/admin/backup/runs", adminPrincipal()))
		}},
		{"restore", func() *httptest.ResponseRecorder {
			r := req(http.MethodPost, "/api/v1/admin/backup/restores", adminPrincipal())
			r.Body = io.NopCloser(strings.NewReader(`{"source_key":"k","confirm":true}`))
			return do(h.Restore, r)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := tc.do()
			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("%s = %d, want 500 (body %s)", tc.name, rec.Code, rec.Body.String())
			}
		})
	}
}

// TestPutConfigS3Destination verifies the s3 destination path builds a
// scheduler successfully.
func TestPutConfigS3Destination(t *testing.T) {
	s := testStore(t)
	h := newHandler(t, s)

	r := req(http.MethodPut, "/api/v1/admin/backup/config", adminPrincipal())
	r.Body = io.NopCloser(strings.NewReader(`{"schedule":"0 0 2 * * *","destination":"s3","prefix":"b"}`))
	r.Header.Set("Content-Type", "application/json")
	rec := do(h.PutConfig, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("put s3 = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	got := decode[dto.BackupConfig](t, rec)
	if got.Destination != "s3" {
		t.Fatalf("config = %+v", got)
	}
}

// TestPutConfigInvalidCron verifies a schedule that passes field validation but
// is not a valid cron expression fails to restart the scheduler and returns
// 500 (the config is still persisted).
func TestPutConfigInvalidCron(t *testing.T) {
	s := testStore(t)
	h := newHandler(t, s)

	r := req(http.MethodPut, "/api/v1/admin/backup/config", adminPrincipal())
	r.Body = io.NopCloser(strings.NewReader(`{"schedule":"not-a-cron","destination":"fs","prefix":"p"}`))
	r.Header.Set("Content-Type", "application/json")
	rec := do(h.PutConfig, r)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("invalid cron = %d, want 500 (body %s)", rec.Code, rec.Body.String())
	}
}

// TestNewNilLogger verifies New accepts a nil logger without panicking.
func TestNewNilLogger(t *testing.T) {
	s := testStore(t)
	fs := &storage.FS{Root: t.TempDir()}
	sched := backup.NewScheduler(backup.Config{Destination: &backup.FSDestination{Backend: fs, Prefix: "backups"}}, nil)
	h := v1backup.New(s, nil, sched, nil, fs)
	if h == nil {
		t.Fatal("New with nil logger returned nil handler")
	}
}

// TestPathValueEmpty verifies an empty path segment yields 404, not a store
// call.
func TestPathValueEmpty(t *testing.T) {
	s := testStore(t)
	h := newHandler(t, s)
	rec := do(h.RunByID, req(http.MethodGet, "/api/v1/admin/backup/runs/", adminPrincipal()))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("empty id = %d, want 404", rec.Code)
	}
}
