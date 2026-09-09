package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestBackupConfigUpsertGet verifies the single-row config persists and
// round-trips through the RFC 3339 TEXT updated_at column.
func TestBackupConfigUpsertGet(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	// No config yet -> ErrNotFound.
	if _, err := s.GetBackupConfig(ctx); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing config = %v, want ErrNotFound", err)
	}

	must(t, s.UpsertBackupConfig(ctx, "0 2 * * *", "fs", "backups"))
	cfg, err := s.GetBackupConfig(ctx)
	must(t, err)
	if cfg.Schedule != "0 2 * * *" || cfg.Destination != "fs" || cfg.Prefix != "backups" {
		t.Fatalf("config = %+v", cfg)
	}
	if cfg.UpdatedAt.IsZero() {
		t.Fatal("updated_at not parsed")
	}

	// Upsert replaces the single row.
	must(t, s.UpsertBackupConfig(ctx, "0 3 * * *", "s3", "b2"))
	cfg, err = s.GetBackupConfig(ctx)
	must(t, err)
	if cfg.Schedule != "0 3 * * *" || cfg.Destination != "s3" || cfg.Prefix != "b2" {
		t.Fatalf("config after upsert = %+v", cfg)
	}
}

// TestBackupRunCRUD verifies create/list/get/update for backup runs.
func TestBackupRunCRUD(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	now := time.Now().UTC()
	r := &BackupRun{ID: "r1", StartedAt: now, Status: "running"}
	must(t, s.CreateBackupRun(ctx, r))

	// List.
	runs, total, err := s.ListBackupRuns(ctx, 10, 0)
	must(t, err)
	assertBackupRunList(t, runs, total, 1, 1, "r1", "running")

	// Get.
	got, err := s.BackupRunByID(ctx, "r1")
	must(t, err)
	if got.ID != "r1" || got.FinishedAt != nil {
		t.Fatalf("got = %+v", got)
	}

	// Update to success.
	must(t, s.UpdateBackupRun(ctx, "r1", "succeeded", "", 1234, "backups/x.tar.gz"))
	got, err = s.BackupRunByID(ctx, "r1")
	must(t, err)
	assertBackupRunSucceeded(t, got)

	// Update to failure clears size/key and sets error.
	must(t, s.UpdateBackupRun(ctx, "r1", "failed", "disk full", 0, ""))
	got, _ = s.BackupRunByID(ctx, "r1")
	assertBackupRunFailed(t, got)

	// Missing run.
	if _, err := s.BackupRunByID(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing = %v, want ErrNotFound", err)
	}
	mustErrNotFound(t, s.UpdateBackupRun(ctx, "missing", "succeeded", "", 0, ""))
}

// assertBackupRunSucceeded checks a run updated to success.
func assertBackupRunSucceeded(t *testing.T, got *BackupRun) {
	t.Helper()
	if got.Status != "succeeded" || got.SizeBytes != 1234 || got.DestinationKey != "backups/x.tar.gz" {
		t.Fatalf("updated = %+v", got)
	}
	if got.FinishedAt == nil {
		t.Fatal("finished_at not set")
	}
}

// assertBackupRunFailed checks a run updated to failure cleared size/key.
func assertBackupRunFailed(t *testing.T, got *BackupRun) {
	t.Helper()
	if got.Status != "failed" || got.Error == nil || *got.Error != "disk full" {
		t.Fatalf("failed = %+v", got)
	}
	if got.SizeBytes != 0 || got.DestinationKey != "" {
		t.Fatalf("failed run should clear size/key: %+v", got)
	}
}

// assertBackupRunList checks a backup-run list page's total/len and the first
// run's id/status.
func assertBackupRunList(t *testing.T, runs []BackupRun, total, wantTotal, wantLen int, wantID, wantStatus string) {
	t.Helper()
	if total != wantTotal || len(runs) != wantLen {
		t.Fatalf("list = %d/%d, want %d/%d", len(runs), total, wantLen, wantTotal)
	}
	if runs[0].ID != wantID || runs[0].Status != wantStatus {
		t.Fatalf("run = %+v", runs[0])
	}
	if runs[0].StartedAt.IsZero() {
		t.Fatal("started_at not parsed")
	}
}

// TestBackupRestoreCRUD verifies create/list/get/update for restores.
func TestBackupRestoreCRUD(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	now := time.Now().UTC()
	rest := &BackupRestore{ID: "x1", StartedAt: now, Status: "running", SourceKey: "backups/x.tar.gz", RequestedBy: "admin"}
	must(t, s.CreateBackupRestore(ctx, rest))

	restores, total, err := s.ListBackupRestores(ctx, 10, 0)
	must(t, err)
	assertBackupRestoreList(t, restores, total)

	got, err := s.BackupRestoreByID(ctx, "x1")
	must(t, err)
	if got.ID != "x1" || got.FinishedAt != nil {
		t.Fatalf("got = %+v", got)
	}

	must(t, s.UpdateBackupRestore(ctx, "x1", "succeeded", ""))
	got, _ = s.BackupRestoreByID(ctx, "x1")
	assertBackupRestoreSucceeded(t, got)

	must(t, s.UpdateBackupRestore(ctx, "x1", "failed", "corrupt"))
	got, _ = s.BackupRestoreByID(ctx, "x1")
	assertBackupRestoreFailed(t, got)

	if _, err := s.BackupRestoreByID(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing = %v, want ErrNotFound", err)
	}
	mustErrNotFound(t, s.UpdateBackupRestore(ctx, "missing", "succeeded", ""))
}

// assertBackupRestoreList checks a restore list page's total/len and fields.
func assertBackupRestoreList(t *testing.T, restores []BackupRestore, total int) {
	t.Helper()
	if total != 1 || len(restores) != 1 {
		t.Fatalf("list = %d/%d, want 1/1", len(restores), total)
	}
	if restores[0].SourceKey != "backups/x.tar.gz" || restores[0].RequestedBy != "admin" {
		t.Fatalf("restore = %+v", restores[0])
	}
}

// assertBackupRestoreSucceeded checks a restore updated to success.
func assertBackupRestoreSucceeded(t *testing.T, got *BackupRestore) {
	t.Helper()
	if got.Status != "succeeded" || got.FinishedAt == nil {
		t.Fatalf("updated = %+v", got)
	}
}

// assertBackupRestoreFailed checks a restore updated to failure.
func assertBackupRestoreFailed(t *testing.T, got *BackupRestore) {
	t.Helper()
	if got.Status != "failed" || got.Error == nil || *got.Error != "corrupt" {
		t.Fatalf("failed = %+v", got)
	}
}

// TestBackupRunRFC3339RoundTrip verifies a run's timestamps survive a
// write/read cycle through the TEXT columns.
func TestBackupRunRFC3339RoundTrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	started := time.Date(2026, 9, 5, 12, 30, 0, 0, time.UTC)
	r := &BackupRun{ID: "r2", StartedAt: started, Status: "running"}
	if err := s.CreateBackupRun(ctx, r); err != nil {
		t.Fatalf("CreateBackupRun: %v", err)
	}
	got, err := s.BackupRunByID(ctx, "r2")
	if err != nil {
		t.Fatalf("BackupRunByID: %v", err)
	}
	if !got.StartedAt.Equal(started) {
		t.Fatalf("started_at = %v, want %v", got.StartedAt, started)
	}
}
