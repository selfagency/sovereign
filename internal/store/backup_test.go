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

	if err := s.UpsertBackupConfig(ctx, "0 2 * * *", "fs", "backups"); err != nil {
		t.Fatalf("UpsertBackupConfig: %v", err)
	}
	cfg, err := s.GetBackupConfig(ctx)
	if err != nil {
		t.Fatalf("GetBackupConfig: %v", err)
	}
	if cfg.Schedule != "0 2 * * *" || cfg.Destination != "fs" || cfg.Prefix != "backups" {
		t.Fatalf("config = %+v", cfg)
	}
	if cfg.UpdatedAt.IsZero() {
		t.Fatal("updated_at not parsed")
	}

	// Upsert replaces the single row.
	if err := s.UpsertBackupConfig(ctx, "0 3 * * *", "s3", "b2"); err != nil {
		t.Fatalf("UpsertBackupConfig: %v", err)
	}
	cfg, err = s.GetBackupConfig(ctx)
	if err != nil {
		t.Fatalf("GetBackupConfig: %v", err)
	}
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
	if err := s.CreateBackupRun(ctx, r); err != nil {
		t.Fatalf("CreateBackupRun: %v", err)
	}

	// List.
	runs, total, err := s.ListBackupRuns(ctx, 10, 0)
	if err != nil {
		t.Fatalf("ListBackupRuns: %v", err)
	}
	if total != 1 || len(runs) != 1 {
		t.Fatalf("list = %d/%d, want 1/1", len(runs), total)
	}
	if runs[0].ID != "r1" || runs[0].Status != "running" {
		t.Fatalf("run = %+v", runs[0])
	}
	if runs[0].StartedAt.IsZero() {
		t.Fatal("started_at not parsed")
	}

	// Get.
	got, err := s.BackupRunByID(ctx, "r1")
	if err != nil {
		t.Fatalf("BackupRunByID: %v", err)
	}
	if got.ID != "r1" || got.FinishedAt != nil {
		t.Fatalf("got = %+v", got)
	}

	// Update to success.
	if err := s.UpdateBackupRun(ctx, "r1", "succeeded", "", 1234, "backups/x.tar.gz"); err != nil {
		t.Fatalf("UpdateBackupRun: %v", err)
	}
	got, err = s.BackupRunByID(ctx, "r1")
	if err != nil {
		t.Fatalf("BackupRunByID: %v", err)
	}
	if got.Status != "succeeded" || got.SizeBytes != 1234 || got.DestinationKey != "backups/x.tar.gz" {
		t.Fatalf("updated = %+v", got)
	}
	if got.FinishedAt == nil {
		t.Fatal("finished_at not set")
	}

	// Update to failure clears size/key and sets error.
	if err := s.UpdateBackupRun(ctx, "r1", "failed", "disk full", 0, ""); err != nil {
		t.Fatalf("UpdateBackupRun: %v", err)
	}
	got, _ = s.BackupRunByID(ctx, "r1")
	if got.Status != "failed" || got.Error == nil || *got.Error != "disk full" {
		t.Fatalf("failed = %+v", got)
	}
	if got.SizeBytes != 0 || got.DestinationKey != "" {
		t.Fatalf("failed run should clear size/key: %+v", got)
	}

	// Missing run.
	if _, err := s.BackupRunByID(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing = %v, want ErrNotFound", err)
	}
	if err := s.UpdateBackupRun(ctx, "missing", "succeeded", "", 0, ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("update missing = %v, want ErrNotFound", err)
	}
}

// TestBackupRestoreCRUD verifies create/list/get/update for restores.
func TestBackupRestoreCRUD(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	now := time.Now().UTC()
	rest := &BackupRestore{ID: "x1", StartedAt: now, Status: "running", SourceKey: "backups/x.tar.gz", RequestedBy: "admin"}
	if err := s.CreateBackupRestore(ctx, rest); err != nil {
		t.Fatalf("CreateBackupRestore: %v", err)
	}

	restores, total, err := s.ListBackupRestores(ctx, 10, 0)
	if err != nil {
		t.Fatalf("ListBackupRestores: %v", err)
	}
	if total != 1 || len(restores) != 1 {
		t.Fatalf("list = %d/%d, want 1/1", len(restores), total)
	}
	if restores[0].SourceKey != "backups/x.tar.gz" || restores[0].RequestedBy != "admin" {
		t.Fatalf("restore = %+v", restores[0])
	}

	got, err := s.BackupRestoreByID(ctx, "x1")
	if err != nil {
		t.Fatalf("BackupRestoreByID: %v", err)
	}
	if got.ID != "x1" || got.FinishedAt != nil {
		t.Fatalf("got = %+v", got)
	}

	if err := s.UpdateBackupRestore(ctx, "x1", "succeeded", ""); err != nil {
		t.Fatalf("UpdateBackupRestore: %v", err)
	}
	got, _ = s.BackupRestoreByID(ctx, "x1")
	if got.Status != "succeeded" || got.FinishedAt == nil {
		t.Fatalf("updated = %+v", got)
	}

	if err := s.UpdateBackupRestore(ctx, "x1", "failed", "corrupt"); err != nil {
		t.Fatalf("UpdateBackupRestore: %v", err)
	}
	got, _ = s.BackupRestoreByID(ctx, "x1")
	if got.Status != "failed" || got.Error == nil || *got.Error != "corrupt" {
		t.Fatalf("failed = %+v", got)
	}

	if _, err := s.BackupRestoreByID(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing = %v, want ErrNotFound", err)
	}
	if err := s.UpdateBackupRestore(ctx, "missing", "succeeded", ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("update missing = %v, want ErrNotFound", err)
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
