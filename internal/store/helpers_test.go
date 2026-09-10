package store

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestPtrStringNil verifies the nil branches of the backup scan helpers.
func TestPtrStringNil(t *testing.T) {
	if got := ptrString(nil); got != "" {
		t.Fatalf("ptrString(nil) = %q, want empty", got)
	}
	s := "x"
	if got := ptrString(&s); got != "x" {
		t.Fatalf("ptrString(&x) = %q, want x", got)
	}
	if got := nullableTimePtr(nil); got != nil {
		t.Fatalf("nullableTimePtr(nil) = %v, want nil", got)
	}
	ts := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	if got := nullableTimePtr(&ts); got != "2026-09-10T12:00:00Z" {
		t.Fatalf("nullableTimePtr(&ts) = %v, want RFC3339", got)
	}
}

// TestOpenMkdirAllError verifies Open surfaces a MkdirAll failure when the
// parent path cannot be created (a file in the way).
func TestOpenMkdirAllError(t *testing.T) {
	dir := t.TempDir()
	// A regular file where the parent directory should be.
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(filepath.Join(blocker, "db", "test.db")); err == nil {
		t.Fatal("Open with file-as-parent succeeded, want error")
	}
}

// TestMigrateCanceledContext drives the migrate/applyMigration error branches
// via a canceled context on a fresh store (schema_version creation fails).
func TestMigrateCanceledContext(t *testing.T) {
	s := newTestStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.migrate(ctx); err == nil {
		t.Fatal("migrate with canceled ctx succeeded, want error")
	}
}
