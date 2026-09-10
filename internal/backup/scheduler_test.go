package backup

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/selfagency/sovereign/internal/storage"
)

// TestRunNow verifies the manual-trigger path runs a backup synchronously and
// returns the destination key and error, recording the attempt in Status().
func TestRunNow(t *testing.T) {
	fs := &storage.FS{Root: t.TempDir()}
	s := NewScheduler(Config{
		Destination: &FSDestination{Backend: fs, Prefix: "backups"},
	}, func(ctx context.Context) (io.Reader, error) {
		return strings.NewReader("data"), nil
	})

	key, _, err := s.RunNow(context.Background())
	if err != nil {
		t.Fatalf("RunNow: %v", err)
	}
	if !strings.HasPrefix(key, "backups/backup-") {
		t.Fatalf("key = %q, want backups/backup- prefix", key)
	}
	lastRun, lastErr := s.Status()
	if lastRun.IsZero() {
		t.Fatal("LastRun not set")
	}
	if lastErr != "" {
		t.Fatalf("LastError = %q, want cleared", lastErr)
	}
}

// TestRunNowError verifies RunNow surfaces a BackupFn error.
func TestRunNowError(t *testing.T) {
	fs := &storage.FS{Root: t.TempDir()}
	s := NewScheduler(Config{
		Destination: &FSDestination{Backend: fs, Prefix: "backups"},
	}, func(ctx context.Context) (io.Reader, error) {
		return nil, errors.New("disk full")
	})

	if _, _, err := s.RunNow(context.Background()); err == nil {
		t.Fatal("expected error from RunNow")
	}
	_, lastErr := s.Status()
	if !strings.Contains(lastErr, "disk full") {
		t.Fatalf("LastError = %q, want disk full", lastErr)
	}
}

// TestRunNowNilBackupFn verifies RunNow errors when no BackupFn is set.
func TestRunNowNilBackupFn(t *testing.T) {
	fs := &storage.FS{Root: t.TempDir()}
	s := NewScheduler(Config{Destination: &FSDestination{Backend: fs, Prefix: "backups"}}, nil)
	if _, _, err := s.RunNow(context.Background()); err == nil {
		t.Fatal("expected error for nil BackupFn")
	}
}

// TestSchedulerStart verifies a valid schedule starts and runs a backup.
func TestSchedulerStart(t *testing.T) {
	fs := &storage.FS{Root: t.TempDir()}
	dest := &FSDestination{Backend: fs, Prefix: "backups"}

	ran := make(chan string, 1)
	s := NewScheduler(Config{
		Schedule:    "* * * * * *", // every second (seconds field enabled)
		Destination: dest,
	}, func(ctx context.Context) (io.Reader, error) {
		ran <- "ran"
		return strings.NewReader("backup-data"), nil
	})

	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer s.Stop()

	// Wait for the backup to run (cron fires within a second).
	select {
	case <-ran:
	case <-time.After(3 * time.Second):
		t.Fatal("backup did not run")
	}

	// Poll for the backup to be written (WriteBackup runs after BackupFn).
	deadline := time.Now().Add(3 * time.Second)
	for {
		blobs, err := fs.List(context.Background(), "backups/")
		if err != nil {
			t.Fatal(err)
		}
		if len(blobs) == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("backups = %d, want 1", len(blobs))
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestSchedulerEmptySchedule verifies an empty schedule is rejected.
func TestSchedulerEmptySchedule(t *testing.T) {
	fs := &storage.FS{Root: t.TempDir()}
	s := NewScheduler(Config{Schedule: "", Destination: &FSDestination{Backend: fs}}, nil)
	if err := s.Start(); err == nil {
		t.Fatal("expected error for empty schedule")
	}
}

// TestSchedulerNilDestination verifies a nil destination is rejected.
func TestSchedulerNilDestination(t *testing.T) {
	s := NewScheduler(Config{Schedule: "0 2 * * *"}, nil)
	if err := s.Start(); err == nil {
		t.Fatal("expected error for nil destination")
	}
}

// TestSchedulerInvalidSchedule verifies a bad cron expression is rejected.
func TestSchedulerInvalidSchedule(t *testing.T) {
	fs := &storage.FS{Root: t.TempDir()}
	s := NewScheduler(Config{Schedule: "not-a-cron", Destination: &FSDestination{Backend: fs}}, nil)
	if err := s.Start(); err == nil {
		t.Fatal("expected error for invalid schedule")
	}
}

// TestFSDestinationWrite verifies FS destination writes a backup.
func TestFSDestinationWrite(t *testing.T) {
	fs := &storage.FS{Root: t.TempDir()}
	dest := &FSDestination{Backend: fs, Prefix: "backups"}
	key, err := dest.WriteBackup(context.Background(), "backup-1.tar.gz", strings.NewReader("data"))
	if err != nil {
		t.Fatalf("WriteBackup: %v", err)
	}
	if key != "backups/backup-1.tar.gz" {
		t.Fatalf("key = %q", key)
	}
	rc, _, err := fs.Get(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rc.Close() }()
	body, _ := io.ReadAll(rc)
	if string(body) != "data" {
		t.Fatalf("body = %q, want data", body)
	}
}

// TestS3DestinationWrites verifies S3 destination writes a backup.
func TestS3DestinationWrites(t *testing.T) {
	fs := &storage.FS{Root: t.TempDir()}
	dest := &S3Destination{Backend: fs, Prefix: "backups"}
	key, err := dest.WriteBackup(context.Background(), "backup-1.tar.gz", strings.NewReader("data"))
	if err != nil {
		t.Fatalf("WriteBackup: %v", err)
	}
	if key != "backups/backup-1.tar.gz" {
		t.Fatalf("key = %q", key)
	}
}

// TestSchedulerBackupFnNil verifies a nil BackupFn is a no-op.
func TestSchedulerBackupFnNil(t *testing.T) {
	fs := &storage.FS{Root: t.TempDir()}
	s := NewScheduler(Config{Schedule: "* * * * * *", Destination: &FSDestination{Backend: fs, Prefix: "backups"}}, nil)
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer s.Stop()
	// Should not panic; wait briefly.
	time.Sleep(100 * time.Millisecond)
}

// TestRunBackupErrorSurfaced verifies a BackupFn error is surfaced via
// Status() and logged (previously swallowed silently).
func TestRunBackupErrorSurfaced(t *testing.T) {
	fs := &storage.FS{Root: t.TempDir()}
	s := NewScheduler(Config{
		Schedule:    "* * * * * *",
		Destination: &FSDestination{Backend: fs, Prefix: "backups"},
	}, func(ctx context.Context) (io.Reader, error) {
		return nil, errors.New("disk full")
	})

	var logged string
	s.Logger = slog.New(slog.NewTextHandler(&logWriter{&logged}, nil))

	s.runBackup()

	lastRun, lastErr := s.Status()
	if lastRun.IsZero() {
		t.Fatal("LastRun not set")
	}
	if !strings.Contains(lastErr, "disk full") {
		t.Fatalf("LastError = %q, want disk full", lastErr)
	}
	if !strings.Contains(logged, "disk full") {
		t.Fatalf("log = %q, want disk full", logged)
	}
}

// TestRunBackupWriteErrorSurfaced verifies a destination write error is
// surfaced via Status() and logged.
func TestRunBackupWriteErrorSurfaced(t *testing.T) {
	fs := &storage.FS{Root: t.TempDir()}
	s := &Scheduler{
		config: Config{
			Schedule:    "* * * * * *",
			Destination: &FSDestination{Backend: fs, Prefix: "backups"},
		},
		BackupFn: func(ctx context.Context) (io.Reader, error) {
			return strings.NewReader("data"), nil
		},
	}

	// A failing destination.
	s.config.Destination = &failingDestination{}

	var log string
	s.Logger = slog.New(slog.NewTextHandler(&logWriter{&log}, nil))

	s.runBackup()

	_, lastErr := s.Status()
	if !strings.Contains(lastErr, "write") {
		t.Fatalf("LastError = %q, want write error", lastErr)
	}
	if !strings.Contains(log, "write") {
		t.Fatalf("log = %q, want write error", log)
	}
}

// TestRunBackupSuccessClearsError verifies a successful backup clears the
// last error.
func TestRunBackupSuccessClearsError(t *testing.T) {
	fs := &storage.FS{Root: t.TempDir()}
	s := &Scheduler{
		config: Config{
			Destination: &FSDestination{Backend: fs, Prefix: "backups"},
		},
		BackupFn: func(ctx context.Context) (io.Reader, error) {
			return strings.NewReader("data"), nil
		},
	}

	// Simulate a prior failure.
	s.mu.Lock()
	s.LastError = "old error"
	s.mu.Unlock()

	s.runBackup()

	_, lastErr := s.Status()
	if lastErr != "" {
		t.Fatalf("LastError = %q, want cleared", lastErr)
	}
}

// failingDestination always fails writes.
type failingDestination struct{}

func (failingDestination) WriteBackup(ctx context.Context, name string, r io.Reader) (string, error) {
	return "", errors.New("destination unreachable")
}

func (failingDestination) ReadBackup(ctx context.Context, key string) (io.ReadCloser, error) {
	return nil, errors.New("destination unreachable")
}

// TestFSDestinationRestoreRoundTrip proves a backup written to FS can be read
// back byte-for-byte.
func TestFSDestinationRestoreRoundTrip(t *testing.T) {
	fs := &storage.FS{Root: t.TempDir()}
	dest := &FSDestination{Backend: fs, Prefix: "backups"}
	want := []byte("greatest-backup-ever")

	key, err := dest.WriteBackup(context.Background(), "b1.tar.gz", strings.NewReader(string(want)))
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	rc, err := dest.ReadBackup(context.Background(), key)
	if err != nil {
		t.Fatalf("ReadBackup: %v", err)
	}
	defer func() { _ = rc.Close() }()
	got, _ := io.ReadAll(rc)
	if !bytes.Equal(got, want) {
		t.Fatalf("restore round-trip mismatch: got %q want %q", got, want)
	}
}

// TestS3DestinationRestoreRoundTrip proves an S3 backup can be read back.
func TestS3DestinationRestoreRoundTrip(t *testing.T) {
	fs := &storage.FS{Root: t.TempDir()}
	dest := &S3Destination{Backend: fs, Prefix: "backups"}
	want := []byte("s3-backup")

	key, err := dest.WriteBackup(context.Background(), "b1.tar.gz", strings.NewReader(string(want)))
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	rc, err := dest.ReadBackup(context.Background(), key)
	if err != nil {
		t.Fatalf("ReadBackup: %v", err)
	}
	defer func() { _ = rc.Close() }()
	got, _ := io.ReadAll(rc)
	if !bytes.Equal(got, want) {
		t.Fatalf("restore round-trip mismatch: got %q want %q", got, want)
	}
}

// TestSchedulerRestore verifies Restore streams a backup into the RestoreFn.
func TestSchedulerRestore(t *testing.T) {
	fs := &storage.FS{Root: t.TempDir()}
	dest := &FSDestination{Backend: fs, Prefix: "backups"}
	want := []byte("restore-me")
	key, err := dest.WriteBackup(context.Background(), "b1.tar.gz", strings.NewReader(string(want)))
	if err != nil {
		t.Fatalf("write: %v", err)
	}

	var restored []byte
	s := NewScheduler(Config{Destination: dest}, nil)
	s.RestoreFn = func(ctx context.Context, r io.Reader) error {
		restored, _ = io.ReadAll(r)
		return nil
	}
	if err := s.Restore(context.Background(), key); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if !bytes.Equal(restored, want) {
		t.Fatalf("restored = %q, want %q", restored, want)
	}
}

// logWriter captures slog output.
type logWriter struct {
	buf *string
}

func (w *logWriter) Write(p []byte) (int, error) {
	*w.buf += string(p)
	return len(p), nil
}
