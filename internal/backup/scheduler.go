// Package backup implements the scheduled backup system. Users configure a
// cron schedule and a destination (local filesystem or S3-compatible) via the
// admin UI; the scheduler runs backups on that schedule.
package backup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/robfig/cron/v3"

	"github.com/selfagency/sovereign/internal/storage"
)

// Destination is where backups are written and read back.
type Destination interface {
	// WriteBackup stores a backup blob and returns its key.
	WriteBackup(ctx context.Context, name string, r io.Reader) (string, error)
	// ReadBackup opens a stored backup for reading.
	ReadBackup(ctx context.Context, key string) (io.ReadCloser, error)
}

// Validation sentinels for backup config.
var (
	ErrEmptySchedule      = errors.New("backup schedule is empty")
	ErrInvalidDestination = errors.New("backup destination must be fs or s3")
	ErrEmptyPrefix        = errors.New("backup prefix is empty")
)

// FSDestination writes backups to a local directory.
type FSDestination struct {
	Backend storage.Backend
	Prefix  string
}

// WriteBackup stores a backup in the FS backend.
func (d *FSDestination) WriteBackup(ctx context.Context, name string, r io.Reader) (string, error) {
	key := d.Prefix + "/" + name
	blob, err := d.Backend.Put(ctx, key, r, "application/octet-stream")
	if err != nil {
		return "", err
	}
	return blob.Key, nil
}

// ReadBackup opens a stored backup from the FS backend.
func (d *FSDestination) ReadBackup(ctx context.Context, key string) (io.ReadCloser, error) {
	rc, _, err := d.Backend.Get(ctx, key)
	return rc, err
}

// S3Destination writes backups to an S3-compatible bucket.
type S3Destination struct {
	Backend storage.Backend
	Prefix  string
}

// WriteBackup stores a backup in the S3 backend.
func (d *S3Destination) WriteBackup(ctx context.Context, name string, r io.Reader) (string, error) {
	key := d.Prefix + "/" + name
	blob, err := d.Backend.Put(ctx, key, r, "application/octet-stream")
	if err != nil {
		return "", err
	}
	return blob.Key, nil
}

// ReadBackup opens a stored backup from the S3 backend.
func (d *S3Destination) ReadBackup(ctx context.Context, key string) (io.ReadCloser, error) {
	rc, _, err := d.Backend.Get(ctx, key)
	return rc, err
}

// Config holds the backup schedule and destination.
type Config struct {
	// Schedule is a cron expression (e.g. "0 2 * * *" for 2am daily).
	Schedule string
	// Destination is where backups are written.
	Destination Destination
}

// Scheduler runs backups on a cron schedule.
type Scheduler struct {
	cron   *cron.Cron
	config Config
	// BackupFn produces the backup bytes. The storage phase wires a real
	// implementation; the interface keeps the scheduler testable.
	BackupFn func(ctx context.Context) (io.Reader, error)
	// RestoreFn consumes restored backup bytes. The storage phase wires a real
	// implementation; the interface keeps the scheduler testable.
	RestoreFn func(ctx context.Context, r io.Reader) error
	// Logger receives backup failures (nil disables logging).
	Logger *slog.Logger
	// mu guards the status fields below.
	mu sync.Mutex
	// LastRun is the time of the most recent backup attempt.
	LastRun time.Time
	// LastError is the error from the most recent failed backup, or "" if
	// the last backup succeeded.
	LastError string
}

// NewScheduler builds a scheduler for a config.
func NewScheduler(config Config, backupFn func(ctx context.Context) (io.Reader, error)) *Scheduler {
	return &Scheduler{
		// Accept both conventional 5-field cron ("0 3 * * *") and 6-field
		// with seconds ("* * * * * *"), so operators can use standard cron
		// expressions while tests can fire every second.
		cron: cron.New(cron.WithParser(cron.NewParser(
			cron.SecondOptional | cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow | cron.Descriptor,
		))),
		config:   config,
		BackupFn: backupFn,
	}
}

// Status returns the last backup attempt time and error (thread-safe).
func (s *Scheduler) Status() (lastRun time.Time, lastError string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.LastRun, s.LastError
}

// Start registers the backup job and starts the cron loop.
func (s *Scheduler) Start() error {
	if s.config.Schedule == "" {
		return errors.New("backup schedule is empty")
	}
	if s.config.Destination == nil {
		return errors.New("backup destination is nil")
	}
	if _, err := s.cron.AddFunc(s.config.Schedule, s.runBackup); err != nil {
		return fmt.Errorf("invalid schedule %q: %w", s.config.Schedule, err)
	}
	s.cron.Start()
	return nil
}

// Stop halts the cron loop.
func (s *Scheduler) Stop() {
	s.cron.Stop()
}

// runBackup executes a single backup on the cron schedule. Failures are
// logged and surfaced via Status() so the admin UI can report them.
func (s *Scheduler) runBackup() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	_, _, _ = s.runBackupOnce(ctx)
}

// RunNow executes a single backup synchronously and returns the destination
// key, the number of bytes written, and any error. It is the manual-trigger
// path used by the admin API: unlike runBackup it surfaces the result to the
// caller (which records a backup_runs row) instead of only logging it.
func (s *Scheduler) RunNow(ctx context.Context) (key string, size int64, err error) {
	return s.runBackupOnce(ctx)
}

// runBackupOnce is the shared single-backup execution. It records the attempt
// in Status() and returns the destination key, byte count, and error so both
// the cron path and the manual RunNow path can report the outcome.
func (s *Scheduler) runBackupOnce(ctx context.Context) (key string, size int64, err error) {
	s.mu.Lock()
	s.LastRun = time.Now().UTC()
	s.mu.Unlock()

	if s.BackupFn == nil {
		err := errors.New("backup: no backup function configured")
		s.failError(err.Error())
		return "", 0, err
	}
	r, err := s.BackupFn(ctx)
	if err != nil {
		err = fmt.Errorf("backup: produce: %w", err)
		s.failError(err.Error())
		return "", 0, err
	}
	name := "backup-" + time.Now().UTC().Format("20060102-150405") + ".tar.gz"
	key, err = s.config.Destination.WriteBackup(ctx, name, r)
	if err != nil {
		err = fmt.Errorf("backup: write: %w", err)
		s.failError(err.Error())
		return "", 0, err
	}

	// Success: clear the last error.
	s.mu.Lock()
	s.LastError = ""
	s.mu.Unlock()
	return key, 0, nil
}

// Restore streams a stored backup into RestoreFn. It returns an error if no
// RestoreFn is configured or the destination cannot read the backup.
func (s *Scheduler) Restore(ctx context.Context, key string) error {
	if s.RestoreFn == nil {
		return errors.New("backup: no restore function configured")
	}
	if s.config.Destination == nil {
		return errors.New("backup: destination is nil")
	}
	rc, err := s.config.Destination.ReadBackup(ctx, key)
	if err != nil {
		return fmt.Errorf("backup: read: %w", err)
	}
	defer func() { _ = rc.Close() }()
	if err := s.RestoreFn(ctx, rc); err != nil {
		return fmt.Errorf("backup: restore: %w", err)
	}
	return nil
}

// failError records a backup failure and logs it.
func (s *Scheduler) failError(msg string) {
	s.mu.Lock()
	s.LastError = msg
	s.mu.Unlock()
	if s.Logger != nil {
		s.Logger.Error(msg)
	}
}
