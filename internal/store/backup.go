package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// BackupConfig is the persisted backup schedule/destination. The table holds a
// single row (id=1); UpsertBackupConfig replaces it. Timestamps are stored as
// RFC 3339 TEXT (matching the takedowns pattern) so they round-trip through
// modernc/sqlite.
type BackupConfig struct {
	ID          int64
	Schedule    string
	Destination string
	Prefix      string
	UpdatedAt   time.Time
}

// BackupRun is one backup execution. FinishedAt/Error are null while the run
// is in progress or succeeded. SizeBytes is best-effort (0 when unknown).
type BackupRun struct {
	ID             string
	StartedAt      time.Time
	FinishedAt     *time.Time
	Status         string
	Error          *string
	SizeBytes      int64
	DestinationKey string
}

// BackupRestore is one restore execution. FinishedAt/Error are null while the
// restore is in progress or succeeded.
type BackupRestore struct {
	ID          string
	StartedAt   time.Time
	FinishedAt  *time.Time
	Status      string
	Error       *string
	SourceKey   string
	RequestedBy string
}

// GetBackupConfig returns the single backup config row, or ErrNotFound when
// none has been persisted yet.
func (s *Store) GetBackupConfig(ctx context.Context) (*BackupConfig, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, schedule, destination, prefix, updated_at FROM backup_config WHERE id = 1`)
	var c BackupConfig
	var updatedAt string
	err := row.Scan(&c.ID, &c.Schedule, &c.Destination, &c.Prefix, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: get backup config: %w", err)
	}
	if ts, perr := time.Parse(time.RFC3339, updatedAt); perr == nil {
		c.UpdatedAt = ts
	}
	return &c, nil
}

// UpsertBackupConfig persists the single backup config row, replacing any
// prior value and stamping updated_at.
func (s *Store) UpsertBackupConfig(ctx context.Context, schedule, destination, prefix string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO backup_config (id, schedule, destination, prefix, updated_at) VALUES (1, ?, ?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET
		   schedule = excluded.schedule,
		   destination = excluded.destination,
		   prefix = excluded.prefix,
		   updated_at = excluded.updated_at`,
		schedule, destination, prefix, time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("store: upsert backup config: %w", err)
	}
	return nil
}

// ListBackupRuns returns a page of backup runs (newest first) plus the total
// count. Offset/limit pagination matches the other admin list endpoints.
func (s *Store) ListBackupRuns(ctx context.Context, limit, offset int) ([]BackupRun, int, error) {
	if limit <= 0 {
		limit = 100
	}
	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM backup_runs`).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("store: list backup runs: %w", err)
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, started_at, finished_at, status, error, size_bytes, destination_key
		 FROM backup_runs ORDER BY started_at DESC LIMIT ? OFFSET ?`, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("store: list backup runs: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []BackupRun
	for rows.Next() {
		var r BackupRun
		if err := scanBackupRun(rows.Scan, &r); err != nil {
			return nil, 0, err
		}
		out = append(out, r)
	}
	return out, total, rows.Err()
}

// CreateBackupRun inserts a backup run row.
func (s *Store) CreateBackupRun(ctx context.Context, r *BackupRun) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO backup_runs (id, started_at, finished_at, status, error, size_bytes, destination_key)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		r.ID, r.StartedAt.Format(time.RFC3339), nullableTimePtr(r.FinishedAt), r.Status,
		nullableString(ptrString(r.Error)), r.SizeBytes, nullableString(r.DestinationKey))
	if err != nil {
		return fmt.Errorf("store: create backup run: %w", err)
	}
	return nil
}

// BackupRunByID returns a single backup run by ID, or ErrNotFound.
func (s *Store) BackupRunByID(ctx context.Context, id string) (*BackupRun, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, started_at, finished_at, status, error, size_bytes, destination_key
		 FROM backup_runs WHERE id = ?`, id)
	var r BackupRun
	err := scanBackupRun(row.Scan, &r)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: backup run by id: %w", err)
	}
	return &r, nil
}

// UpdateBackupRun records the outcome of a run. errMsg is empty on success;
// size and key are best-effort. Returns ErrNotFound when the run is missing.
func (s *Store) UpdateBackupRun(ctx context.Context, id, status, errMsg string, size int64, key string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE backup_runs SET finished_at = ?, status = ?, error = ?, size_bytes = ?, destination_key = ?
		 WHERE id = ?`,
		time.Now().UTC().Format(time.RFC3339), status, nullableString(errMsg), size, nullableString(key), id)
	if err != nil {
		return fmt.Errorf("store: update backup run: %w", err)
	}
	return requireAffected(res)
}

// ListBackupRestores returns a page of restore executions (newest first) plus
// the total count.
func (s *Store) ListBackupRestores(ctx context.Context, limit, offset int) ([]BackupRestore, int, error) {
	if limit <= 0 {
		limit = 100
	}
	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM backup_restores`).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("store: list backup restores: %w", err)
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, started_at, finished_at, status, error, source_key, requested_by
		 FROM backup_restores ORDER BY started_at DESC LIMIT ? OFFSET ?`, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("store: list backup restores: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []BackupRestore
	for rows.Next() {
		var r BackupRestore
		if err := scanBackupRestore(rows.Scan, &r); err != nil {
			return nil, 0, err
		}
		out = append(out, r)
	}
	return out, total, rows.Err()
}

// CreateBackupRestore inserts a restore execution row.
func (s *Store) CreateBackupRestore(ctx context.Context, r *BackupRestore) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO backup_restores (id, started_at, finished_at, status, error, source_key, requested_by)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		r.ID, r.StartedAt.Format(time.RFC3339), nullableTimePtr(r.FinishedAt), r.Status,
		nullableString(ptrString(r.Error)), nullableString(r.SourceKey), nullableString(r.RequestedBy))
	if err != nil {
		return fmt.Errorf("store: create backup restore: %w", err)
	}
	return nil
}

// BackupRestoreByID returns a single restore by ID, or ErrNotFound.
func (s *Store) BackupRestoreByID(ctx context.Context, id string) (*BackupRestore, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, started_at, finished_at, status, error, source_key, requested_by
		 FROM backup_restores WHERE id = ?`, id)
	var r BackupRestore
	err := scanBackupRestore(row.Scan, &r)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: backup restore by id: %w", err)
	}
	return &r, nil
}

// UpdateBackupRestore records the outcome of a restore. errMsg is empty on
// success. Returns ErrNotFound when the restore is missing.
func (s *Store) UpdateBackupRestore(ctx context.Context, id, status, errMsg string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE backup_restores SET finished_at = ?, status = ?, error = ? WHERE id = ?`,
		time.Now().UTC().Format(time.RFC3339), status, nullableString(errMsg), id)
	if err != nil {
		return fmt.Errorf("store: update backup restore: %w", err)
	}
	return requireAffected(res)
}

// scanBackupRun scans a backup_runs row, parsing TEXT timestamps as RFC 3339.
func scanBackupRun(scan func(...any) error, r *BackupRun) error {
	var startedAt string
	var finishedAt, errMsg, destKey sql.NullString
	var size sql.NullInt64
	if err := scan(&r.ID, &startedAt, &finishedAt, &r.Status, &errMsg, &size, &destKey); err != nil {
		return err
	}
	if ts, perr := time.Parse(time.RFC3339, startedAt); perr == nil {
		r.StartedAt = ts
	}
	if finishedAt.Valid {
		if ts, perr := time.Parse(time.RFC3339, finishedAt.String); perr == nil {
			r.FinishedAt = &ts
		}
	}
	if errMsg.Valid {
		r.Error = &errMsg.String
	}
	if size.Valid {
		r.SizeBytes = size.Int64
	}
	if destKey.Valid {
		r.DestinationKey = destKey.String
	}
	return nil
}

// scanBackupRestore scans a backup_restores row, parsing TEXT timestamps as
// RFC 3339.
func scanBackupRestore(scan func(...any) error, r *BackupRestore) error {
	var startedAt string
	var finishedAt, errMsg, sourceKey, requestedBy sql.NullString
	if err := scan(&r.ID, &startedAt, &finishedAt, &r.Status, &errMsg, &sourceKey, &requestedBy); err != nil {
		return err
	}
	if ts, perr := time.Parse(time.RFC3339, startedAt); perr == nil {
		r.StartedAt = ts
	}
	if finishedAt.Valid {
		if ts, perr := time.Parse(time.RFC3339, finishedAt.String); perr == nil {
			r.FinishedAt = &ts
		}
	}
	if errMsg.Valid {
		r.Error = &errMsg.String
	}
	if sourceKey.Valid {
		r.SourceKey = sourceKey.String
	}
	if requestedBy.Valid {
		r.RequestedBy = requestedBy.String
	}
	return nil
}

// ptrString dereferences a *string, returning "" for nil.
func ptrString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// nullableTimePtr converts a *time.Time to a NULL-able value for SQLite.
func nullableTimePtr(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.Format(time.RFC3339)
}
