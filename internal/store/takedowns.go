package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Takedown is a moderation takedown record. Takedowns are INSTANCE-scoped:
// they are created and managed by instance admins and are not filtered by
// tenant. The tenant whose resource was taken down is recorded only in the
// audit log entry written alongside the takedown.
type Takedown struct {
	ID        string
	Resource  string
	Reason    string
	ActedBy   string
	CreatedAt time.Time
}

// ListTakedowns returns a page of takedowns (newest first) plus the total
// count. Offset/limit pagination is used, matching the other admin list
// endpoints.
func (s *Store) ListTakedowns(ctx context.Context, limit, offset int) ([]Takedown, int, error) {
	if limit <= 0 {
		limit = 100
	}
	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM takedowns`).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("store: list takedowns: %w", err)
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, resource, reason, acted_by, created_at FROM takedowns ORDER BY created_at DESC LIMIT ? OFFSET ?`,
		limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("store: list takedowns: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Takedown
	for rows.Next() {
		var t Takedown
		if err := scanTakedown(rows.Scan, &t); err != nil {
			return nil, 0, err
		}
		out = append(out, t)
	}
	return out, total, rows.Err()
}

// CreateTakedown inserts a takedown record.
func (s *Store) CreateTakedown(ctx context.Context, t *Takedown) error {
	// The takedowns table (migration v8) declares created_at as TEXT, so
	// timestamps are persisted as RFC 3339 strings (not time.Time, which does
	// not round-trip through a TEXT column in modernc/sqlite).
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO takedowns (id, resource, reason, acted_by, created_at) VALUES (?, ?, ?, ?, ?)`,
		t.ID, t.Resource, t.Reason, t.ActedBy, t.CreatedAt.Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("store: create takedown: %w", err)
	}
	return nil
}

// TakedownByID returns a single takedown by ID, or ErrNotFound.
func (s *Store) TakedownByID(ctx context.Context, id string) (*Takedown, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, resource, reason, acted_by, created_at FROM takedowns WHERE id = ?`, id)
	var t Takedown
	err := scanTakedown(row.Scan, &t)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: takedown by id: %w", err)
	}
	return &t, nil
}

// DeleteTakedown removes a takedown by ID (lifts the takedown), or ErrNotFound.
func (s *Store) DeleteTakedown(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM takedowns WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("store: delete takedown: %w", err)
	}
	return requireAffected(res)
}

// scanTakedown scans a takedown row, parsing the TEXT created_at column as
// RFC 3339 (matching the pending_deletions pattern).
func scanTakedown(scan func(...any) error, t *Takedown) error {
	var createdAt string
	if err := scan(&t.ID, &t.Resource, &t.Reason, &t.ActedBy, &createdAt); err != nil {
		return err
	}
	if ts, err := time.Parse(time.RFC3339, createdAt); err == nil {
		t.CreatedAt = ts
	}
	return nil
}
