package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// PendingDeletion is a scheduled account-deletion request awaiting admin
// approval (M2). Creating one does NOT delete the user; only an admin approval
// flow may cascade-delete via DeleteUser.
type PendingDeletion struct {
	ID          string
	UserID      string
	RequestedAt time.Time
	Status      string // "pending" | "approved" | "rejected"
	ApprovedBy  *string
	ApprovedAt  *time.Time
}

// CreatePendingDeletion records an account-deletion request for a user in the
// 'pending' state. The user must exist; the user row is left untouched so the
// account remains usable until an admin approves the deletion. Returns the
// newly created request.
func (s *Store) CreatePendingDeletion(ctx context.Context, userID string) (*PendingDeletion, error) {
	// Guard: refuse to record a deletion request for a non-existent user.
	var exists int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE id = ?`, userID).Scan(&exists); err != nil {
		return nil, fmt.Errorf("store: create pending deletion: %w", err)
	}
	if exists == 0 {
		return nil, ErrNotFound
	}
	now := time.Now().UTC()
	p := &PendingDeletion{
		ID:          NewSessionID(),
		UserID:      userID,
		RequestedAt: now,
		Status:      "pending",
	}
	// The pending_deletions table (migration v9) declares requested_at/approved_at
	// as TEXT, so timestamps are persisted as RFC 3339 strings (not time.Time,
	// which does not round-trip through a TEXT column in modernc/sqlite).
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO pending_deletions (id, user_id, requested_at, status, approved_by, approved_at)
		 VALUES (?, ?, ?, ?, NULL, NULL)`,
		p.ID, p.UserID, p.RequestedAt.Format(time.RFC3339), p.Status)
	if err != nil {
		return nil, fmt.Errorf("store: create pending deletion: %w", err)
	}
	return p, nil
}

// PendingDeletionByUser returns the most recent deletion request for a user,
// or ErrNotFound if none exists.
func (s *Store) PendingDeletionByUser(ctx context.Context, userID string) (*PendingDeletion, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, user_id, requested_at, status, approved_by, approved_at
		 FROM pending_deletions WHERE user_id = ? ORDER BY requested_at DESC LIMIT 1`, userID)
	return scanPendingDeletion(row)
}

func scanPendingDeletion(row *sql.Row) (*PendingDeletion, error) {
	var p PendingDeletion
	var requestedAt, approvedAt sql.NullString
	var approvedBy sql.NullString
	err := row.Scan(&p.ID, &p.UserID, &requestedAt, &p.Status, &approvedBy, &approvedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if !requestedAt.Valid {
		return nil, errors.New("store: pending deletion missing requested_at")
	}
	if t, perr := time.Parse(time.RFC3339, requestedAt.String); perr == nil {
		p.RequestedAt = t
	}
	if approvedBy.Valid {
		p.ApprovedBy = &approvedBy.String
	}
	if approvedAt.Valid {
		if t, perr := time.Parse(time.RFC3339, approvedAt.String); perr == nil {
			p.ApprovedAt = &t
		}
	}
	return &p, nil
}

// ListPendingDeletions returns a page of deletion requests (newest first)
// plus the total count. It is instance-scoped (admin listing), so it is not
// filtered by tenant.
func (s *Store) ListPendingDeletions(ctx context.Context, limit, offset int) ([]PendingDeletion, int, error) {
	if limit <= 0 {
		limit = 100
	}
	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM pending_deletions`).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("store: list pending deletions: %w", err)
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, user_id, requested_at, status, approved_by, approved_at
		 FROM pending_deletions ORDER BY requested_at DESC LIMIT ? OFFSET ?`, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("store: list pending deletions: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []PendingDeletion
	for rows.Next() {
		var p PendingDeletion
		if err := scanPendingDeletionRows(rows.Scan, &p); err != nil {
			return nil, 0, err
		}
		out = append(out, p)
	}
	return out, total, rows.Err()
}

// PendingDeletionByID returns a deletion request by its ID, or ErrNotFound.
func (s *Store) PendingDeletionByID(ctx context.Context, id string) (*PendingDeletion, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, user_id, requested_at, status, approved_by, approved_at
		 FROM pending_deletions WHERE id = ?`, id)
	return scanPendingDeletion(row)
}

// ApprovePendingDeletion marks a deletion request approved by adminID and
// cascade-deletes the user (DeleteUser). It is idempotent: an already-approved
// or already-rejected request is a no-op that returns nil. Returns ErrNotFound
// when the request does not exist.
func (s *Store) ApprovePendingDeletion(ctx context.Context, id, adminID string) error {
	p, err := s.PendingDeletionByID(ctx, id)
	if err != nil {
		return err
	}
	if p.Status != "pending" {
		return nil // already processed; idempotent no-op
	}
	now := time.Now().UTC()
	if _, err := s.db.ExecContext(ctx,
		`UPDATE pending_deletions SET status = 'approved', approved_by = ?, approved_at = ? WHERE id = ?`,
		adminID, now.Format(time.RFC3339), id); err != nil {
		return fmt.Errorf("store: approve pending deletion: %w", err)
	}
	// Cascade-delete the user. The request is already marked approved, so a
	// failure here leaves the account marked for deletion but intact; the
	// operator can retry (idempotent) or clean up manually.
	if err := s.DeleteUser(ctx, p.UserID); err != nil && !errors.Is(err, ErrNotFound) {
		return fmt.Errorf("store: approve pending deletion: %w", err)
	}
	return nil
}

// RejectPendingDeletion marks a deletion request rejected by adminID. It is a
// no-op for an already-processed request (idempotent) and returns ErrNotFound
// when the request does not exist.
func (s *Store) RejectPendingDeletion(ctx context.Context, id, adminID string) error {
	p, err := s.PendingDeletionByID(ctx, id)
	if err != nil {
		return err
	}
	if p.Status != "pending" {
		return nil // already processed; idempotent no-op
	}
	now := time.Now().UTC()
	if _, err := s.db.ExecContext(ctx,
		`UPDATE pending_deletions SET status = 'rejected', approved_by = ?, approved_at = ? WHERE id = ?`,
		adminID, now.Format(time.RFC3339), id); err != nil {
		return fmt.Errorf("store: reject pending deletion: %w", err)
	}
	return nil
}

// scanPendingDeletionRows scans a pending_deletions row via a rows.Scan,
// sharing the column parsing with scanPendingDeletion.
func scanPendingDeletionRows(scan func(...any) error, p *PendingDeletion) error {
	var requestedAt, approvedAt sql.NullString
	var approvedBy sql.NullString
	if err := scan(&p.ID, &p.UserID, &requestedAt, &p.Status, &approvedBy, &approvedAt); err != nil {
		return err
	}
	if !requestedAt.Valid {
		return errors.New("store: pending deletion missing requested_at")
	}
	if t, perr := time.Parse(time.RFC3339, requestedAt.String); perr == nil {
		p.RequestedAt = t
	}
	if approvedBy.Valid {
		p.ApprovedBy = &approvedBy.String
	}
	if approvedAt.Valid {
		if t, perr := time.Parse(time.RFC3339, approvedAt.String); perr == nil {
			p.ApprovedAt = &t
		}
	}
	return nil
}
