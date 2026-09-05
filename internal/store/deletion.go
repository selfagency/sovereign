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
