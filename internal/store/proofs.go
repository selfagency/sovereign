package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// ProofClaim is a stored proof claim row.
type ProofClaim struct {
	ID            string
	TenantID      string
	AccountID     string
	AnchorType    string
	AnchorValue   string
	Service       string
	ClaimLocation string
	ExpectedToken string
	Status        string // "pending" | "verified" | "failed"
	LastCheckedAt *time.Time
	LastError     string
	CreatedAt     time.Time
}

// CreateProofClaim inserts a claim, rejecting duplicates.
func (s *Store) CreateProofClaim(ctx context.Context, c *ProofClaim) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO proof_claims (id, tenant_id, account_id, anchor_type, anchor_value, service, claim_location, expected_token, status, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.ID, c.TenantID, c.AccountID, c.AnchorType, c.AnchorValue, c.Service,
		c.ClaimLocation, c.ExpectedToken, c.Status, c.CreatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrDuplicateClaim
		}
		return err
	}
	return nil
}

// ErrDuplicateClaim is returned when a tenant already has a claim for the
// same service + location.
var ErrDuplicateClaim = errors.New("store: duplicate claim")

// GetProofClaim returns a single claim scoped to a tenant. It returns
// ErrNotFound when the claim does not exist in the tenant.
func (s *Store) GetProofClaim(ctx context.Context, tenantID, id string) (*ProofClaim, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, tenant_id, account_id, anchor_type, anchor_value, service, claim_location, expected_token, status, last_checked_at, last_error, created_at
		 FROM proof_claims WHERE tenant_id = ? AND id = ?`, tenantID, id)
	var c ProofClaim
	var lastErr sql.NullString
	if err := row.Scan(&c.ID, &c.TenantID, &c.AccountID, &c.AnchorType, &c.AnchorValue,
		&c.Service, &c.ClaimLocation, &c.ExpectedToken, &c.Status, &c.LastCheckedAt, &lastErr, &c.CreatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	c.LastError = lastErr.String
	return &c, nil
}

// ListProofClaims returns a tenant's claims.
func (s *Store) ListProofClaims(ctx context.Context, tenantID string) ([]ProofClaim, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, tenant_id, account_id, anchor_type, anchor_value, service, claim_location, expected_token, status, last_checked_at, last_error, created_at
		 FROM proof_claims WHERE tenant_id = ? ORDER BY created_at`, tenantID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []ProofClaim
	for rows.Next() {
		var c ProofClaim
		var lastErr sql.NullString
		if err := rows.Scan(&c.ID, &c.TenantID, &c.AccountID, &c.AnchorType, &c.AnchorValue,
			&c.Service, &c.ClaimLocation, &c.ExpectedToken, &c.Status, &c.LastCheckedAt, &lastErr, &c.CreatedAt); err != nil {
			return nil, err
		}
		c.LastError = lastErr.String
		out = append(out, c)
	}
	return out, rows.Err()
}

// UpdateProofClaimStatus updates a claim's verification status.
func (s *Store) UpdateProofClaimStatus(ctx context.Context, tenantID, id, status, lastError string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE proof_claims SET status = ?, last_error = ?, last_checked_at = ? WHERE tenant_id = ? AND id = ?`,
		status, lastError, time.Now().UTC(), tenantID, id)
	if err != nil {
		return err
	}
	return requireAffected(res)
}

// DeleteProofClaim removes a claim (scoped to tenant + account).
func (s *Store) DeleteProofClaim(ctx context.Context, tenantID, accountID, id string) error {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM proof_claims WHERE tenant_id = ? AND account_id = ? AND id = ?`,
		tenantID, accountID, id)
	if err != nil {
		return err
	}
	return requireAffected(res)
}

// VerifiedProofClaims returns a tenant's verified claims (for public display).
func (s *Store) VerifiedProofClaims(ctx context.Context, tenantID string) ([]ProofClaim, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, tenant_id, account_id, anchor_type, anchor_value, service, claim_location, expected_token, status, last_checked_at, last_error, created_at
		 FROM proof_claims WHERE tenant_id = ? AND status = 'verified' ORDER BY created_at`, tenantID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []ProofClaim
	for rows.Next() {
		var c ProofClaim
		var lastErr sql.NullString
		if err := rows.Scan(&c.ID, &c.TenantID, &c.AccountID, &c.AnchorType, &c.AnchorValue,
			&c.Service, &c.ClaimLocation, &c.ExpectedToken, &c.Status, &c.LastCheckedAt, &lastErr, &c.CreatedAt); err != nil {
			return nil, err
		}
		c.LastError = lastErr.String
		out = append(out, c)
	}
	return out, rows.Err()
}
