package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// APIToken is a persisted programmatic API token. TokenHash holds the SHA-256
// hash of the raw token, never the token itself; the raw token is returned to
// the client exactly once at creation (show-once). Scopes are the granted
// scope subset the client selected. FamilyID groups tokens so revocation can
// revoke a whole family.
type APIToken struct {
	ID         string
	UserID     string
	TokenHash  string
	FamilyID   string
	Name       string
	Scopes     []string
	ExpiresAt  time.Time
	LastUsedAt *time.Time
	CreatedAt  time.Time
}

// ErrInvalidScope is returned when a requested programmatic token scope is not
// a subset of the principal's granted scopes.
var ErrInvalidScope = errors.New("store: requested scope not granted")

// GenerateAPIToken returns a new random opaque API token (32 bytes, base64url).
func GenerateAPIToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return strings.TrimRight(base64.RawURLEncoding.EncodeToString(b), "="), nil
}

// HashAPIToken returns the hex SHA-256 hash of a raw API token.
func HashAPIToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// CreateAPIToken inserts a new API token. rawToken is hashed before storage;
// the caller is responsible for returning it to the client exactly once.
func (s *Store) CreateAPIToken(ctx context.Context, t *APIToken) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO api_tokens (id, user_id, token_hash, family_id, name, scopes, expires_at, last_used_at, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?)`,
		t.ID, t.UserID, t.TokenHash, t.FamilyID, nullableString(t.Name), strings.Join(t.Scopes, ","),
		nullableTime(t.ExpiresAt), t.CreatedAt)
	if err != nil {
		return fmt.Errorf("store: create api token: %w", err)
	}
	return nil
}

// GetAPIToken returns an API token row by its token hash.
func (s *Store) GetAPIToken(ctx context.Context, tokenHash string) (*APIToken, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, user_id, token_hash, family_id, name, scopes, expires_at, last_used_at, created_at
		 FROM api_tokens WHERE token_hash = ?`, tokenHash)
	return scanAPIToken(row)
}

// ListAPITokens returns all API tokens for a user, oldest first.
func (s *Store) ListAPITokens(ctx context.Context, userID string) ([]APIToken, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, user_id, token_hash, family_id, name, scopes, expires_at, last_used_at, created_at
		 FROM api_tokens WHERE user_id = ? ORDER BY created_at ASC`, userID)
	if err != nil {
		return nil, fmt.Errorf("store: list api tokens: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []APIToken
	for rows.Next() {
		t, err := scanAPIToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *t)
	}
	return out, rows.Err()
}

// TouchAPIToken records a use of an API token (updates last_used_at).
func (s *Store) TouchAPIToken(ctx context.Context, tokenHash string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE api_tokens SET last_used_at = ? WHERE token_hash = ?`,
		time.Now().UTC(), tokenHash)
	return err
}

// RevokeAPITokenFamily revokes every API token sharing a family for the user,
// scoped so a caller cannot revoke another user's tokens (IDOR boundary).
func (s *Store) RevokeAPITokenFamily(ctx context.Context, userID, familyID string) error {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM api_tokens WHERE family_id = ? AND user_id = ?`, familyID, userID)
	if err != nil {
		return fmt.Errorf("store: revoke api token family: %w", err)
	}
	return requireAffected(res)
}

// scanAPIToken scans a *sql.Row or *sql.Rows into an APIToken.
func scanAPIToken(row rowScanner) (*APIToken, error) {
	var t APIToken
	var name sql.NullString
	var scopes string
	var expires sql.NullTime
	var lastUsed sql.NullTime
	err := row.Scan(&t.ID, &t.UserID, &t.TokenHash, &t.FamilyID, &name, &scopes, &expires, &lastUsed, &t.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	t.Name = name.String
	t.Scopes = splitCSV(scopes)
	t.ExpiresAt = expires.Time
	if lastUsed.Valid {
		t.LastUsedAt = &lastUsed.Time
	}
	return &t, nil
}
