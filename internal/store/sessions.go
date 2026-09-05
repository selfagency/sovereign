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

// Session is a server-side session row. TokenHash holds the SHA-256 hash of
// the raw opaque session token, never the token itself. LastSeenAt is updated
// on every use; ExpiresAt advances on sliding renewal; RevokedAt is set when
// the session is explicitly revoked. Expired or revoked sessions must not
// authenticate.
type Session struct {
	ID            string     `json:"id"`
	UserID        string     `json:"user_id"`
	TokenHash     string     `json:"token_hash"`
	CreatedAt     time.Time  `json:"created_at"`
	LastSeenAt    *time.Time `json:"last_seen_at"`
	ExpiresAt     time.Time  `json:"expires_at"`
	RevokedAt     *time.Time `json:"revoked_at"`
	UserAgentHash string     `json:"user_agent_hash"`
	IPHash        string     `json:"ip_hash"`
}

// HashSessionToken returns the hex SHA-256 hash of a session token. Tokens are
// persisted only as their hash so a leaked database cannot yield usable
// session cookies.
func HashSessionToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// IsSessionToken reports whether an opaque cookie value has the session-token
// shape: a single random base64url string with no dots. A JWT has exactly two
// dots (header.payload.signature); anything else is treated as a session
// token. This keeps the dual-read distinction unambiguous for the authn
// middleware, which rejects a request carrying both shapes in one cookie.
func IsSessionToken(token string) bool {
	return strings.Count(token, ".") != 2
}

// GenerateSessionToken returns a new random opaque session token (32 random
// bytes, base64url-encoded, no dots).
func GenerateSessionToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return strings.TrimRight(base64.RawURLEncoding.EncodeToString(b), "="), nil
}

// NewSessionID returns a new random URL-safe session row ID.
func NewSessionID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// rand.Read from crypto/rand never fails on supported platforms.
		panic("store: crypto/rand unavailable")
	}
	return strings.TrimRight(base64.RawURLEncoding.EncodeToString(b), "=")
}

// CreateSession inserts a new session row keyed by the SHA-256 hash of the
// raw token and returns the resulting Session. The caller is responsible for
// passing an already-hashed tokenHash (see HashSessionToken).
func (s *Store) CreateSession(ctx context.Context, userID, tokenHash string, ttl time.Duration, uaHash, ipHash string) (*Session, error) {
	now := time.Now().UTC()
	lastSeen := now
	sess := &Session{
		ID:            NewSessionID(),
		UserID:        userID,
		TokenHash:     tokenHash,
		CreatedAt:     now,
		LastSeenAt:    &lastSeen,
		ExpiresAt:     now.Add(ttl),
		UserAgentHash: uaHash,
		IPHash:        ipHash,
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO sessions (id, user_id, token_hash, created_at, last_seen_at, expires_at, revoked_at, user_agent_hash, ip_hash)
		 VALUES (?, ?, ?, ?, ?, ?, NULL, ?, ?)`,
		sess.ID, sess.UserID, sess.TokenHash, sess.CreatedAt, sess.LastSeenAt, sess.ExpiresAt,
		nullableString(sess.UserAgentHash), nullableString(sess.IPHash))
	if err != nil {
		return nil, fmt.Errorf("store: create session: %w", err)
	}
	return sess, nil
}

// GetSessionByTokenHash returns the session row by its token hash. The caller
// checks expiry/revocation (see Session.IsExpired / RevokedAt).
func (s *Store) GetSessionByTokenHash(ctx context.Context, tokenHash string) (*Session, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, user_id, token_hash, created_at, last_seen_at, expires_at, revoked_at, user_agent_hash, ip_hash
		 FROM sessions WHERE token_hash = ?`, tokenHash)
	return scanSession(row)
}

// GetSessionByID returns a session row by its ID.
func (s *Store) GetSessionByID(ctx context.Context, id string) (*Session, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, user_id, token_hash, created_at, last_seen_at, expires_at, revoked_at, user_agent_hash, ip_hash
		 FROM sessions WHERE id = ?`, id)
	return scanSession(row)
}

// TouchSession performs sliding renewal: it advances expires_at and updates
// last_seen_at. It fails if the session does not exist.
func (s *Store) TouchSession(ctx context.Context, id string, newExpiresAt time.Time) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE sessions SET last_seen_at = ?, expires_at = ? WHERE id = ?`,
		time.Now().UTC(), newExpiresAt, id)
	if err != nil {
		return fmt.Errorf("store: touch session: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("store: touch session: %w", err)
	} else if n == 0 {
		return ErrNotFound
	}
	return nil
}

// RevokeSession sets revoked_at on a single session, invalidating it. Revoking
// an already-missing session is a no-op error-wise only if the row existed.
func (s *Store) RevokeSession(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE sessions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`,
		time.Now().UTC(), id)
	if err != nil {
		return fmt.Errorf("store: revoke session: %w", err)
	}
	return nil
}

// RevokeUserSessions revokes every session for a user.
func (s *Store) RevokeUserSessions(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL`,
		time.Now().UTC(), userID)
	if err != nil {
		return fmt.Errorf("store: revoke user sessions: %w", err)
	}
	return nil
}

// ListUserSessions returns all session rows for a user.
func (s *Store) ListUserSessions(ctx context.Context, userID string) ([]Session, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, user_id, token_hash, created_at, last_seen_at, expires_at, revoked_at, user_agent_hash, ip_hash
		 FROM sessions WHERE user_id = ? ORDER BY created_at ASC`, userID)
	if err != nil {
		return nil, fmt.Errorf("store: list user sessions: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []Session
	for rows.Next() {
		sess, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *sess)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list user sessions: %w", err)
	}
	return out, nil
}

// PruneUserSessions enforces an absolute cap on active (non-revoked,
// non-expired) sessions per user: when the count exceeds limit, the oldest
// active sessions are revoked until only limit remain. It returns the number
// of sessions revoked.
func (s *Store) PruneUserSessions(ctx context.Context, userID string, limit int) (int, error) {
	if limit < 1 {
		return 0, nil
	}
	now := time.Now().UTC()
	// Revoke the oldest active sessions beyond the cap. Only rows that are
	// still active count toward the limit; expired-but-unrevoked rows are
	// treated as consumed so they do not resurrect on the next prune.
	res, err := s.db.ExecContext(ctx, `
		UPDATE sessions SET revoked_at = ?
		WHERE user_id = ? AND revoked_at IS NULL
		  AND id IN (
		    SELECT id FROM sessions
		    WHERE user_id = ? AND revoked_at IS NULL
		      AND (expires_at > ?)
		    ORDER BY created_at DESC
		    LIMIT -1 OFFSET ?
		  )`,
		now, userID, userID, now, limit)
	if err != nil {
		return 0, fmt.Errorf("store: prune user sessions: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("store: prune user sessions: %w", err)
	}
	return int(n), nil
}

// IsExpired reports whether the session's expiry has passed. Expired sessions
// must not authenticate.
func (s *Session) IsExpired() bool {
	return time.Now().UTC().After(s.ExpiresAt)
}

// scanSession scans a *sql.Row or *sql.Rows into a Session.
type rowScanner interface{ Scan(dest ...any) error }

func scanSession(row rowScanner) (*Session, error) {
	var sess Session
	var lastSeen, revoked sql.NullTime
	var uaHash, ipHash sql.NullString
	err := row.Scan(&sess.ID, &sess.UserID, &sess.TokenHash, &sess.CreatedAt, &lastSeen, &sess.ExpiresAt, &revoked, &uaHash, &ipHash)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if lastSeen.Valid {
		sess.LastSeenAt = &lastSeen.Time
	}
	if revoked.Valid {
		sess.RevokedAt = &revoked.Time
	}
	sess.UserAgentHash = uaHash.String
	sess.IPHash = ipHash.String
	return &sess, nil
}
