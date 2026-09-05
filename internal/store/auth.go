package store

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
)

// AuthSigningKey is a persisted OIDC signing key.
type AuthSigningKey struct {
	ID        string
	KeyPEM    string // PEM-encoded RSA private key
	CreatedAt time.Time
}

// AuthRefreshToken is a persisted refresh token grant. The Token field holds
// the SHA-256 hash of the raw token, never the raw token itself.
//
// FamilyID groups tokens minted from a single initial grant so reuse detection
// can revoke the whole family when a rotated token is replayed. It is NULL for
// pre-migration (grandfathered) tokens and is seeded on their first rotation.
// RotatedAt is set when a token is redeemed and rotated, marking it as
// potentially-reused so a later replay revokes the family.
type AuthRefreshToken struct {
	Token     string
	Subject   string
	ClientID  string
	Scopes    string // comma-joined
	AuthTime  time.Time
	ExpiresAt time.Time
	RevokedAt time.Time
	FamilyID  string
	RotatedAt time.Time
	CreatedAt time.Time
}

// SaveAuthSigningKey persists the signing key (idempotent by ID).
func (s *Store) SaveAuthSigningKey(ctx context.Context, k AuthSigningKey) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO auth_signing_keys (id, key_pem, created_at) VALUES (?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET key_pem = excluded.key_pem`,
		k.ID, k.KeyPEM, k.CreatedAt)
	return err
}

// GetAuthSigningKey returns the signing key by ID.
func (s *Store) GetAuthSigningKey(ctx context.Context, id string) (*AuthSigningKey, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, key_pem, created_at FROM auth_signing_keys WHERE id = ?`, id)
	var k AuthSigningKey
	err := row.Scan(&k.ID, &k.KeyPEM, &k.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &k, err
}

// SaveAuthRefreshToken persists a refresh token grant.
func (s *Store) SaveAuthRefreshToken(ctx context.Context, t *AuthRefreshToken) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT OR REPLACE INTO auth_refresh_tokens (token, subject, client_id, scopes, auth_time, expires_at, revoked_at, family_id, rotated_at, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		t.Token, t.Subject, t.ClientID, t.Scopes, t.AuthTime, nullableTime(t.ExpiresAt), nullableTime(t.RevokedAt), nullableString(t.FamilyID), nullableTime(t.RotatedAt), t.CreatedAt)
	return err
}

// RotateAuthRefreshToken atomically marks the old token as rotated and persists
// the successor token in a single transaction. It fails (and rolls back) if the
// old token is missing or already rotated, so a replayed token cannot slip
// through the rotation path. The old row is kept (with rotated_at set) so a
// later replay is detected as reuse and revokes the whole family.
func (s *Store) RotateAuthRefreshToken(ctx context.Context, oldHash string, newToken *AuthRefreshToken) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: rotate refresh token: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now().UTC()
	res, err := tx.ExecContext(ctx,
		`UPDATE auth_refresh_tokens SET rotated_at = ? WHERE token = ? AND rotated_at IS NULL`,
		now, oldHash)
	if err != nil {
		return fmt.Errorf("store: rotate refresh token: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: rotate refresh token: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("store: rotate refresh token: token not found or already rotated")
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO auth_refresh_tokens (token, subject, client_id, scopes, auth_time, expires_at, revoked_at, family_id, rotated_at, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		newToken.Token, newToken.Subject, newToken.ClientID, newToken.Scopes, newToken.AuthTime, nullableTime(newToken.ExpiresAt), nullableTime(newToken.RevokedAt), nullableString(newToken.FamilyID), nullableTime(newToken.RotatedAt), newToken.CreatedAt); err != nil {
		return fmt.Errorf("store: rotate refresh token: %w", err)
	}
	return tx.Commit()
}

// RevokeAuthRefreshTokenFamily revokes every token sharing a family. Used when
// reuse detection fires: replaying a rotated token invalidates the entire
// family, including the current successor token.
func (s *Store) RevokeAuthRefreshTokenFamily(ctx context.Context, familyID string) error {
	if familyID == "" {
		return nil
	}
	_, err := s.db.ExecContext(ctx,
		`UPDATE auth_refresh_tokens SET revoked_at = ? WHERE family_id = ?`,
		time.Now().UTC(), familyID)
	return err
}

// GetAuthRefreshToken returns a refresh token grant.
func (s *Store) GetAuthRefreshToken(ctx context.Context, token string) (*AuthRefreshToken, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT token, subject, client_id, scopes, auth_time, expires_at, revoked_at, family_id, rotated_at, created_at FROM auth_refresh_tokens WHERE token = ?`, token)
	var t AuthRefreshToken
	var exp, rev, rot sql.NullTime
	var family sql.NullString
	err := row.Scan(&t.Token, &t.Subject, &t.ClientID, &t.Scopes, &t.AuthTime, &exp, &rev, &family, &rot, &t.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	t.ExpiresAt = exp.Time
	t.RevokedAt = rev.Time
	t.FamilyID = family.String
	t.RotatedAt = rot.Time
	return &t, err
}

// GetAuthRefreshTokenByHash returns a refresh token grant by its hashed value.
func (s *Store) GetAuthRefreshTokenByHash(ctx context.Context, hash string) (subject, clientID string, scopes []string, err error) {
	t, err := s.GetAuthRefreshToken(ctx, hash)
	if err != nil {
		return "", "", nil, err
	}
	if !t.RevokedAt.IsZero() {
		return "", "", nil, ErrNotFound
	}
	if !t.ExpiresAt.IsZero() && time.Now().After(t.ExpiresAt) {
		return "", "", nil, ErrNotFound
	}
	return t.Subject, t.ClientID, splitCSV(t.Scopes), nil
}

// DeleteAuthRefreshToken removes a refresh token (revocation).
func (s *Store) DeleteAuthRefreshToken(ctx context.Context, token string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM auth_refresh_tokens WHERE token = ?`, token)
	return err
}

// User is an OIDC/WebAuthn subject that can authenticate and hold passkeys.
type User struct {
	ID           string
	TenantID     string
	Handle       string
	DisplayName  string
	Email        string
	IsAdmin      bool
	ToSAccepted  bool
	PasskeySetup bool
	CreatedAt    time.Time
}

// Client is an OIDC relying party registered with the provider.
type Client struct {
	ID           string
	Secret       string
	RedirectURIs []string
	Scopes       []string
	CreatedAt    time.Time
}

// WebAuthnCredential is a stored passkey for a user.
type WebAuthnCredential struct {
	ID           string
	UserID       string
	CredentialID []byte
	PublicKey    []byte
	SignCount    uint32
	Data         []byte // full go-webauthn Credential JSON
	CreatedAt    time.Time
}

// AuditEntry is a single row in the persistent audit log.
type AuditEntry struct {
	ID        string
	TenantID  string
	Actor     string
	Action    string
	Target    string
	Detail    string
	CreatedAt time.Time
}

// ErrDuplicateUser is returned when a user already exists for a tenant+handle.
var ErrDuplicateUser = errors.New("store: user already exists")

// ErrDuplicateClient is returned when a client ID already exists.
var ErrDuplicateClient = errors.New("store: client already exists")

// ErrClientSecretTooLong is returned when a client secret exceeds the maximum
// allowed length.
var ErrClientSecretTooLong = errors.New("store: client secret too long (max 128 bytes)")

// Client secret hashing parameters (argon2id). These are shared by the SQL
// store and the in-memory store so both paths use identical parameters.
const (
	argon2Time    = 3
	argon2Memory  = 64 * 1024 // 64 MiB
	argon2Threads = 1
	argon2KeyLen  = 32
	argon2SaltLen = 16
)

// maxClientSecretLen is the maximum accepted client-secret length in bytes.
const maxClientSecretLen = 128

// invalidatedSecret is the sentinel written by migration v5 in place of
// pre-v5 plaintext client secrets. It can never be a valid argon2id hash and
// is explicitly rejected by the verifier, so invalidated clients cannot
// authenticate until re-registered via `sovereign clients set-secret`.
const invalidatedSecret = "!invalidated-by-migration-v5"

// HashClientSecret derives an argon2id hash of a client secret using the
// shared parameters. The returned string is a PHC-encoded hash carrying the
// salt and parameters, so verification needs no external state.
func HashClientSecret(secret string) (string, error) {
	salt := make([]byte, argon2SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("store: hash client secret: %w", err)
	}
	hash := argon2.IDKey([]byte(secret), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argon2Memory, argon2Time, argon2Threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash)), nil
}

// VerifyClientSecret reports whether secret matches the stored argon2id hash.
// It uses a constant-time comparison and fails closed: the sentinel and any
// non-argon2id-prefixed stored value are rejected outright.
func VerifyClientSecret(secret, stored string) bool {
	if stored == invalidatedSecret {
		return false
	}
	parts := strings.Split(stored, "$")
	// Expected: ["", "argon2id", "v=19", "m=..,t=..,p=..", salt, hash]
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var memory, t uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &t, &threads); err != nil {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	expected, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}
	// The derived-key length must fit in uint32 (argon2's keyLen).
	if uint64(len(expected)) > math.MaxUint32 {
		return false
	}
	// #nosec G115 -- len(expected) is bounded to <= math.MaxUint32 above.
	keyLen := uint32(len(expected))
	got := argon2.IDKey([]byte(secret), salt, t, memory, threads, keyLen)
	return subtle.ConstantTimeCompare(got, expected) == 1
}

// CreateUser inserts a user. The first user in the store becomes the instance
// admin (is_admin = 1); subsequent users default to non-admin unless the
// caller sets IsAdmin explicitly. The returned struct's IsAdmin reflects the
// actual DB outcome (read back via RETURNING), so the first user reports
// admin even when the caller did not request it.
func (s *Store) CreateUser(ctx context.Context, u *User) error {
	// The first user in the store becomes the instance admin. The decision is
	// made atomically in a single INSERT (SQLite serializes concurrent
	// writers), so concurrent first-user registration cannot both see zero
	// rows and both become admin. Later users honor the caller's explicit
	// IsAdmin override.
	isAdmin := u.IsAdmin
	var actualAdmin bool
	err := s.db.QueryRowContext(ctx,
		`INSERT INTO users (id, tenant_id, handle, display_name, email, is_admin)
		 VALUES (?, ?, ?, ?, ?, CASE WHEN (SELECT COUNT(*) FROM users) = 0 THEN 1 ELSE ? END)
		 RETURNING is_admin`,
		u.ID, u.TenantID, u.Handle, u.DisplayName, u.Email, isAdmin).Scan(&actualAdmin)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return ErrDuplicateUser
		}
		return fmt.Errorf("store: create user: %w", err)
	}
	u.IsAdmin = actualAdmin
	return nil
}

// UserByHandle returns a user by tenant + handle.
func (s *Store) UserByHandle(ctx context.Context, tenantID, handle string) (*User, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, tenant_id, handle, display_name, email, is_admin, tos_accepted, passkey_setup, created_at FROM users WHERE tenant_id = ? AND handle = ?`,
		tenantID, handle)
	var u User
	err := row.Scan(&u.ID, &u.TenantID, &u.Handle, &u.DisplayName, &u.Email, &u.IsAdmin, &u.ToSAccepted, &u.PasskeySetup, &u.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &u, err
}

// UserByID returns a user by ID.
func (s *Store) UserByID(ctx context.Context, id string) (*User, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, tenant_id, handle, display_name, email, is_admin, tos_accepted, passkey_setup, created_at FROM users WHERE id = ?`, id)
	var u User
	err := row.Scan(&u.ID, &u.TenantID, &u.Handle, &u.DisplayName, &u.Email, &u.IsAdmin, &u.ToSAccepted, &u.PasskeySetup, &u.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &u, err
}

// ListUsers returns all users for a tenant.
func (s *Store) ListUsers(ctx context.Context, tenantID string) ([]User, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, tenant_id, handle, display_name, email, is_admin, tos_accepted, passkey_setup, created_at FROM users WHERE tenant_id = ? ORDER BY created_at`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("store: list users: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.TenantID, &u.Handle, &u.DisplayName, &u.Email, &u.IsAdmin, &u.ToSAccepted, &u.PasskeySetup, &u.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// SetUserAdmin toggles a user's admin flag.
func (s *Store) SetUserAdmin(ctx context.Context, id string, isAdmin bool) error {
	res, err := s.db.ExecContext(ctx, `UPDATE users SET is_admin = ? WHERE id = ?`, isAdmin, id)
	if err != nil {
		return fmt.Errorf("store: set user admin: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// SetUserEmail sets a user's email address.
func (s *Store) SetUserEmail(ctx context.Context, id, email string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE users SET email = ? WHERE id = ?`, email, id)
	if err != nil {
		return fmt.Errorf("store: set user email: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// SetToSAccepted records that a user accepted the Terms of Service.
func (s *Store) SetToSAccepted(ctx context.Context, id string, accepted bool) error {
	res, err := s.db.ExecContext(ctx, `UPDATE users SET tos_accepted = ? WHERE id = ?`, accepted, id)
	if err != nil {
		return fmt.Errorf("store: set tos accepted: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// SetPasskeySetup records whether a user has completed passkey setup.
func (s *Store) SetPasskeySetup(ctx context.Context, id string, done bool) error {
	res, err := s.db.ExecContext(ctx, `UPDATE users SET passkey_setup = ? WHERE id = ?`, done, id)
	if err != nil {
		return fmt.Errorf("store: set passkey setup: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// InviteToken is a one-time magic-link token for user onboarding.
// TokenHash holds the SHA-256 hash of the raw token, never the raw token.
type InviteToken struct {
	ID        string
	TokenHash string
	UserID    string
	CreatedAt time.Time
	ExpiresAt time.Time
	UsedAt    time.Time
}

// CreateInviteToken persists a hashed invite token.
func (s *Store) CreateInviteToken(ctx context.Context, t *InviteToken) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO invite_tokens (id, token_hash, user_id, expires_at) VALUES (?, ?, ?, ?)`,
		t.ID, t.TokenHash, t.UserID, t.ExpiresAt)
	if err != nil {
		return fmt.Errorf("store: create invite token: %w", err)
	}
	return nil
}

// InviteTokenByHash returns an invite token by its hashed value.
func (s *Store) InviteTokenByHash(ctx context.Context, hash string) (*InviteToken, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, token_hash, user_id, created_at, expires_at, used_at FROM invite_tokens WHERE token_hash = ?`, hash)
	var t InviteToken
	var used sql.NullTime
	err := row.Scan(&t.ID, &t.TokenHash, &t.UserID, &t.CreatedAt, &t.ExpiresAt, &used)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	t.UsedAt = used.Time
	return &t, nil
}

// MarkInviteTokenUsed marks an invite token as consumed.
func (s *Store) MarkInviteTokenUsed(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE invite_tokens SET used_at = ? WHERE id = ?`, time.Now(), id)
	if err != nil {
		return fmt.Errorf("store: mark invite token used: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ErrInviteUsed is returned when redeeming an already-consumed invite token.
var ErrInviteUsed = errors.New("store: invite token already used")

// ErrInviteExpired is returned when redeeming an expired invite token.
var ErrInviteExpired = errors.New("store: invite token expired")

// ErrInviteInvalid is returned when redeeming an unknown invite token.
var ErrInviteInvalid = errors.New("store: invite token invalid")

// RedeemInviteToken atomically consumes a single-use invite token. The UPDATE
// is the authoritative single-use gate: it only affects a row that is unused
// and unexpired, and redemption succeeds only when exactly one row is updated.
// On zero rows a follow-up SELECT classifies the failure for the caller
// (used/expired/not-found); the UPDATE remains authoritative for single-use.
func (s *Store) RedeemInviteToken(ctx context.Context, tokenHash string, now time.Time) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE invite_tokens SET used_at = ? WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?`,
		now, tokenHash, now)
	if err != nil {
		return fmt.Errorf("store: redeem invite token: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: redeem invite token: %w", err)
	}
	if n == 1 {
		return nil
	}
	// Zero rows: classify the failure via a follow-up read. The UPDATE is
	// authoritative for single-use; this SELECT only explains the response.
	it, err := s.InviteTokenByHash(ctx, tokenHash)
	if err != nil {
		return ErrInviteInvalid
	}
	if !it.UsedAt.IsZero() {
		return ErrInviteUsed
	}
	if now.After(it.ExpiresAt) {
		return ErrInviteExpired
	}
	return ErrInviteInvalid
}

// CreateClient inserts an OIDC client. The secret is stored as an argon2id
// hash, never plaintext, and is capped at maxClientSecretLen bytes.
func (s *Store) CreateClient(ctx context.Context, c *Client) error {
	if len(c.Secret) > maxClientSecretLen {
		return ErrClientSecretTooLong
	}
	hash, err := HashClientSecret(c.Secret)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO clients (id, secret, redirect_uris, scopes) VALUES (?, ?, ?, ?)`,
		c.ID, hash, strings.Join(c.RedirectURIs, ","), strings.Join(c.Scopes, ","))
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return ErrDuplicateClient
		}
		return fmt.Errorf("store: create client: %w", err)
	}
	return nil
}

// SetClientSecret re-registers a client's secret (used by the admin CLI after
// migration v5 invalidates plaintext secrets). It hashes the secret and
// updates the row in place, sidestepping CreateClient's unique constraint.
func (s *Store) SetClientSecret(ctx context.Context, id, secret string) error {
	if len(secret) > maxClientSecretLen {
		return ErrClientSecretTooLong
	}
	hash, err := HashClientSecret(secret)
	if err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx, `UPDATE clients SET secret = ? WHERE id = ?`, hash, id)
	if err != nil {
		return fmt.Errorf("store: set client secret: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteClient removes an OIDC client by ID. Returns ErrNotFound when the
// client does not exist.
func (s *Store) DeleteClient(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM clients WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("store: delete client: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ClientByID returns an OIDC client by ID.
func (s *Store) ClientByID(ctx context.Context, id string) (*Client, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, secret, redirect_uris, scopes, created_at FROM clients WHERE id = ?`, id)
	var c Client
	var redirects, scopes string
	err := row.Scan(&c.ID, &c.Secret, &redirects, &scopes, &c.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	c.RedirectURIs = splitCSV(redirects)
	c.Scopes = splitCSV(scopes)
	return &c, nil
}

// ListClients returns all OIDC clients.
func (s *Store) ListClients(ctx context.Context) ([]Client, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, secret, redirect_uris, scopes, created_at FROM clients ORDER BY created_at`)
	if err != nil {
		return nil, fmt.Errorf("store: list clients: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Client
	for rows.Next() {
		var c Client
		var redirects, scopes string
		if err := rows.Scan(&c.ID, &c.Secret, &redirects, &scopes, &c.CreatedAt); err != nil {
			return nil, err
		}
		c.RedirectURIs = splitCSV(redirects)
		c.Scopes = splitCSV(scopes)
		out = append(out, c)
	}
	return out, rows.Err()
}

// AddWebAuthnCredential stores a passkey for a user.
func (s *Store) AddWebAuthnCredential(ctx context.Context, c *WebAuthnCredential) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO webauthn_credentials (id, user_id, credential_id, public_key, sign_count, data) VALUES (?, ?, ?, ?, ?, ?)`,
		c.ID, c.UserID, c.CredentialID, c.PublicKey, c.SignCount, c.Data)
	if err != nil {
		return fmt.Errorf("store: add webauthn credential: %w", err)
	}
	return nil
}

// ListWebAuthnCredentials returns all passkeys for a user.
func (s *Store) ListWebAuthnCredentials(ctx context.Context, userID string) ([]WebAuthnCredential, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, user_id, credential_id, public_key, sign_count, data, created_at FROM webauthn_credentials WHERE user_id = ?`, userID)
	if err != nil {
		return nil, fmt.Errorf("store: list webauthn credentials: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []WebAuthnCredential
	for rows.Next() {
		var c WebAuthnCredential
		if err := rows.Scan(&c.ID, &c.UserID, &c.CredentialID, &c.PublicKey, &c.SignCount, &c.Data, &c.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// GetWebAuthnCredential returns a passkey by credential ID.
func (s *Store) GetWebAuthnCredential(ctx context.Context, credentialID []byte) (*WebAuthnCredential, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, user_id, credential_id, public_key, sign_count, data, created_at FROM webauthn_credentials WHERE credential_id = ?`, credentialID)
	var c WebAuthnCredential
	err := row.Scan(&c.ID, &c.UserID, &c.CredentialID, &c.PublicKey, &c.SignCount, &c.Data, &c.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &c, err
}

// UpdateWebAuthnSignCount updates a passkey's sign count after a login.
func (s *Store) UpdateWebAuthnSignCount(ctx context.Context, id string, signCount uint32) error {
	_, err := s.db.ExecContext(ctx, `UPDATE webauthn_credentials SET sign_count = ? WHERE id = ?`, signCount, id)
	if err != nil {
		return fmt.Errorf("store: update webauthn sign count: %w", err)
	}
	return nil
}

// AppendAudit writes an entry to the persistent audit log.
func (s *Store) AppendAudit(ctx context.Context, e *AuditEntry) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO audit_log (id, tenant_id, actor, action, target, detail) VALUES (?, ?, ?, ?, ?, ?)`,
		e.ID, e.TenantID, e.Actor, e.Action, e.Target, e.Detail)
	if err != nil {
		return fmt.Errorf("store: append audit: %w", err)
	}
	return nil
}

// ListAudit returns audit entries for a tenant, newest first.
func (s *Store) ListAudit(ctx context.Context, tenantID string, limit int) ([]AuditEntry, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, tenant_id, actor, action, target, detail, created_at FROM audit_log WHERE tenant_id = ? ORDER BY created_at DESC LIMIT ?`,
		tenantID, limit)
	if err != nil {
		return nil, fmt.Errorf("store: list audit: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.TenantID, &e.Actor, &e.Action, &e.Target, &e.Detail, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// splitCSV splits a comma-joined column into a slice, dropping empties.
func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
