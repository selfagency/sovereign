package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// ErrLastCredential is returned when deleting a user's only WebAuthn
// credential. A user must always retain at least one passkey so they can
// authenticate.
var ErrLastCredential = errors.New("store: cannot delete last webauthn credential")

// SetUserDisplayName updates a user's display name. The column lives on the
// users table (migration v3), so no profile-page indirection is needed.
func (s *Store) SetUserDisplayName(ctx context.Context, id, displayName string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE users SET display_name = ? WHERE id = ?`, displayName, id)
	if err != nil {
		return fmt.Errorf("store: set user display name: %w", err)
	}
	return requireAffected(res)
}

// UpdateProfileLink updates a profile link, scoped to its profile page so a
// caller cannot mutate another page's links.
func (s *Store) UpdateProfileLink(ctx context.Context, profilePageID, linkID string, link *ProfileLink) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE profile_links SET position = ?, kind = ?, brand_key = ?, label = ?, url = ?, icon_blob_key = ?, is_visible = ?
		 WHERE profile_page_id = ? AND id = ?`,
		link.Position, link.Kind, link.BrandKey, link.Label, link.URL, link.IconBlobKey, link.IsVisible,
		profilePageID, linkID)
	if err != nil {
		return fmt.Errorf("store: update profile link: %w", err)
	}
	return requireAffected(res)
}

// DeleteWebAuthnCredential removes a passkey, refusing to delete a user's last
// credential (ErrLastCredential). The existence check, count, and delete run in
// one transaction so the guard cannot be raced.
func (s *Store) DeleteWebAuthnCredential(ctx context.Context, userID string, credentialID []byte) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: delete webauthn credential: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var exists int
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM webauthn_credentials WHERE user_id = ? AND credential_id = ?`,
		userID, credentialID).Scan(&exists); err != nil {
		return fmt.Errorf("store: delete webauthn credential: %w", err)
	}
	if exists == 0 {
		return ErrNotFound
	}
	var count int
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM webauthn_credentials WHERE user_id = ?`, userID).Scan(&count); err != nil {
		return fmt.Errorf("store: delete webauthn credential: %w", err)
	}
	if count <= 1 {
		return ErrLastCredential
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM webauthn_credentials WHERE user_id = ? AND credential_id = ?`,
		userID, credentialID); err != nil {
		return fmt.Errorf("store: delete webauthn credential: %w", err)
	}
	return tx.Commit()
}

// GetTenantByID returns a tenant by its ID.
func (s *Store) GetTenantByID(ctx context.Context, tenantID string) (*Tenant, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, handle, did_method, did, created_at FROM tenants WHERE id = ?`, tenantID)
	var t Tenant
	err := row.Scan(&t.ID, &t.Handle, &t.DIDMethod, &t.DID, &t.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &t, err
}

// GetTenantByDID returns a tenant by its DID.
func (s *Store) GetTenantByDID(ctx context.Context, did string) (*Tenant, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, handle, did_method, did, created_at FROM tenants WHERE did = ?`, did)
	var t Tenant
	err := row.Scan(&t.ID, &t.Handle, &t.DIDMethod, &t.DID, &t.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &t, err
}

// ListUsersPage returns a page of users for a tenant plus the total count.
func (s *Store) ListUsersPage(ctx context.Context, tenantID string, limit, offset int) ([]User, int, error) {
	if limit <= 0 {
		limit = 100
	}
	var total int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM users WHERE tenant_id = ?`, tenantID).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("store: list users page: %w", err)
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, tenant_id, handle, display_name, email, is_admin, tos_accepted, passkey_setup, created_at
		 FROM users WHERE tenant_id = ? ORDER BY created_at LIMIT ? OFFSET ?`, tenantID, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("store: list users page: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.TenantID, &u.Handle, &u.DisplayName, &u.Email, &u.IsAdmin, &u.ToSAccepted, &u.PasskeySetup, &u.CreatedAt); err != nil {
			return nil, 0, err
		}
		out = append(out, u)
	}
	return out, total, rows.Err()
}

// ListAuditPage returns a page of audit entries for a tenant (newest first)
// plus the total count. Offset/limit pagination is used for now; cursor-based
// pagination is deferred.
func (s *Store) ListAuditPage(ctx context.Context, tenantID string, limit, offset int) ([]AuditEntry, int, error) {
	if limit <= 0 {
		limit = 100
	}
	var total int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM audit_log WHERE tenant_id = ?`, tenantID).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("store: list audit page: %w", err)
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, tenant_id, actor, action, target, detail, created_at
		 FROM audit_log WHERE tenant_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?`, tenantID, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("store: list audit page: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.TenantID, &e.Actor, &e.Action, &e.Target, &e.Detail, &e.CreatedAt); err != nil {
			return nil, 0, err
		}
		out = append(out, e)
	}
	return out, total, rows.Err()
}

// ListClientsPage returns a page of OIDC clients plus the total count.
func (s *Store) ListClientsPage(ctx context.Context, limit, offset int) ([]Client, int, error) {
	if limit <= 0 {
		limit = 100
	}
	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM clients`).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("store: list clients page: %w", err)
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, secret, redirect_uris, scopes, created_at FROM clients ORDER BY created_at LIMIT ? OFFSET ?`, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("store: list clients page: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Client
	for rows.Next() {
		var c Client
		var redirects, scopes string
		if err := rows.Scan(&c.ID, &c.Secret, &redirects, &scopes, &c.CreatedAt); err != nil {
			return nil, 0, err
		}
		c.RedirectURIs = splitCSV(redirects)
		c.Scopes = splitCSV(scopes)
		out = append(out, c)
	}
	return out, total, rows.Err()
}

// ListTenantsPage returns a page of tenants plus the total count.
func (s *Store) ListTenantsPage(ctx context.Context, limit, offset int) ([]Tenant, int, error) {
	if limit <= 0 {
		limit = 100
	}
	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM tenants`).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("store: list tenants page: %w", err)
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, handle, did_method, did, created_at FROM tenants ORDER BY handle LIMIT ? OFFSET ?`, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("store: list tenants page: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Tenant
	for rows.Next() {
		var t Tenant
		if err := rows.Scan(&t.ID, &t.Handle, &t.DIDMethod, &t.DID, &t.CreatedAt); err != nil {
			return nil, 0, err
		}
		out = append(out, t)
	}
	return out, total, rows.Err()
}

// CountUsers returns the number of users in a tenant.
func (s *Store) CountUsers(ctx context.Context, tenantID string) (int, error) {
	var n int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM users WHERE tenant_id = ?`, tenantID).Scan(&n); err != nil {
		return 0, fmt.Errorf("store: count users: %w", err)
	}
	return n, nil
}

// DeleteUser removes a user and all of their data in a single transaction:
// sessions, WebAuthn credentials, profile page and links, public keys, proof
// claims, refresh tokens, and invite tokens. The schema is FK-less for these
// relations (only webauthn_credentials and invite_tokens carry an ON DELETE
// CASCADE FK to users), so every dependent table is deleted explicitly.
func (s *Store) DeleteUser(ctx context.Context, id string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: delete user: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Guard: the user must exist before we delete their data.
	var exists int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE id = ?`, id).Scan(&exists); err != nil {
		return fmt.Errorf("store: delete user: %w", err)
	}
	if exists == 0 {
		return ErrNotFound
	}

	// Every dependent table, in dependency order (profile_links reference
	// profile_pages, so the former goes first).
	del := []struct {
		query string
		arg   string
	}{
		{`DELETE FROM profile_links WHERE profile_page_id IN (SELECT id FROM profile_pages WHERE account_id = ?)`, id},
		{`DELETE FROM profile_pages WHERE account_id = ?`, id},
		{`DELETE FROM sessions WHERE user_id = ?`, id},
		{`DELETE FROM webauthn_credentials WHERE user_id = ?`, id},
		{`DELETE FROM public_keys WHERE account_id = ?`, id},
		{`DELETE FROM proof_claims WHERE account_id = ?`, id},
		{`DELETE FROM auth_refresh_tokens WHERE subject = ?`, id},
		{`DELETE FROM invite_tokens WHERE user_id = ?`, id},
		{`DELETE FROM users WHERE id = ?`, id},
	}
	for _, d := range del {
		if _, err := tx.ExecContext(ctx, d.query, d.arg); err != nil {
			return fmt.Errorf("store: delete user: %w", err)
		}
	}
	return tx.Commit()
}
