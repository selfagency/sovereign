package store

import (
	"context"
	"database/sql"
	"fmt"
	"log"
)

// migration is a single versioned schema change. Migrations run in order and
// are applied transactionally; once applied, a version is recorded in
// schema_version and never re-run. Never edit a shipped migration — add a new
// one instead.
type migration struct {
	version int
	name    string
	up      func(ctx context.Context, tx *sql.Tx) error
}

// migrations is the ordered list of schema migrations. Version 1 is the
// initial schema (previously applied ad-hoc by migrate()); later versions
// evolve it.
var migrations = []migration{
	{version: 1, name: "initial_schema", up: migrateV1},
	{version: 2, name: "accounts_table", up: migrateV2},
	{version: 3, name: "auth_tables", up: migrateV3},
	{version: 4, name: "invites_and_user_state", up: migrateV4},
	{version: 5, name: "invalidate_plaintext_client_secrets", up: migrateV5},
	{version: 6, name: "refresh_token_expiry_and_rotation", up: migrateV6},
	{version: 7, name: "sessions_and_idempotency", up: migrateV7},
	{version: 8, name: "backup_and_takedown_and_tos", up: migrateV8},
	{version: 9, name: "pending_deletions_and_tos_docs", up: migrateV9},
}

// migrate runs all pending migrations inside transactions and records each
// applied version in schema_version. It is safe to call on every Open.
func (s *Store) migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_version (
		version    INTEGER PRIMARY KEY,
		name       TEXT NOT NULL,
		applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`); err != nil {
		return fmt.Errorf("store: create schema_version: %w", err)
	}

	current, err := s.currentVersion(ctx)
	if err != nil {
		return err
	}

	for _, m := range migrations {
		if m.version <= current {
			continue
		}
		if err := s.applyMigration(ctx, m); err != nil {
			return fmt.Errorf("store: migration %d (%s): %w", m.version, m.name, err)
		}
	}
	return nil
}

// currentVersion returns the highest applied migration version (0 if none).
func (s *Store) currentVersion(ctx context.Context) (int, error) {
	var v int
	err := s.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_version`).Scan(&v)
	if err != nil {
		return 0, fmt.Errorf("store: read schema_version: %w", err)
	}
	return v, nil
}

// applyMigration runs one migration in a transaction and records it.
func (s *Store) applyMigration(ctx context.Context, m migration) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if err := m.up(ctx, tx); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO schema_version (version, name) VALUES (?, ?)`, m.version, m.name); err != nil {
		return err
	}
	return tx.Commit()
}

// migrateV1 is the initial schema. It is idempotent (CREATE IF NOT EXISTS) so
// databases created before the migration runner was introduced converge to the
// same shape.
func migrateV1(ctx context.Context, tx *sql.Tx) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS public_keys (
			id            TEXT PRIMARY KEY,
			tenant_id     TEXT NOT NULL,
			account_id    TEXT NOT NULL,
			key_type      TEXT NOT NULL,
			label         TEXT,
			fingerprint   TEXT NOT NULL,
			key_material  TEXT NOT NULL,
			algorithm     TEXT,
			revoked_at    TIMESTAMP,
			expires_at    TIMESTAMP,
			created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(tenant_id, fingerprint)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_public_keys_account ON public_keys(account_id, key_type)`,
		`CREATE TABLE IF NOT EXISTS profile_pages (
			id              TEXT PRIMARY KEY,
			tenant_id       TEXT NOT NULL UNIQUE,
			account_id      TEXT NOT NULL,
			display_name    TEXT,
			bio             TEXT,
			avatar_blob_key TEXT,
			theme           TEXT NOT NULL DEFAULT 'default',
			is_published    BOOLEAN NOT NULL DEFAULT 0,
			sync_atproto_profile BOOLEAN NOT NULL DEFAULT 0,
			updated_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS profile_links (
			id              TEXT PRIMARY KEY,
			profile_page_id TEXT NOT NULL REFERENCES profile_pages(id) ON DELETE CASCADE,
			position        INTEGER NOT NULL,
			kind            TEXT NOT NULL,
			brand_key       TEXT,
			label           TEXT NOT NULL,
			url             TEXT NOT NULL,
			icon_blob_key   TEXT,
			is_visible      BOOLEAN NOT NULL DEFAULT 1,
			click_count     INTEGER NOT NULL DEFAULT 0,
			created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_profile_links_page_position ON profile_links(profile_page_id, position)`,
		`CREATE TABLE IF NOT EXISTS proof_claims (
			id              TEXT PRIMARY KEY,
			tenant_id       TEXT NOT NULL,
			account_id      TEXT NOT NULL,
			anchor_type     TEXT NOT NULL,
			anchor_value    TEXT NOT NULL,
			service         TEXT NOT NULL,
			claim_location  TEXT NOT NULL,
			expected_token  TEXT NOT NULL,
			status          TEXT NOT NULL DEFAULT 'pending',
			last_checked_at TIMESTAMP,
			last_error      TEXT,
			created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(tenant_id, service, claim_location)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_proof_claims_recheck ON proof_claims(status, last_checked_at)`,
		`CREATE TABLE IF NOT EXISTS auth_signing_keys (
			id         TEXT PRIMARY KEY,
			key_pem    TEXT NOT NULL,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS auth_refresh_tokens (
			token      TEXT PRIMARY KEY,
			subject    TEXT NOT NULL,
			client_id  TEXT NOT NULL,
			scopes     TEXT NOT NULL,
			auth_time  TIMESTAMP NOT NULL,
			expires_at TIMESTAMP,
			revoked_at TIMESTAMP,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS tenants (
			id         TEXT PRIMARY KEY,
			handle     TEXT NOT NULL UNIQUE,
			did_method TEXT NOT NULL DEFAULT 'web',
			did        TEXT,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
	}
	for _, stmt := range stmts {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
}

// migrateV2 creates the minimal accounts table. It holds the identity
// primitives (DID, WebID) that authorization and profile features depend on.
// Web3/SIWE/ENS identity is deliberately out of scope (decision 7).
func migrateV2(ctx context.Context, tx *sql.Tx) error {
	_, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS accounts (
		id         TEXT PRIMARY KEY,
		tenant_id  TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
		did        TEXT,
		webid      TEXT,
		created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(tenant_id, did)
	)`)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS idx_accounts_tenant ON accounts(tenant_id)`)
	return err
}

// migrateV3 creates the auth tables: users (OIDC/WebAuthn subjects with an
// admin flag), OIDC clients, WebAuthn credentials, and the persistent audit
// log. The first user created is the instance admin (enforced in store code,
// not here).
func migrateV3(ctx context.Context, tx *sql.Tx) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id           TEXT PRIMARY KEY,
			tenant_id    TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
			handle       TEXT NOT NULL,
			display_name TEXT,
			is_admin     BOOLEAN NOT NULL DEFAULT 0,
			created_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(tenant_id, handle)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_users_tenant ON users(tenant_id)`,
		`CREATE TABLE IF NOT EXISTS clients (
			id            TEXT PRIMARY KEY,
			secret        TEXT NOT NULL,
			redirect_uris TEXT NOT NULL,
			scopes        TEXT NOT NULL,
			created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS webauthn_credentials (
			id            TEXT PRIMARY KEY,
			user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			credential_id BLOB NOT NULL,
			public_key    BLOB NOT NULL,
			sign_count    INTEGER NOT NULL DEFAULT 0,
			data          BLOB NOT NULL,
			created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(user_id, credential_id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_webauthn_user ON webauthn_credentials(user_id)`,
		`CREATE TABLE IF NOT EXISTS audit_log (
			id         TEXT PRIMARY KEY,
			tenant_id  TEXT NOT NULL,
			actor      TEXT NOT NULL,
			action     TEXT NOT NULL,
			target     TEXT,
			detail     TEXT,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_tenant ON audit_log(tenant_id, created_at)`,
		`CREATE TABLE IF NOT EXISTS ipfs_pins (
			cid        TEXT PRIMARY KEY,
			status     TEXT NOT NULL DEFAULT 'pinned',
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
	}
	for _, stmt := range stmts {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
}

// migrateV5 invalidates pre-v5 plaintext client secrets by replacing them with
// the sentinel invalidatedSecret. Affected client IDs are logged at WARN so
// operators can re-register them via `sovereign clients set-secret`. The
// UPDATE is idempotent: rows already holding the sentinel are untouched.
func migrateV5(ctx context.Context, tx *sql.Tx) error {
	rows, err := tx.QueryContext(ctx, `SELECT id FROM clients WHERE secret != ?`, invalidatedSecret)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, id := range ids {
		// Log the client ID (not the secret) so operators can re-register.
		log.Printf("store: migration v5 invalidated plaintext client secret for client %q; re-register via `sovereign clients set-secret %s`", id, id)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE clients SET secret = ? WHERE secret != ?`, invalidatedSecret, invalidatedSecret); err != nil {
		return err
	}
	return nil
}

// migrateV4 adds user onboarding state (email, ToS acceptance, passkey setup)
// and the invite-token table used for admin-issued magic links.
func migrateV4(ctx context.Context, tx *sql.Tx) error {
	stmts := []string{
		`ALTER TABLE users ADD COLUMN email TEXT`,
		`ALTER TABLE users ADD COLUMN tos_accepted BOOLEAN NOT NULL DEFAULT 0`,
		`ALTER TABLE users ADD COLUMN passkey_setup BOOLEAN NOT NULL DEFAULT 0`,
		`CREATE TABLE IF NOT EXISTS invite_tokens (
			id         TEXT PRIMARY KEY,
			token_hash TEXT NOT NULL UNIQUE,
			user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			expires_at TIMESTAMP NOT NULL,
			used_at    TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_invite_user ON invite_tokens(user_id)`,
	}
	for _, stmt := range stmts {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
}

// migrateV7 adds server-side sessions and idempotency-key storage for the REST
// API. sessions stores opaque session rows keyed by token hash; idempotency_keys
// stores request hashes and their recorded responses so retries with the same
// key return the stored result instead of re-executing the side effect.
func migrateV7(ctx context.Context, tx *sql.Tx) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS sessions (
			id             TEXT PRIMARY KEY,
			user_id        TEXT NOT NULL,
			token_hash     TEXT NOT NULL UNIQUE,
			created_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			last_seen_at   TIMESTAMP,
			expires_at     TIMESTAMP NOT NULL,
			revoked_at     TIMESTAMP,
			user_agent_hash TEXT,
			ip_hash        TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)`,
		`CREATE TABLE IF NOT EXISTS idempotency_keys (
			id              TEXT PRIMARY KEY,
			key             TEXT NOT NULL,
			request_hash    TEXT NOT NULL,
			response_status INTEGER,
			response_body   BLOB,
			created_at      TEXT NOT NULL,
			expires_at      TEXT NOT NULL
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_idempotency_keys_key ON idempotency_keys(key)`,
	}
	for _, stmt := range stmts {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
}

// migrateV8 adds backup configuration/run tracking, restore tracking, and
// content-takedown records used by the admin and moderation surfaces.
func migrateV8(ctx context.Context, tx *sql.Tx) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS backup_config (
			id          INTEGER PRIMARY KEY,
			schedule    TEXT,
			destination TEXT,
			prefix      TEXT,
			updated_at  TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS backup_runs (
			id              TEXT PRIMARY KEY,
			started_at      TEXT NOT NULL,
			finished_at     TEXT,
			status          TEXT NOT NULL,
			error           TEXT,
			size_bytes      INTEGER,
			destination_key TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS backup_restores (
			id          TEXT PRIMARY KEY,
			started_at  TEXT NOT NULL,
			finished_at TEXT,
			status      TEXT NOT NULL,
			error       TEXT,
			source_key  TEXT,
			requested_by TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS takedowns (
			id         TEXT PRIMARY KEY,
			resource   TEXT NOT NULL,
			reason     TEXT NOT NULL,
			acted_by   TEXT NOT NULL,
			created_at TEXT NOT NULL
		)`,
	}
	for _, stmt := range stmts {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
}

// migrateV9 adds account-deletion requests and published ToS documents. It
// also adds an updated_at column to core content tables so callers can detect
// mutation and implement optimistic concurrency. The ALTERs are guarded against
// an existing column so re-running on a converged schema is a no-op (matching
// the migrateV6 pattern).
func migrateV9(ctx context.Context, tx *sql.Tx) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS pending_deletions (
			id           TEXT PRIMARY KEY,
			user_id      TEXT NOT NULL,
			requested_at TEXT NOT NULL,
			status       TEXT NOT NULL DEFAULT 'pending',
			approved_by  TEXT,
			approved_at  TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS tos_documents (
			id           TEXT PRIMARY KEY,
			version      TEXT NOT NULL,
			content      TEXT NOT NULL,
			published_at TEXT NOT NULL,
			published_by TEXT
		)`,
	}
	for _, stmt := range stmts {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	// Add updated_at to existing content tables if not already present.
	for _, table := range []string{"users", "public_keys", "proof_claims", "profile_links"} {
		var n int
		if err := tx.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM pragma_table_info(?) WHERE name = 'updated_at'`, table).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			continue
		}
		if _, err := tx.ExecContext(ctx, `ALTER TABLE `+table+` ADD COLUMN updated_at TEXT`); err != nil {
			return err
		}
	}
	return nil
}

// migrateV6 adds refresh-token expiry, rotation, and family markers (E2).
// family_id groups tokens minted from a single initial grant so reuse detection
// can revoke the whole family; it stays NULL for pre-migration (grandfathered)
// tokens until their first rotation seeds a family. rotated_at is set when a
// token is redeemed and rotated, so a later replay is detected as reuse. Both
// ALTERs are guarded so re-running on a converged schema is a no-op.
func migrateV6(ctx context.Context, tx *sql.Tx) error {
	for _, col := range []string{"family_id", "rotated_at"} {
		var n int
		if err := tx.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM pragma_table_info('auth_refresh_tokens') WHERE name = ?`, col).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			continue
		}
		switch col {
		case "family_id":
			if _, err := tx.ExecContext(ctx, `ALTER TABLE auth_refresh_tokens ADD COLUMN family_id TEXT`); err != nil {
				return err
			}
		case "rotated_at":
			if _, err := tx.ExecContext(ctx, `ALTER TABLE auth_refresh_tokens ADD COLUMN rotated_at TIMESTAMP`); err != nil {
				return err
			}
		}
	}
	return nil
}
