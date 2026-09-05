package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

// TestMigrationRunner verifies the versioned migration runner applies all
// migrations in order and records them in schema_version.
func TestMigrationRunner(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	// All migrations applied.
	v, err := s.currentVersion(ctx)
	if err != nil {
		t.Fatalf("currentVersion: %v", err)
	}
	if v != len(migrations) {
		t.Fatalf("schema version = %d, want %d", v, len(migrations))
	}

	// schema_version rows exist for each migration.
	var count int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_version`).Scan(&count); err != nil {
		t.Fatalf("count schema_version: %v", err)
	}
	if count != len(migrations) {
		t.Fatalf("schema_version rows = %d, want %d", count, len(migrations))
	}
}

// TestMigrationV7Tables verifies sessions and idempotency_keys are created with
// the expected columns and indexes.
func TestMigrationV7Tables(t *testing.T) {
	s := newTestStore(t)

	wantCols := map[string][]string{
		"sessions": {
			"id", "user_id", "token_hash", "created_at", "last_seen_at",
			"expires_at", "revoked_at", "user_agent_hash", "ip_hash",
		},
		"idempotency_keys": {
			"id", "key", "request_hash", "response_status",
			"response_body", "created_at", "expires_at",
		},
	}
	for table, cols := range wantCols {
		if !tableExists(t, s, table) {
			t.Fatalf("table %s not created by migrations", table)
		}
		assertColumns(t, s, table, cols)
	}

	// sessions: token_hash UNIQUE + index on user_id; idempotency_keys: key UNIQUE.
	if !columnIndexed(t, s, "sessions", "token_hash", true) {
		t.Fatal("sessions.token_hash not uniquely indexed")
	}
	if !columnIndexed(t, s, "sessions", "user_id", false) {
		t.Fatal("sessions.user_id not indexed")
	}
	if !columnIndexed(t, s, "idempotency_keys", "key", true) {
		t.Fatal("idempotency_keys.key not uniquely indexed")
	}
}

// TestMigrationV8Tables verifies backup_* and takedowns tables exist.
func TestMigrationV8Tables(t *testing.T) {
	s := newTestStore(t)

	wantCols := map[string][]string{
		"backup_config":   {"id", "schedule", "destination", "prefix", "updated_at"},
		"backup_runs":     {"id", "started_at", "finished_at", "status", "error", "size_bytes", "destination_key"},
		"backup_restores": {"id", "started_at", "finished_at", "status", "error", "source_key", "requested_by"},
		"takedowns":       {"id", "resource", "reason", "acted_by", "created_at"},
	}
	for table, cols := range wantCols {
		if !tableExists(t, s, table) {
			t.Fatalf("table %s not created by migrations", table)
		}
		assertColumns(t, s, table, cols)
	}
}

// TestMigrationV9Tables verifies pending_deletions and tos_documents exist and
// updated_at was added to the existing content tables.
func TestMigrationV9Tables(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	wantCols := map[string][]string{
		"pending_deletions": {"id", "user_id", "requested_at", "status", "approved_by", "approved_at"},
		"tos_documents":     {"id", "version", "content", "published_at", "published_by"},
	}
	for table, cols := range wantCols {
		if !tableExists(t, s, table) {
			t.Fatalf("table %s not created by migrations", table)
		}
		assertColumns(t, s, table, cols)
	}

	// pending_deletions.status defaults to 'pending'.
	var dflt string
	if err := s.db.QueryRowContext(ctx,
		`SELECT dflt_value FROM pragma_table_info('pending_deletions') WHERE name = 'status'`).Scan(&dflt); err != nil {
		t.Fatalf("read status default: %v", err)
	}
	if dflt != "'pending'" {
		t.Fatalf("status default = %q, want 'pending'", dflt)
	}

	// updated_at added to existing content tables.
	for _, table := range []string{"users", "public_keys", "proof_claims", "profile_links"} {
		assertColumns(t, s, table, []string{"updated_at"})
	}
}

func tableExists(t *testing.T, s *Store, name string) bool {
	t.Helper()
	var n int
	if err := s.db.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?`, name).Scan(&n); err != nil {
		t.Fatalf("check table %s: %v", name, err)
	}
	return n > 0
}

func assertColumns(t *testing.T, s *Store, table string, cols []string) {
	t.Helper()
	for _, col := range cols {
		var n int
		if err := s.db.QueryRowContext(context.Background(),
			`SELECT COUNT(*) FROM pragma_table_info(?) WHERE name = ?`, table, col).Scan(&n); err != nil {
			t.Fatalf("check column %s.%s: %v", table, col, err)
		}
		if n == 0 {
			t.Fatalf("column %s.%s missing after migrations", table, col)
		}
	}
}

func columnIndexed(t *testing.T, s *Store, table, col string, wantUnique bool) bool {
	t.Helper()
	rows, err := s.db.QueryContext(context.Background(), `PRAGMA index_list(`+table+`)`)
	if err != nil {
		t.Fatalf("index_list %s: %v", table, err)
	}
	defer func() { _ = rows.Close() }()
	type idx struct {
		name string
		uniq bool
	}
	var found []idx
	for rows.Next() {
		var seq int
		var name string
		var uniq int
		var origin, partial string
		if err := rows.Scan(&seq, &name, &uniq, &origin, &partial); err != nil {
			t.Fatalf("scan index_list: %v", err)
		}
		found = append(found, idx{name: name, uniq: uniq != 0})
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("index_list rows: %v", err)
	}
	for _, i := range found {
		if i.uniq != wantUnique {
			continue
		}
		var n int
		if err := s.db.QueryRowContext(context.Background(),
			`SELECT COUNT(*) FROM pragma_index_info(?) WHERE name = ?`, i.name, col).Scan(&n); err != nil {
			t.Fatalf("pragma_index_info %s: %v", i.name, err)
		}
		if n > 0 {
			return true
		}
	}
	return false
}

// TestMigrationInvalidatesPlaintextSecrets verifies migration v5 replaces
// pre-v5 plaintext client secrets with the sentinel, making them unverifiable.
func TestMigrationInvalidatesPlaintextSecrets(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "test.db")

	// Open a store (all migrations run, including v5), insert a plaintext
	// client secret directly, then remove the v5 (and any later) schema_version
	// rows so the reopen re-runs v5 against the plaintext row — simulating a
	// pre-v5 DB.
	s1, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s1.db.ExecContext(ctx,
		`INSERT INTO clients (id, secret, redirect_uris, scopes) VALUES (?, ?, ?, ?)`,
		"legacy", "plaintext-secret", "", ""); err != nil {
		t.Fatalf("insert legacy client: %v", err)
	}
	if _, err := s1.db.ExecContext(ctx, `DELETE FROM schema_version WHERE version >= 5`); err != nil {
		t.Fatalf("remove v5+ markers: %v", err)
	}
	if err := s1.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopen: migration v5 runs and invalidates the plaintext secret.
	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s2.Close() }()

	c, err := s2.ClientByID(ctx, "legacy")
	if err != nil {
		t.Fatal(err)
	}
	if c.Secret != invalidatedSecret {
		t.Fatalf("secret = %q, want sentinel %q", c.Secret, invalidatedSecret)
	}
	if VerifyClientSecret("plaintext-secret", c.Secret) {
		t.Fatal("invalidated plaintext secret still verifies")
	}
}

// TestMigrationIdempotent verifies reopening an existing DB does not re-run
// migrations or lose data.
func TestMigrationIdempotent(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "test.db")

	s1, err := Open(path)
	if err != nil {
		t.Fatalf("Open 1: %v", err)
	}
	if err := s1.CreateTenant(ctx, &Tenant{ID: "t1", Handle: "alice.example.com", DIDMethod: "web"}); err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	_ = s1.Close()

	// Reopen: migrations must not re-run, data preserved.
	s2, err := Open(path)
	if err != nil {
		t.Fatalf("Open 2: %v", err)
	}
	defer func() { _ = s2.Close() }()

	got, err := s2.GetTenantByHandle(ctx, "alice.example.com")
	if err != nil || got.ID != "t1" {
		t.Fatalf("tenant after reopen = %+v, %v", got, err)
	}
}

// TestAccountsTable verifies the accounts table exists and enforces the
// tenant FK (C2). Inserting an account with a dangling tenant_id must fail.
func TestAccountsTable(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	// Insert a tenant, then an account referencing it.
	if err := s.CreateTenant(ctx, &Tenant{ID: "t1", Handle: "alice.example.com", DIDMethod: "web"}); err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO accounts (id, tenant_id, did, webid) VALUES (?, ?, ?, ?)`,
		"a1", "t1", "did:web:alice.example.com", "https://alice.example.com/profile#me"); err != nil {
		t.Fatalf("insert account: %v", err)
	}

	// Dangling tenant_id must be rejected by the FK.
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO accounts (id, tenant_id, did) VALUES (?, ?, ?)`,
		"a2", "no-such-tenant", "did:web:x"); err == nil {
		t.Fatal("expected FK violation for dangling tenant_id")
	}
}

// TestAccountCRUD verifies CreateAccount and AccountByWebID.
func TestAccountCRUD(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	if err := s.CreateTenant(ctx, &Tenant{ID: "t1", Handle: "alice.example.com", DIDMethod: "web"}); err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}

	if err := s.CreateAccount(ctx, &Account{
		ID: "a1", TenantID: "t1", DID: "did:web:alice.example.com",
		WebID: "https://alice.example.com/profile/card#me",
	}); err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}

	// Lookup by WebID.
	got, err := s.AccountByWebID(ctx, "https://alice.example.com/profile/card#me")
	if err != nil {
		t.Fatalf("AccountByWebID: %v", err)
	}
	if got.TenantID != "t1" || got.DID != "did:web:alice.example.com" {
		t.Fatalf("account = %+v", got)
	}

	// Duplicate (tenant_id, did) rejected.
	if err := s.CreateAccount(ctx, &Account{ID: "a2", TenantID: "t1", DID: "did:web:alice.example.com"}); !errors.Is(err, ErrDuplicateAccount) {
		t.Fatalf("duplicate = %v, want ErrDuplicateAccount", err)
	}

	// Unknown WebID -> ErrNotFound.
	if _, err := s.AccountByWebID(ctx, "https://nobody.example.com/profile#me"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown webid = %v, want ErrNotFound", err)
	}
}

// TestForeignKeysEnforcedAcrossPool verifies PRAGMA foreign_keys is applied
// via the DSN so it holds on every pooled connection (C3).
func TestForeignKeysEnforcedAcrossPool(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	// profile_links.profile_page_id references profile_pages(id). Inserting a
	// link with a dangling page id must fail if foreign_keys is on.
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO profile_links (id, profile_page_id, position, kind, label, url) VALUES (?, ?, ?, ?, ?, ?)`,
		"l1", "no-such-page", 0, "link", "x", "https://x"); err == nil {
		t.Fatal("expected FK violation for dangling profile_page_id")
	}
}
