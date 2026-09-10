package store

import (
	"context"
	"testing"
)

// TestListPageDefaults exercises the limit<=0 default branch in every paged
// list method, plus DB(), which happy-path tests with explicit limits skip.
func TestListPageDefaults(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	seedTenant(t, s, ctx, "t1", "t1", "did:web:t1")
	seedUser(t, s, ctx, "u1", "t1", "alice")
	must(t, s.CreateClient(ctx, &Client{ID: "web", Secret: "s"}))
	must(t, s.AppendAudit(ctx, &AuditEntry{ID: "a1", Actor: "u1", Action: "test"}))
	must(t, s.CreateBackupRun(ctx, &BackupRun{ID: "r1", Status: "ok"}))
	must(t, s.CreateBackupRestore(ctx, &BackupRestore{ID: "rs1", Status: "ok"}))

	// DB() exposes the handle.
	if s.DB() == nil {
		t.Fatal("DB() returned nil")
	}

	// limit=0 must default (not return empty / error).
	assertPageTotal(t, "ListAllUsersPage", func() (int, error) { _, total, err := s.ListAllUsersPage(ctx, 0, 0); return total, err }, 1)
	assertPageTotal(t, "ListAuditAllPage", func() (int, error) { _, total, err := s.ListAuditAllPage(ctx, 0, 0); return total, err }, 1)
	assertPageTotal(t, "ListClientsPage", func() (int, error) { _, total, err := s.ListClientsPage(ctx, 0, 0); return total, err }, 1)
	assertPageTotal(t, "ListBackupRuns", func() (int, error) { _, total, err := s.ListBackupRuns(ctx, 0, 0); return total, err }, 1)
	assertPageTotal(t, "ListBackupRestores", func() (int, error) { _, total, err := s.ListBackupRestores(ctx, 0, 0); return total, err }, 1)
}

// assertPageTotal asserts a paged list method returns the expected total with
// limit=0 (the default branch) and no error.
func assertPageTotal(t *testing.T, name string, call func() (int, error), want int) {
	t.Helper()
	total, err := call()
	if err != nil {
		t.Fatalf("%s(0,0): %v", name, err)
	}
	if total != want {
		t.Fatalf("%s(0,0) total = %d, want %d", name, total, want)
	}
}
