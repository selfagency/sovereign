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
	if err := s.CreateClient(ctx, &Client{ID: "web", Secret: "s"}); err != nil {
		t.Fatal(err)
	}
	if err := s.AppendAudit(ctx, &AuditEntry{ID: "a1", Actor: "u1", Action: "test"}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateBackupRun(ctx, &BackupRun{ID: "r1", Status: "ok"}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateBackupRestore(ctx, &BackupRestore{ID: "rs1", Status: "ok"}); err != nil {
		t.Fatal(err)
	}

	// DB() exposes the handle.
	if s.DB() == nil {
		t.Fatal("DB() returned nil")
	}

	// limit=0 must default (not return empty / error).
	if _, total, err := s.ListAllUsersPage(ctx, 0, 0); err != nil || total != 1 {
		t.Fatalf("ListAllUsersPage(0,0) = total %d, err %v", total, err)
	}
	if _, total, err := s.ListAuditAllPage(ctx, 0, 0); err != nil || total != 1 {
		t.Fatalf("ListAuditAllPage(0,0) = total %d, err %v", total, err)
	}
	if _, total, err := s.ListClientsPage(ctx, 0, 0); err != nil || total != 1 {
		t.Fatalf("ListClientsPage(0,0) = total %d, err %v", total, err)
	}
	if runs, total, err := s.ListBackupRuns(ctx, 0, 0); err != nil || len(runs) != 1 || total != 1 {
		t.Fatalf("ListBackupRuns(0,0) = %d runs/%d total, err %v", len(runs), total, err)
	}
	if restores, total, err := s.ListBackupRestores(ctx, 0, 0); err != nil || len(restores) != 1 || total != 1 {
		t.Fatalf("ListBackupRestores(0,0) = %d restores/%d total, err %v", len(restores), total, err)
	}
}
