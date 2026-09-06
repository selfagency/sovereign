package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestListAuditAllPage(t *testing.T) {
	s := newAdminTestStore(t)
	ctx := context.Background()
	seedTenant(t, s, ctx, "t1", "t1", "did:web:t1")
	seedTenant(t, s, ctx, "t2", "t2", "did:web:t2")

	// Two tenants, three entries.
	entries := []*AuditEntry{
		{ID: "a1", TenantID: "t1", Actor: "admin1", Action: "takedown", Target: "res1", Detail: "d1", CreatedAt: time.Now().Add(-3 * time.Minute)},
		{ID: "a2", TenantID: "t2", Actor: "admin2", Action: "deletion.approve", Target: "res2", Detail: "d2", CreatedAt: time.Now().Add(-2 * time.Minute)},
		{ID: "a3", TenantID: "t1", Actor: "admin1", Action: "deletion.reject", Target: "res3", Detail: "d3", CreatedAt: time.Now().Add(-1 * time.Minute)},
	}
	for _, e := range entries {
		if err := s.AppendAudit(ctx, e); err != nil {
			t.Fatalf("AppendAudit: %v", err)
		}
	}

	// Instance-scoped: all three regardless of tenant.
	page, total, err := s.ListAuditAllPage(ctx, 10, 0)
	if err != nil {
		t.Fatalf("ListAuditAllPage: %v", err)
	}
	if total != 3 || len(page) != 3 {
		t.Fatalf("total/len = %d/%d, want 3/3", total, len(page))
	}
	// created_at is second-precision CURRENT_TIMESTAMP (AppendAudit does not
	// write it), so equal-second inserts have no guaranteed order; assert the
	// full set is present.
	got := map[string]bool{}
	for _, e := range page {
		got[e.ID] = true
	}
	for _, wantID := range []string{"a1", "a2", "a3"} {
		if !got[wantID] {
			t.Fatalf("audit page missing %q (got %v)", wantID, ids(page))
		}
	}

	// Pagination.
	page, total, err = s.ListAuditAllPage(ctx, 2, 0)
	if err != nil {
		t.Fatalf("ListAuditAllPage page1: %v", err)
	}
	if total != 3 || len(page) != 2 {
		t.Fatalf("page1 total/len = %d/%d, want 3/2", total, len(page))
	}
	page, _, err = s.ListAuditAllPage(ctx, 2, 2)
	if err != nil {
		t.Fatalf("ListAuditAllPage page2: %v", err)
	}
	if len(page) != 1 {
		t.Fatalf("page2 len = %d, want 1", len(page))
	}
}

func ids(entries []AuditEntry) []string {
	out := make([]string, len(entries))
	for i, e := range entries {
		out[i] = e.ID
	}
	return out
}

func TestPendingDeletionsLifecycle(t *testing.T) {
	s := newAdminTestStore(t)
	ctx := context.Background()
	seedTenant(t, s, ctx, "t1", "t1", "did:web:t1")
	seedUser(t, s, ctx, "u1", "t1", "alice")
	seedUser(t, s, ctx, "u2", "t1", "bob")

	p, err := s.CreatePendingDeletion(ctx, "u1")
	if err != nil {
		t.Fatalf("CreatePendingDeletion: %v", err)
	}
	_, err = s.CreatePendingDeletion(ctx, "u2")
	if err != nil {
		t.Fatalf("CreatePendingDeletion u2: %v", err)
	}

	// List returns both, newest first.
	page, total, err := s.ListPendingDeletions(ctx, 10, 0)
	if err != nil {
		t.Fatalf("ListPendingDeletions: %v", err)
	}
	if total != 2 || len(page) != 2 {
		t.Fatalf("total/len = %d/%d, want 2/2", total, len(page))
	}

	// ByID round-trips.
	got, err := s.PendingDeletionByID(ctx, p.ID)
	if err != nil {
		t.Fatalf("PendingDeletionByID: %v", err)
	}
	if got.ID != p.ID || got.UserID != "u1" || got.Status != "pending" {
		t.Fatalf("by id = %+v", got)
	}

	// Reject is a no-op leaving the account intact.
	if err := s.RejectPendingDeletion(ctx, p.ID, "admin1"); err != nil {
		t.Fatalf("RejectPendingDeletion: %v", err)
	}
	got, err = s.PendingDeletionByID(ctx, p.ID)
	if err != nil {
		t.Fatalf("PendingDeletionByID after reject: %v", err)
	}
	if got.Status != "rejected" || got.ApprovedBy == nil || *got.ApprovedBy != "admin1" {
		t.Fatalf("rejected = %+v", got)
	}
	if _, err := s.UserByID(ctx, "u1"); err != nil {
		t.Fatalf("reject must not delete the user: %v", err)
	}
	// Rejecting again is idempotent (no error, no change).
	if err := s.RejectPendingDeletion(ctx, p.ID, "admin2"); err != nil {
		t.Fatalf("re-reject: %v", err)
	}
}

func TestApprovePendingDeletionCascadesDelete(t *testing.T) {
	s := newAdminTestStore(t)
	ctx := context.Background()
	seedTenant(t, s, ctx, "t1", "t1", "did:web:t1")
	seedUser(t, s, ctx, "u1", "t1", "alice")

	p, err := s.CreatePendingDeletion(ctx, "u1")
	if err != nil {
		t.Fatalf("CreatePendingDeletion: %v", err)
	}

	if err := s.ApprovePendingDeletion(ctx, p.ID, "admin1"); err != nil {
		t.Fatalf("ApprovePendingDeletion: %v", err)
	}
	got, err := s.PendingDeletionByID(ctx, p.ID)
	if err != nil {
		t.Fatalf("PendingDeletionByID after approve: %v", err)
	}
	if got.Status != "approved" || got.ApprovedBy == nil || *got.ApprovedBy != "admin1" {
		t.Fatalf("approved = %+v", got)
	}
	// The user is cascade-deleted.
	if _, err := s.UserByID(ctx, "u1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("user still present after approve, want ErrNotFound (got %v)", err)
	}
	// Approving again is idempotent.
	if err := s.ApprovePendingDeletion(ctx, p.ID, "admin1"); err != nil {
		t.Fatalf("re-approve: %v", err)
	}
}

func TestPendingDeletionByIDNotFound(t *testing.T) {
	s := newAdminTestStore(t)
	ctx := context.Background()
	if _, err := s.PendingDeletionByID(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing = %v, want ErrNotFound", err)
	}
	if err := s.ApprovePendingDeletion(ctx, "missing", "admin"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("approve missing = %v, want ErrNotFound", err)
	}
	if err := s.RejectPendingDeletion(ctx, "missing", "admin"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("reject missing = %v, want ErrNotFound", err)
	}
}
