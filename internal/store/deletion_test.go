package store

import (
	"context"
	"errors"
	"testing"
)

// TestPendingDeletionByUser verifies the most-recent deletion request for a
// user is returned, and a user with none yields ErrNotFound.
func TestPendingDeletionByUser(t *testing.T) {
	s := newAdminTestStore(t)
	ctx := context.Background()
	seedTenant(t, s, ctx, "t1", "t1", "did:web:t1")
	seedUser(t, s, ctx, "u1", "t1", "alice")

	p, err := s.CreatePendingDeletion(ctx, "u1")
	if err != nil {
		t.Fatalf("CreatePendingDeletion: %v", err)
	}
	got, err := s.PendingDeletionByUser(ctx, "u1")
	if err != nil {
		t.Fatalf("PendingDeletionByUser: %v", err)
	}
	if got.ID != p.ID || got.UserID != "u1" || got.Status != "pending" {
		t.Fatalf("by user = %+v", got)
	}
	// A user with no request -> ErrNotFound.
	if _, err := s.PendingDeletionByUser(ctx, "nobody"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing user = %v, want ErrNotFound", err)
	}
}

// TestListPendingDeletionsDefaultLimit exercises the limit <= 0 default branch
// (limit -> 100) and the empty-table 0/0 case.
func TestListPendingDeletionsDefaultLimit(t *testing.T) {
	s := newAdminTestStore(t)
	ctx := context.Background()
	seedTenant(t, s, ctx, "t1", "t1", "did:web:t1")
	seedUser(t, s, ctx, "u1", "t1", "alice")
	if _, err := s.CreatePendingDeletion(ctx, "u1"); err != nil {
		t.Fatalf("CreatePendingDeletion: %v", err)
	}
	page, total, err := s.ListPendingDeletions(ctx, 0, 0)
	if err != nil {
		t.Fatalf("ListPendingDeletions default limit: %v", err)
	}
	if total != 1 || len(page) != 1 {
		t.Fatalf("got %d/%d, want 1/1", len(page), total)
	}

	// Empty table.
	empty := newAdminTestStore(t)
	epage, etotal, err := empty.ListPendingDeletions(ctx, 10, 0)
	if err != nil {
		t.Fatalf("ListPendingDeletions empty: %v", err)
	}
	if len(epage) != 0 || etotal != 0 {
		t.Fatalf("empty = %d/%d, want 0/0", len(epage), etotal)
	}
}

// TestPendingDeletionCanceledCtx drives the SQL error branches in
// ListPendingDeletions and CreatePendingDeletion via a canceled context.
func TestPendingDeletionCanceledCtx(t *testing.T) {
	s := newAdminTestStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, _, err := s.ListPendingDeletions(ctx, 10, 0); err == nil {
		t.Fatal("ListPendingDeletions: want error from canceled ctx")
	}
	if _, err := s.CreatePendingDeletion(ctx, "u1"); err == nil {
		t.Fatal("CreatePendingDeletion: want error from canceled ctx")
	}
}
