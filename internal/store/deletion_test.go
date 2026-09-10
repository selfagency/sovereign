package store

import (
	"context"
	"database/sql"
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

// TestScanPendingDeletionRows exercises the shared row scanner directly: the
// approved_by/approved_at branches (set and unset) and the missing
// requested_at error.
func TestScanPendingDeletionRows(t *testing.T) {
	// Approved row: all fields set.
	p := &PendingDeletion{}
	err := scanPendingDeletionRows(func(dst ...any) error {
		*dst[0].(*string) = "d1"
		*dst[1].(*string) = "u1"
		*dst[2].(*sql.NullString) = sql.NullString{String: "2026-09-10T12:00:00Z", Valid: true}
		*dst[3].(*string) = "approved"
		*dst[4].(*sql.NullString) = sql.NullString{String: "admin1", Valid: true}
		*dst[5].(*sql.NullString) = sql.NullString{String: "2026-09-10T12:05:00Z", Valid: true}
		return nil
	}, p)
	if err != nil {
		t.Fatalf("scan approved: %v", err)
	}
	if p.ID != "d1" || p.UserID != "u1" || p.Status != "approved" {
		t.Fatalf("approved scan = %+v", p)
	}
	if p.ApprovedBy == nil || *p.ApprovedBy != "admin1" {
		t.Fatalf("approved_by = %v, want admin1", p.ApprovedBy)
	}
	if p.ApprovedAt == nil || p.ApprovedAt.Year() != 2026 {
		t.Fatalf("approved_at = %v, want 2026", p.ApprovedAt)
	}
	if p.RequestedAt.Year() != 2026 {
		t.Fatalf("requested_at = %v, want 2026", p.RequestedAt)
	}

	// Pending row: approved fields unset.
	p = &PendingDeletion{}
	err = scanPendingDeletionRows(func(dst ...any) error {
		*dst[0].(*string) = "d2"
		*dst[1].(*string) = "u2"
		*dst[2].(*sql.NullString) = sql.NullString{String: "2026-09-10T13:00:00Z", Valid: true}
		*dst[3].(*string) = "pending"
		*dst[4].(*sql.NullString) = sql.NullString{}
		*dst[5].(*sql.NullString) = sql.NullString{}
		return nil
	}, p)
	if err != nil {
		t.Fatalf("scan pending: %v", err)
	}
	if p.ApprovedBy != nil || p.ApprovedAt != nil {
		t.Fatalf("pending scan set approved fields: %+v", p)
	}

	// Missing requested_at -> error.
	p = &PendingDeletion{}
	err = scanPendingDeletionRows(func(dst ...any) error {
		*dst[0].(*string) = "d3"
		*dst[1].(*string) = "u3"
		*dst[2].(*sql.NullString) = sql.NullString{}
		*dst[3].(*string) = "pending"
		*dst[4].(*sql.NullString) = sql.NullString{}
		*dst[5].(*sql.NullString) = sql.NullString{}
		return nil
	}, p)
	if err == nil {
		t.Fatal("missing requested_at accepted")
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
