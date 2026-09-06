package store

import (
	"context"
	"errors"
	"testing"
)

// TestIPFSPinCRUD verifies AddIPFSPin is idempotent and GetIPFSPin returns
// the record or ErrNotFound.
func TestIPFSPinCRUD(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	cid := "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"

	// Add then get.
	if err := s.AddIPFSPin(ctx, cid, "pinned"); err != nil {
		t.Fatalf("AddIPFSPin: %v", err)
	}
	p, err := s.GetIPFSPin(ctx, cid)
	if err != nil {
		t.Fatalf("GetIPFSPin: %v", err)
	}
	if p.CID != cid || p.Status != "pinned" {
		t.Fatalf("GetIPFSPin = %+v, want cid=%s status=pinned", p, cid)
	}

	// Idempotent re-add updates status.
	if err := s.AddIPFSPin(ctx, cid, "pinning"); err != nil {
		t.Fatalf("AddIPFSPin (update): %v", err)
	}
	p, _ = s.GetIPFSPin(ctx, cid)
	if p.Status != "pinning" {
		t.Fatalf("status after re-add = %q, want pinning", p.Status)
	}
}

// TestGetIPFSPinMissing verifies a missing CID returns ErrNotFound.
func TestGetIPFSPinMissing(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.GetIPFSPin(context.Background(), "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing = %v, want ErrNotFound", err)
	}
}

// TestListIPFSPins verifies listing returns all pins oldest first.
func TestListIPFSPins(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	for _, cid := range []string{"cid-a", "cid-b", "cid-c"} {
		if err := s.AddIPFSPin(ctx, cid, "pinned"); err != nil {
			t.Fatal(err)
		}
	}
	pins, err := s.ListIPFSPins(ctx)
	if err != nil {
		t.Fatalf("ListIPFSPins: %v", err)
	}
	if len(pins) != 3 {
		t.Fatalf("ListIPFSPins len = %d, want 3", len(pins))
	}
	// Ordered by created_at ascending: a, b, c.
	if pins[0].CID != "cid-a" || pins[1].CID != "cid-b" || pins[2].CID != "cid-c" {
		t.Fatalf("ListIPFSPins order = %+v", pins)
	}
}
