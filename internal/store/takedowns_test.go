package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestTakedownLifecycle verifies the full takedown lifecycle: create, list
// (newest first + total), get by id, and delete (lift). Takedowns are
// instance-scoped moderation records.
func TestTakedownLifecycle(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	now := time.Now().UTC()
	tds := []*Takedown{
		{ID: "td1", Resource: "did:web:alice.example", Reason: "spam", ActedBy: "admin1", CreatedAt: now.Add(-3 * time.Minute)},
		{ID: "td2", Resource: "did:web:bob.example", Reason: "abuse", ActedBy: "admin2", CreatedAt: now.Add(-2 * time.Minute)},
		{ID: "td3", Resource: "did:web:carol.example", Reason: "illegal", ActedBy: "admin1", CreatedAt: now.Add(-1 * time.Minute)},
	}
	for _, td := range tds {
		must(t, s.CreateTakedown(ctx, td))
	}

	// List returns all three, newest first, with the total.
	page, total, err := s.ListTakedowns(ctx, 10, 0)
	must(t, err)
	assertTakedownPage(t, page, total, 3, 3, []string{"td3", "td2", "td1"})

	// Pagination.
	page, total, err = s.ListTakedowns(ctx, 2, 0)
	must(t, err)
	assertTakedownPage(t, page, total, 3, 2, nil)
	page, _, err = s.ListTakedowns(ctx, 2, 2)
	must(t, err)
	if len(page) != 1 {
		t.Fatalf("page2 len = %d, want 1", len(page))
	}

	// Get by id round-trips the RFC3339 created_at.
	got, err := s.TakedownByID(ctx, "td2")
	must(t, err)
	if got.ID != "td2" || got.Resource != "did:web:bob.example" || got.Reason != "abuse" || got.ActedBy != "admin2" {
		t.Fatalf("by id = %+v", got)
	}
	if got.CreatedAt.IsZero() {
		t.Fatal("created_at not parsed from TEXT column")
	}

	// Delete (lift) removes the record.
	must(t, s.DeleteTakedown(ctx, "td1"))
	if _, err := s.TakedownByID(ctx, "td1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after delete = %v, want ErrNotFound", err)
	}
	page, total, _ = s.ListTakedowns(ctx, 10, 0)
	assertTakedownPage(t, page, total, 2, 2, nil)
}

// assertTakedownPage checks a takedown list page's total/len and, when
// wantIDs is non-nil, the exact id order.
func assertTakedownPage(t *testing.T, page []Takedown, total, wantTotal, wantLen int, wantIDs []string) {
	t.Helper()
	if total != wantTotal || len(page) != wantLen {
		t.Fatalf("total/len = %d/%d, want %d/%d", total, len(page), wantTotal, wantLen)
	}
	for i, id := range wantIDs {
		if page[i].ID != id {
			t.Fatalf("list order = %+v, want %v (newest first)", idsOf(page), wantIDs)
		}
	}
}

// TestTakedownNotFound verifies missing takedown lookups and deletes return
// ErrNotFound.
func TestTakedownNotFound(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if _, err := s.TakedownByID(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("by id missing = %v, want ErrNotFound", err)
	}
	if err := s.DeleteTakedown(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete missing = %v, want ErrNotFound", err)
	}
}

// TestListTakedownsEmpty verifies an empty table returns 0/0 and exercises the
// default-limit branch (limit <= 0 -> 100).
func TestListTakedownsEmpty(t *testing.T) {
	s := newTestStore(t)
	page, total, err := s.ListTakedowns(context.Background(), 0, 0)
	if err != nil {
		t.Fatalf("ListTakedowns empty: %v", err)
	}
	if len(page) != 0 || total != 0 {
		t.Fatalf("empty = %d/%d, want 0/0", len(page), total)
	}
}

// TestTakedownCanceledCtx drives each takedown method's SQL error branch via a
// canceled context. These branches (fmt.Errorf wraps) are otherwise
// unreachable with a healthy store.
func TestTakedownCanceledCtx(t *testing.T) {
	s := newTestStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := s.CreateTakedown(ctx, &Takedown{ID: "x", Resource: "r", Reason: "z", ActedBy: "a"}); err == nil {
		t.Fatal("CreateTakedown: want error from canceled ctx")
	}
	if _, _, err := s.ListTakedowns(ctx, 10, 0); err == nil {
		t.Fatal("ListTakedowns: want error from canceled ctx")
	}
	if _, err := s.TakedownByID(ctx, "x"); err == nil {
		t.Fatal("TakedownByID: want error from canceled ctx")
	}
	if err := s.DeleteTakedown(ctx, "x"); err == nil {
		t.Fatal("DeleteTakedown: want error from canceled ctx")
	}
}

func idsOf(tds []Takedown) []string {
	out := make([]string, len(tds))
	for i, td := range tds {
		out[i] = td.ID
	}
	return out
}
