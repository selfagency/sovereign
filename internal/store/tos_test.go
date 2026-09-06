package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestToSDocumentRoundtrip verifies UpsertToSDocument persists and
// GetLatestToSDocument returns the most recent version.
func TestToSDocumentRoundtrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	// No doc yet.
	if _, err := s.GetLatestToSDocument(ctx); !errors.Is(err, ErrNotFound) {
		t.Fatalf("empty = %v, want ErrNotFound", err)
	}

	d1 := &ToSDocument{ID: "d1", Version: "v1", Content: "first", PublishedAt: time.Now().UTC().Add(-time.Hour), PublishedBy: "admin"}
	if err := s.UpsertToSDocument(ctx, d1); err != nil {
		t.Fatalf("UpsertToSDocument: %v", err)
	}
	d2 := &ToSDocument{ID: "d2", Version: "v2", Content: "second", PublishedAt: time.Now().UTC()}
	if err := s.UpsertToSDocument(ctx, d2); err != nil {
		t.Fatalf("UpsertToSDocument: %v", err)
	}

	got, err := s.GetLatestToSDocument(ctx)
	if err != nil {
		t.Fatalf("GetLatestToSDocument: %v", err)
	}
	if got.Version != "v2" || got.Content != "second" {
		t.Fatalf("latest = %+v, want v2/second", got)
	}
	if got.PublishedAt.IsZero() {
		t.Fatal("latest PublishedAt is zero")
	}
}

// TestListAllUsersPage verifies instance-wide paginated listing.
func TestListAllUsersPage(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if err := s.CreateTenant(ctx, &Tenant{ID: "t1", Handle: "t1.example.com", DIDMethod: "web"}); err != nil {
		t.Fatal(err)
	}
	for i, h := range []string{"a", "b", "c"} {
		if err := s.CreateUser(ctx, &User{ID: "u" + string(rune('0'+i)), TenantID: "t1", Handle: h, Email: h + "@x.test"}); err != nil {
			t.Fatal(err)
		}
	}
	users, total, err := s.ListAllUsersPage(ctx, 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	if total != 3 || len(users) != 2 {
		t.Fatalf("page1 = total %d len %d, want 3/2", total, len(users))
	}
	users2, _, err := s.ListAllUsersPage(ctx, 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(users2) != 1 {
		t.Fatalf("page2 len = %d, want 1", len(users2))
	}
}
