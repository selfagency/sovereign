package profile_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/selfagency/sovereign/internal/api/dto"
	"github.com/selfagency/sovereign/internal/api/middleware"
	v1profile "github.com/selfagency/sovereign/internal/api/v1/me/profile"
	"github.com/selfagency/sovereign/internal/storage"
	"github.com/selfagency/sovereign/internal/store"
)

func testStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func seedTenantUser(t *testing.T, s *store.Store, tenantID, handle string) *store.User {
	t.Helper()
	ctx := context.Background()
	if err := s.CreateTenant(ctx, &store.Tenant{ID: tenantID, Handle: handle + ".example.com", DIDMethod: "web"}); err != nil && !errors.Is(err, store.ErrDuplicateTenant) {
		t.Fatal(err)
	}
	u := &store.User{ID: "user-" + tenantID + "-" + handle, TenantID: tenantID, Handle: handle, DisplayName: handle}
	if err := s.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	return u
}

func principal(userID, tenantID string) *middleware.Principal {
	return &middleware.Principal{UserID: userID, TenantID: tenantID, Scopes: []string{"profile"}}
}

// newHandler wires a profile handler against the store and a temp FS backend.
// It returns the handler and the backend (so tests can assert on stored blobs).
func newHandler(t *testing.T, s *store.Store) (*v1profile.Handler, storage.Backend) {
	t.Helper()
	b := testBackend(t)
	return v1profile.New(s, b, slog.New(slog.NewTextHandler(io.Discard, nil))), b
}

func testBackend(t *testing.T) storage.Backend {
	t.Helper()
	return &storage.FS{Root: filepath.Join(t.TempDir(), "blobs")}
}

// withPrincipal returns a copy of the request carrying the principal in context.
func withPrincipal(r *http.Request, p *middleware.Principal) *http.Request {
	return r.WithContext(middleware.WithPrincipal(r.Context(), p))
}

// req builds an httptest request for method/path carrying the given principal.
func req(method, path string, p *middleware.Principal) *http.Request {
	r := httptest.NewRequest(method, path, http.NoBody)
	return withPrincipal(r, p)
}

// reqBody builds a request with a JSON body and content type.
func reqBody(method, path string, p *middleware.Principal, body string) *http.Request {
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	r := httptest.NewRequest(method, path, rd)
	r.Header.Set("Content-Type", "application/json")
	return withPrincipal(r, p)
}

func do(h http.HandlerFunc, r *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func decode[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode %T: %v (body %s)", v, err, rec.Body.String())
	}
	return v
}

// --- profile CRUD ---

func TestGetProfile(t *testing.T) {
	s := testStore(t)
	h, _ := newHandler(t, s)
	u := seedTenantUser(t, s, "tenant-a", "alice")
	ctx := context.Background()
	_ = s.UpsertProfilePage(ctx, &store.ProfilePage{
		ID: "p1", TenantID: u.TenantID, AccountID: u.ID,
		DisplayName: "Alice", Bio: "hi", Theme: "default", IsPublished: true,
	})

	rec := do(h.Get, req(http.MethodGet, "/me/profile", principal(u.ID, u.TenantID)))
	if rec.Code != http.StatusOK {
		t.Fatalf("get = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	p := decode[dto.ProfilePage](t, rec)
	if p.DisplayName != "Alice" || p.Bio != "hi" || !p.IsPublished || p.UserID != u.ID {
		t.Fatalf("profile = %+v", p)
	}
}

func TestGetProfileNotFound(t *testing.T) {
	s := testStore(t)
	h, _ := newHandler(t, s)
	u := seedTenantUser(t, s, "tenant-a", "alice")
	rec := do(h.Get, req(http.MethodGet, "/me/profile", principal(u.ID, u.TenantID)))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("get missing = %d, want 404", rec.Code)
	}
}

func TestGetProfileUnauthenticated(t *testing.T) {
	s := testStore(t)
	h, _ := newHandler(t, s)
	rec := do(h.Get, req(http.MethodGet, "/me/profile", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated = %d, want 401", rec.Code)
	}
}

func TestUpsertProfile(t *testing.T) {
	s := testStore(t)
	h, _ := newHandler(t, s)
	u := seedTenantUser(t, s, "tenant-a", "alice")
	p := principal(u.ID, u.TenantID)

	// First PUT creates.
	rec := do(h.Put, reqBody(http.MethodPut, "/me/profile", p, `{"display_name":"Alice","bio":"hello"}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("put create = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	created := decode[dto.ProfilePage](t, rec)
	if created.DisplayName != "Alice" || created.Bio != "hello" || created.UserID != u.ID {
		t.Fatalf("created profile = %+v", created)
	}
	if created.ID == "" || created.UpdatedAt.IsZero() {
		t.Fatalf("missing id/updated_at: %+v", created)
	}

	// Second PUT updates in place (same ID).
	rec = do(h.Put, reqBody(http.MethodPut, "/me/profile", p, `{"display_name":"Alice2","bio":"bye"}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("put update = %d (body %s)", rec.Code, rec.Body.String())
	}
	updated := decode[dto.ProfilePage](t, rec)
	if updated.ID != created.ID {
		t.Fatalf("update changed id %q -> %q", created.ID, updated.ID)
	}
	if updated.DisplayName != "Alice2" || updated.Bio != "bye" {
		t.Fatalf("updated = %+v", updated)
	}

	stored, err := s.GetProfilePage(context.Background(), u.TenantID)
	if err != nil || stored.DisplayName != "Alice2" {
		t.Fatalf("stored = %+v, %v", stored, err)
	}
}

func TestUpsertProfileInvalidBody(t *testing.T) {
	s := testStore(t)
	h, _ := newHandler(t, s)
	u := seedTenantUser(t, s, "tenant-a", "alice")
	p := principal(u.ID, u.TenantID)

	// Malformed JSON -> 400.
	rec := do(h.Put, reqBody(http.MethodPut, "/me/profile", p, `{"display_name":`))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad json = %d, want 400", rec.Code)
	}

	// Blank display name -> 422.
	rec = do(h.Put, reqBody(http.MethodPut, "/me/profile", p, `{"display_name":"  "}`))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("blank name = %d, want 422 (body %s)", rec.Code, rec.Body.String())
	}
}

// --- publish toggle ---

func TestPublishUnpublish(t *testing.T) {
	s := testStore(t)
	h, _ := newHandler(t, s)
	u := seedTenantUser(t, s, "tenant-a", "alice")
	ctx := context.Background()
	_ = s.UpsertProfilePage(ctx, &store.ProfilePage{
		ID: "p1", TenantID: u.TenantID, AccountID: u.ID, DisplayName: "Alice",
		Theme: "default", IsPublished: false,
	})
	p := principal(u.ID, u.TenantID)

	rec := do(h.Publish, req(http.MethodPost, "/me/profile:publish", p))
	if rec.Code != http.StatusOK {
		t.Fatalf("publish = %d (body %s)", rec.Code, rec.Body.String())
	}
	if !decode[dto.ProfilePage](t, rec).IsPublished {
		t.Fatal("publish did not set is_published")
	}
	if stored, _ := s.GetProfilePage(ctx, u.TenantID); !stored.IsPublished {
		t.Fatal("store not published")
	}

	rec = do(h.Unpublish, req(http.MethodPost, "/me/profile:unpublish", p))
	if rec.Code != http.StatusOK {
		t.Fatalf("unpublish = %d (body %s)", rec.Code, rec.Body.String())
	}
	if decode[dto.ProfilePage](t, rec).IsPublished {
		t.Fatal("unpublish did not clear is_published")
	}
	if stored, _ := s.GetProfilePage(ctx, u.TenantID); stored.IsPublished {
		t.Fatal("store still published")
	}
}

func TestPublishNoProfile(t *testing.T) {
	s := testStore(t)
	h, _ := newHandler(t, s)
	u := seedTenantUser(t, s, "tenant-a", "alice")
	rec := do(h.Publish, req(http.MethodPost, "/me/profile:publish", principal(u.ID, u.TenantID)))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("publish missing profile = %d, want 404", rec.Code)
	}
}

// --- delete ---

func TestDeleteProfile(t *testing.T) {
	s := testStore(t)
	h, _ := newHandler(t, s)
	u := seedTenantUser(t, s, "tenant-a", "alice")
	ctx := context.Background()
	_ = s.UpsertProfilePage(ctx, &store.ProfilePage{ID: "p1", TenantID: u.TenantID, AccountID: u.ID, DisplayName: "Alice", Theme: "default"})

	rec := do(h.Delete, req(http.MethodDelete, "/me/profile", principal(u.ID, u.TenantID)))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete = %d, want 204 (body %s)", rec.Code, rec.Body.String())
	}
	if _, err := s.GetProfilePage(ctx, u.TenantID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("after delete = %v, want ErrNotFound", err)
	}
}

func TestDeleteProfileNotFound(t *testing.T) {
	s := testStore(t)
	h, _ := newHandler(t, s)
	u := seedTenantUser(t, s, "tenant-a", "alice")
	rec := do(h.Delete, req(http.MethodDelete, "/me/profile", principal(u.ID, u.TenantID)))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("delete missing = %d, want 404", rec.Code)
	}
}

// --- links ---

func TestLinkLifecycle(t *testing.T) {
	s := testStore(t)
	h, _ := newHandler(t, s)
	u := seedTenantUser(t, s, "tenant-a", "alice")
	ctx := context.Background()
	_ = s.UpsertProfilePage(ctx, &store.ProfilePage{ID: "p1", TenantID: u.TenantID, AccountID: u.ID, DisplayName: "Alice", Theme: "default"})
	p := principal(u.ID, u.TenantID)

	rec := do(h.AddLink, reqBody(http.MethodPost, "/me/profile/links", p, `{"label":"Site","url":"https://example.com"}`))
	if rec.Code != http.StatusCreated {
		t.Fatalf("add link = %d (body %s)", rec.Code, rec.Body.String())
	}
	l1 := decode[dto.ProfileLink](t, rec)
	if l1.ID == "" || l1.Label != "Site" || l1.URL != "https://example.com" || l1.Position != 0 {
		t.Fatalf("link1 = %+v", l1)
	}

	rec = do(h.AddLink, reqBody(http.MethodPost, "/me/profile/links", p, `{"label":"Blog","url":"https://blog.example.com"}`))
	l2 := decode[dto.ProfileLink](t, rec)
	if l2.Position != 1 {
		t.Fatalf("link2 position = %d, want 1", l2.Position)
	}

	rec = do(h.ListLinks, req(http.MethodGet, "/me/profile/links", p))
	if rec.Code != http.StatusOK {
		t.Fatalf("list = %d", rec.Code)
	}
	links := decode[[]dto.ProfileLink](t, rec)
	if len(links) != 2 || links[0].ID != l1.ID || links[1].ID != l2.ID {
		t.Fatalf("links = %+v", links)
	}

	rec = do(h.UpdateLink, reqBody(http.MethodPatch, "/me/profile/links/"+l2.ID, p, `{"label":"Blog2","url":"https://blog2.example.com"}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("patch link = %d (body %s)", rec.Code, rec.Body.String())
	}
	upd := decode[dto.ProfileLink](t, rec)
	if upd.Label != "Blog2" || upd.URL != "https://blog2.example.com" || upd.ID != l2.ID {
		t.Fatalf("updated link = %+v", upd)
	}

	rec = do(h.ReorderLinks, reqBody(http.MethodPost, "/me/profile/links:reorder", p, `{"ids":["`+l2.ID+`","`+l1.ID+`"]}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("reorder = %d (body %s)", rec.Code, rec.Body.String())
	}
	links = decode[[]dto.ProfileLink](t, rec)
	if len(links) != 2 || links[0].ID != l2.ID || links[1].ID != l1.ID {
		t.Fatalf("reordered = %+v", links)
	}

	rec = do(h.DeleteLink, req(http.MethodDelete, "/me/profile/links/"+l1.ID, p))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete link = %d, want 204 (body %s)", rec.Code, rec.Body.String())
	}
	links = decode[[]dto.ProfileLink](t, do(h.ListLinks, req(http.MethodGet, "/me/profile/links", p)))
	if len(links) != 1 || links[0].ID != l2.ID {
		t.Fatalf("after delete = %+v", links)
	}
}

func TestLinkValidation(t *testing.T) {
	s := testStore(t)
	h, _ := newHandler(t, s)
	u := seedTenantUser(t, s, "tenant-a", "alice")
	_ = s.UpsertProfilePage(context.Background(), &store.ProfilePage{ID: "p1", TenantID: u.TenantID, AccountID: u.ID, DisplayName: "Alice", Theme: "default"})
	p := principal(u.ID, u.TenantID)

	rec := do(h.AddLink, reqBody(http.MethodPost, "/me/profile/links", p, `{"url":"https://example.com"}`))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("missing label = %d, want 422", rec.Code)
	}
	rec = do(h.AddLink, reqBody(http.MethodPost, "/me/profile/links", p, `{"label":"x","url":"not-a-url"}`))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("bad url = %d, want 422", rec.Code)
	}
}

func TestLinkNotFound(t *testing.T) {
	s := testStore(t)
	h, _ := newHandler(t, s)
	u := seedTenantUser(t, s, "tenant-a", "alice")
	_ = s.UpsertProfilePage(context.Background(), &store.ProfilePage{ID: "p1", TenantID: u.TenantID, AccountID: u.ID, DisplayName: "Alice", Theme: "default"})
	p := principal(u.ID, u.TenantID)

	rec := do(h.UpdateLink, reqBody(http.MethodPatch, "/me/profile/links/missing", p, `{"label":"x"}`))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("patch missing = %d, want 404", rec.Code)
	}
	rec = do(h.DeleteLink, req(http.MethodDelete, "/me/profile/links/missing", p))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("delete missing = %d, want 404", rec.Code)
	}
}

// --- avatar ---

func TestAvatarUpload(t *testing.T) {
	s := testStore(t)
	h, fs := newHandler(t, s)
	u := seedTenantUser(t, s, "tenant-a", "alice")
	ctx := context.Background()
	_ = s.UpsertProfilePage(ctx, &store.ProfilePage{ID: "p1", TenantID: u.TenantID, AccountID: u.ID, DisplayName: "Alice", Theme: "default"})

	blobBody, ct := multipartBody(t, "avatar", "me.png", "fake-png-bytes")
	r := httptest.NewRequest(http.MethodPut, "/me/profile/avatar", blobBody)
	r.Header.Set("Content-Type", ct)
	r = withPrincipal(r, principal(u.ID, u.TenantID))

	rec := do(h.UploadAvatar, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("avatar upload = %d (body %s)", rec.Code, rec.Body.String())
	}
	resp := decode[map[string]string](t, rec)
	if resp["avatar_url"] == "" {
		t.Fatal("empty avatar url")
	}

	stored, err := s.GetProfilePage(ctx, u.TenantID)
	if err != nil || stored.AvatarBlobKey == "" {
		t.Fatalf("stored avatar key missing: %+v, %v", stored, err)
	}
	// Verify the blob landed on the backend.
	rc, _, err := fs.Get(ctx, stored.AvatarBlobKey)
	if err != nil {
		t.Fatalf("blob get: %v", err)
	}
	defer rc.Close()
	data, _ := io.ReadAll(rc)
	if string(data) != "fake-png-bytes" {
		t.Fatalf("blob content = %q", string(data))
	}
}

func TestAvatarOversized(t *testing.T) {
	s := testStore(t)
	h, _ := newHandler(t, s)
	u := seedTenantUser(t, s, "tenant-a", "alice")
	_ = s.UpsertProfilePage(context.Background(), &store.ProfilePage{ID: "p1", TenantID: u.TenantID, AccountID: u.ID, DisplayName: "Alice", Theme: "default"})

	blobBody, ct := multipartBody(t, "avatar", "big.png", string(bytes.Repeat([]byte("x"), v1profile.MaxAvatarBytes+1024)))
	r := httptest.NewRequest(http.MethodPut, "/me/profile/avatar", blobBody)
	r.Header.Set("Content-Type", ct)
	r = withPrincipal(r, principal(u.ID, u.TenantID))

	rec := do(h.UploadAvatar, r)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized avatar = %d, want 413", rec.Code)
	}
}

func TestAvatarMissingFile(t *testing.T) {
	s := testStore(t)
	h, _ := newHandler(t, s)
	u := seedTenantUser(t, s, "tenant-a", "alice")
	_ = s.UpsertProfilePage(context.Background(), &store.ProfilePage{ID: "p1", TenantID: u.TenantID, AccountID: u.ID, DisplayName: "Alice", Theme: "default"})

	blobBody, ct := multipartBody(t, "not-avatar", "me.png", "x")
	r := httptest.NewRequest(http.MethodPut, "/me/profile/avatar", blobBody)
	r.Header.Set("Content-Type", ct)
	r = withPrincipal(r, principal(u.ID, u.TenantID))

	rec := do(h.UploadAvatar, r)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing avatar field = %d, want 400", rec.Code)
	}
}

func TestDeleteAvatar(t *testing.T) {
	s := testStore(t)
	h, fs := newHandler(t, s)
	u := seedTenantUser(t, s, "tenant-a", "alice")
	ctx := context.Background()
	_ = s.UpsertProfilePage(ctx, &store.ProfilePage{ID: "p1", TenantID: u.TenantID, AccountID: u.ID, DisplayName: "Alice", Theme: "default", AvatarBlobKey: "avatars/old.png"})
	_, _ = fs.Put(ctx, "avatars/old.png", strings.NewReader("data"), "image/png")

	rec := do(h.DeleteAvatar, req(http.MethodDelete, "/me/profile/avatar", principal(u.ID, u.TenantID)))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete avatar = %d, want 204 (body %s)", rec.Code, rec.Body.String())
	}
	if stored, _ := s.GetProfilePage(ctx, u.TenantID); stored.AvatarBlobKey != "" {
		t.Fatalf("avatar key not cleared: %+v", stored)
	}
}

// --- cross-tenant IDOR ---

func TestCrossTenantIDOR(t *testing.T) {
	s := testStore(t)
	h, _ := newHandler(t, s)
	alice := seedTenantUser(t, s, "tenant-a", "alice")
	bob := seedTenantUser(t, s, "tenant-b", "bob")
	ctx := context.Background()
	_ = s.UpsertProfilePage(ctx, &store.ProfilePage{ID: "pa", TenantID: alice.TenantID, AccountID: alice.ID, DisplayName: "Alice", Theme: "default"})
	_ = s.UpsertProfilePage(ctx, &store.ProfilePage{ID: "pb", TenantID: bob.TenantID, AccountID: bob.ID, DisplayName: "Bob", Theme: "default"})

	// Bob reads his own profile.
	rec := do(h.Get, req(http.MethodGet, "/me/profile", principal(bob.ID, bob.TenantID)))
	if rec.Code != http.StatusOK {
		t.Fatalf("bob get = %d", rec.Code)
	}
	if p := decode[dto.ProfilePage](t, rec); p.DisplayName != "Bob" {
		t.Fatalf("bob read alice: %+v", p)
	}

	// Bob's write targets only Bob's tenant, never Alice's.
	_ = do(h.Put, reqBody(http.MethodPut, "/me/profile", principal(bob.ID, bob.TenantID), `{"display_name":"Hax"}`))
	alicePage, _ := s.GetProfilePage(ctx, alice.TenantID)
	if alicePage == nil || alicePage.DisplayName != "Alice" {
		t.Fatalf("cross-tenant write mutated alice: %+v", alicePage)
	}

	// Bob's delete removes only Bob's page.
	_ = do(h.Delete, req(http.MethodDelete, "/me/profile", principal(bob.ID, bob.TenantID)))
	if alicePage, _ := s.GetProfilePage(ctx, alice.TenantID); alicePage == nil {
		t.Fatal("cross-tenant delete removed alice's profile")
	}
	if _, err := s.GetProfilePage(ctx, bob.TenantID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("bob profile should be deleted, got %v", err)
	}
}

// multipartBody builds a multipart form body with the named field/file,
// returning the buffer and its Content-Type.
func multipartBody(t *testing.T, field, filename, content string) (body *bytes.Buffer, contentType string) {
	t.Helper()
	body = new(bytes.Buffer)
	mw := multipart.NewWriter(body)
	fw, err := mw.CreateFormFile(field, filename)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fw.Write([]byte(content))
	_ = mw.Close()
	return body, mw.FormDataContentType()
}
