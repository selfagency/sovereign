package users_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"

	"github.com/selfagency/sovereign/internal/api/dto"
	"github.com/selfagency/sovereign/internal/api/middleware"
	v1users "github.com/selfagency/sovereign/internal/api/v1/admin/users"
	"github.com/selfagency/sovereign/internal/mail"
	"github.com/selfagency/sovereign/internal/store"
)

type fakeSender struct {
	mu   sync.Mutex
	sent []mail.Message
}

func (f *fakeSender) Send(_ context.Context, m mail.Message) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, m)
	return nil
}

func testStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func newHandler(s *store.Store, sender mail.Sender) *v1users.Handler {
	return v1users.New(s, sender, "https://id.example.test", slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func adminPrincipal() *middleware.Principal {
	return &middleware.Principal{UserID: "admin", TenantID: "identity", Scopes: []string{"admin:users:read", "admin:users:write"}, IsAdmin: true}
}

func nonAdminPrincipal() *middleware.Principal {
	return &middleware.Principal{UserID: "user", TenantID: "tenant-a", Scopes: []string{"self"}, IsAdmin: false}
}

func req(method, path string, body []byte, p *middleware.Principal) *http.Request {
	var r *http.Request
	if body != nil {
		r = httptest.NewRequest(method, path, bytes.NewReader(body))
	} else {
		r = httptest.NewRequest(method, path, http.NoBody)
	}
	if p != nil {
		r = r.WithContext(middleware.WithPrincipal(r.Context(), p))
	}
	return r
}

func do(h http.HandlerFunc, r *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

// pathIDReq builds a request with the named {id} path value set, matching how
// the ServeMux populates it for sub-resource routes like /users/{id}/invites.
func pathIDReq(method, path, id string, body []byte, p *middleware.Principal) *http.Request {
	r := req(method, path, body, p)
	r.SetPathValue("id", id)
	return r
}

func seedUser(t *testing.T, s *store.Store, id, tenantID, handle, email string, isAdmin bool) {
	t.Helper()
	seedTenant(t, s, tenantID)
	if err := s.CreateUser(context.Background(), &store.User{ID: id, TenantID: tenantID, Handle: handle, Email: email, IsAdmin: isAdmin}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
}

// seedTenant ensures the named tenant exists so the users FK constraint holds.
func seedTenant(t *testing.T, s *store.Store, id string) {
	t.Helper()
	err := s.CreateTenant(context.Background(), &store.Tenant{ID: id, Handle: id + ".example.com", DIDMethod: "web", DID: "did:web:" + id + ".example.com"})
	if err != nil && err.Error() == "store: duplicate tenant" {
		return
	}
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
}

func TestCreateUser(t *testing.T) {
	s := testStore(t)
	sender := &fakeSender{}
	seedTenant(t, s, "identity")
	h := newHandler(s, sender)
	body, _ := json.Marshal(map[string]any{"handle": "alice", "email": "alice@example.com", "display_name": "Alice"})
	rec := do(h.Create, req(http.MethodPost, "/api/v1/admin/users", body, adminPrincipal()))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d, want 201 (body %s)", rec.Code, rec.Body.String())
	}
	var out struct {
		User dto.User `json:"user"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.User.Handle != "alice" || out.User.Email != "alice@example.com" {
		t.Fatalf("create = %+v", out)
	}
	// The invite email was sent.
	sender.mu.Lock()
	n := len(sender.sent)
	sender.mu.Unlock()
	if n != 1 {
		t.Fatalf("create sent %d emails, want 1", n)
	}
}

func TestCreateUserMissingFields(t *testing.T) {
	s := testStore(t)
	h := newHandler(s, &fakeSender{})
	for _, body := range []string{`{"handle":"","email":"a@b.c"}`, `{"handle":"x","email":""}`, `not-json`} {
		rec := do(h.Create, req(http.MethodPost, "/api/v1/admin/users", []byte(body), adminPrincipal()))
		if rec.Code != http.StatusBadRequest && rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("create %q = %d, want 4xx", body, rec.Code)
		}
	}
}

func TestCreateUserDuplicate(t *testing.T) {
	s := testStore(t)
	h := newHandler(s, &fakeSender{})
	seedTenant(t, s, "identity")
	seedUser(t, s, "u1", "identity", "alice", "alice@example.com", false)
	body, _ := json.Marshal(map[string]string{"handle": "alice", "email": "a@b.c"})
	rec := do(h.Create, req(http.MethodPost, "/api/v1/admin/users", body, adminPrincipal()))
	if rec.Code != http.StatusConflict {
		t.Fatalf("create dup = %d, want 409", rec.Code)
	}
}

func TestCreateUserNonAdminForbidden(t *testing.T) {
	s := testStore(t)
	h := newHandler(s, &fakeSender{})
	body, _ := json.Marshal(map[string]string{"handle": "x", "email": "x@y.z"})
	rec := do(h.Create, req(http.MethodPost, "/api/v1/admin/users", body, nonAdminPrincipal()))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("create non-admin = %d, want 403", rec.Code)
	}
}

func TestListUsers(t *testing.T) {
	s := testStore(t)
	h := newHandler(s, &fakeSender{})
	seedUser(t, s, "u1", "identity", "alice", "alice@example.com", false)
	seedUser(t, s, "u2", "identity", "bob", "bob@example.com", false)
	rec := do(h.List, req(http.MethodGet, "/api/v1/admin/users?limit=10&offset=0", nil, adminPrincipal()))
	if rec.Code != http.StatusOK {
		t.Fatalf("list = %d, want 200", rec.Code)
	}
	var out dto.List[dto.User]
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Total != 2 || len(out.Data) != 2 {
		t.Fatalf("list = %+v, want 2/2", out)
	}
}

func TestListUsersInvalidPagination(t *testing.T) {
	s := testStore(t)
	h := newHandler(s, &fakeSender{})
	for _, q := range []string{"limit=abc", "limit=-1", "offset=xyz"} {
		rec := do(h.List, req(http.MethodGet, "/api/v1/admin/users?"+q, nil, adminPrincipal()))
		if rec.Code != http.StatusBadRequest && rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("%s = %d, want 4xx", q, rec.Code)
		}
	}
}

func TestGetByID(t *testing.T) {
	s := testStore(t)
	h := newHandler(s, &fakeSender{})
	seedUser(t, s, "u1", "identity", "alice", "alice@example.com", false)
	rec := do(h.GetByID, req(http.MethodGet, "/api/v1/admin/users/u1", nil, adminPrincipal()))
	if rec.Code != http.StatusOK {
		t.Fatalf("get = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	var out dto.User
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.ID != "u1" || out.Handle != "alice" {
		t.Fatalf("get = %+v", out)
	}
}

func TestGetByIDNotFound(t *testing.T) {
	s := testStore(t)
	h := newHandler(s, &fakeSender{})
	rec := do(h.GetByID, req(http.MethodGet, "/api/v1/admin/users/nope", nil, adminPrincipal()))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("get missing = %d, want 404", rec.Code)
	}
}

func TestUpdateUser(t *testing.T) {
	s := testStore(t)
	h := newHandler(s, &fakeSender{})
	seedUser(t, s, "u1", "identity", "alice", "alice@example.com", false)
	body, _ := json.Marshal(map[string]any{"is_admin": true, "display_name": "Alice A"})
	rec := do(h.Update, req(http.MethodPatch, "/api/v1/admin/users/u1", body, adminPrincipal()))
	if rec.Code != http.StatusOK {
		t.Fatalf("update = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	u, err := s.UserByID(context.Background(), "u1")
	if err != nil {
		t.Fatal(err)
	}
	if !u.IsAdmin || u.DisplayName != "Alice A" {
		t.Fatalf("update not persisted: %+v", u)
	}
}

func TestUpdateUserNotFound(t *testing.T) {
	s := testStore(t)
	h := newHandler(s, &fakeSender{})
	body, _ := json.Marshal(map[string]any{"is_admin": true})
	rec := do(h.Update, req(http.MethodPatch, "/api/v1/admin/users/nope", body, adminPrincipal()))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("update missing = %d, want 404", rec.Code)
	}
}

func TestDeleteUser(t *testing.T) {
	s := testStore(t)
	h := newHandler(s, &fakeSender{})
	seedUser(t, s, "u1", "identity", "alice", "alice@example.com", false)
	rec := do(h.Delete, req(http.MethodDelete, "/api/v1/admin/users/u1", nil, adminPrincipal()))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete = %d, want 204", rec.Code)
	}
	if _, err := s.UserByID(context.Background(), "u1"); err == nil {
		t.Fatal("user still exists after delete")
	}
}

func TestDeleteUserNotFound(t *testing.T) {
	s := testStore(t)
	h := newHandler(s, &fakeSender{})
	rec := do(h.Delete, req(http.MethodDelete, "/api/v1/admin/users/nope", nil, adminPrincipal()))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("delete missing = %d, want 404", rec.Code)
	}
}

func TestCreateInvite(t *testing.T) {
	s := testStore(t)
	sender := &fakeSender{}
	h := newHandler(s, sender)
	seedUser(t, s, "u1", "identity", "alice", "alice@example.com", false)
	rec := do(h.CreateInvite, pathIDReq(http.MethodPost, "/api/v1/admin/users/u1/invites", "u1", nil, adminPrincipal()))
	if rec.Code != http.StatusCreated {
		t.Fatalf("invite = %d, want 201 (body %s)", rec.Code, rec.Body.String())
	}
	sender.mu.Lock()
	n := len(sender.sent)
	sender.mu.Unlock()
	if n != 1 {
		t.Fatalf("invite sent %d emails, want 1", n)
	}
}

func TestCreateInviteNotFound(t *testing.T) {
	s := testStore(t)
	h := newHandler(s, &fakeSender{})
	rec := do(h.CreateInvite, pathIDReq(http.MethodPost, "/api/v1/admin/users/nope/invites", "nope", nil, adminPrincipal()))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("invite missing = %d, want 404", rec.Code)
	}
}

func TestListCredentials(t *testing.T) {
	s := testStore(t)
	h := newHandler(s, &fakeSender{})
	seedUser(t, s, "u1", "identity", "alice", "alice@example.com", false)
	rec := do(h.ListCredentials, pathIDReq(http.MethodGet, "/api/v1/admin/users/u1/credentials", "u1", nil, adminPrincipal()))
	if rec.Code != http.StatusOK {
		t.Fatalf("credentials = %d, want 200", rec.Code)
	}
}

func TestListCredentialsNotFound(t *testing.T) {
	s := testStore(t)
	h := newHandler(s, &fakeSender{})
	rec := do(h.ListCredentials, pathIDReq(http.MethodGet, "/api/v1/admin/users/nope/credentials", "nope", nil, adminPrincipal()))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("credentials missing = %d, want 404", rec.Code)
	}
}

func TestRevokeSessions(t *testing.T) {
	s := testStore(t)
	h := newHandler(s, &fakeSender{})
	seedUser(t, s, "u1", "identity", "alice", "alice@example.com", false)
	rec := do(h.RevokeSessions, pathIDReq(http.MethodPost, "/api/v1/admin/users/u1/sessions:revoke", "u1", nil, adminPrincipal()))
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
}

func TestRevokeSessionsNotFound(t *testing.T) {
	s := testStore(t)
	h := newHandler(s, &fakeSender{})
	rec := do(h.RevokeSessions, pathIDReq(http.MethodPost, "/api/v1/admin/users/nope/sessions:revoke", "nope", nil, adminPrincipal()))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("revoke missing = %d, want 404", rec.Code)
	}
}

// TestUpdateUserEmailAndDisplayName verifies the email and display_name update
// branches (the existing TestUpdateUser only exercises is_admin).
func TestUpdateUserEmailAndDisplayName(t *testing.T) {
	s := testStore(t)
	h := newHandler(s, &fakeSender{})
	seedUser(t, s, "u1", "identity", "alice", "alice@example.com", false)
	body, _ := json.Marshal(map[string]string{"email": "new@example.com", "display_name": "Alice B"})
	rec := do(h.Update, req(http.MethodPatch, "/api/v1/admin/users/u1", body, adminPrincipal()))
	if rec.Code != http.StatusOK {
		t.Fatalf("update = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	u, err := s.UserByID(context.Background(), "u1")
	if err != nil {
		t.Fatal(err)
	}
	if u.Email != "new@example.com" || u.DisplayName != "Alice B" {
		t.Fatalf("update not persisted: %+v", u)
	}
}

// TestUpdateUserInvalidBody verifies a malformed update body is a 400.
func TestUpdateUserInvalidBody(t *testing.T) {
	s := testStore(t)
	h := newHandler(s, &fakeSender{})
	seedUser(t, s, "u1", "identity", "alice", "alice@example.com", false)
	rec := do(h.Update, req(http.MethodPatch, "/api/v1/admin/users/u1", []byte(`{`), adminPrincipal()))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad body = %d, want 400 (body %s)", rec.Code, rec.Body.String())
	}
}

// TestCreateUserWithTenantID verifies an explicit tenant_id is honored and the
// user is created into that tenant.
func TestCreateUserWithTenantID(t *testing.T) {
	s := testStore(t)
	h := newHandler(s, &fakeSender{})
	seedTenant(t, s, "tenant-a")
	body, _ := json.Marshal(map[string]any{"tenant_id": "tenant-a", "handle": "bob", "email": "bob@example.com"})
	rec := do(h.Create, req(http.MethodPost, "/api/v1/admin/users", body, adminPrincipal()))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d, want 201 (body %s)", rec.Code, rec.Body.String())
	}
	var out struct {
		User dto.User `json:"user"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.User.TenantID != "tenant-a" {
		t.Fatalf("tenant = %q, want tenant-a", out.User.TenantID)
	}
}

// TestCreateUserInviteFailure verifies a sender failure after user creation
// returns 500 (the user exists but the invite could not be sent).
func TestCreateUserInviteFailure(t *testing.T) {
	s := testStore(t)
	seedTenant(t, s, "identity")
	h := newHandler(s, &errSender{})
	body, _ := json.Marshal(map[string]string{"handle": "carol", "email": "carol@example.com"})
	rec := do(h.Create, req(http.MethodPost, "/api/v1/admin/users", body, adminPrincipal()))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("create invite fail = %d, want 500 (body %s)", rec.Code, rec.Body.String())
	}
}

// TestListCredentialsWithData verifies credential DTO rendering when a user has
// passkeys.
func TestListCredentialsWithData(t *testing.T) {
	s := testStore(t)
	h := newHandler(s, &fakeSender{})
	seedUser(t, s, "u1", "identity", "alice", "alice@example.com", false)
	if err := s.AddWebAuthnCredential(context.Background(), &store.WebAuthnCredential{
		ID: "c1", UserID: "u1", CredentialID: []byte("cred"), PublicKey: []byte("pk"), Data: []byte("d"),
	}); err != nil {
		t.Fatal(err)
	}
	rec := do(h.ListCredentials, pathIDReq(http.MethodGet, "/api/v1/admin/users/u1/credentials", "u1", nil, adminPrincipal()))
	if rec.Code != http.StatusOK {
		t.Fatalf("credentials = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	var out []dto.WebAuthnCredential
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0].ID != "c1" || out[0].CredentialID == "" {
		t.Fatalf("credentials = %+v", out)
	}
}

// TestUnauthenticated verifies every handler returns 401 without a principal.
func TestUnauthenticated(t *testing.T) {
	s := testStore(t)
	h := newHandler(s, &fakeSender{})
	for name, fn := range map[string]http.HandlerFunc{
		"list":   h.List,
		"create": h.Create,
		"get":    h.GetByID,
		"update": h.Update,
		"delete": h.Delete,
		"invite": h.CreateInvite,
		"creds":  h.ListCredentials,
		"revoke": h.RevokeSessions,
	} {
		rec := do(fn, req(http.MethodGet, "/api/v1/admin/users", nil, nil))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s unauthenticated = %d, want 401", name, rec.Code)
		}
	}
}

// errSender is a mail.Sender that always fails.
type errSender struct{}

func (errSender) Send(_ context.Context, _ mail.Message) error {
	return errors.New("smtp down")
}

// TestNewNilLogger verifies New defaults the logger when nil is passed.
func TestNewNilLogger(t *testing.T) {
	s := testStore(t)
	h := v1users.New(s, &fakeSender{}, "https://id.example.test", nil)
	if h == nil {
		t.Fatal("New with nil logger returned nil handler")
	}
}

// TestListInternalError verifies a store failure (canceled context) surfaces as
// a 500, exercising the writeStoreErr non-NotFound branch.
func TestListInternalError(t *testing.T) {
	s := testStore(t)
	h := newHandler(s, &fakeSender{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ctx = middleware.WithPrincipal(ctx, adminPrincipal())
	r := httptest.NewRequest(http.MethodGet, "/api/v1/admin/users", http.NoBody).WithContext(ctx)
	rec := do(h.List, r)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("list canceled = %d, want 500 (body %s)", rec.Code, rec.Body.String())
	}
}
