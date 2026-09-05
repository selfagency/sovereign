package keys_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"golang.org/x/crypto/ssh"

	"github.com/selfagency/sovereign/internal/api/dto"
	"github.com/selfagency/sovereign/internal/api/middleware"
	v1keys "github.com/selfagency/sovereign/internal/api/v1/me/keys"
	"github.com/selfagency/sovereign/internal/store"
)

// testSSHKey is a valid ed25519 public key (matches internal/keys fixture).
const testSSHKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl test@example.com"

// testSSHKey2 is a second distinct ed25519 public key for create/list tests.
const testSSHKey2 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICp8mG0v3h9mKq7sUc4dF5gH6jK1lM2nO3pQ4rS5tU7 test2@example.com"

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

func newHandler(s *store.Store) *v1keys.Handler {
	return v1keys.New(s, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func principal(userID, tenantID string) *middleware.Principal {
	return &middleware.Principal{UserID: userID, TenantID: tenantID, Scopes: []string{"self"}}
}

func req(method, path string, p *middleware.Principal, body string) *http.Request {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
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

func decode[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode %T: %v (body %s)", v, err, rec.Body.String())
	}
	return v
}

func seedKey(t *testing.T, s *store.Store, u *store.User, id string) *store.PublicKey {
	t.Helper()
	k := &store.PublicKey{
		ID: id, TenantID: u.TenantID, AccountID: u.ID, KeyType: "ssh",
		Label: "laptop", Fingerprint: "sha256:fp-" + id, KeyMaterial: testSSHKey, Algorithm: "ssh-ed25519",
	}
	if err := s.CreatePublicKey(context.Background(), k); err != nil {
		t.Fatal(err)
	}
	return k
}

func TestListKeys(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	u := seedTenantUser(t, s, "tenant-a", "alice")
	seedKey(t, s, u, "key-1")
	seedKey(t, s, u, "key-2")

	rec := do(h.List, req(http.MethodGet, "/api/v1/me/keys", principal(u.ID, u.TenantID), ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("list = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	got := decode[[]dto.PublicKey](t, rec)
	if len(got) != 2 {
		t.Fatalf("list len = %d, want 2", len(got))
	}
	if got[0].UserID != u.ID || got[0].Type != "ssh" || got[0].Fingerprint == "" {
		t.Fatalf("key dto = %+v", got[0])
	}
}

func TestListKeysFilterByType(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	u := seedTenantUser(t, s, "tenant-a", "alice")
	seedKey(t, s, u, "key-1")

	// No PGP keys exist; ?type=pgp must return an empty array.
	rec := do(h.List, req(http.MethodGet, "/api/v1/me/keys?type=pgp", principal(u.ID, u.TenantID), ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("list pgp = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	got := decode[[]dto.PublicKey](t, rec)
	if len(got) != 0 {
		t.Fatalf("pgp list = %d, want 0", len(got))
	}

	// Invalid type filter.
	bad := do(h.List, req(http.MethodGet, "/api/v1/me/keys?type=gpg", principal(u.ID, u.TenantID), ""))
	if bad.Code != http.StatusUnprocessableEntity && bad.Code != http.StatusBadRequest {
		t.Fatalf("invalid type filter = %d, want 4xx", bad.Code)
	}
}

func TestListKeysEmpty(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	u := seedTenantUser(t, s, "tenant-a", "alice")
	rec := do(h.List, req(http.MethodGet, "/api/v1/me/keys", principal(u.ID, u.TenantID), ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("list = %d, want 200", rec.Code)
	}
	got := decode[[]dto.PublicKey](t, rec)
	if len(got) != 0 {
		t.Fatalf("fresh user list should be empty, got %d", len(got))
	}
}

func TestGetKey(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	u := seedTenantUser(t, s, "tenant-a", "alice")
	seedKey(t, s, u, "key-1")

	rec := do(h.Get, req(http.MethodGet, "/api/v1/me/keys/key-1", principal(u.ID, u.TenantID), ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("get = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	got := decode[dto.PublicKey](t, rec)
	if got.ID != "key-1" || got.UserID != u.ID || got.Fingerprint == "" {
		t.Fatalf("key = %+v", got)
	}
}

func TestGetKeyNotFound(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	u := seedTenantUser(t, s, "tenant-a", "alice")
	rec := do(h.Get, req(http.MethodGet, "/api/v1/me/keys/missing", principal(u.ID, u.TenantID), ""))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("get missing = %d, want 404 (body %s)", rec.Code, rec.Body.String())
	}
}

func TestCreateKeySSH(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	u := seedTenantUser(t, s, "tenant-a", "alice")
	body := `{"type":"ssh","public_key":"` + testSSHKey + `","label":"laptop"}`

	rec := do(h.Create, req(http.MethodPost, "/api/v1/me/keys", principal(u.ID, u.TenantID), body))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d, want 201 (body %s)", rec.Code, rec.Body.String())
	}
	got := decode[dto.PublicKey](t, rec)
	if got.Type != "ssh" || got.Fingerprint == "" || got.PublicKey == "" {
		t.Fatalf("created key = %+v", got)
	}
	// Persisted and tenant-scoped.
	persisted, err := s.GetPublicKey(context.Background(), u.TenantID, got.ID)
	if err != nil || persisted.AccountID != u.ID {
		t.Fatalf("persisted: err=%v key=%+v", err, persisted)
	}
}

func TestCreateKeyPGP(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	u := seedTenantUser(t, s, "tenant-a", "alice")
	pgp := loadFixture(t, "../../../../keys/testdata/pub.asc")
	body := `{"type":"pgp","public_key":` + strconvQuote(pgp) + `}`

	rec := do(h.Create, req(http.MethodPost, "/api/v1/me/keys", principal(u.ID, u.TenantID), body))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create pgp = %d, want 201 (body %s)", rec.Code, rec.Body.String())
	}
	got := decode[dto.PublicKey](t, rec)
	if got.Type != "pgp" || got.Fingerprint == "" {
		t.Fatalf("created pgp key = %+v", got)
	}
}

func TestCreateKeyRejectsPrivateMaterial(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	u := seedTenantUser(t, s, "tenant-a", "alice")

	priv := privatePGPKey(t)
	cases := []struct {
		name string
		body string
	}{
		{"pgp-private", `{"type":"pgp","public_key":` + strconvQuote(priv) + `}`},
		{"unknown-type", `{"type":"gpg","public_key":"whatever"}`},
		{"malformed-ssh", `{"type":"ssh","public_key":"not a key"}`},
		{"ssh-private", `{"type":"ssh","public_key":` + strconvQuote(privateSSHKey(t)) + `}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := do(h.Create, req(http.MethodPost, "/api/v1/me/keys", principal(u.ID, u.TenantID), tc.body))
			if rec.Code != http.StatusBadRequest && rec.Code != http.StatusUnprocessableEntity {
				t.Fatalf("%s = %d, want 4xx (body %s)", tc.name, rec.Code, rec.Body.String())
			}
		})
	}
}

func TestCreateKeyDuplicateFingerprint(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	u := seedTenantUser(t, s, "tenant-a", "alice")
	body := `{"type":"ssh","public_key":"` + testSSHKey + `"}`
	if rec := do(h.Create, req(http.MethodPost, "/api/v1/me/keys", principal(u.ID, u.TenantID), body)); rec.Code != http.StatusCreated {
		t.Fatalf("first create = %d (body %s)", rec.Code, rec.Body.String())
	}
	rec := do(h.Create, req(http.MethodPost, "/api/v1/me/keys", principal(u.ID, u.TenantID), body))
	if rec.Code != http.StatusConflict {
		t.Fatalf("duplicate create = %d, want 409 (body %s)", rec.Code, rec.Body.String())
	}
}

func TestCreateKeyValidationMissingFields(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	u := seedTenantUser(t, s, "tenant-a", "alice")
	cases := []string{
		`{}`,
		`{"type":"ssh"}`,
		`{"type":"","public_key":"` + testSSHKey + `"}`,
	}
	for i, body := range cases {
		rec := do(h.Create, req(http.MethodPost, "/api/v1/me/keys", principal(u.ID, u.TenantID), body))
		if rec.Code != http.StatusBadRequest && rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("case %d = %d, want 4xx (body %s)", i, rec.Code, rec.Body.String())
		}
	}
}

func TestDeleteKey(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	u := seedTenantUser(t, s, "tenant-a", "alice")
	seedKey(t, s, u, "key-1")

	rec := do(h.Delete, req(http.MethodDelete, "/api/v1/me/keys/key-1", principal(u.ID, u.TenantID), ""))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete = %d, want 204 (body %s)", rec.Code, rec.Body.String())
	}
	if _, err := s.GetPublicKey(context.Background(), u.TenantID, "key-1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("key not deleted: %v", err)
	}
}

func TestDeleteKeyNotFound(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	u := seedTenantUser(t, s, "tenant-a", "alice")
	rec := do(h.Delete, req(http.MethodDelete, "/api/v1/me/keys/missing", principal(u.ID, u.TenantID), ""))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("delete missing = %d, want 404 (body %s)", rec.Code, rec.Body.String())
	}
}

func TestRevokeKey(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	u := seedTenantUser(t, s, "tenant-a", "alice")
	seedKey(t, s, u, "key-1")

	r := req(http.MethodPost, "/api/v1/me/keys/key-1/revoke", principal(u.ID, u.TenantID), "")
	r.SetPathValue("id", "key-1")
	rec := do(h.Revoke, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	got := decode[dto.PublicKey](t, rec)
	if got.RevokedAt == nil {
		t.Fatalf("key not revoked: %+v", got)
	}
}

func TestRevokeKeyNotFound(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	u := seedTenantUser(t, s, "tenant-a", "alice")
	r := req(http.MethodPost, "/api/v1/me/keys/missing/revoke", principal(u.ID, u.TenantID), "")
	r.SetPathValue("id", "missing")
	rec := do(h.Revoke, r)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("revoke missing = %d, want 404 (body %s)", rec.Code, rec.Body.String())
	}
}

func TestUnauthenticated(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	for name, fn := range map[string]http.HandlerFunc{
		"list":   h.List,
		"get":    h.Get,
		"create": h.Create,
		"delete": h.Delete,
		"revoke": h.Revoke,
	} {
		t.Run(name, func(t *testing.T) {
			rec := do(fn, req(http.MethodGet, "/api/v1/me/keys", nil, ""))
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("%s unauthenticated = %d, want 401", name, rec.Code)
			}
		})
	}
}

func TestCrossTenantIsolation(t *testing.T) {
	s := testStore(t)
	h := newHandler(s)
	a := seedTenantUser(t, s, "tenant-a", "alice")
	b := seedTenantUser(t, s, "tenant-b", "bob")
	// B owns key-bob-1.
	if err := s.CreatePublicKey(context.Background(), &store.PublicKey{
		ID: "key-bob-1", TenantID: b.TenantID, AccountID: b.ID, KeyType: "ssh",
		Fingerprint: "sha256:fp-bob", KeyMaterial: testSSHKey2, Algorithm: "ssh-ed25519",
	}); err != nil {
		t.Fatal(err)
	}

	// A cannot get B's key by ID -> 404 (not 403, so existence is not leaked).
	rec := do(h.Get, req(http.MethodGet, "/api/v1/me/keys/key-bob-1", principal(a.ID, a.TenantID), ""))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant get = %d, want 404 (body %s)", rec.Code, rec.Body.String())
	}
	// A cannot delete or revoke B's key -> 404.
	del := do(h.Delete, req(http.MethodDelete, "/api/v1/me/keys/key-bob-1", principal(a.ID, a.TenantID), ""))
	if del.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant delete = %d, want 404", del.Code)
	}
	revR := req(http.MethodPost, "/api/v1/me/keys/key-bob-1/revoke", principal(a.ID, a.TenantID), "")
	revR.SetPathValue("id", "key-bob-1")
	rev := do(h.Revoke, revR)
	if rev.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant revoke = %d, want 404", rev.Code)
	}
	// A's list sees only A's keys.
	list := do(h.List, req(http.MethodGet, "/api/v1/me/keys", principal(a.ID, a.TenantID), ""))
	got := decode[[]dto.PublicKey](t, list)
	if len(got) != 0 {
		t.Fatalf("A list leaked B's keys: %+v", got)
	}
	// B's key is still intact and unrevoked.
	persisted, err := s.GetPublicKey(context.Background(), b.TenantID, "key-bob-1")
	if err != nil || persisted.RevokedAt != nil {
		t.Fatalf("B's key affected by A: err=%v key=%+v", err, persisted)
	}
}

// --- fixtures ---

// loadFixture reads a test fixture file (relative to this package).
func loadFixture(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return string(data)
}

// strconvQuote produces a JSON string literal from raw text.
func strconvQuote(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// privatePGPKey generates a real private key block at runtime (never commits
// key material) and returns its armored form.
func privatePGPKey(t *testing.T) string {
	t.Helper()
	entity, err := openpgp.NewEntity("Test User", "", "test@example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	var buf strings.Builder
	w, err := armor.Encode(&buf, "PGP PRIVATE KEY BLOCK", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := entity.SerializePrivate(w, nil); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

// privateSSHKey generates a fresh RSA private key at runtime and returns its
// OpenSSH serialized form. Generated (not literal) so the private key never
// appears as committed material (pre-commit detect-private-key).
func privateSSHKey(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(key, "test")
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(block))
}
