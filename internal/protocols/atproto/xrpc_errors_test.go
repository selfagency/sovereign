package atproto

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bluesky-social/indigo/atproto/atcrypto"

	"github.com/selfagency/sovereign/internal/auth"
	"github.com/selfagency/sovereign/internal/storage"
	"github.com/selfagency/sovereign/internal/store"
	"github.com/selfagency/sovereign/internal/tenant"
)

// wiredServer builds an XRPCServer with all deps wired and a valid tenant
// token, for exercising handler error branches.
func wiredServer(t *testing.T) (x *XRPCServer, tok string) {
	t.Helper()
	s := newTestStore(t)
	ctx := context.Background()
	if err := s.CreateTenant(ctx, &store.Tenant{ID: "t1", Handle: "alice.example.com", DIDMethod: "web", DID: "did:web:alice.example.com"}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateAccount(ctx, &store.Account{ID: "a1", TenantID: "t1", DID: "did:web:alice.example.com", WebID: "https://alice.example.com/profile/card#me"}); err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(randReader(), 2048)
	if err != nil {
		t.Fatal(err)
	}
	sk, err := atcrypto.GeneratePrivateKeyP256()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	x = &XRPCServer{
		Store:      s,
		SigningKey: key,
		Issuer:     "https://id.example.com",
		Audience:   "sovereign-api",
		Backend: func(tenantID string) storage.Backend {
			return &storage.FS{Root: filepath.Join(dir, tenantID)}
		},
		RepoFactory: func(ctx context.Context, did string) (*Repo, error) {
			return NewRepo(ctx, did, sk, filepath.Join(dir, "repo-"+strings.TrimPrefix(did, "did:web:")+".db"))
		},
	}
	tok, err = auth.MintAccessTokenWebID(key, "a1", "https://alice.example.com/profile/card#me", []string{"atproto"}, time.Minute, "https://id.example.com", "sovereign-api")
	if err != nil {
		t.Fatal(err)
	}
	return x, tok
}

func authReq(t *testing.T, x *XRPCServer, tok, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r = r.WithContext(tenant.WithTenant(r.Context(), &tenant.Tenant{ID: "t1", DID: "did:web:alice.example.com"}))
	r.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	x.ServeHTTP(rec, r)
	return rec
}

// TestBlobErrorBranches covers the uploadBlob/getBlob failure paths (audit
// A2 body cap, A5 tenant prefix).
func TestBlobErrorBranches(t *testing.T) {
	// Backend nil -> 500 on both.
	x, tok := wiredServer(t)
	x.Backend = nil
	rec := authReq(t, x, tok, http.MethodPost, "/xrpc/com.atproto.repo.uploadBlob", "data")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("uploadBlob nil backend = %d, want 500", rec.Code)
	}
	rec = authReq(t, x, tok, http.MethodGet, "/xrpc/com.atproto.sync.getBlob?cid=bafyabc", "")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("getBlob nil backend = %d, want 500", rec.Code)
	}

	// Missing cid -> 400.
	x, tok = wiredServer(t)
	rec = authReq(t, x, tok, http.MethodGet, "/xrpc/com.atproto.sync.getBlob", "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("getBlob missing cid = %d, want 400", rec.Code)
	}

	// Unknown blob -> 404.
	rec = authReq(t, x, tok, http.MethodGet, "/xrpc/com.atproto.sync.getBlob?cid=bafyabc", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("getBlob unknown = %d, want 404", rec.Code)
	}

	// No tenant context -> 401.
	r := httptest.NewRequest(http.MethodPost, "/xrpc/com.atproto.repo.uploadBlob", strings.NewReader("data"))
	r.Header.Set("Authorization", "Bearer "+tok)
	rec = httptest.NewRecorder()
	x.ServeHTTP(rec, r)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("uploadBlob no tenant = %d, want 401", rec.Code)
	}
}

// TestBlobRoundTrip verifies uploadBlob stores under the tenant prefix and
// getBlob retrieves it (A5).
func TestBlobRoundTrip(t *testing.T) {
	x, tok := wiredServer(t)
	rec := authReq(t, x, tok, http.MethodPost, "/xrpc/com.atproto.repo.uploadBlob", "hello blob")
	if rec.Code != http.StatusOK {
		t.Fatalf("uploadBlob = %d, want 200 (body %q)", rec.Code, rec.Body.String())
	}
	var out struct {
		Blob struct {
			Ref struct {
				Link string `json:"$link"`
			} `json:"ref"`
		} `json:"blob"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode upload response: %v", err)
	}
	if out.Blob.Ref.Link == "" {
		t.Fatal("uploadBlob returned empty blob ref")
	}
	rec = authReq(t, x, tok, http.MethodGet, "/xrpc/com.atproto.sync.getBlob?cid="+out.Blob.Ref.Link, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("getBlob = %d, want 200 (body %q)", rec.Code, rec.Body.String())
	}
	if got := rec.Body.String(); got != "hello blob" {
		t.Fatalf("getBlob body = %q, want %q", got, "hello blob")
	}
}

// TestCreateRecordErrorBranches covers the createRecord failure paths.
func TestCreateRecordErrorBranches(t *testing.T) {
	x, tok := wiredServer(t)

	// Bad JSON body.
	rec := authReq(t, x, tok, http.MethodPost, "/xrpc/com.atproto.repo.createRecord", "{not json")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad body = %d, want 400", rec.Code)
	}
	// Missing fields.
	rec = authReq(t, x, tok, http.MethodPost, "/xrpc/com.atproto.repo.createRecord", `{"repo":"did:web:alice.example.com"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing fields = %d, want 400", rec.Code)
	}
	// Repo not owned by tenant.
	rec = authReq(t, x, tok, http.MethodPost, "/xrpc/com.atproto.repo.createRecord", `{"repo":"did:plc:other","collection":"app.bsky.feed.post","record":{"text":"hi"}}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("foreign repo = %d, want 403", rec.Code)
	}
	// Invalid record JSON (malformed, not parseable).
	rec = authReq(t, x, tok, http.MethodPost, "/xrpc/com.atproto.repo.createRecord", `{"repo":"did:web:alice.example.com","collection":"app.bsky.feed.post","record":{"text":`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid record = %d, want 400 (body %q)", rec.Code, rec.Body.String())
	}

	// RepoFactory nil -> 500.
	x2, tok2 := wiredServer(t)
	x2.RepoFactory = nil
	rec = authReq(t, x2, tok2, http.MethodPost, "/xrpc/com.atproto.repo.createRecord", `{"repo":"did:web:alice.example.com","collection":"app.bsky.feed.post","record":{"text":"hi"}}`)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("nil factory = %d, want 500", rec.Code)
	}

	// RepoFactory error -> 500.
	x3, tok3 := wiredServer(t)
	x3.RepoFactory = func(ctx context.Context, did string) (*Repo, error) {
		return nil, errors.New("boom")
	}
	rec = authReq(t, x3, tok3, http.MethodPost, "/xrpc/com.atproto.repo.createRecord", `{"repo":"did:web:alice.example.com","collection":"app.bsky.feed.post","record":{"text":"hi"}}`)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("factory error = %d, want 500", rec.Code)
	}
}

// TestGetRecordErrorBranches covers the getRecord failure paths.
func TestGetRecordErrorBranches(t *testing.T) {
	x, tok := wiredServer(t)

	// Missing params.
	rec := authReq(t, x, tok, http.MethodGet, "/xrpc/com.atproto.repo.getRecord?repo=did:web:alice.example.com", "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing params = %d, want 400", rec.Code)
	}
	// Foreign repo.
	rec = authReq(t, x, tok, http.MethodGet, "/xrpc/com.atproto.repo.getRecord?repo=did:plc:other&collection=app.bsky.feed.post&rkey=1", "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("foreign repo = %d, want 403", rec.Code)
	}
	// Record not found.
	rec = authReq(t, x, tok, http.MethodGet, "/xrpc/com.atproto.repo.getRecord?repo=did:web:alice.example.com&collection=app.bsky.feed.post&rkey=nope", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("missing record = %d, want 404", rec.Code)
	}
}

// TestUploadBlobErrorBranches covers the uploadBlob failure paths.
func TestUploadBlobErrorBranches(t *testing.T) {
	x, tok := wiredServer(t)

	// No tenant context -> 401.
	r := httptest.NewRequest(http.MethodPost, "/xrpc/com.atproto.repo.uploadBlob", strings.NewReader("data"))
	r.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	x.ServeHTTP(rec, r)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no tenant = %d, want 401", rec.Code)
	}

	// Backend nil -> 500.
	x2 := &XRPCServer{Store: x.Store, SigningKey: x.SigningKey, Issuer: x.Issuer, Audience: x.Audience}
	rec = authReq(t, x2, tok, http.MethodPost, "/xrpc/com.atproto.repo.uploadBlob", "data")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("nil backend = %d, want 500", rec.Code)
	}
}

// TestGetBlobErrorBranches covers the getBlob failure paths.
func TestGetBlobErrorBranches(t *testing.T) {
	x, tok := wiredServer(t)

	// Missing cid.
	rec := authReq(t, x, tok, http.MethodGet, "/xrpc/com.atproto.sync.getBlob", "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing cid = %d, want 400", rec.Code)
	}
	// Blob not found.
	rec = authReq(t, x, tok, http.MethodGet, "/xrpc/com.atproto.sync.getBlob?cid=deadbeef", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("missing blob = %d, want 404", rec.Code)
	}
}

// TestGetRepoErrorBranches covers the getRepo failure paths.
func TestGetRepoErrorBranches(t *testing.T) {
	x, tok := wiredServer(t)

	// Missing did.
	rec := authReq(t, x, tok, http.MethodGet, "/xrpc/com.atproto.sync.getRepo", "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing did = %d, want 400", rec.Code)
	}
	// Foreign did.
	rec = authReq(t, x, tok, http.MethodGet, "/xrpc/com.atproto.sync.getRepo?did=did:plc:other", "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("foreign did = %d, want 403", rec.Code)
	}
	// Empty repo (nothing committed) -> 404.
	rec = authReq(t, x, tok, http.MethodGet, "/xrpc/com.atproto.sync.getRepo?did=did:web:alice.example.com", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("empty repo = %d, want 404 (body %q)", rec.Code, rec.Body.String())
	}
}

// TestGetRepoCAR verifies a committed repo exports as a CAR (WriteCAR success
// path).
func TestGetRepoCAR(t *testing.T) {
	x, tok := wiredServer(t)

	// Create + commit a record first.
	rec := authReq(t, x, tok, http.MethodPost, "/xrpc/com.atproto.repo.createRecord",
		`{"repo":"did:web:alice.example.com","collection":"app.bsky.feed.post","record":{"text":"hello"}}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("createRecord = %d, want 200 (body %q)", rec.Code, rec.Body.String())
	}

	rec = authReq(t, x, tok, http.MethodGet, "/xrpc/com.atproto.sync.getRepo?did=did:web:alice.example.com", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("getRepo = %d, want 200 (body %q)", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/vnd.ipld.car" {
		t.Fatalf("getRepo content-type = %q, want application/vnd.ipld.car", ct)
	}
	if rec.Body.Len() == 0 {
		t.Fatal("getRepo returned empty CAR")
	}
}

// TestBlobStoreErrorBranches covers BlobStore Put/Get/Delete failures.
func TestBlobStoreErrorBranches(t *testing.T) {
	ctx := context.Background()
	// A backend whose Put always fails.
	fail := &failingBackend{}
	bs := NewBlobStore(fail)
	if _, err := bs.Put(ctx, strings.NewReader("data")); err == nil {
		t.Fatal("Put on failing backend succeeded, want error")
	}
	if _, err := bs.Get(ctx, "key"); err == nil {
		t.Fatal("Get on failing backend succeeded, want error")
	}
	if err := bs.Delete(ctx, "key"); err == nil {
		t.Fatal("Delete on failing backend succeeded, want error")
	}
}

// failingBackend is a storage.Backend whose every operation fails.
type failingBackend struct{}

func (f *failingBackend) Put(ctx context.Context, key string, r io.Reader, ct string) (storage.Blob, error) {
	return storage.Blob{}, errors.New("put failed")
}

func (f *failingBackend) Get(ctx context.Context, key string) (io.ReadCloser, storage.Blob, error) {
	return nil, storage.Blob{}, errors.New("get failed")
}

func (f *failingBackend) Delete(ctx context.Context, key string) error {
	return errors.New("delete failed")
}

func (f *failingBackend) List(ctx context.Context, prefix string) ([]storage.Blob, error) {
	return nil, errors.New("list failed")
}

// TestUnwrapRecordError verifies unwrapRecord rejects non-CBOR data.
func TestUnwrapRecordError(t *testing.T) {
	if _, err := unwrapRecord([]byte("not cbor")); err == nil {
		t.Fatal("unwrapRecord on garbage succeeded, want error")
	}
}

// TestMarshalCBORInvalidJSON verifies jsonRecord rejects invalid JSON.
func TestMarshalCBORInvalidJSON(t *testing.T) {
	j := &jsonRecord{data: []byte("{not json")}
	if err := j.MarshalCBOR(io.Discard); err == nil {
		t.Fatal("MarshalCBOR on invalid JSON succeeded, want error")
	}
}

// TestGetProfileDIDNotFound verifies an unknown DID returns 404 (A7).
func TestGetProfileDIDNotFound(t *testing.T) {
	s := newTestStore(t)
	x := &XRPCServer{Store: s}
	rec := httptest.NewRecorder()
	x.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/xrpc/app.bsky.actor.getProfile?actor=did:plc:unknown", http.NoBody))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("getProfile unknown did = %d, want 404", rec.Code)
	}
}

// TestRequireAuthErrorBranches covers the authn gate failure paths.
func TestRequireAuthErrorBranches(t *testing.T) {
	x, tok := wiredServer(t)

	// No Authorization header -> 401.
	r := httptest.NewRequest(http.MethodPost, "/xrpc/com.atproto.repo.createRecord", strings.NewReader(`{}`))
	r = r.WithContext(tenant.WithTenant(r.Context(), &tenant.Tenant{ID: "t1", DID: "did:web:alice.example.com"}))
	rec := httptest.NewRecorder()
	x.ServeHTTP(rec, r)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no header = %d, want 401", rec.Code)
	}

	// Garbage token -> 401.
	r = httptest.NewRequest(http.MethodPost, "/xrpc/com.atproto.repo.createRecord", strings.NewReader(`{}`))
	r = r.WithContext(tenant.WithTenant(r.Context(), &tenant.Tenant{ID: "t1", DID: "did:web:alice.example.com"}))
	r.Header.Set("Authorization", "Bearer garbage")
	rec = httptest.NewRecorder()
	x.ServeHTTP(rec, r)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("garbage token = %d, want 401", rec.Code)
	}

	// No tenant context -> 401.
	r = httptest.NewRequest(http.MethodPost, "/xrpc/com.atproto.repo.createRecord", strings.NewReader(`{}`))
	r.Header.Set("Authorization", "Bearer "+tok)
	rec = httptest.NewRecorder()
	x.ServeHTTP(rec, r)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no tenant ctx = %d, want 401", rec.Code)
	}
}

// TestJSONRecordRoundTrip verifies a small record round-trips through the
// DAG-CBOR encoding (A6).
func TestJSONRecordRoundTrip(t *testing.T) {
	raw := []byte(`{"text":"hello","n":42,"tags":["a","b"]}`)
	j := &jsonRecord{data: raw}
	var buf strings.Builder
	if err := j.MarshalCBOR(&buf); err != nil {
		t.Fatal(err)
	}
	got, err := unwrapRecord([]byte(buf.String()))
	if err != nil {
		t.Fatal(err)
	}
	var a, b map[string]any
	if err := json.Unmarshal(raw, &a); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(got, &b); err != nil {
		t.Fatal(err)
	}
	if a["text"] != b["text"] || a["n"] != b["n"] {
		t.Fatalf("round-trip mismatch: %s vs %s", got, raw)
	}
}
