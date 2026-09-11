package atproto

import (
	"context"
	"crypto/rsa"
	"encoding/json"
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

// TestDataPlaneRequiresAuth verifies the atproto data-plane methods are gated
// behind authn+scope+tenant (security audit A1-A3): without a bearer token
// every data-plane method returns 401 AuthRequired. createSession stays 501
// (no password store yet). The public reads (resolveHandle, getProfile)
// remain live.
func TestDataPlaneRequiresAuth(t *testing.T) {
	s := newTestStore(t)
	x := &XRPCServer{Store: s}

	cases := []struct {
		name   string
		method string
		path   string
		body   string
	}{
		{"createRecord", http.MethodPost, "/xrpc/com.atproto.repo.createRecord", `{"repo":"did:plc:abc","collection":"app.bsky.feed.post","record":{"text":"hi"}}`},
		{"getRecord", http.MethodGet, "/xrpc/com.atproto.repo.getRecord?repo=did:plc:abc&collection=app.bsky.feed.post&rkey=1", ""},
		{"uploadBlob", http.MethodPost, "/xrpc/com.atproto.repo.uploadBlob", "blob-bytes"},
		{"getBlob", http.MethodGet, "/xrpc/com.atproto.sync.getBlob?cid=abc", ""},
		{"getRepo", http.MethodGet, "/xrpc/com.atproto.sync.getRepo?did=did:plc:abc", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			rec := httptest.NewRecorder()
			x.ServeHTTP(rec, req)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("%s = %d, want 401 (body %q)", tc.name, rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), "AuthRequired") {
				t.Fatalf("%s body missing AuthRequired: %q", tc.name, rec.Body.String())
			}
		})
	}

	// createSession stays fail-closed (501): no password store exists.
	t.Run("createSession", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/xrpc/com.atproto.server.createSession", strings.NewReader(`{"identifier":"alice","password":"x"}`))
		rec := httptest.NewRecorder()
		x.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotImplemented {
			t.Fatalf("createSession = %d, want 501", rec.Code)
		}
	})
}

// TestDataPlaneScopeAndTenantGate verifies the authn gate rejects tokens
// without the atproto scope and tokens whose subject is not in the request's
// tenant (audit A1-A3).
func TestDataPlaneScopeAndTenantGate(t *testing.T) {
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
	x := &XRPCServer{
		Store:      s,
		SigningKey: key,
		Issuer:     "https://id.example.com",
		Audience:   "sovereign-api",
	}

	// Token without the atproto scope -> 403.
	noScope, err := auth.MintAccessToken(key, "a1", []string{"self"}, time.Minute, "https://id.example.com", "sovereign-api")
	if err != nil {
		t.Fatal(err)
	}
	// Token with atproto scope but subject outside the tenant -> 403.
	wrongTenant, err := auth.MintAccessTokenWebID(key, "a1", "https://other.example.com/profile/card#me", []string{"atproto"}, time.Minute, "https://id.example.com", "sovereign-api")
	if err != nil {
		t.Fatal(err)
	}
	// Valid token for the tenant -> passes the gate (handler runs; repo
	// factory nil -> 500, proving the gate let it through).
	valid, err := auth.MintAccessTokenWebID(key, "a1", "https://alice.example.com/profile/card#me", []string{"atproto"}, time.Minute, "https://id.example.com", "sovereign-api")
	if err != nil {
		t.Fatal(err)
	}

	req := func(tok string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/xrpc/com.atproto.repo.createRecord", strings.NewReader(`{"repo":"did:web:alice.example.com","collection":"app.bsky.feed.post","record":{"text":"hi"}}`))
		r = r.WithContext(tenant.WithTenant(r.Context(), &tenant.Tenant{ID: "t1", DID: "did:web:alice.example.com"}))
		if tok != "" {
			r.Header.Set("Authorization", "Bearer "+tok)
		}
		return r
	}

	rec := httptest.NewRecorder()
	x.ServeHTTP(rec, req(noScope))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("no-scope token = %d, want 403 (body %q)", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	x.ServeHTTP(rec, req(wrongTenant))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("wrong-tenant token = %d, want 403 (body %q)", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	x.ServeHTTP(rec, req(valid))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("valid token = %d, want 500 (gate passed, repo factory nil)", rec.Code)
	}
}

// TestDataPlaneWired verifies the full data plane works end-to-end with wired
// deps: repo write + blob + getProfile (T6 acceptance).
func TestDataPlaneWired(t *testing.T) {
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
	x := &XRPCServer{
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
	tok, err := auth.MintAccessTokenWebID(key, "a1", "https://alice.example.com/profile/card#me", []string{"atproto"}, time.Minute, "https://id.example.com", "sovereign-api")
	if err != nil {
		t.Fatal(err)
	}
	authReq := func(method, path, body string) *http.Request {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r = r.WithContext(tenant.WithTenant(r.Context(), &tenant.Tenant{ID: "t1", DID: "did:web:alice.example.com"}))
		r.Header.Set("Authorization", "Bearer "+tok)
		return r
	}

	// createRecord with a >255-byte record (A6).
	big := strings.Repeat("x", 400)
	rec := httptest.NewRecorder()
	x.ServeHTTP(rec, authReq(http.MethodPost, "/xrpc/com.atproto.repo.createRecord",
		`{"repo":"did:web:alice.example.com","collection":"app.bsky.feed.post","record":{"text":"`+big+`"}}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("createRecord = %d, want 200 (body %q)", rec.Code, rec.Body.String())
	}
	var created struct {
		URI string `json:"uri"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.URI == "" {
		t.Fatal("createRecord returned empty uri")
	}
	rkey := created.URI[strings.LastIndex(created.URI, "/")+1:]

	// getRecord round-trips the big record.
	rec = httptest.NewRecorder()
	x.ServeHTTP(rec, authReq(http.MethodGet, "/xrpc/com.atproto.repo.getRecord?repo=did:web:alice.example.com&collection=app.bsky.feed.post&rkey="+rkey, ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("getRecord = %d, want 200 (body %q)", rec.Code, rec.Body.String())
	}
	var got struct {
		Value map[string]string `json:"value"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Value["text"] != big {
		t.Fatalf("record text mismatch: got %d bytes, want %d", len(got.Value["text"]), len(big))
	}

	// uploadBlob stores in the tenant prefix (A5).
	rec = httptest.NewRecorder()
	x.ServeHTTP(rec, authReq(http.MethodPost, "/xrpc/com.atproto.repo.uploadBlob", "blob-data"))
	if rec.Code != http.StatusOK {
		t.Fatalf("uploadBlob = %d, want 200 (body %q)", rec.Code, rec.Body.String())
	}
	var blob struct {
		Blob struct {
			Ref map[string]string `json:"ref"`
		} `json:"blob"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &blob); err != nil {
		t.Fatal(err)
	}
	cid := blob.Blob.Ref["$link"]
	if cid == "" {
		t.Fatal("uploadBlob returned empty blob cid")
	}

	// getBlob reads it back from the tenant prefix.
	rec = httptest.NewRecorder()
	x.ServeHTTP(rec, authReq(http.MethodGet, "/xrpc/com.atproto.sync.getBlob?cid="+cid, ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("getBlob = %d, want 200 (body %q)", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != "blob-data" {
		t.Fatalf("getBlob body = %q, want blob-data", rec.Body.String())
	}

	// getProfile resolves a DID (A7).
	rec = httptest.NewRecorder()
	x.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/xrpc/app.bsky.actor.getProfile?actor=did:web:alice.example.com", http.NoBody))
	if rec.Code != http.StatusOK {
		t.Fatalf("getProfile(did) = %d, want 200 (body %q)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "alice.example.com") {
		t.Fatalf("getProfile(did) body missing handle: %q", rec.Body.String())
	}
}

// randReader returns a deterministic reader for key generation in tests.
func randReader() io.Reader { return strings.NewReader(strings.Repeat("r", 4096)) }
