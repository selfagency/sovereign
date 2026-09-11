package atproto

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/selfagency/sovereign/internal/storage"
)

// TestDataPlaneGated verifies the atproto data-plane methods are disabled at
// the router (security audit A1): the PDS is mounted with nil
// Backend/RepoFactory/SigningKey, and wiring them without an authn+scope+
// tenant gate would expose unauthenticated cross-tenant writes and unbounded
// uploads. Every data-plane method must return 501 MethodNotImplemented until
// Step 7 of the steps5-8-hardening plan wires them WITH authn. The public
// reads (resolveHandle, getProfile) remain live.
func TestDataPlaneGated(t *testing.T) {
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
		{"createSession", http.MethodPost, "/xrpc/com.atproto.server.createSession", `{"accessJwt":"tok"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			rec := httptest.NewRecorder()
			x.ServeHTTP(rec, req)
			if rec.Code != http.StatusNotImplemented {
				t.Fatalf("%s = %d, want 501 (body %q)", tc.name, rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), "MethodNotImplemented") {
				t.Fatalf("%s body missing MethodNotImplemented: %q", tc.name, rec.Body.String())
			}
			// The gate must not leak internal state.
			if strings.Contains(rec.Body.String(), "factory") || strings.Contains(rec.Body.String(), "backend") {
				t.Fatalf("%s leaks internal detail: %q", tc.name, rec.Body.String())
			}
		})
	}
}

// TestDataPlaneGatedEvenWhenWired proves the gate holds even if the data-plane
// dependencies are supplied: the router must not dispatch to the handlers
// until the authn+scope+tenant gate exists (audit A1 footgun).
func TestDataPlaneGatedEvenWhenWired(t *testing.T) {
	s := newTestStore(t)
	x := &XRPCServer{
		Store:   s,
		Backend: func(string) storage.Backend { return &storage.FS{Root: t.TempDir()} },
	}
	req := httptest.NewRequest(http.MethodPost, "/xrpc/com.atproto.repo.createRecord", strings.NewReader(`{"repo":"did:plc:abc","collection":"app.bsky.feed.post","record":{"text":"hi"}}`))
	rec := httptest.NewRecorder()
	x.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("createRecord with wired deps = %d, want 501", rec.Code)
	}
}
