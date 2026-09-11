package solid

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/selfagency/sovereign/internal/storage"
	"github.com/selfagency/sovereign/internal/tenant"
)

// fakeACL grants access based on a map of allowed agents per resource.
type fakeACL struct {
	// read and write are sets of "resource:agent" allowed.
	read  map[string]bool
	write map[string]bool
}

func (f fakeACL) CanRead(_ context.Context, resource string, agent Agent) bool {
	return f.read[resource+":"+agent.WebID] || f.read["*:*"]
}

func (f fakeACL) CanWrite(_ context.Context, resource string, agent Agent) bool {
	return f.write[resource+":"+agent.WebID] || f.write["*:*"]
}

// newTestServer builds a Solid server with an FS backend and permissive ACL.
func newTestServer(t *testing.T) (*Server, *storage.FS) {
	t.Helper()
	fs := &storage.FS{Root: t.TempDir()}
	// Permissive ACL: everyone can read/write everything.
	acl := fakeACL{
		read:  map[string]bool{"*:*": true},
		write: map[string]bool{"*:*": true},
	}
	return &Server{Backend: func(string) storage.Backend { return fs }, ACL: acl}, fs
}

// withTenant wraps a handler with the tenant middleware.
func withTenant(h http.Handler, handle string) http.Handler {
	store := fakeTenantStore{tenants: map[string]*tenant.Tenant{handle: {ID: "t1", Handle: handle}}}
	return tenant.Middleware(store)(h)
}

type fakeTenantStore struct{ tenants map[string]*tenant.Tenant }

func (f fakeTenantStore) FindByHost(_ context.Context, host string) (*tenant.Tenant, error) {
	t, ok := f.tenants[host]
	if !ok {
		return nil, tenant.ErrNotFound
	}
	return t, nil
}

// TestPutGetDeleteRoundTrip verifies the LDP resource lifecycle.
func TestPutGetDeleteRoundTrip(t *testing.T) {
	srv, _ := newTestServer(t)
	h := withTenant(srv, "alice.example.com")

	// PUT
	putReq := httptest.NewRequest("PUT", "/docs/note.ttl", strings.NewReader("@prefix : <#>.\n:note a :Note."))
	putReq.Host = "alice.example.com"
	putReq.Header.Set("Content-Type", "text/turtle")
	putRec := httptest.NewRecorder()
	h.ServeHTTP(putRec, putReq)
	if putRec.Code != http.StatusCreated {
		t.Fatalf("PUT status = %d, want 201", putRec.Code)
	}

	// GET
	getReq := httptest.NewRequest("GET", "/docs/note.ttl", http.NoBody)
	getReq.Host = "alice.example.com"
	getRec := httptest.NewRecorder()
	h.ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Fatalf("GET status = %d, want 200", getRec.Code)
	}
	if !strings.Contains(getRec.Body.String(), ":Note") {
		t.Fatalf("GET body missing content: %q", getRec.Body.String())
	}

	// DELETE
	delReq := httptest.NewRequest("DELETE", "/docs/note.ttl", http.NoBody)
	delReq.Host = "alice.example.com"
	delRec := httptest.NewRecorder()
	h.ServeHTTP(delRec, delReq)
	if delRec.Code != http.StatusNoContent {
		t.Fatalf("DELETE status = %d, want 204", delRec.Code)
	}

	// GET after delete -> 404 (resource gone)
	getReq2 := httptest.NewRequest("GET", "/docs/note.ttl", http.NoBody)
	getReq2.Host = "alice.example.com"
	getRec2 := httptest.NewRecorder()
	h.ServeHTTP(getRec2, getReq2)
	if getRec2.Code != http.StatusNotFound {
		t.Fatalf("GET after delete = %d, want 404", getRec2.Code)
	}
}

// TestContainerListing verifies a container returns Turtle with Link header.
func TestContainerListing(t *testing.T) {
	srv, fs := newTestServer(t)
	h := withTenant(srv, "alice.example.com")

	// Seed a resource.
	if _, err := fs.Put(context.Background(), "docs/a.ttl", strings.NewReader(":a a :A."), "text/turtle"); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("GET", "/docs/", http.NoBody)
	req.Host = "alice.example.com"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("container status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/turtle" {
		t.Fatalf("content-type = %q, want text/turtle", ct)
	}
	if link := rec.Header().Get("Link"); link != containerType {
		t.Fatalf("link = %q, want %q", link, containerType)
	}
	if !strings.Contains(rec.Body.String(), "ldp:BasicContainer") {
		t.Fatalf("container body missing BasicContainer: %q", rec.Body.String())
	}
}

// TestACLDenied verifies ACL denial returns 403.
func TestACLDenied(t *testing.T) {
	fs := &storage.FS{Root: t.TempDir()}
	// No access for anyone.
	srv := &Server{
		Backend: func(string) storage.Backend { return fs },
		ACL:     fakeACL{read: map[string]bool{}, write: map[string]bool{}},
	}
	h := withTenant(srv, "alice.example.com")

	req := httptest.NewRequest("GET", "/docs/x", http.NoBody)
	req.Host = "alice.example.com"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("ACL denied GET = %d, want 403", rec.Code)
	}

	putReq := httptest.NewRequest("PUT", "/docs/x", strings.NewReader("data"))
	putReq.Host = "alice.example.com"
	putRec := httptest.NewRecorder()
	h.ServeHTTP(putRec, putReq)
	if putRec.Code != http.StatusForbidden {
		t.Fatalf("ACL denied PUT = %d, want 403", putRec.Code)
	}
}

// TestNoTenant verifies a missing tenant is a 404.
func TestNoTenant(t *testing.T) {
	srv, _ := newTestServer(t)
	req := httptest.NewRequest("GET", "/docs/x", http.NoBody)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("no tenant = %d, want 404", rec.Code)
	}
}

// TestMethodNotAllowed verifies unsupported methods are rejected.
func TestMethodNotAllowed(t *testing.T) {
	srv, _ := newTestServer(t)
	h := withTenant(srv, "alice.example.com")
	req := httptest.NewRequest("TRACE", "/docs/x", http.NoBody)
	req.Host = "alice.example.com"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("TRACE = %d, want 405", rec.Code)
	}
}

// TestAgentFromRequest verifies agent extraction from context.
func TestAgentFromRequest(t *testing.T) {
	// No WebID -> public agent.
	req := httptest.NewRequest("GET", "/", http.NoBody)
	if a := AgentFromRequest(req); a.WebID != "" {
		t.Fatalf("public agent WebID = %q, want empty", a.WebID)
	}

	// With WebID in context.
	ctx := WithWebID(req.Context(), "https://alice.example.com/profile#me")
	req2 := req.WithContext(ctx)
	if a := AgentFromRequest(req2); a.WebID != "https://alice.example.com/profile#me" {
		t.Fatalf("agent WebID = %q", a.WebID)
	}
}

// fakeTokenValidator returns a fixed subject for a valid token.
type fakeTokenValidator struct {
	subject string
	err     error
}

func (f fakeTokenValidator) ValidateToken(ctx context.Context, token string) (string, error) {
	return f.subject, f.err
}

// TestAgentFromRequestBearer verifies the server derives the agent from a
// valid bearer token.
func TestAgentFromRequestBearer(t *testing.T) {
	s := &Server{Tokens: fakeTokenValidator{subject: "alice"}}

	// Valid bearer token -> agent WebID = subject.
	req := httptest.NewRequest("GET", "/", http.NoBody)
	req.Header.Set("Authorization", "Bearer tok")
	if a := s.agentFromRequest(req); a.WebID != "alice" {
		t.Fatalf("agent WebID = %q, want alice", a.WebID)
	}

	// No token -> public agent.
	req2 := httptest.NewRequest("GET", "/", http.NoBody)
	if a := s.agentFromRequest(req2); a.WebID != "" {
		t.Fatalf("no-token agent WebID = %q, want empty", a.WebID)
	}

	// Invalid token -> public agent.
	s2 := &Server{Tokens: fakeTokenValidator{err: errors.New("invalid")}}
	req3 := httptest.NewRequest("GET", "/", http.NoBody)
	req3.Header.Set("Authorization", "Bearer bad")
	if a := s2.agentFromRequest(req3); a.WebID != "" {
		t.Fatalf("invalid-token agent WebID = %q, want empty", a.WebID)
	}

	// No TokenValidator configured -> falls back to context agent.
	s3 := &Server{}
	req4 := httptest.NewRequest("GET", "/", http.NoBody)
	req4.Header.Set("Authorization", "Bearer x")
	if a := s3.agentFromRequest(req4); a.WebID != "" {
		t.Fatalf("no-validator agent WebID = %q, want empty", a.WebID)
	}
}

// seedTTL stores a Turtle resource and returns the server.
func seedTTL(t *testing.T, h http.Handler, key, body string) {
	t.Helper()
	req := httptest.NewRequest("PUT", "/"+key, strings.NewReader(body))
	req.Host = "alice.example.com"
	req.Header.Set("Content-Type", "text/turtle")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("seed PUT %s = %d, want 201", key, rec.Code)
	}
}

// TestPatchInsertData proves LDP PATCH with INSERT DATA adds triples.
func TestPatchInsertData(t *testing.T) {
	srv, _ := newTestServer(t)
	h := withTenant(srv, "alice.example.com")
	seedTTL(t, h, "docs/note.ttl", "@prefix dc: <http://purl.org/dc/terms/>.\n<> dc:title \"Old\".")

	patch := `INSERT DATA { <> <http://purl.org/dc/terms/title> "New" . }`
	req := httptest.NewRequest("PATCH", "/docs/note.ttl", strings.NewReader(patch))
	req.Host = "alice.example.com"
	req.Header.Set("Content-Type", "application/sparql-update")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("PATCH INSERT DATA = %d, want 204", rec.Code)
	}

	getReq := httptest.NewRequest("GET", "/docs/note.ttl", http.NoBody)
	getReq.Host = "alice.example.com"
	getRec := httptest.NewRecorder()
	h.ServeHTTP(getRec, getReq)
	if !strings.Contains(getRec.Body.String(), `"New"`) {
		t.Fatalf("PATCH did not add triple; body = %q", getRec.Body.String())
	}
}

// TestPatchDeleteData proves LDP PATCH with DELETE DATA removes triples.
func TestPatchDeleteData(t *testing.T) {
	srv, _ := newTestServer(t)
	h := withTenant(srv, "alice.example.com")
	seedTTL(t, h, "docs/note.ttl", "@prefix dc: <http://purl.org/dc/terms/>.\n<> dc:title \"Old\".")

	patch := `DELETE DATA { <> <http://purl.org/dc/terms/title> "Old" . }`
	req := httptest.NewRequest("PATCH", "/docs/note.ttl", strings.NewReader(patch))
	req.Host = "alice.example.com"
	req.Header.Set("Content-Type", "application/sparql-update")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("PATCH DELETE DATA = %d, want 204", rec.Code)
	}

	getReq := httptest.NewRequest("GET", "/docs/note.ttl", http.NoBody)
	getReq.Host = "alice.example.com"
	getRec := httptest.NewRecorder()
	h.ServeHTTP(getRec, getReq)
	if strings.Contains(getRec.Body.String(), `"Old"`) {
		t.Fatalf("PATCH did not remove triple; body = %q", getRec.Body.String())
	}
}

// TestPatchInvalidSyntax proves a malformed SPARQL patch returns 400 (audit
// B1: the raw parse error is logged, not returned to the client).
func TestPatchInvalidSyntax(t *testing.T) {
	srv, _ := newTestServer(t)
	h := withTenant(srv, "alice.example.com")
	seedTTL(t, h, "docs/note.ttl", "@prefix dc: <http://purl.org/dc/terms/>.\n<> dc:title \"Old\".")

	patch := `DELETE WHERE { <> <http://purl.org/dc/terms/title> "Old" }` // unsupported op
	req := httptest.NewRequest("PATCH", "/docs/note.ttl", strings.NewReader(patch))
	req.Host = "alice.example.com"
	req.Header.Set("Content-Type", "application/sparql-update")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("PATCH invalid = %d, want 400 (body %q)", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "parse") || strings.Contains(rec.Body.String(), "error") {
		t.Fatalf("PATCH invalid leaked raw error: %q", rec.Body.String())
	}
}

// TestPatchUnsupportedMediaType proves non-RDF patch bodies are rejected.
func TestPatchUnsupportedMediaType(t *testing.T) {
	srv, _ := newTestServer(t)
	h := withTenant(srv, "alice.example.com")
	seedTTL(t, h, "docs/note.ttl", "<> a <http://example.com/Thing>.")

	req := httptest.NewRequest("PATCH", "/docs/note.ttl", strings.NewReader("not rdf"))
	req.Host = "alice.example.com"
	req.Header.Set("Content-Type", "text/plain")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("PATCH text/plain = %d, want 415", rec.Code)
	}
}

// TestHeadReturnsHeadersNoBody proves HEAD returns headers without a body.
func TestHeadReturnsHeadersNoBody(t *testing.T) {
	srv, _ := newTestServer(t)
	h := withTenant(srv, "alice.example.com")
	seedTTL(t, h, "docs/note.ttl", "<> a <http://example.com/Thing>.")

	req := httptest.NewRequest("HEAD", "/docs/note.ttl", http.NoBody)
	req.Host = "alice.example.com"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("HEAD = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/turtle" {
		t.Fatalf("HEAD content-type = %q, want text/turtle", ct)
	}
	if rec.Body.Len() != 0 {
		t.Fatalf("HEAD body = %q, want empty", rec.Body.String())
	}
}

// TestOptionsAdvertisesPatch proves OPTIONS advertises PATCH + Accept-Patch.
func TestOptionsAdvertisesPatch(t *testing.T) {
	srv, _ := newTestServer(t)
	h := withTenant(srv, "alice.example.com")

	req := httptest.NewRequest("OPTIONS", "/docs/x", http.NoBody)
	req.Host = "alice.example.com"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("OPTIONS = %d, want 204", rec.Code)
	}
	if allow := rec.Header().Get("Allow"); !strings.Contains(allow, "PATCH") {
		t.Fatalf("OPTIONS Allow = %q, want PATCH", allow)
	}
	if ap := rec.Header().Get("Accept-Patch"); !strings.Contains(ap, "application/sparql-update") {
		t.Fatalf("OPTIONS Accept-Patch = %q, want application/sparql-update", ap)
	}
}
