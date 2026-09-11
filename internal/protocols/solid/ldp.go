package solid

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/selfagency/sovereign/internal/storage"
	"github.com/selfagency/sovereign/internal/tenant"
)

// Server is the Solid LDP HTTP handler.
type Server struct {
	// Backend returns the storage backend for a tenant.
	Backend func(tenantID string) storage.Backend
	// ACL authorizes access.
	ACL ACLChecker
	// Tokens validates bearer tokens to derive the authenticated agent.
	Tokens TokenValidator
}

// containerType is the LDP BasicContainer link relation.
const containerType = `<http://www.w3.org/ns/ldp#BasicContainer>; rel="type"`

// ServeHTTP handles LDP requests for the tenant in context.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	t, ok := tenant.FromContext(r.Context())
	if !ok {
		http.NotFound(w, r)
		return
	}
	agent := s.agentFromRequest(r)
	backend := s.Backend(t.ID)
	// r.URL.Path starts with "/"; the storage key is the path without the
	// leading slash (the Prefixed backend rejects absolute keys).
	key := strings.TrimPrefix(r.URL.Path, "/")

	switch r.Method {
	case http.MethodGet:
		s.handleGet(w, r, backend, key, agent)
	case http.MethodHead:
		s.handleHead(w, r, backend, key, agent)
	case http.MethodOptions:
		w.Header().Set("Allow", "GET, HEAD, OPTIONS, PUT, POST, PATCH, DELETE")
		w.Header().Set("Accept-Patch", "application/sparql-update, text/npatch")
		w.WriteHeader(http.StatusNoContent)
	case http.MethodPut, http.MethodPost:
		s.handleWrite(w, r, backend, key, agent)
	case http.MethodPatch:
		s.handlePatch(w, r, backend, key, agent)
	case http.MethodDelete:
		s.handleDelete(w, r, backend, key, agent)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleGet serves a resource or container listing. Containers are identified
// by a trailing slash (Solid Protocol §3.1 URI Slash Semantics).
func (s *Server) handleGet(w http.ResponseWriter, r *http.Request, backend storage.Backend, key string, agent Agent) {
	if !s.ACL.CanRead(r.Context(), key, agent) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if strings.HasSuffix(key, "/") {
		s.serveContainer(w, r, backend, key)
		return
	}
	rc, blob, err := backend.Get(r.Context(), key)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer func() { _ = rc.Close() }()
	w.Header().Set("Content-Type", blob.ContentType)
	w.Header().Set("Allow", "GET, HEAD, OPTIONS, PUT, POST, PATCH, DELETE")
	if _, err := io.Copy(w, rc); err != nil {
		http.Error(w, "read error", http.StatusInternalServerError)
		return
	}
}

// serveContainer lists the children of a container as Turtle.
func (s *Server) serveContainer(w http.ResponseWriter, r *http.Request, backend storage.Backend, key string) {
	blobs, err := backend.List(r.Context(), key)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/turtle")
	w.Header().Set("Link", containerType)
	w.Header().Set("Allow", "GET, HEAD, OPTIONS, PUT, POST, PATCH, DELETE")
	writeContainerTurtle(w, key, blobs)
}

// handleWrite stores a resource (PUT) or creates a child (POST).
func (s *Server) handleWrite(w http.ResponseWriter, r *http.Request, backend storage.Backend, key string, agent Agent) {
	if !s.ACL.CanWrite(r.Context(), key, agent) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}
	if _, err := backend.Put(r.Context(), key, bytes.NewReader(body), r.Header.Get("Content-Type")); err != nil {
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

// handleHead serves the headers for a resource without a body.
func (s *Server) handleHead(w http.ResponseWriter, r *http.Request, backend storage.Backend, key string, agent Agent) {
	if !s.ACL.CanRead(r.Context(), key, agent) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	rc, blob, err := backend.Get(r.Context(), key)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	_ = rc.Close()
	w.Header().Set("Content-Type", blob.ContentType)
	w.Header().Set("Allow", "GET, HEAD, OPTIONS, PUT, POST, PATCH, DELETE")
	w.WriteHeader(http.StatusOK)
}

// handlePatch applies an LDP patch (SPARQL-update INSERT DATA / DELETE DATA
// subset) to an RDF resource. Non-RDF content types are rejected.
func (s *Server) handlePatch(w http.ResponseWriter, r *http.Request, backend storage.Backend, key string, agent Agent) {
	if !s.ACL.CanWrite(r.Context(), key, agent) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	ct := r.Header.Get("Content-Type")
	if ct != "application/sparql-update" && ct != "text/npatch" {
		http.Error(w, "unsupported patch media type", http.StatusUnsupportedMediaType)
		return
	}
	rc, _, err := backend.Get(r.Context(), key)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer func() { _ = rc.Close() }()
	current, err := io.ReadAll(rc)
	if err != nil {
		http.Error(w, "read error", http.StatusInternalServerError)
		return
	}
	patch, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}
	merged, err := applyNPatch(string(current), string(patch))
	if err != nil {
		slog.Error("solid: apply patch", "err", err)
		http.Error(w, "invalid patch", http.StatusBadRequest)
		return
	}
	if _, err := backend.Put(r.Context(), key, strings.NewReader(merged), "text/turtle"); err != nil {
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleDelete removes a resource.
func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request, backend storage.Backend, key string, agent Agent) {
	if !s.ACL.CanWrite(r.Context(), key, agent) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := backend.Delete(r.Context(), key); err != nil {
		http.NotFound(w, r)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// agentFromRequest derives the authenticated agent from the request. If a
// bearer token is present and valid, the subject becomes the agent's WebID;
// otherwise the public agent is used.
func (s *Server) agentFromRequest(r *http.Request) Agent {
	if s.Tokens == nil {
		return AgentFromRequest(r)
	}
	auth := r.Header.Get("Authorization")
	if len(auth) < 7 || auth[:7] != "Bearer " {
		return AgentFromRequest(r)
	}
	subject, err := s.Tokens.ValidateToken(r.Context(), auth[7:])
	if err != nil {
		return AgentFromRequest(r)
	}
	return Agent{WebID: subject}
}

// writeContainerTurtle renders a container listing as Turtle.
func writeContainerTurtle(w io.Writer, key string, blobs []storage.Blob) {
	base := strings.TrimSuffix(key, "/")
	_, _ = io.WriteString(w, "@prefix ldp: <http://www.w3.org/ns/ldp#>.\n\n")
	_, _ = io.WriteString(w, "<"+base+"> a ldp:BasicContainer.\n")
	for _, b := range blobs {
		_, _ = io.WriteString(w, "<"+base+"/"+b.Key+"> a ldp:Resource.\n")
	}
}
