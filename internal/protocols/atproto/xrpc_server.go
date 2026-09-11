package atproto

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/fxamacker/cbor/v2"

	"github.com/selfagency/sovereign/internal/auth"
	"github.com/selfagency/sovereign/internal/storage"
	"github.com/selfagency/sovereign/internal/store"
	"github.com/selfagency/sovereign/internal/tenant"
)

// maxBlobBytes caps uploadBlob request bodies (audit A2: unbounded uploads).
const maxBlobBytes = 10 << 20 // 10 MiB

// XRPCServer serves atproto XRPC endpoints (com.atproto.*) for the tenant
// in the request context.
type XRPCServer struct {
	Store *store.Store
	// Backend returns the storage backend for a tenant (used for blobs).
	Backend func(tenantID string) storage.Backend
	// RepoFactory builds a repo for a DID (per-tenant blockstore).
	RepoFactory func(ctx context.Context, did string) (*Repo, error)
	// SigningKey signs atproto session JWTs.
	SigningKey *rsa.PrivateKey
	// Issuer and Audience are the expected iss/aud for validated access tokens.
	Issuer   string
	Audience string
}

// ServeHTTP routes XRPC method calls.
func (s *XRPCServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Path is /xrpc/<method>.
	method := strings.TrimPrefix(r.URL.Path, "/xrpc/")
	switch method {
	case "com.atproto.identity.resolveHandle":
		s.resolveHandle(w, r)
	case "app.bsky.actor.getProfile":
		s.getProfile(w, r)
	case "com.atproto.repo.createRecord":
		s.requireAuth(w, r, s.createRecord)
	case "com.atproto.repo.getRecord":
		s.requireAuth(w, r, s.getRecord)
	case "com.atproto.repo.uploadBlob":
		s.requireAuth(w, r, s.uploadBlob)
	case "com.atproto.sync.getBlob":
		s.requireAuth(w, r, s.getBlob)
	case "com.atproto.sync.getRepo":
		s.requireAuth(w, r, s.getRepo)
	case "com.atproto.server.createSession":
		// Session bootstrap needs a password store that does not exist yet;
		// keep it fail-closed (501) rather than minting tokens on a fake
		// credential check. Clients authenticate via the control-plane
		// /api/v1/auth endpoints and use the resulting access token.
		writeXRPCError(w, http.StatusNotImplemented, "MethodNotImplemented", "method not implemented")
	default:
		writeXRPCError(w, http.StatusNotImplemented, "MethodNotImplemented", "method not implemented: "+method)
	}
}

// requireAuth wraps a data-plane handler with the authn+scope+tenant gate
// (audit A1-A3): a valid bearer access token carrying the atproto scope whose
// subject resolves to an account in the request's tenant.
func (s *XRPCServer) requireAuth(w http.ResponseWriter, r *http.Request, h func(http.ResponseWriter, *http.Request)) {
	authz := r.Header.Get("Authorization")
	if len(authz) < 7 || authz[:7] != "Bearer " {
		writeXRPCError(w, http.StatusUnauthorized, "AuthRequired", "authentication required")
		return
	}
	claims, err := auth.ValidateAccessToken(s.SigningKey, authz[7:], s.Issuer, s.Audience)
	if err != nil {
		writeXRPCError(w, http.StatusUnauthorized, "AuthRequired", "invalid or expired token")
		return
	}
	if !hasScope(claims.Scopes, "atproto") {
		writeXRPCError(w, http.StatusForbidden, "Forbidden", "insufficient scope")
		return
	}
	// Tenant binding: the principal must belong to the request's tenant.
	t, ok := tenant.FromContext(r.Context())
	if !ok {
		writeXRPCError(w, http.StatusUnauthorized, "AuthRequired", "no tenant context")
		return
	}
	acct, err := s.Store.AccountByWebID(r.Context(), claims.WebID)
	if err != nil || acct.TenantID != t.ID {
		writeXRPCError(w, http.StatusForbidden, "Forbidden", "tenant mismatch")
		return
	}
	h(w, r)
}

// hasScope reports whether scopes contains the required scope.
func hasScope(scopes []string, required string) bool {
	for _, s := range scopes {
		if s == required {
			return true
		}
	}
	return false
}

// resolveHandle resolves a handle to a DID.
func (s *XRPCServer) resolveHandle(w http.ResponseWriter, r *http.Request) {
	handle := r.URL.Query().Get("handle")
	if handle == "" {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "handle is required")
		return
	}
	t, err := s.Store.GetTenantByHandle(r.Context(), handle)
	if err != nil {
		writeXRPCError(w, http.StatusNotFound, "HandleNotFound", "handle not found")
		return
	}
	did := t.DID
	if did == "" {
		did = "did:web:" + handle
	}
	writeJSON(w, map[string]string{"did": did})
}

// getProfile implements app.bsky.actor.getProfile. The actor may be a handle
// or a DID; DIDs are resolved via the tenant store (A7).
func (s *XRPCServer) getProfile(w http.ResponseWriter, r *http.Request) {
	actor := r.URL.Query().Get("actor")
	if actor == "" {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "actor is required")
		return
	}
	var t *store.Tenant
	var err error
	if strings.HasPrefix(actor, "did:") {
		t, err = s.Store.GetTenantByDID(r.Context(), actor)
	} else {
		t, err = s.Store.GetTenantByHandle(r.Context(), actor)
	}
	if err != nil {
		writeXRPCError(w, http.StatusNotFound, "ActorNotFound", "actor not found")
		return
	}
	writeJSON(w, map[string]any{
		"did":         t.DID,
		"handle":      t.Handle,
		"displayName": t.Handle,
	})
}

// createRecord implements com.atproto.repo.createRecord. It writes a record
// to the repo for the authenticated tenant's DID and commits it.
func (s *XRPCServer) createRecord(w http.ResponseWriter, r *http.Request) {
	if s.RepoFactory == nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalError", "repo factory not configured")
		return
	}
	var in struct {
		Repo       string          `json:"repo"`
		Collection string          `json:"collection"`
		Record     json.RawMessage `json:"record"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "bad body")
		return
	}
	if in.Repo == "" || in.Collection == "" || len(in.Record) == 0 {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "repo, collection, and record are required")
		return
	}
	// Tenant binding: the repo must be the request tenant's own DID.
	t, ok := tenant.FromContext(r.Context())
	if !ok || t.DID != in.Repo {
		writeXRPCError(w, http.StatusForbidden, "Forbidden", "repo does not belong to this tenant")
		return
	}
	repo, err := s.RepoFactory(r.Context(), in.Repo)
	if err != nil {
		slog.Error("atproto: open repo", "err", err)
		writeXRPCError(w, http.StatusInternalServerError, "InternalError", "repo unavailable")
		return
	}
	defer func() { _ = repo.Close() }()
	rec := &jsonRecord{data: in.Record}
	cid, tid, err := repo.CreateRecord(r.Context(), in.Collection, rec)
	if err != nil {
		slog.Error("atproto: create record", "err", err)
		writeXRPCError(w, http.StatusBadRequest, "InvalidRecord", "invalid record")
		return
	}
	commitCid, rev, err := repo.Commit(r.Context())
	if err != nil {
		slog.Error("atproto: commit repo", "err", err)
		writeXRPCError(w, http.StatusInternalServerError, "InternalError", "commit failed")
		return
	}
	writeJSON(w, map[string]any{
		"uri":    "at://" + in.Repo + "/" + in.Collection + "/" + tid,
		"cid":    cid,
		"commit": map[string]string{"cid": commitCid, "rev": rev},
	})
}

// getRecord implements com.atproto.repo.getRecord. It reads a record back
// from the repo.
func (s *XRPCServer) getRecord(w http.ResponseWriter, r *http.Request) {
	if s.RepoFactory == nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalError", "repo factory not configured")
		return
	}
	repo := r.URL.Query().Get("repo")
	collection := r.URL.Query().Get("collection")
	rkey := r.URL.Query().Get("rkey")
	if repo == "" || collection == "" || rkey == "" {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "repo, collection, and rkey are required")
		return
	}
	t, ok := tenant.FromContext(r.Context())
	if !ok || t.DID != repo {
		writeXRPCError(w, http.StatusForbidden, "Forbidden", "repo does not belong to this tenant")
		return
	}
	rp, err := s.RepoFactory(r.Context(), repo)
	if err != nil {
		slog.Error("atproto: open repo", "err", err)
		writeXRPCError(w, http.StatusInternalServerError, "InternalError", "repo unavailable")
		return
	}
	defer func() { _ = rp.Close() }()
	_, data, err := rp.GetRecordBytes(r.Context(), collection+"/"+rkey)
	if err != nil {
		writeXRPCError(w, http.StatusNotFound, "RecordNotFound", "record not found")
		return
	}
	value, err := unwrapRecord(data)
	if err != nil {
		slog.Error("atproto: decode record", "err", err)
		writeXRPCError(w, http.StatusInternalServerError, "InternalError", "record decode failed")
		return
	}
	writeJSON(w, map[string]any{
		"uri":   "at://" + repo + "/" + collection + "/" + rkey,
		"value": json.RawMessage(value),
	})
}

// jsonRecord adapts a raw JSON record to the repo's CborMarshaler. It
// encodes the record as a proper DAG-CBOR map (canonical CBOR), so records
// of any size round-trip (A6).
type jsonRecord struct {
	data json.RawMessage
}

// MarshalCBOR encodes the JSON record as a canonical CBOR map (DAG-CBOR
// compatible for JSON-shaped data).
func (j *jsonRecord) MarshalCBOR(w io.Writer) error {
	var v any
	if err := json.Unmarshal(j.data, &v); err != nil {
		return fmt.Errorf("atproto: record is not valid JSON: %w", err)
	}
	enc, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		return fmt.Errorf("atproto: cbor encoder: %w", err)
	}
	b, err := enc.Marshal(v)
	if err != nil {
		return fmt.Errorf("atproto: encode record: %w", err)
	}
	_, err = w.Write(b)
	return err
}

// unwrapRecord decodes a DAG-CBOR record back to its original JSON form.
func unwrapRecord(data []byte) ([]byte, error) {
	var v any
	if err := cbor.Unmarshal(data, &v); err != nil {
		return nil, fmt.Errorf("atproto: decode record: %w", err)
	}
	return json.Marshal(v)
}

// uploadBlob implements com.atproto.repo.uploadBlob. It stores the request
// body as a content-addressed blob in the request tenant's backend prefix
// (A5) and returns its CID. The body is capped (audit A2).
func (s *XRPCServer) uploadBlob(w http.ResponseWriter, r *http.Request) {
	if s.Backend == nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalError", "blob backend not configured")
		return
	}
	t, ok := tenant.FromContext(r.Context())
	if !ok {
		writeXRPCError(w, http.StatusUnauthorized, "AuthRequired", "no tenant context")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBlobBytes)
	bs := NewBlobStore(s.Backend(t.ID))
	key, err := bs.Put(r.Context(), r.Body)
	if err != nil {
		slog.Error("atproto: store blob", "err", err)
		writeXRPCError(w, http.StatusInternalServerError, "InternalError", "blob storage failed")
		return
	}
	writeJSON(w, map[string]any{
		"blob": map[string]any{
			"ref":      map[string]string{"$link": key},
			"mimeType": r.Header.Get("Content-Type"),
			"size":     r.ContentLength,
		},
	})
}

// getBlob implements com.atproto.sync.getBlob. It serves a stored blob by
// its content CID from the request tenant's backend prefix (A5).
func (s *XRPCServer) getBlob(w http.ResponseWriter, r *http.Request) {
	if s.Backend == nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalError", "blob backend not configured")
		return
	}
	cid := r.URL.Query().Get("cid")
	if cid == "" {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "cid is required")
		return
	}
	t, ok := tenant.FromContext(r.Context())
	if !ok {
		writeXRPCError(w, http.StatusUnauthorized, "AuthRequired", "no tenant context")
		return
	}
	bs := NewBlobStore(s.Backend(t.ID))
	rc, err := bs.Get(r.Context(), cid)
	if err != nil {
		writeXRPCError(w, http.StatusNotFound, "BlobNotFound", "blob not found")
		return
	}
	defer func() { _ = rc.Close() }()
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = io.Copy(w, rc)
}

// getRepo implements com.atproto.sync.getRepo. It exports the repo as a CAR.
func (s *XRPCServer) getRepo(w http.ResponseWriter, r *http.Request) {
	if s.RepoFactory == nil {
		writeXRPCError(w, http.StatusInternalServerError, "InternalError", "repo factory not configured")
		return
	}
	did := r.URL.Query().Get("did")
	if did == "" {
		writeXRPCError(w, http.StatusBadRequest, "InvalidRequest", "did is required")
		return
	}
	t, ok := tenant.FromContext(r.Context())
	if !ok || t.DID != did {
		writeXRPCError(w, http.StatusForbidden, "Forbidden", "repo does not belong to this tenant")
		return
	}
	rp, err := s.RepoFactory(r.Context(), did)
	if err != nil {
		slog.Error("atproto: open repo", "err", err)
		writeXRPCError(w, http.StatusInternalServerError, "InternalError", "repo unavailable")
		return
	}
	defer func() { _ = rp.Close() }()
	w.Header().Set("Content-Type", "application/vnd.ipld.car")
	if err := rp.WriteCAR(r.Context(), w); err != nil {
		writeXRPCError(w, http.StatusNotFound, "RepoNotFound", "repo not found")
		return
	}
}

// writeJSON writes a JSON response.
func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// writeXRPCError writes an XRPC error response.
func writeXRPCError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "message": message})
}
