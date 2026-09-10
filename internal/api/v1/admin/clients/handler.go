// Package clients implements the /api/v1/admin/clients* instance-admin
// endpoints for managing OIDC clients: list, get by id, create, delete, and
// rotate the client secret. Admin is INSTANCE-scoped. Client secrets are
// argon2id-hashed in the store and are show-once only: the plaintext is
// returned a single time by create and rotate, never re-readable.
package clients

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/selfagency/sovereign/internal/api/dto"
	"github.com/selfagency/sovereign/internal/api/middleware"
	"github.com/selfagency/sovereign/internal/api/problem"
	"github.com/selfagency/sovereign/internal/store"
)

// Handler serves the /api/v1/admin/clients* endpoints.
type Handler struct {
	store  *store.Store
	logger *slog.Logger
}

// New builds an admin clients Handler.
func New(st *store.Store, logger *slog.Logger) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{store: st, logger: logger}
}

// createReq is the body for creating a client. ID is required.
type createReq struct {
	ID string `json:"id"`
}

// ListClients returns all OIDC clients. The secret (and its argon2id hash) is
// never part of the response.
func (h *Handler) ListClients(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.admin(w, r); !ok {
		return
	}
	rows, err := h.store.ListClients(r.Context())
	if err != nil {
		h.logger.Error("clients: list", "err", err)
		problem.Internal().Write(w)
		return
	}
	out := make([]dto.Client, 0, len(rows))
	for i := range rows {
		out = append(out, clientDTO(&rows[i]))
	}
	writeJSON(w, http.StatusOK, dto.List[dto.Client]{Data: out, Offset: 0, Limit: len(out), Total: len(out)})
}

// ClientByID returns a single client by its ID, or 404 when missing. The
// secret is never included.
func (h *Handler) ClientByID(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.admin(w, r); !ok {
		return
	}
	id, ok := pathValue(w, r, "id")
	if !ok {
		return
	}
	c, err := h.store.ClientByID(r.Context(), id)
	if err != nil {
		h.writeStoreErr(w, err, "get client by id")
		return
	}
	writeJSON(w, http.StatusOK, clientDTO(c))
}

// CreateClient validates and stores a new client with a freshly generated
// secret. The plaintext secret is returned exactly once (201); it can never be
// read again. Returns 409 when the client ID already exists.
func (h *Handler) CreateClient(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.admin(w, r); !ok {
		return
	}
	var req createReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		problem.InvalidRequest("invalid or missing body").Write(w)
		return
	}
	req.ID = strings.TrimSpace(req.ID)
	if req.ID == "" {
		problem.ValidationFailed([]problem.FieldError{{Field: "id", Code: "invalid", Detail: "id is required"}}).Write(w)
		return
	}
	secret := newSecret()
	c := &store.Client{ID: req.ID, Secret: secret}
	if err := h.store.CreateClient(r.Context(), c); err != nil {
		if errors.Is(err, store.ErrDuplicateClient) {
			problem.Conflict().Write(w)
			return
		}
		h.logger.Error("clients: create", "err", err)
		problem.Internal().Write(w)
		return
	}
	writeJSON(w, http.StatusCreated, struct {
		Client dto.Client `json:"client"`
		Secret string     `json:"secret"`
	}{
		Client: clientDTO(c),
		Secret: secret,
	})
}

// DeleteClient removes a client by ID. Returns 204 on success, 404 when the
// client does not exist.
func (h *Handler) DeleteClient(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.admin(w, r); !ok {
		return
	}
	id, ok := pathValue(w, r, "id")
	if !ok {
		return
	}
	if err := h.store.DeleteClient(r.Context(), id); err != nil {
		h.writeStoreErr(w, err, "delete client")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// RotateSecret generates a new plaintext client secret, hashes and stores it
// via SetClientSecret, and returns the plaintext once (200). The returned
// value is never re-readable: a subsequent get/list excludes it, and the
// previous secret no longer verifies. Returns 404 when the client is missing.
func (h *Handler) RotateSecret(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.admin(w, r); !ok {
		return
	}
	id, ok := pathValue(w, r, "id")
	if !ok {
		return
	}
	secret := newSecret()
	if err := h.store.SetClientSecret(r.Context(), id, secret); err != nil {
		h.writeStoreErr(w, err, "rotate client secret")
		return
	}
	writeJSON(w, http.StatusOK, struct {
		Secret string `json:"secret"`
	}{Secret: secret})
}

// --- helpers ---

// admin returns the authenticated principal, requiring it to be an instance
// admin. It writes 401 when unauthenticated and 403 when the principal is not
// an admin. Defense-in-depth beyond the scope middleware.
func (h *Handler) admin(w http.ResponseWriter, r *http.Request) (*middleware.Principal, bool) {
	p := middleware.PrincipalFromContext(r.Context())
	if p == nil {
		problem.Unauthenticated().Write(w)
		return nil, false
	}
	if !p.IsAdmin {
		problem.Forbidden().Write(w)
		return nil, false
	}
	return p, true
}

func (h *Handler) writeStoreErr(w http.ResponseWriter, err error, op string) {
	if errors.Is(err, store.ErrNotFound) {
		problem.NotFound().Write(w)
		return
	}
	h.logger.Error("clients: "+op, "err", err)
	problem.Internal().Write(w)
}

// pathValue extracts the named path segment, falling back to the last path
// segment for direct handler invocation in tests. The :rotate suffix is
// stripped from the id.
func pathValue(w http.ResponseWriter, r *http.Request, name string) (string, bool) {
	v := r.PathValue(name)
	if v == "" {
		seg := strings.Split(strings.TrimSuffix(r.URL.Path, "/"), "/")
		v = seg[len(seg)-1]
	}
	v = strings.TrimSuffix(v, ":rotate")
	if v == "" {
		problem.NotFound().Write(w)
		return "", false
	}
	return v, true
}

// newSecret returns a fresh 32-byte base64url client secret (matching the CLI
// set-secret generation).
func newSecret() string {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		// crypto/rand never fails on supported platforms.
		panic("clients: crypto/rand unavailable")
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

// clientDTO converts a stored client to the wire DTO, omitting the secret and
// its hash. The store model carries redirect URIs and scopes rather than a
// display name/audience; the DTO's name/audience fields are left empty.
func clientDTO(c *store.Client) dto.Client {
	return dto.Client{
		ID:        c.ID,
		CreatedAt: c.CreatedAt,
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
