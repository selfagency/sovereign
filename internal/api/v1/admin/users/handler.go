// Package users implements the /api/v1/admin/users* instance-admin endpoints
// for managing users across every tenant: list, create (+invite), get by id,
// update, delete, create an invite, list WebAuthn credentials, and revoke a
// user's sessions. Admin is INSTANCE-scoped. Email sending for invites happens
// INSIDE the idempotent create handlers so a retried request does not send a
// second email. The raw invite token is emailed; only its hash is persisted.
// Authorization is enforced by the scope middleware (admin:users:* + IsAdmin);
// the handlers additionally require an admin principal as defense-in-depth.
package users

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/selfagency/sovereign/internal/api/dto"
	"github.com/selfagency/sovereign/internal/api/middleware"
	"github.com/selfagency/sovereign/internal/api/problem"
	"github.com/selfagency/sovereign/internal/mail"
	"github.com/selfagency/sovereign/internal/store"
)

// inviteTTL is the lifetime of a one-time magic-link invite token.
const inviteTTL = 24 * time.Hour

// identityTenant is the tenant ID users are created into by default.
const identityTenant = "identity"

// Handler serves the /api/v1/admin/users* endpoints.
type Handler struct {
	store   *store.Store
	sender  mail.Sender
	baseURL string // e.g. https://id.example.com
	logger  *slog.Logger
}

// New builds an admin users Handler. sender delivers invite emails; baseURL is
// the identity-host base used to build magic links.
func New(st *store.Store, sender mail.Sender, baseURL string, logger *slog.Logger) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{store: st, sender: sender, baseURL: baseURL, logger: logger}
}

// createReq is the body for creating a user.
type createReq struct {
	TenantID    string `json:"tenant_id"`
	Handle      string `json:"handle"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
	IsAdmin     bool   `json:"is_admin"`
}

// createResp is the create-user response (invite link is NOT included; the raw
// token is only emailed).
type createResp struct {
	User dto.User `json:"user"`
}

// inviteResp reports a created invite (the raw token is never returned; it is
// only emailed).
type inviteResp struct {
	UserID string `json:"user_id"`
}

// List returns a page of users across ALL tenants, newest first, with the
// total count. limit and offset are read from the query string (defaults:
// limit 100, offset 0).
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.admin(w, r); !ok {
		return
	}
	limit, offset := 100, 0
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			problem.ValidationFailed([]problem.FieldError{{Field: "limit", Code: "invalid", Detail: "limit must be a non-negative integer"}}).Write(w)
			return
		}
		limit = n
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			problem.ValidationFailed([]problem.FieldError{{Field: "offset", Code: "invalid", Detail: "offset must be a non-negative integer"}}).Write(w)
			return
		}
		offset = n
	}
	rows, total, err := h.store.ListAllUsersPage(r.Context(), limit, offset)
	if err != nil {
		h.logger.Error("admin: users list", "err", err)
		problem.Internal().Write(w)
		return
	}
	out := make([]dto.User, 0, len(rows))
	for i := range rows {
		out = append(out, userDTO(&rows[i]))
	}
	writeJSON(w, http.StatusOK, dto.List[dto.User]{Data: out, Offset: offset, Limit: limit, Total: total})
}

// Create creates a user and sends a one-time magic-link invite. Both the user
// creation and the invite email happen inside the idempotent handler so a
// replayed request (same Idempotency-Key) does not create a duplicate user or
// send a second email. Returns 201 with the created user.
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.admin(w, r); !ok {
		return
	}
	var req createReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		problem.InvalidRequest("invalid or missing body").Write(w)
		return
	}
	req.Handle = strings.TrimSpace(req.Handle)
	req.Email = strings.TrimSpace(req.Email)
	req.DisplayName = strings.TrimSpace(req.DisplayName)
	if req.Handle == "" || req.Email == "" {
		problem.ValidationFailed([]problem.FieldError{{Field: "body", Code: "invalid", Detail: "handle and email are required"}}).Write(w)
		return
	}
	if req.TenantID == "" {
		req.TenantID = identityTenant
	}
	uid, err := newID()
	if err != nil {
		h.logger.Error("admin: users create id", "err", err)
		problem.Internal().Write(w)
		return
	}
	u := &store.User{
		ID:          uid,
		TenantID:    req.TenantID,
		Handle:      req.Handle,
		Email:       req.Email,
		DisplayName: req.DisplayName,
		IsAdmin:     req.IsAdmin,
	}
	if err := h.store.CreateUser(r.Context(), u); err != nil {
		if errors.Is(err, store.ErrDuplicateUser) {
			problem.Conflict().Write(w)
			return
		}
		h.logger.Error("admin: users create", "err", err)
		problem.Internal().Write(w)
		return
	}
	if err := h.sendInvite(r, u.ID, u.Email); err != nil {
		// The user was created but the invite could not be sent. Return an
		// error so the caller knows to retry with a fresh key; the store is
		// idempotent on the user by handle, so a retry is safe.
		h.logger.Error("admin: users invite", "err", err)
		problem.Internal().Write(w)
		return
	}
	writeJSON(w, http.StatusCreated, createResp{User: userDTO(u)})
}

// GetByID returns a single user by ID, or 404 when missing.
func (h *Handler) GetByID(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.admin(w, r); !ok {
		return
	}
	id, ok := pathValue(w, r, "id")
	if !ok {
		return
	}
	u, err := h.store.UserByID(r.Context(), id)
	if err != nil {
		h.writeStoreErr(w, err, "get user by id")
		return
	}
	writeJSON(w, http.StatusOK, userDTO(u))
}

// updateReq is the body for updating a user.
type updateReq struct {
	IsAdmin     *bool  `json:"is_admin"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
}

// Update updates a user's admin flag, email, and/or display name. Any subset of
// fields may be provided; omitted fields are left unchanged. Returns 200 with
// the updated user.
func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.admin(w, r); !ok {
		return
	}
	id, ok := pathValue(w, r, "id")
	if !ok {
		return
	}
	var req updateReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		problem.InvalidRequest("invalid or missing body").Write(w)
		return
	}
	if _, err := h.store.UserByID(r.Context(), id); err != nil {
		h.writeStoreErr(w, err, "update user")
		return
	}
	if !h.applyUserUpdate(w, r, id, req) {
		return
	}
	u, err := h.store.UserByID(r.Context(), id)
	if err != nil {
		h.writeStoreErr(w, err, "update user")
		return
	}
	writeJSON(w, http.StatusOK, userDTO(u))
}

// Delete removes a user and all of their data. Returns 204 on success, 404 when
// missing.
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.admin(w, r); !ok {
		return
	}
	id, ok := pathValue(w, r, "id")
	if !ok {
		return
	}
	if err := h.store.DeleteUser(r.Context(), id); err != nil {
		h.writeStoreErr(w, err, "delete user")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// CreateInvite creates a one-time magic-link invite for an existing user and
// emails it. The email is sent inside the idempotent handler so a replay does
// not send a second one. Returns 201 with the user ID.
func (h *Handler) CreateInvite(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.admin(w, r); !ok {
		return
	}
	id, ok := pathValue(w, r, "id")
	if !ok {
		return
	}
	u, err := h.store.UserByID(r.Context(), id)
	if err != nil {
		h.writeStoreErr(w, err, "create invite")
		return
	}
	if err := h.sendInvite(r, u.ID, u.Email); err != nil {
		h.logger.Error("admin: users invite", "err", err)
		problem.Internal().Write(w)
		return
	}
	writeJSON(w, http.StatusCreated, inviteResp{UserID: u.ID})
}

// ListCredentials returns a user's WebAuthn passkeys as public metadata only.
func (h *Handler) ListCredentials(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.admin(w, r); !ok {
		return
	}
	id, ok := pathValue(w, r, "id")
	if !ok {
		return
	}
	if _, err := h.store.UserByID(r.Context(), id); err != nil {
		h.writeStoreErr(w, err, "list credentials")
		return
	}
	rows, err := h.store.ListWebAuthnCredentials(r.Context(), id)
	if err != nil {
		h.logger.Error("admin: users credentials", "err", err)
		problem.Internal().Write(w)
		return
	}
	out := make([]dto.WebAuthnCredential, 0, len(rows))
	for i := range rows {
		out = append(out, credentialDTO(&rows[i]))
	}
	writeJSON(w, http.StatusOK, out)
}

// RevokeSessions revokes every server-side session for a user. Returns 200.
func (h *Handler) RevokeSessions(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.admin(w, r); !ok {
		return
	}
	id, ok := pathValue(w, r, "id")
	if !ok {
		return
	}
	if _, err := h.store.UserByID(r.Context(), id); err != nil {
		h.writeStoreErr(w, err, "revoke user sessions")
		return
	}
	if err := h.store.RevokeUserSessions(r.Context(), id); err != nil {
		h.logger.Error("admin: users revoke sessions", "err", err)
		problem.Internal().Write(w)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"revoked": true})
}

// --- helpers ---

// applyUserUpdate applies the subset of updateReq fields that are present,
// writing a problem response and returning false on the first failure. It is
// extracted from Update to keep the handler's branching flat.
func (h *Handler) applyUserUpdate(w http.ResponseWriter, r *http.Request, id string, req updateReq) bool {
	if req.IsAdmin != nil {
		if err := h.store.SetUserAdmin(r.Context(), id, *req.IsAdmin); err != nil {
			h.writeStoreErr(w, err, "update user admin")
			return false
		}
	}
	if req.Email != "" {
		if err := h.store.SetUserEmail(r.Context(), id, req.Email); err != nil {
			h.writeStoreErr(w, err, "update user email")
			return false
		}
	}
	if req.DisplayName != "" {
		if err := h.store.SetUserDisplayName(r.Context(), id, req.DisplayName); err != nil {
			h.writeStoreErr(w, err, "update user display name")
			return false
		}
	}
	return true
}

// sendInvite creates a one-time magic link for the user, persists its hash,
// and emails the raw token to the user's address.
func (h *Handler) sendInvite(r *http.Request, userID, email string) error {
	raw, err := newID()
	if err != nil {
		return err
	}
	itID, err := newID()
	if err != nil {
		return err
	}
	it := &store.InviteToken{
		ID:        itID,
		TokenHash: hashToken(raw),
		UserID:    userID,
		ExpiresAt: time.Now().Add(inviteTTL),
	}
	if err := h.store.CreateInviteToken(r.Context(), it); err != nil {
		return err
	}
	link := strings.TrimSuffix(h.baseURL, "/") + "/invite/" + raw
	return h.sender.Send(r.Context(), mail.Message{
		To:      email,
		Subject: "Your Sovereign invite",
		Body:    "Welcome to Sovereign. Set up your account here:\n\n" + link,
	})
}

func (h *Handler) writeStoreErr(w http.ResponseWriter, err error, op string) {
	if errors.Is(err, store.ErrNotFound) {
		problem.NotFound().Write(w)
		return
	}
	h.logger.Error("admin: users "+op, "err", err)
	problem.Internal().Write(w)
}

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

// pathValue extracts the named path segment, falling back to the last path
// segment for direct handler invocation in tests.
func pathValue(w http.ResponseWriter, r *http.Request, name string) (string, bool) {
	v := r.PathValue(name)
	if v == "" {
		seg := splitPath(r.URL.Path)
		v = seg[len(seg)-1]
	}
	if v == "" {
		problem.NotFound().Write(w)
		return "", false
	}
	return v, true
}

func splitPath(p string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(p); i++ {
		if i == len(p) || p[i] == '/' {
			if i > start {
				out = append(out, p[start:i])
			}
			start = i + 1
		}
	}
	return out
}

func userDTO(u *store.User) dto.User {
	return dto.User{
		ID:          u.ID,
		TenantID:    u.TenantID,
		Handle:      u.Handle,
		Email:       u.Email,
		DisplayName: u.DisplayName,
		IsAdmin:     u.IsAdmin,
		TOSAccepted: u.ToSAccepted,
		CreatedAt:   u.CreatedAt,
	}
}

func credentialDTO(c *store.WebAuthnCredential) dto.WebAuthnCredential {
	return dto.WebAuthnCredential{
		ID:           c.ID,
		CredentialID: base64.RawURLEncoding.EncodeToString(c.CredentialID),
		CreatedAt:    c.CreatedAt,
	}
}

// newID returns a random URL-safe token.
func newID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Reader.Read(b); err != nil {
		return "", errors.New("admin: users: crypto/rand unavailable")
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// hashToken returns the hex SHA-256 hash of a token.
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
