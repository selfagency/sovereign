// Package profile implements the /api/v1/me/profile* self-service endpoints:
// read/upsert/delete the authenticated tenant's profile page, toggle
// publish/unpublish, upload/remove an avatar, and manage the ordered profile
// links. Every handler derives the tenant from the authenticated principal in
// the request context; it never accepts a tenant or profile-page ID from the
// client, so a principal cannot read or mutate another tenant's profile (IDOR
// boundary).
package profile

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/selfagency/sovereign/internal/api/dto"
	"github.com/selfagency/sovereign/internal/api/middleware"
	"github.com/selfagency/sovereign/internal/api/problem"
	"github.com/selfagency/sovereign/internal/storage"
	"github.com/selfagency/sovereign/internal/store"
)

// MaxAvatarBytes bounds an avatar upload to 2 MiB. The route body-limit
// middleware (64 KiB default) does not cover multipart avatar bodies, so the
// handler enforces its own limit via http.MaxBytesReader.
const MaxAvatarBytes = 2 * 1024 * 1024

// avatarKeyPrefix is the blob namespace for avatars. The stored key is
// "avatars/<tenant-id>/<token>.<ext>"; tenants are already isolated by the
// tenant-scoped backend prefix, so the tenant-id segment is informational.
const avatarKeyPrefix = "avatars"

// avatarURLPrefix is the public base path under which avatars are served. The
// DTO carries a full URL; this prefix keeps it stable and independently
// addressable without coupling to a CDN origin.
const avatarURLPrefix = "/api/v1/public/avatar/"

// profileIDPrefix is the ID prefix for profile pages and links.
const (
	profileIDPrefix = "profile-"
	linkIDPrefix    = "link-"
)

// Handler serves the /api/v1/me/profile* endpoints.
type Handler struct {
	store  *store.Store
	blobs  storage.Backend
	logger *slog.Logger
}

// New builds a profile Handler against the store and the blob backend.
func New(st *store.Store, blobs storage.Backend, logger *slog.Logger) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{store: st, blobs: blobs, logger: logger}
}

// Get returns the authenticated tenant's profile page, or 404 if none exists.
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	page, ok := h.selfPage(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, profilePageDTO(page))
}

// Put upserts the authenticated tenant's profile page (PUT semantics: the
// submitted display_name/bio fully replace the existing values). It creates
// the page on first write and updates in place thereafter.
func (h *Handler) Put(w http.ResponseWriter, r *http.Request) {
	u, ok := h.selfUser(w, r)
	if !ok {
		return
	}
	var req updateReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		problem.InvalidRequest("invalid or missing body").Write(w)
		return
	}
	displayName := strings.TrimSpace(req.DisplayName)
	if err := validateDisplayName(displayName); err != nil {
		problem.ValidationFailed([]problem.FieldError{{Field: "display_name", Code: "invalid", Detail: err.Error()}}).Write(w)
		return
	}
	bio := strings.TrimSpace(req.Bio)

	ctx := r.Context()
	now := time.Now().UTC()
	// Deterministic ID per tenant so re-PUTs update the same row.
	page := &store.ProfilePage{
		ID:          profileIDPrefix + u.ID,
		TenantID:    u.TenantID,
		AccountID:   u.ID,
		DisplayName: displayName,
		Bio:         bio,
		UpdatedAt:   now,
	}
	// Preserve existing publish state, avatar key, and theme unless the client
	// explicitly overrides publish state. A PUT of just display_name/bio must not
	// wipe the avatar or accidentally unpublish the page.
	if existing, err := h.store.GetProfilePage(ctx, u.TenantID); err == nil {
		page.IsPublished = existing.IsPublished
		page.AvatarBlobKey = existing.AvatarBlobKey
		page.Theme = existing.Theme
	}
	if req.IsPublished != nil {
		page.IsPublished = *req.IsPublished
	}
	if err := h.store.UpsertProfilePage(ctx, page); err != nil {
		h.logger.Error("profile: upsert", "err", err)
		problem.Internal().Write(w)
		return
	}
	writeJSON(w, http.StatusOK, profilePageDTO(page))
}

// Delete removes the authenticated tenant's profile page (cascading to its
// links).
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	u, ok := h.selfUser(w, r)
	if !ok {
		return
	}
	if err := h.store.DeleteProfilePage(r.Context(), u.TenantID); err != nil {
		h.writeStoreErr(w, err, "delete profile")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Publish marks the tenant's profile page as published.
func (h *Handler) Publish(w http.ResponseWriter, r *http.Request) {
	h.setPublished(w, r, true)
}

// Unpublish marks the tenant's profile page as unpublished.
func (h *Handler) Unpublish(w http.ResponseWriter, r *http.Request) {
	h.setPublished(w, r, false)
}

// setPublished flips the IsPublished flag on the tenant's existing profile.
func (h *Handler) setPublished(w http.ResponseWriter, r *http.Request, published bool) {
	u, ok := h.selfUser(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	page, err := h.store.GetProfilePage(ctx, u.TenantID)
	if err != nil {
		h.writeStoreErr(w, err, "get profile for publish")
		return
	}
	page.IsPublished = published
	page.UpdatedAt = time.Now().UTC()
	if err := h.store.UpsertProfilePage(ctx, page); err != nil {
		h.logger.Error("profile: set published", "err", err)
		problem.Internal().Write(w)
		return
	}
	writeJSON(w, http.StatusOK, profilePageDTO(page))
}

// UploadAvatar reads a multipart "avatar" file (max MaxAvatarBytes), stores it
// on the blob backend, records the key on the tenant's profile, and returns
// the avatar URL. Requires an existing profile page.
func (h *Handler) UploadAvatar(w http.ResponseWriter, r *http.Request) {
	u, ok := h.selfUser(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	page, err := h.store.GetProfilePage(ctx, u.TenantID)
	if err != nil {
		h.writeStoreErr(w, err, "get profile for avatar")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, MaxAvatarBytes)
	// http.MaxBytesReader above caps the total body; maxMemory only bounds the
	// in-memory buffered portion. nolint:gosec // G120 is a false positive here.
	if err := r.ParseMultipartForm(MaxAvatarBytes); err != nil { //nolint:gosec // body bounded by MaxBytesReader above

		if errors.As(err, &maxBytesErr) {
			problem.PayloadTooLarge().Write(w)
			return
		}
		problem.InvalidRequest("invalid multipart body").Write(w)
		return
	}
	file, _, err := r.FormFile("avatar")
	if err != nil {
		problem.InvalidRequest("missing avatar file").Write(w)
		return
	}
	defer func() { _ = file.Close() }()

	key := avatarKeyPrefix + "/" + u.TenantID + "/" + strconv.FormatInt(time.Now().UnixNano(), 36) + ".bin"
	blob, err := h.blobs.Put(ctx, key, file, "application/octet-stream")
	if err != nil {
		h.logger.Error("profile: avatar put", "err", err)
		problem.Internal().Write(w)
		return
	}
	page.AvatarBlobKey = blob.Key
	page.UpdatedAt = time.Now().UTC()
	if err := h.store.UpsertProfilePage(ctx, page); err != nil {
		h.logger.Error("profile: save avatar key", "err", err)
		problem.Internal().Write(w)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"avatar_url": avatarURL(blob.Key)})
}

// DeleteAvatar removes the tenant's avatar blob and clears the profile's key.
func (h *Handler) DeleteAvatar(w http.ResponseWriter, r *http.Request) {
	u, ok := h.selfUser(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	page, err := h.store.GetProfilePage(ctx, u.TenantID)
	if err != nil {
		h.writeStoreErr(w, err, "get profile for avatar delete")
		return
	}
	if page.AvatarBlobKey != "" {
		_ = h.blobs.Delete(ctx, page.AvatarBlobKey)
	}
	page.AvatarBlobKey = ""
	page.UpdatedAt = time.Now().UTC()
	if err := h.store.UpsertProfilePage(ctx, page); err != nil {
		h.logger.Error("profile: clear avatar key", "err", err)
		problem.Internal().Write(w)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ListLinks returns the authenticated tenant's profile links ordered by
// position.
func (h *Handler) ListLinks(w http.ResponseWriter, r *http.Request) {
	page, ok := h.selfPage(w, r)
	if !ok {
		return
	}
	links, err := h.store.ListProfileLinks(r.Context(), page.ID)
	if err != nil {
		h.logger.Error("profile: list links", "err", err)
		problem.Internal().Write(w)
		return
	}
	out := make([]dto.ProfileLink, 0, len(links))
	for i := range links {
		out = append(out, profileLinkDTO(&links[i]))
	}
	writeJSON(w, http.StatusOK, out)
}

// AddLink appends a link to the authenticated tenant's profile. A profile
// page must exist first.
func (h *Handler) AddLink(w http.ResponseWriter, r *http.Request) {
	page, ok := h.selfPage(w, r)
	if !ok {
		return
	}
	var req linkReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		problem.InvalidRequest("invalid or missing body").Write(w)
		return
	}
	if req.Label == nil || req.URL == nil {
		problem.ValidationFailed([]problem.FieldError{{Field: "body", Code: "missing", Detail: "label and url are required"}}).Write(w)
		return
	}
	if err := validateLink(req); err != nil {
		problem.ValidationFailed([]problem.FieldError{{Field: err.field, Code: "invalid", Detail: err.detail}}).Write(w)
		return
	}
	ctx := r.Context()
	links, err := h.store.ListProfileLinks(ctx, page.ID)
	if err != nil {
		h.logger.Error("profile: list links for position", "err", err)
		problem.Internal().Write(w)
		return
	}
	l := &store.ProfileLink{
		ID:            linkIDPrefix + strconv.FormatInt(time.Now().UnixNano(), 36),
		ProfilePageID: page.ID,
		Position:      len(links),
		Kind:          "custom",
		Label:         strings.TrimSpace(*req.Label),
		URL:           strings.TrimSpace(*req.URL),
		IsVisible:     true,
		CreatedAt:     time.Now().UTC(),
	}
	if err := h.store.AddProfileLink(ctx, l); err != nil {
		h.logger.Error("profile: add link", "err", err)
		problem.Internal().Write(w)
		return
	}
	writeJSON(w, http.StatusCreated, profileLinkDTO(l))
}

// UpdateLink patches an existing link on the authenticated tenant's profile.
func (h *Handler) UpdateLink(w http.ResponseWriter, r *http.Request) {
	page, ok := h.selfPage(w, r)
	if !ok {
		return
	}
	linkID, ok := linkIDFromPath(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	existing, err := h.linkByID(ctx, page.ID, linkID)
	if err != nil {
		h.writeStoreErr(w, err, "get link for update")
		return
	}
	var req linkReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		problem.InvalidRequest("invalid or missing body").Write(w)
		return
	}
	if req.Label != nil {
		existing.Label = strings.TrimSpace(*req.Label)
	}
	if req.URL != nil {
		existing.URL = strings.TrimSpace(*req.URL)
	}
	if err := validateLink(linkReq{Label: &existing.Label, URL: &existing.URL}); err != nil {
		problem.ValidationFailed([]problem.FieldError{{Field: err.field, Code: "invalid", Detail: err.detail}}).Write(w)
		return
	}
	if err := h.store.UpdateProfileLink(ctx, page.ID, linkID, existing); err != nil {
		h.writeStoreErr(w, err, "update link")
		return
	}
	writeJSON(w, http.StatusOK, profileLinkDTO(existing))
}

// DeleteLink removes a link from the authenticated tenant's profile.
func (h *Handler) DeleteLink(w http.ResponseWriter, r *http.Request) {
	page, ok := h.selfPage(w, r)
	if !ok {
		return
	}
	linkID, ok := linkIDFromPath(w, r)
	if !ok {
		return
	}
	if err := h.store.DeleteProfileLink(r.Context(), page.ID, linkID); err != nil {
		h.writeStoreErr(w, err, "delete link")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ReorderLinks atomically sets the position of each link by the ordered ID
// list supplied in the body. IDs not present are left unchanged; returns the
// resulting ordered list.
func (h *Handler) ReorderLinks(w http.ResponseWriter, r *http.Request) {
	page, ok := h.selfPage(w, r)
	if !ok {
		return
	}
	var req reorderReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		problem.InvalidRequest("invalid or missing body").Write(w)
		return
	}
	ctx := r.Context()
	if err := h.store.ReorderProfileLinks(ctx, page.ID, req.IDs); err != nil {
		h.logger.Error("profile: reorder links", "err", err)
		problem.Internal().Write(w)
		return
	}
	links, err := h.store.ListProfileLinks(ctx, page.ID)
	if err != nil {
		h.logger.Error("profile: list after reorder", "err", err)
		problem.Internal().Write(w)
		return
	}
	out := make([]dto.ProfileLink, 0, len(links))
	for i := range links {
		out = append(out, profileLinkDTO(&links[i]))
	}
	writeJSON(w, http.StatusOK, out)
}

// --- helpers ---

// selfUser returns the authenticated principal's user record.
func (h *Handler) selfUser(w http.ResponseWriter, r *http.Request) (*store.User, bool) {
	p := middleware.PrincipalFromContext(r.Context())
	if p == nil {
		problem.Unauthenticated().Write(w)
		return nil, false
	}
	u, err := h.store.UserByID(r.Context(), p.UserID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			problem.NotFound().Write(w)
		} else {
			h.logger.Error("profile: load user", "err", err)
			problem.Internal().Write(w)
		}
		return nil, false
	}
	return u, true
}

// selfPage returns the authenticated tenant's profile page.
func (h *Handler) selfPage(w http.ResponseWriter, r *http.Request) (*store.ProfilePage, bool) {
	u, ok := h.selfUser(w, r)
	if !ok {
		return nil, false
	}
	page, err := h.store.GetProfilePage(r.Context(), u.TenantID)
	if err != nil {
		h.writeStoreErr(w, err, "get profile")
		return nil, false
	}
	return page, true
}

// linkByID finds a link belonging to the given profile page.
func (h *Handler) linkByID(ctx context.Context, pageID, linkID string) (*store.ProfileLink, error) {
	links, err := h.store.ListProfileLinks(ctx, pageID)
	if err != nil {
		return nil, err
	}
	for i := range links {
		if links[i].ID == linkID {
			return &links[i], nil
		}
	}
	return nil, store.ErrNotFound
}

func (h *Handler) writeStoreErr(w http.ResponseWriter, err error, op string) {
	if errors.Is(err, store.ErrNotFound) {
		problem.NotFound().Write(w)
		return
	}
	h.logger.Error("profile: "+op, "err", err)
	problem.Internal().Write(w)
}

// linkIDFromPath extracts the {id} segment from the request path. ServeMux
// populates PathValue when the route is registered with a {id} pattern; for
// direct handler invocation (tests) it falls back to the last path segment.
func linkIDFromPath(w http.ResponseWriter, r *http.Request) (string, bool) {
	id := r.PathValue("id")
	if id == "" {
		seg := strings.Split(strings.TrimSuffix(r.URL.Path, "/"), "/")
		id = seg[len(seg)-1]
	}
	if id == "" {
		problem.NotFound().Write(w)
		return "", false
	}
	return id, true
}

// avatarURL maps a blob key to its public URL.
func avatarURL(key string) string {
	return avatarURLPrefix + url.PathEscape(key)
}

// validateDisplayName rejects empty or overlong display names.
func validateDisplayName(name string) error {
	if name == "" {
		return errors.New("display_name must not be empty")
	}
	if len(name) > 100 {
		return errors.New("display_name exceeds maximum length")
	}
	return nil
}

// linkFieldError carries the field + detail for a link validation failure.
type linkFieldError struct{ field, detail string }

func (e *linkFieldError) Error() string { return e.field + ": " + e.detail }

// validateLink ensures label is present and URL is a valid absolute http(s)
// URL. label/url are pointers so partial PATCH bodies validate only the
// present fields.
func validateLink(req linkReq) *linkFieldError {
	if req.Label != nil && strings.TrimSpace(*req.Label) == "" {
		return &linkFieldError{field: "label", detail: "label must not be empty"}
	}
	if req.URL != nil {
		u := strings.TrimSpace(*req.URL)
		if !isHTTPURL(u) {
			return &linkFieldError{field: "url", detail: "url must be an absolute http(s) URL"}
		}
	}
	return nil
}

func isHTTPURL(raw string) bool {
	if raw == "" {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	return (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

// profilePageDTO converts a stored page to the wire DTO.
func profilePageDTO(p *store.ProfilePage) dto.ProfilePage {
	return dto.ProfilePage{
		ID:          p.ID,
		UserID:      p.AccountID,
		DisplayName: p.DisplayName,
		Bio:         p.Bio,
		AvatarURL:   avatarURL(p.AvatarBlobKey),
		IsPublished: p.IsPublished,
		UpdatedAt:   p.UpdatedAt,
	}
}

func profileLinkDTO(l *store.ProfileLink) dto.ProfileLink {
	return dto.ProfileLink{
		ID:        l.ID,
		Label:     l.Label,
		URL:       l.URL,
		Position:  l.Position,
		CreatedAt: l.CreatedAt,
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// maxBytesErr is used to detect an oversize multipart body.
var maxBytesErr = &http.MaxBytesError{}

// updateReq is the PUT body for upserting a profile page. IsPublished is a
// pointer so an omitted field preserves the current publish state.
type updateReq struct {
	DisplayName string `json:"display_name"`
	Bio         string `json:"bio"`
	IsPublished *bool  `json:"is_published"`
}

// linkReq is the create/update body for a profile link. Pointer fields on
// update distinguish omitted from empty.
type linkReq struct {
	Label *string `json:"label"`
	URL   *string `json:"url"`
}

// reorderReq is the body for reordering links.
type reorderReq struct {
	IDs []string `json:"ids"`
}
