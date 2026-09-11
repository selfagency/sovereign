// Package proofs implements the /api/v1/me/proofs* self-service endpoints:
// list/get/create/delete the authenticated tenant's proof claims and trigger
// SSRF-safe verification of a claim. Every handler derives the tenant from the
// authenticated principal in the request context; it never accepts a tenant ID
// from the client, so a principal cannot read or mutate another tenant's
// proofs (IDOR boundary). Verification is the one place thin cross-store
// orchestration is allowed: it runs the internal/proofs verifier (which
// enforces the SSRF guard) and persists the resulting status.
package proofs

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/selfagency/sovereign/internal/api/dto"
	"github.com/selfagency/sovereign/internal/api/middleware"
	"github.com/selfagency/sovereign/internal/api/problem"
	"github.com/selfagency/sovereign/internal/proofs"
	"github.com/selfagency/sovereign/internal/store"
)

// supportedServices is the set of proof services the verifier can check.
var supportedServices = map[string]bool{
	"dns": true, "github_gist": true, "custom_url": true, "mastodon": true, "bluesky": true,
}

// Handler serves the /api/v1/me/proofs* endpoints.
type Handler struct {
	store    *store.Store
	verifier *proofs.Verifier
	logger   *slog.Logger

	// jobs is the background verification queue (audit D2): Verify enqueues
	// a claim and returns 202 pending; a worker goroutine runs the SSRF-safe
	// verifier off the request path and persists the result. AGENTS.md
	// requires SSRF-sensitive fetches to run in the background, not
	// synchronously in the request path.
	jobs chan verifyJob
	stop chan struct{}
}

// verifyJob is one queued claim verification.
type verifyJob struct {
	tenantID string
	claimID  string
}

// New builds a proofs Handler against the store and the SSRF-safe verifier.
// When verifier is nil a default is built with a strict timeout and a bounded
// redirect chain; the SSRF guard itself lives in internal/proofs. A background
// worker is started to process verification jobs; call Close to stop it.
func New(st *store.Store, verifier *proofs.Verifier, logger *slog.Logger) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	if verifier == nil {
		verifier = &proofs.Verifier{
			HTTPClient: &http.Client{
				Timeout:       10 * time.Second,
				CheckRedirect: proofs.SafeRedirect(net.DefaultResolver),
			},
			Resolver: net.DefaultResolver,
		}
	}
	h := &Handler{
		store:    st,
		verifier: verifier,
		logger:   logger,
		jobs:     make(chan verifyJob, 64),
		stop:     make(chan struct{}),
	}
	go h.worker()
	return h
}

// Close stops the background verification worker.
func (h *Handler) Close() {
	select {
	case <-h.stop:
		return // already closed
	default:
	}
	close(h.stop)
}

// worker drains the verification queue off the request path (audit D2).
func (h *Handler) worker() {
	for {
		select {
		case <-h.stop:
			return
		case job := <-h.jobs:
			h.verifyAndPersist(job)
		}
	}
}

// verifyAndPersist runs the SSRF-safe verifier for a queued claim and
// persists the resulting status. It runs in the background worker, never in
// the request path.
func (h *Handler) verifyAndPersist(job verifyJob) {
	ctx := context.Background()
	c, err := h.store.GetProofClaim(ctx, job.tenantID, job.claimID)
	if err != nil {
		h.logger.Error("proofs: background verify load", "tenant", job.tenantID, "claim", job.claimID, "err", err)
		return
	}
	res, verr := h.verifier.Verify(ctx, &proofs.Claim{
		ID:            c.ID,
		AnchorType:    c.AnchorType,
		AnchorValue:   c.AnchorValue,
		Service:       c.Service,
		ClaimLocation: c.ClaimLocation,
		ExpectedToken: c.ExpectedToken,
	})
	status := res.Status
	lastErr := ""
	if verr != nil {
		lastErr = verr.Error()
	}
	if err := h.store.UpdateProofClaimStatus(ctx, job.tenantID, c.ID, status, lastErr); err != nil {
		h.logger.Error("proofs: background verify persist", "tenant", job.tenantID, "claim", c.ID, "err", err)
	}
}

// List returns the authenticated tenant's proof claims.
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	u, ok := h.self(w, r)
	if !ok {
		return
	}
	claims, err := h.store.ListProofClaims(r.Context(), u.TenantID)
	if err != nil {
		h.logger.Error("proofs: list", "err", err)
		problem.Internal().Write(w)
		return
	}
	out := make([]dto.ProofClaim, 0, len(claims))
	for i := range claims {
		out = append(out, proofClaimDTO(&claims[i]))
	}
	writeJSON(w, http.StatusOK, out)
}

// Get returns a single proof claim by id, scoped to the principal's tenant.
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	u, ok := h.self(w, r)
	if !ok {
		return
	}
	id, ok := idFromPath(w, r)
	if !ok {
		return
	}
	c, err := h.store.GetProofClaim(r.Context(), u.TenantID, id)
	if err != nil {
		h.writeStoreErr(w, err, "get proof")
		return
	}
	writeJSON(w, http.StatusOK, proofClaimDTO(c))
}

// Create inserts a new proof claim for the principal's tenant. The claim is
// created in the "pending" state; verification is a separate step.
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	u, ok := h.self(w, r)
	if !ok {
		return
	}
	var req createReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		problem.InvalidRequest("invalid or missing body").Write(w)
		return
	}
	if err := validateCreate(&req); err != nil {
		problem.ValidationFailed([]problem.FieldError{{Field: err.field, Code: "invalid", Detail: err.detail}}).Write(w)
		return
	}
	id, err := newID()
	if err != nil {
		h.logger.Error("proofs: generate id", "err", err)
		problem.Internal().Write(w)
		return
	}
	c := &store.ProofClaim{
		ID:            id,
		TenantID:      u.TenantID,
		AccountID:     u.ID,
		AnchorType:    req.AnchorType,
		AnchorValue:   req.AnchorValue,
		Service:       req.Service,
		ClaimLocation: req.ClaimLocation,
		ExpectedToken: req.ExpectedToken,
		Status:        "pending",
		CreatedAt:     time.Now().UTC(),
	}
	if err := h.store.CreateProofClaim(r.Context(), c); err != nil {
		if errors.Is(err, store.ErrDuplicateClaim) {
			problem.Conflict().Write(w)
			return
		}
		h.logger.Error("proofs: create", "err", err)
		problem.Internal().Write(w)
		return
	}
	writeJSON(w, http.StatusCreated, proofClaimDTO(c))
}

// Delete removes a proof claim by id, scoped to the principal's tenant.
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	u, ok := h.self(w, r)
	if !ok {
		return
	}
	id, ok := idFromPath(w, r)
	if !ok {
		return
	}
	if err := h.store.DeleteProofClaim(r.Context(), u.TenantID, u.ID, id); err != nil {
		h.writeStoreErr(w, err, "delete proof")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Verify queues SSRF-safe verification of a claim by id and returns 202
// Accepted with the claim in the pending state. The actual fetch runs in a
// background worker (audit D2 / AGENTS.md: SSRF-sensitive fetches must not
// run synchronously in the request path); the persisted status is updated
// when the worker finishes. The internal/proofs verifier enforces the SSRF
// guard (DNS resolve, reject private/loopback/link-local/metadata ranges,
// bounded redirects and body size, strict timeout) before any fetch.
func (h *Handler) Verify(w http.ResponseWriter, r *http.Request) {
	u, ok := h.self(w, r)
	if !ok {
		return
	}
	id, ok := idFromPath(w, r)
	if !ok {
		return
	}
	c, err := h.store.GetProofClaim(r.Context(), u.TenantID, id)
	if err != nil {
		h.writeStoreErr(w, err, "get proof for verify")
		return
	}
	// Mark pending and enqueue; the worker persists the outcome.
	if err := h.store.UpdateProofClaimStatus(r.Context(), u.TenantID, c.ID, "pending", ""); err != nil {
		h.logger.Error("proofs: mark pending", "err", err)
		problem.Internal().Write(w)
		return
	}
	select {
	case h.jobs <- verifyJob{tenantID: u.TenantID, claimID: c.ID}:
	default:
		// Queue full: fail closed rather than silently dropping the job.
		h.logger.Error("proofs: verify queue full", "claim", c.ID)
		problem.Internal().Write(w)
		return
	}
	c.Status = "pending"
	c.LastError = ""
	writeJSON(w, http.StatusAccepted, proofClaimDTO(c))
}

// --- helpers ---

// self returns the authenticated principal's user record, or writes a 401/404
// problem and returns ok=false.
func (h *Handler) self(w http.ResponseWriter, r *http.Request) (*store.User, bool) {
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
			h.logger.Error("proofs: load user", "err", err)
			problem.Internal().Write(w)
		}
		return nil, false
	}
	return u, true
}

func (h *Handler) writeStoreErr(w http.ResponseWriter, err error, op string) {
	if errors.Is(err, store.ErrNotFound) {
		problem.NotFound().Write(w)
		return
	}
	h.logger.Error("proofs: "+op, "err", err)
	problem.Internal().Write(w)
}

// idFromPath extracts the {id} segment from the request path. ServeMux
// populates PathValue when the route is registered with a {id} pattern; for
// direct handler invocation (tests) it falls back to the path segments,
// skipping a trailing "verify" sub-path segment.
func idFromPath(w http.ResponseWriter, r *http.Request) (string, bool) {
	id := r.PathValue("id")
	if id == "" {
		seg := strings.Split(strings.TrimSuffix(r.URL.Path, "/"), "/")
		id = seg[len(seg)-1]
		if id == "verify" && len(seg) >= 2 {
			id = seg[len(seg)-2]
		}
	}
	if id == "" {
		problem.NotFound().Write(w)
		return "", false
	}
	return id, true
}

// createReq is the POST body for creating a proof claim.
type createReq struct {
	AnchorType    string `json:"anchor_type"`
	AnchorValue   string `json:"anchor_value"`
	Service       string `json:"service"`
	ClaimLocation string `json:"claim_location"`
	ExpectedToken string `json:"expected_token"`
}

// fieldError carries the field + detail for a validation failure.
type fieldError struct{ field, detail string }

func (e *fieldError) Error() string { return e.field + ": " + e.detail }

// validateCreate trims and validates a create request. All fields are
// required; service must be one the verifier supports, and non-DNS claim
// locations must be absolute http(s) URLs.
func validateCreate(req *createReq) *fieldError {
	req.AnchorType = strings.TrimSpace(req.AnchorType)
	req.AnchorValue = strings.TrimSpace(req.AnchorValue)
	req.Service = strings.TrimSpace(req.Service)
	req.ClaimLocation = strings.TrimSpace(req.ClaimLocation)
	req.ExpectedToken = strings.TrimSpace(req.ExpectedToken)
	if req.AnchorType == "" {
		return &fieldError{field: "anchor_type", detail: "anchor_type must not be empty"}
	}
	if req.AnchorValue == "" {
		return &fieldError{field: "anchor_value", detail: "anchor_value must not be empty"}
	}
	if !supportedServices[req.Service] {
		return &fieldError{field: "service", detail: "service must be one of dns, github_gist, mastodon, bluesky, custom_url"}
	}
	if req.ClaimLocation == "" {
		return &fieldError{field: "claim_location", detail: "claim_location must not be empty"}
	}
	if req.Service != "dns" && !isHTTPURL(req.ClaimLocation) {
		return &fieldError{field: "claim_location", detail: "claim_location must be an absolute http(s) URL"}
	}
	if req.ExpectedToken == "" {
		return &fieldError{field: "expected_token", detail: "expected_token must not be empty"}
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

// proofClaimDTO converts a stored claim to the wire DTO.
func proofClaimDTO(c *store.ProofClaim) dto.ProofClaim {
	return dto.ProofClaim{
		ID:        c.ID,
		UserID:    c.AccountID,
		Type:      c.AnchorType,
		Target:    c.AnchorValue,
		Status:    c.Status,
		CreatedAt: c.CreatedAt,
	}
}

// newID returns a random hex claim ID.
func newID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Reader.Read(b); err != nil {
		return "", fmt.Errorf("proofs: generate id: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
