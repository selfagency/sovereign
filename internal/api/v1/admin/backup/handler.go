// Package backup implements the /api/v1/admin/backup* instance-admin
// endpoints: read/update the backup config (which genuinely persists and
// drives the backup.Scheduler), list/trigger backup runs, fetch a run by id,
// and trigger restores. Runs and restores are LONG-RUNNING (declared in the
// route-table timeout column, so the default per-route timeout never kills
// them) and require an Idempotency-Key so a replay does not double-run.
//
// Admin is INSTANCE-scoped. The handlers require an admin principal as
// defense-in-depth beyond the scope middleware.
package backup

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/selfagency/sovereign/internal/api/dto"
	"github.com/selfagency/sovereign/internal/api/middleware"
	"github.com/selfagency/sovereign/internal/api/problem"
	"github.com/selfagency/sovereign/internal/backup"
	"github.com/selfagency/sovereign/internal/storage"
	"github.com/selfagency/sovereign/internal/store"
)

// Handler serves the /api/v1/admin/backup* endpoints. It owns the current
// backup.Scheduler so a config PUT can stop the old scheduler and start a new
// one with the persisted config.
type Handler struct {
	store  *store.Store
	logger *slog.Logger

	mu    sync.Mutex
	sched *backup.Scheduler
	// backupFn produces the backup bytes for a freshly built scheduler.
	backupFn func(ctx context.Context) (io.Reader, error)
	// backend is the blob backend used to build the destination.
	backend storage.Backend
}

// New builds an admin backup Handler. sched is the initial scheduler; backupFn
// and backend are the factory inputs used to rebuild the scheduler when the
// config changes.
func New(st *store.Store, logger *slog.Logger, sched *backup.Scheduler, backupFn func(ctx context.Context) (io.Reader, error), backend storage.Backend) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{store: st, logger: logger, sched: sched, backupFn: backupFn, backend: backend}
}

// configReq is the body for PUT /admin/backup/config.
type configReq struct {
	Schedule    string `json:"schedule"`
	Destination string `json:"destination"`
	Prefix      string `json:"prefix"`
}

// restoreReq is the body for POST /admin/backup/restores.
type restoreReq struct {
	SourceKey string `json:"source_key"`
	Confirm   bool   `json:"confirm"`
}

// GetConfig returns the persisted backup config, or 404 when none has been
// saved yet.
func (h *Handler) GetConfig(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.admin(w, r); !ok {
		return
	}
	cfg, err := h.store.GetBackupConfig(r.Context())
	if err != nil {
		h.writeStoreErr(w, err, "get backup config")
		return
	}
	writeJSON(w, http.StatusOK, configDTO(cfg))
}

// PutConfig validates, persists, and applies a new backup config. On success
// it stops the current scheduler and starts a new one with the persisted
// config, so the config genuinely drives the scheduler (A3). Returns 422 on
// validation failure.
func (h *Handler) PutConfig(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.admin(w, r); !ok {
		return
	}
	var req configReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		problem.InvalidRequest("invalid or missing body").Write(w)
		return
	}
	req.Schedule = strings.TrimSpace(req.Schedule)
	req.Destination = strings.TrimSpace(req.Destination)
	req.Prefix = strings.TrimSpace(req.Prefix)
	if err := validateConfig(&req); err != nil {
		problem.ValidationFailed([]problem.FieldError{{Field: "body", Code: "invalid", Detail: err.Error()}}).Write(w)
		return
	}
	if err := h.store.UpsertBackupConfig(r.Context(), req.Schedule, req.Destination, req.Prefix); err != nil {
		h.logger.Error("backup: persist config", "err", err)
		problem.Internal().Write(w)
		return
	}
	if err := h.restartScheduler(req.Schedule, req.Destination, req.Prefix); err != nil {
		h.logger.Error("backup: restart scheduler", "err", err)
		problem.Internal().Write(w)
		return
	}
	cfg, err := h.store.GetBackupConfig(r.Context())
	if err != nil {
		h.writeStoreErr(w, err, "get backup config")
		return
	}
	writeJSON(w, http.StatusOK, configDTO(cfg))
}

// ListRuns returns a page of backup runs (newest first) with the total count.
func (h *Handler) ListRuns(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.admin(w, r); !ok {
		return
	}
	limit, offset, ok := pageParams(w, r)
	if !ok {
		return
	}
	rows, total, err := h.store.ListBackupRuns(r.Context(), limit, offset)
	if err != nil {
		h.logger.Error("backup: list runs", "err", err)
		problem.Internal().Write(w)
		return
	}
	out := make([]dto.BackupRun, 0, len(rows))
	for i := range rows {
		out = append(out, runDTO(&rows[i]))
	}
	writeJSON(w, http.StatusOK, dto.List[dto.BackupRun]{Data: out, Offset: offset, Limit: limit, Total: total})
}

// RunByID returns a single backup run by id, or 404 when missing.
func (h *Handler) RunByID(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.admin(w, r); !ok {
		return
	}
	id, ok := pathValue(w, r, "id")
	if !ok {
		return
	}
	run, err := h.store.BackupRunByID(r.Context(), id)
	if err != nil {
		h.writeStoreErr(w, err, "get backup run by id")
		return
	}
	writeJSON(w, http.StatusOK, runDTO(run))
}

// TriggerRun runs a backup now, synchronously, and records the outcome as a
// backup_runs row. It is LONG-RUNNING and requires an Idempotency-Key so a
// replay returns the original result instead of double-running. Returns 201
// with the completed run.
func (h *Handler) TriggerRun(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.admin(w, r); !ok {
		return
	}
	run := &store.BackupRun{
		ID:        newRunID(),
		StartedAt: time.Now().UTC(),
		Status:    "running",
	}
	if err := h.store.CreateBackupRun(r.Context(), run); err != nil {
		h.logger.Error("backup: create run", "err", err)
		problem.Internal().Write(w)
		return
	}

	key, _, err := h.currentScheduler().RunNow(r.Context())
	if err != nil {
		msg := err.Error()
		run.Status = "failed"
		run.Error = &msg
		_ = h.store.UpdateBackupRun(r.Context(), run.ID, "failed", msg, 0, "")
		writeJSON(w, http.StatusCreated, runDTO(run))
		return
	}
	run.Status = "succeeded"
	run.DestinationKey = key
	_ = h.store.UpdateBackupRun(r.Context(), run.ID, "succeeded", "", 0, key)
	writeJSON(w, http.StatusCreated, runDTO(run))
}

// ListRestores returns a page of restore executions (newest first) with the
// total count.
func (h *Handler) ListRestores(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.admin(w, r); !ok {
		return
	}
	limit, offset, ok := pageParams(w, r)
	if !ok {
		return
	}
	rows, total, err := h.store.ListBackupRestores(r.Context(), limit, offset)
	if err != nil {
		h.logger.Error("backup: list restores", "err", err)
		problem.Internal().Write(w)
		return
	}
	out := make([]dto.BackupRestore, 0, len(rows))
	for i := range rows {
		out = append(out, restoreDTO(&rows[i]))
	}
	writeJSON(w, http.StatusOK, dto.List[dto.BackupRestore]{Data: out, Offset: offset, Limit: limit, Total: total})
}

// RestoreByID returns a single restore by id, or 404 when missing.
func (h *Handler) RestoreByID(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.admin(w, r); !ok {
		return
	}
	id, ok := pathValue(w, r, "id")
	if !ok {
		return
	}
	rest, err := h.store.BackupRestoreByID(r.Context(), id)
	if err != nil {
		h.writeStoreErr(w, err, "get backup restore by id")
		return
	}
	writeJSON(w, http.StatusOK, restoreDTO(rest))
}

// Restore triggers a restore of a stored backup. It requires confirm:true and
// an Idempotency-Key, and is LONG-RUNNING so a slow restore is never killed by
// the default timeout. Returns 201 with the completed restore.
func (h *Handler) Restore(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.admin(w, r); !ok {
		return
	}
	var req restoreReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		problem.InvalidRequest("invalid or missing body").Write(w)
		return
	}
	req.SourceKey = strings.TrimSpace(req.SourceKey)
	if req.SourceKey == "" {
		problem.ValidationFailed([]problem.FieldError{{Field: "source_key", Code: "required", Detail: "source_key is required"}}).Write(w)
		return
	}
	if !req.Confirm {
		problem.ValidationFailed([]problem.FieldError{{Field: "confirm", Code: "required", Detail: "confirm must be true to restore"}}).Write(w)
		return
	}

	rest := &store.BackupRestore{
		ID:          newRunID(),
		StartedAt:   time.Now().UTC(),
		Status:      "running",
		SourceKey:   req.SourceKey,
		RequestedBy: principalID(r),
	}
	if err := h.store.CreateBackupRestore(r.Context(), rest); err != nil {
		h.logger.Error("backup: create restore", "err", err)
		problem.Internal().Write(w)
		return
	}

	if err := h.currentScheduler().Restore(r.Context(), req.SourceKey); err != nil {
		msg := err.Error()
		rest.Status = "failed"
		rest.Error = &msg
		_ = h.store.UpdateBackupRestore(r.Context(), rest.ID, "failed", msg)
		writeJSON(w, http.StatusCreated, restoreDTO(rest))
		return
	}
	rest.Status = "succeeded"
	_ = h.store.UpdateBackupRestore(r.Context(), rest.ID, "succeeded", "")
	writeJSON(w, http.StatusCreated, restoreDTO(rest))
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
	h.logger.Error("backup: "+op, "err", err)
	problem.Internal().Write(w)
}

// currentScheduler returns the live scheduler under the mutex.
func (h *Handler) currentScheduler() *backup.Scheduler {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.sched
}

// restartScheduler stops the current scheduler and starts a new one built from
// the persisted config. It is the A3 fix: the config genuinely drives the
// scheduler rather than only being logged.
func (h *Handler) restartScheduler(schedule, destination, prefix string) error {
	dest, err := buildDestination(h.backend, destination, prefix)
	if err != nil {
		return err
	}
	cfg := backup.Config{Schedule: schedule, Destination: dest}
	next := backup.NewScheduler(cfg, h.backupFn)

	h.mu.Lock()
	if h.sched != nil {
		h.sched.Stop()
	}
	h.sched = next
	h.mu.Unlock()

	return next.Start()
}

// validateConfig validates a backup config against the scheduler sentinels.
func validateConfig(req *configReq) error {
	if req.Schedule == "" {
		return backup.ErrEmptySchedule
	}
	if req.Destination != "fs" && req.Destination != "s3" {
		return backup.ErrInvalidDestination
	}
	if req.Prefix == "" {
		return backup.ErrEmptyPrefix
	}
	return nil
}

// buildDestination maps a destination string + prefix to a backup.Destination.
func buildDestination(backend storage.Backend, destination, prefix string) (backup.Destination, error) {
	switch destination {
	case "fs":
		return &backup.FSDestination{Backend: backend, Prefix: prefix}, nil
	case "s3":
		return &backup.S3Destination{Backend: backend, Prefix: prefix}, nil
	default:
		return nil, backup.ErrInvalidDestination
	}
}

// pageParams reads limit/offset from the query string (defaults: limit 100,
// offset 0). It writes a 422 and returns ok=false on invalid values.
func pageParams(w http.ResponseWriter, r *http.Request) (limit, offset int, ok bool) {
	limit, offset = 100, 0
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			problem.ValidationFailed([]problem.FieldError{{Field: "limit", Code: "invalid", Detail: "limit must be a non-negative integer"}}).Write(w)
			return 0, 0, false
		}
		limit = n
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			problem.ValidationFailed([]problem.FieldError{{Field: "offset", Code: "invalid", Detail: "offset must be a non-negative integer"}}).Write(w)
			return 0, 0, false
		}
		offset = n
	}
	return limit, offset, true
}

// pathValue extracts the named path segment, falling back to the last path
// segment for direct handler invocation in tests.
func pathValue(w http.ResponseWriter, r *http.Request, name string) (string, bool) {
	v := r.PathValue(name)
	if v == "" {
		seg := strings.Split(strings.TrimSuffix(r.URL.Path, "/"), "/")
		v = seg[len(seg)-1]
	}
	if v == "" {
		problem.NotFound().Write(w)
		return "", false
	}
	return v, true
}

// principalID returns the authenticated principal's user id, or "".
func principalID(r *http.Request) string {
	if p := middleware.PrincipalFromContext(r.Context()); p != nil {
		return p.UserID
	}
	return ""
}

// newRunID returns a new random hex run/restore id (16 bytes).
func newRunID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand never fails on supported platforms.
		panic("backup: crypto/rand unavailable")
	}
	return hex.EncodeToString(b)
}

func configDTO(c *store.BackupConfig) dto.BackupConfig {
	return dto.BackupConfig{
		Schedule:    c.Schedule,
		Destination: c.Destination,
		Prefix:      c.Prefix,
		UpdatedAt:   c.UpdatedAt,
	}
}

func runDTO(r *store.BackupRun) dto.BackupRun {
	return dto.BackupRun{
		ID:             r.ID,
		StartedAt:      r.StartedAt,
		FinishedAt:     r.FinishedAt,
		Status:         r.Status,
		Error:          r.Error,
		SizeBytes:      r.SizeBytes,
		DestinationKey: r.DestinationKey,
	}
}

func restoreDTO(r *store.BackupRestore) dto.BackupRestore {
	return dto.BackupRestore{
		ID:          r.ID,
		StartedAt:   r.StartedAt,
		FinishedAt:  r.FinishedAt,
		Status:      r.Status,
		Error:       r.Error,
		SourceKey:   r.SourceKey,
		RequestedBy: r.RequestedBy,
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
