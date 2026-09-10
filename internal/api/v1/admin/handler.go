// Package admin aggregates the /api/v1/admin instance-admin handlers into one
// wiring surface. Each endpoint's real logic lives in its domain sub-package
// (internal/api/v1/admin/{tenants,clients,moderation,backup,audit,deletions,
// system,ipfs,users,tos}); this package composes them so the route table
// (internal/api/router.go) can bind a single *admin.Handler to every /admin/*
// route, mirroring how the auth and self handlers are wired. Admin is
// INSTANCE-scoped: these handlers operate on every tenant in the store, not
// just the caller's own. Every handler requires an admin principal
// (defense-in-depth beyond the scope middleware).
package admin

import (
	"context"
	"io"
	"log/slog"

	"github.com/selfagency/sovereign/internal/api/v1/admin/audit"
	"github.com/selfagency/sovereign/internal/api/v1/admin/backup"
	"github.com/selfagency/sovereign/internal/api/v1/admin/capabilities"
	"github.com/selfagency/sovereign/internal/api/v1/admin/clients"
	"github.com/selfagency/sovereign/internal/api/v1/admin/deletions"
	"github.com/selfagency/sovereign/internal/api/v1/admin/ipfs"
	"github.com/selfagency/sovereign/internal/api/v1/admin/moderation"
	"github.com/selfagency/sovereign/internal/api/v1/admin/system"
	"github.com/selfagency/sovereign/internal/api/v1/admin/tenants"
	"github.com/selfagency/sovereign/internal/api/v1/admin/tos"
	"github.com/selfagency/sovereign/internal/api/v1/admin/users"
	backupsvc "github.com/selfagency/sovereign/internal/backup"
	"github.com/selfagency/sovereign/internal/mail"
	"github.com/selfagency/sovereign/internal/protocols/ipfspin"
	"github.com/selfagency/sovereign/internal/storage"
	"github.com/selfagency/sovereign/internal/store"
)

// Handler composes the instance-admin domain handlers behind a single type the
// route table binds against. Fields are exported so router.go can reference
// the method values (ah.Tenants.List, ah.Clients.CreateClient, ...).
type Handler struct {
	Tenants      *tenants.Handler
	Clients      *clients.Handler
	Moderation   *moderation.Handler
	Backup       *backup.Handler
	Audit        *audit.Handler
	Deletions    *deletions.Handler
	System       *system.Handler
	IPFS         *ipfs.Handler
	Users        *users.Handler
	ToS          *tos.Handler
	Capabilities *capabilities.Provider
}

// New builds an admin Handler against the store. The backup handler needs the
// live scheduler, the backup producer, and the blob backend to rebuild its
// scheduler on config change; pass them from the server wiring. sender delivers
// invite emails (may be a dev LogSender); baseURL is the identity-host base used
// to build magic links. ipfsBackend is the optional IPFS pinning backend. info
// is the redacted config summary served by /admin/system/info. Passing a nil
// logger selects the standard slog default in each sub-handler.
func New(
	st *store.Store,
	logger *slog.Logger,
	sched *backupsvc.Scheduler,
	backupFn func(ctx context.Context) (io.Reader, error),
	backend storage.Backend,
	capProvider *capabilities.Provider,
	info *system.Info,
	sender mail.Sender,
	baseURL string,
	ipfsBackend ipfspin.Backend,
) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{
		Tenants:      tenants.New(st, logger),
		Clients:      clients.New(st, logger),
		Moderation:   moderation.New(st, logger),
		Backup:       backup.New(st, logger, sched, backupFn, backend),
		Audit:        audit.New(st, logger),
		Deletions:    deletions.New(st, logger),
		System:       system.New(info),
		IPFS:         ipfs.New(st, ipfsBackend, logger),
		Users:        users.New(st, sender, baseURL, logger),
		ToS:          tos.New(st, logger),
		Capabilities: capProvider,
	}
}
