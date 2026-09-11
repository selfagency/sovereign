// Package self aggregates the /api/v1/me self-service handlers into one
// wiring surface. Each endpoint's real logic lives in its domain sub-package
// (internal/api/v1/me/{identity,profile,keys,proofs,sessions}); this package
// composes them so the route table (internal/api/router.go) can bind a single
// *self.Handler to every /me/* route, mirroring how the auth handler is wired
// for /api/v1/auth/*. Every handler derives its subject from the authenticated
// principal in the request context, never from a client-supplied ID.
package self

import (
	"log/slog"

	"github.com/selfagency/sovereign/internal/api/v1/me/credentials"
	"github.com/selfagency/sovereign/internal/api/v1/me/identity"
	"github.com/selfagency/sovereign/internal/api/v1/me/keys"
	"github.com/selfagency/sovereign/internal/api/v1/me/profile"
	meproofs "github.com/selfagency/sovereign/internal/api/v1/me/proofs"
	"github.com/selfagency/sovereign/internal/api/v1/me/sessions"
	"github.com/selfagency/sovereign/internal/api/v1/me/tokens"
	"github.com/selfagency/sovereign/internal/proofs"
	"github.com/selfagency/sovereign/internal/storage"
	"github.com/selfagency/sovereign/internal/store"
)

// Handler composes the self-service domain handlers behind a single type the
// route table binds against. Fields are exported so router.go can reference
// the method values (sh.Identity.Get, sh.Profile.Put, ...).
type Handler struct {
	Identity    *identity.Handler
	Profile     *profile.Handler
	Keys        *keys.Handler
	Proofs      *meproofs.Handler
	Sessions    *sessions.Handler
	Tokens      *tokens.Handler
	Credentials *credentials.Handler
}

// New builds a self Handler against the store, the blob backend (profile
// avatars), and the SSRF-safe proof verifier. When verifier is nil the proofs
// handler builds its own strict default. Passing a nil logger selects the
// standard slog default in each sub-handler.
func New(st *store.Store, blobs storage.Backend, verifier *proofs.Verifier, logger *slog.Logger) *Handler {
	return &Handler{
		Identity:    identity.New(st, logger),
		Profile:     profile.New(st, blobs, logger),
		Keys:        keys.New(st, logger),
		Proofs:      meproofs.New(st, verifier, logger),
		Sessions:    sessions.New(st, logger),
		Tokens:      tokens.New(st, logger),
		Credentials: credentials.New(st, logger),
	}
}

// Close stops the self-service sub-handlers' background goroutines (the
// proofs verification worker).
func (h *Handler) Close() {
	h.Proofs.Close()
}
