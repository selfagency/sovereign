// Package capabilities derives the machine-readable set of wired features
// from the actual server config and store. It is the single source of truth
// for NodeInfo and the README status table (Phase 4): a capability is reported
// wired only when the backend or config that backs it is actually present,
// never from a static list.
package capabilities

import (
	"github.com/selfagency/sovereign/internal/api/dto"
	"github.com/selfagency/sovereign/internal/store"
)

// Config is the subset of server configuration the provider reads to derive
// wired features. It is a small value type (not internal/server.Config) so
// this package does not import the server package, which would create an
// import cycle (server -> capabilities -> server).
type Config struct {
	IPFSEnabled bool
	SMTPEnabled bool
}

// Provider derives the wired-feature set from the actual server config and
// store.
type Provider struct {
	cfg   Config
	store *store.Store
}

// New builds a Provider from the config subset and store.
func New(cfg Config, st *store.Store) *Provider {
	return &Provider{cfg: cfg, store: st}
}

// Features returns the wired-feature map keyed by feature name. Store-backed
// features are wired only when the store is present; config-driven features
// (ipfs, smtp) are wired only when their config enables them; protocol
// surfaces mounted unconditionally in the router are always wired.
func (p *Provider) Features() map[string]dto.Capability {
	storeWired := p.store != nil
	return map[string]dto.Capability{
		"identity":      {Wired: storeWired, Description: "Account identity and profile data"},
		"profile":       {Wired: storeWired, Description: "Public profile pages and links"},
		"keys":          {Wired: storeWired, Description: "Public SSH/PGP key hosting"},
		"proofs":        {Wired: storeWired, Description: "Keyoxide-style public proof verification"},
		"sessions":      {Wired: storeWired, Description: "Server-side browser sessions"},
		"tenants":       {Wired: storeWired, Description: "Multi-tenant account isolation"},
		"clients":       {Wired: storeWired, Description: "OIDC client management"},
		"backup":        {Wired: storeWired, Description: "Admin backup configuration"},
		"moderation":    {Wired: storeWired, Description: "Admin takedown moderation"},
		"audit":         {Wired: storeWired, Description: "Audit log"},
		"ipfs":          {Wired: p.cfg.IPFSEnabled, Description: "IPFS pinning broker"},
		"smtp":          {Wired: p.cfg.SMTPEnabled, Description: "Outbound email via SMTP"},
		"atproto":       {Wired: true, Description: "AT Protocol PDS (XRPC)"},
		"solid":         {Wired: true, Description: "Solid LDP storage"},
		"remotestorage": {Wired: true, Description: "remoteStorage protocol"},
		"activitypub":   {Wired: true, Description: "ActivityPub actor + HTTP signature verification"},
		"webfinger":     {Wired: true, Description: "WebFinger discovery"},
		"nodeinfo":      {Wired: true, Description: "NodeInfo server metadata"},
		"webauthn":      {Wired: true, Description: "Passkey (WebAuthn) authentication"},
		"oidc":          {Wired: true, Description: "OIDC provider"},
	}
}
