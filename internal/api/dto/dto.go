// Package dto defines the typed request/response DTOs shared by the whole
// REST API. Every response is a named struct: the wire format never falls
// back to a generic string-keyed map. JSON is snake_case; timestamps are
// RFC 3339 UTC, always Z-suffixed.
//
// Collection conventions:
//   - admin lists: {"data":[...],"offset":N,"limit":N,"total":N}
//   - audit log:   {"data":[...],"next_cursor":<opaque cursor>|null}
//   - single resources: plain object
package dto

import "time"

// User is an account exposed to the API.
type User struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	Email       string    `json:"email"`
	DisplayName string    `json:"display_name"`
	IsAdmin     bool      `json:"is_admin"`
	TOSAccepted bool      `json:"tos_accepted"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Tenant is a multi-tenant isolation boundary.
type Tenant struct {
	ID        string    `json:"id"`
	Handle    string    `json:"handle"`
	DID       string    `json:"did"`
	CreatedAt time.Time `json:"created_at"`
}

// Session is a server-side authenticated session. RevokedAt is null while the
// session is active.
type Session struct {
	ID            string     `json:"id"`
	UserID        string     `json:"user_id"`
	CreatedAt     time.Time  `json:"created_at"`
	LastSeenAt    *time.Time `json:"last_seen_at"`
	ExpiresAt     time.Time  `json:"expires_at"`
	RevokedAt     *time.Time `json:"revoked_at"`
	UserAgentHash string     `json:"user_agent_hash"`
	IPHash        string     `json:"ip_hash"`
}

// Principal is the authenticated identity returned by GET /auth/session. It
// mirrors the middleware.Principal plus onboarding state (ToSAccepted).
type Principal struct {
	UserID      string   `json:"user_id"`
	TenantID    string   `json:"tenant_id"`
	Scopes      []string `json:"scopes"`
	IsAdmin     bool     `json:"is_admin"`
	IsCookie    bool     `json:"is_cookie"`
	ToSAccepted bool     `json:"tos_accepted"`
}

// PublicKey is a stored SSH or PGP public key. KeyMaterial holds the public
// key body; a private key is never exposed.
type PublicKey struct {
	ID          string     `json:"id"`
	UserID      string     `json:"user_id"`
	Type        string     `json:"type"` // "ssh" | "pgp"
	Fingerprint string     `json:"fingerprint"`
	PublicKey   string     `json:"public_key"`
	CreatedAt   time.Time  `json:"created_at"`
	RevokedAt   *time.Time `json:"revoked_at"`
}

// ProofClaim is a Keyoxide-style public proof verification record.
type ProofClaim struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	Type      string    `json:"type"`
	Target    string    `json:"target"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}

// ProfileLink is an ordered link on a tenant's profile page.
type ProfileLink struct {
	ID        string    `json:"id"`
	Label     string    `json:"label"`
	URL       string    `json:"url"`
	Position  int       `json:"position"`
	CreatedAt time.Time `json:"created_at"`
}

// ProfilePage is a tenant's published hyperlink-in-bio profile page.
type ProfilePage struct {
	ID          string    `json:"id"`
	UserID      string    `json:"user_id"`
	DisplayName string    `json:"display_name"`
	Bio         string    `json:"bio"`
	AvatarURL   string    `json:"avatar_url"`
	IsPublished bool      `json:"is_published"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Client is an OAuth client. The client secret is show-once only and is never
// part of this response.
type Client struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Audience  string    `json:"audience"`
	CreatedAt time.Time `json:"created_at"`
}

// AuditEntry is a row from the audit log.
type AuditEntry struct {
	ID        string    `json:"id"`
	Actor     string    `json:"actor"`
	Action    string    `json:"action"`
	Resource  string    `json:"resource"`
	Detail    string    `json:"detail"`
	CreatedAt time.Time `json:"created_at"`
}

// BackupConfig describes a scheduled backup job.
type BackupConfig struct {
	Schedule    string    `json:"schedule"`
	Destination string    `json:"destination"`
	Prefix      string    `json:"prefix"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// BackupRun is a single backup execution. FinishedAt and Error are null while
// the run is in progress or succeeded.
type BackupRun struct {
	ID             string     `json:"id"`
	StartedAt      time.Time  `json:"started_at"`
	FinishedAt     *time.Time `json:"finished_at"`
	Status         string     `json:"status"`
	Error          *string    `json:"error"`
	SizeBytes      int64      `json:"size_bytes"`
	DestinationKey string     `json:"destination_key"`
}

// Takedown is a moderation takedown action against a resource.
type Takedown struct {
	ID        string    `json:"id"`
	Resource  string    `json:"resource"`
	Reason    string    `json:"reason"`
	ActedBy   string    `json:"acted_by"`
	CreatedAt time.Time `json:"created_at"`
}

// PendingDeletion is a scheduled account deletion awaiting approval.
type PendingDeletion struct {
	ID          string     `json:"id"`
	UserID      string     `json:"user_id"`
	RequestedAt time.Time  `json:"requested_at"`
	Status      string     `json:"status"`
	ApprovedBy  *string    `json:"approved_by"`
	ApprovedAt  *time.Time `json:"approved_at"`
}

// ToSDocument is a published Terms of Service version.
type ToSDocument struct {
	ID          string    `json:"id"`
	Version     string    `json:"version"`
	Content     string    `json:"content"`
	PublishedAt time.Time `json:"published_at"`
	PublishedBy string    `json:"published_by"`
}

// Capabilities reports which protocol features are actually wired up.
type Capabilities struct {
	Backup   bool `json:"backup"`
	Atproto  bool `json:"atproto"`
	Solid    bool `json:"solid"`
	IPFS     bool `json:"ipfs"`
	Proofs   bool `json:"proofs"`
	WebAuthn bool `json:"webauthn"`
	OIDC     bool `json:"oidc"`
}

// Version reports the build version of the running server.
//
// Commit and GoVersion are omitted (empty) when the build was not stamped
// with them via ldflags.
type Version struct {
	Version   string `json:"version"`
	Commit    string `json:"commit,omitempty"`
	GoVersion string `json:"go_version,omitempty"`
}

// Health is the body of the /health and /ready probes. Status is "ok" or
// "degraded".
type Health struct {
	Status string `json:"status"`
}

// Error is an RFC 9457 Problem Details envelope for error responses.
type Error struct {
	Type     string `json:"type"`
	Title    string `json:"title"`
	Status   int    `json:"status"`
	Detail   string `json:"detail"`
	Instance string `json:"instance"`
}

// List is the offset/limit pagination envelope used by admin list endpoints.
type List[T any] struct {
	Data   []T `json:"data"`
	Offset int `json:"offset"`
	Limit  int `json:"limit"`
	Total  int `json:"total"`
}

// CursorList is the cursor-pagination envelope used by the audit log.
type CursorList[T any] struct {
	Data       []T     `json:"data"`
	NextCursor *string `json:"next_cursor"`
}
