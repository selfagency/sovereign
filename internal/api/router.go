// Package api provides the versioned JSON REST API surface (/api/v1).
//
// The route table in this file is the single source of truth for which
// endpoints exist, what scope each requires, and its per-route timeout.
// The OpenAPI drift test (openapi_drift_test.go) asserts this table stays
// in parity with openapi/sovereign.v1.yaml in both directions.
package api

import (
	"net/http"
	"time"

	"github.com/selfagency/sovereign/internal/api/dto"
	"github.com/selfagency/sovereign/internal/api/middleware"
	"github.com/selfagency/sovereign/internal/api/problem"
	"github.com/selfagency/sovereign/internal/api/v1/admin"
	v1auth "github.com/selfagency/sovereign/internal/api/v1/auth"
	"github.com/selfagency/sovereign/internal/api/v1/meta"
	v1public "github.com/selfagency/sovereign/internal/api/v1/public"
	"github.com/selfagency/sovereign/internal/api/v1/self"
)

// Route describes one HTTP endpoint on the /api/v1 surface.
type Route struct {
	Method  string        // "GET", "POST", ...
	Path    string        // "/api/v1/meta/capabilities"
	Scope   string        // required scope, or "" when Anonymous is set
	Timeout time.Duration // per-route timeout
	Handler http.HandlerFunc

	// Anonymous marks a route that requires no authentication. A route must
	// declare either a non-empty Scope or Anonymous=true; an empty Scope with
	// Anonymous=false is a forgotten declaration and fails the route table
	// validation test.
	Anonymous bool

	// LongRunning marks a route exempt from the per-route timeout column
	// (e.g. Phase 3 backup run/restore). Phase 1 routes must have Timeout > 0.
	LongRunning bool

	// Idempotent marks a POST route that must be protected by the idempotency
	// middleware: it reads an Idempotency-Key header and replays the original
	// response on retry. Only /auth/invite/redeem declares this in Phase 1.
	Idempotent bool
}

// notImplemented returns a 501 stub handler for routes whose real handler
// lands in a later task (T1.6 meta, T1.7 auth).
func notImplemented() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		problem.NotImplemented().Write(w)
	}
}

// New builds a *http.ServeMux from the route table using Go 1.22+ method
// patterns ("GET /api/v1/meta/capabilities"). Each route is wired to its
// handler (a 501 stub until the real handler lands). The returned mux is what
// the middleware chain (T1.4) wraps.
func New(routes []Route) *http.ServeMux {
	mux := http.NewServeMux()
	for _, r := range routes {
		r := r
		mux.HandleFunc(r.Method+" "+r.Path, r.Handler)
	}
	return mux
}

// phase1Meta is the meta/health/ready handler used by the Phase 1 route
// table. It reports only the features actually wired for Phase 1 (the API
// itself, plus web_authn/oidc plumbing); data-plane features are reported
// false until their wiring lands in Phase 3/4. Production wiring (T1.10)
// should construct a meta.Handler with the real dependencies and pass the
// resulting routes in place of these defaults.
var phase1Meta = meta.New(
	meta.WithCapabilities(dto.Capabilities{
		WebAuthn: true,
		OIDC:     true,
	}),
	meta.WithVersion(meta.VersionInfo{}),
)

// RoutesFor returns the current route set with the given meta handler wired
// to the /meta, /health, /ready, and /openapi.json routes, and the auth routes
// as 501 stubs. Routes() uses the Phase-1 default handler; the server passes a
// handler wired to the real capabilities/version/ping when it assembles the
// control plane (T1.10). The route table is the single source of truth for
// both entry points.
func RoutesFor(h *meta.Handler) []Route {
	return routesFor(h, nil, nil, nil, nil)
}

// RoutesForAPI returns the current route set with both the given meta handler
// and the auth handler wired to the /api/v1/auth/* and /invite/{token} routes.
// Pass nil for the auth handler to keep those routes as 501 stubs (the drift
// test checks parity only).
func RoutesForAPI(h *meta.Handler, ah *v1auth.Handler) []Route {
	return routesFor(h, ah, nil, nil, nil)
}

// RoutesForSelf returns the current route set with the given meta, auth, and
// self handlers wired. Pass nil for the self handler to keep the /me/* routes
// as 501 stubs (the drift test checks parity only).
func RoutesForSelf(h *meta.Handler, ah *v1auth.Handler, sh *self.Handler) []Route {
	return routesFor(h, ah, sh, nil, nil)
}

// RoutesForAdmin returns the current route set with the given meta, auth,
// self, and admin handlers wired. Pass nil for the admin handler to keep the
// /admin/* routes as 501 stubs (the drift test checks parity only).
func RoutesForAdmin(h *meta.Handler, ah *v1auth.Handler, sh *self.Handler, adm *admin.Handler) []Route {
	return routesFor(h, ah, sh, adm, nil)
}

// RoutesForPublic returns the current route set with the given meta, auth,
// self, admin, and public handlers wired. Pass nil for the public handler to
// keep the /public/* routes as 501 stubs (the drift test checks parity only).
func RoutesForPublic(h *meta.Handler, ah *v1auth.Handler, sh *self.Handler, adm *admin.Handler, pub *v1public.Handler) []Route {
	return routesFor(h, ah, sh, adm, pub)
}

// Routes returns the current route set with the Phase-1 default meta handler
// (capabilities web_authn+oidc, empty version) and 501 auth stubs. Production
// wiring uses RoutesForAPI with a fully-wired auth handler.
func Routes() []Route {
	return RoutesFor(phase1Meta)
}

// routesFor is the shared route-table constructor. When ah is nil, the auth
// routes are 501 stubs; otherwise they delegate to the auth handler. sh, adm,
// and pub behave the same way for the self, admin, and public routes.
func routesFor(h *meta.Handler, ah *v1auth.Handler, sh *self.Handler, adm *admin.Handler, pub *v1public.Handler) []Route {
	return append([]Route{
		// Meta / health / ready (anonymous).
		{Method: http.MethodGet, Path: "/api/v1/meta/capabilities", Anonymous: true, Timeout: 5 * time.Second, Handler: h.Capabilities},
		{Method: http.MethodGet, Path: "/api/v1/meta/version", Anonymous: true, Timeout: 5 * time.Second, Handler: h.Version},
		{Method: http.MethodGet, Path: "/api/v1/health", Anonymous: true, Timeout: 5 * time.Second, Handler: h.Health},
		{Method: http.MethodGet, Path: "/api/v1/ready", Anonymous: true, Timeout: 5 * time.Second, Handler: h.Ready},
		{Method: http.MethodGet, Path: "/api/v1/openapi.json", Anonymous: true, Timeout: 5 * time.Second, Handler: h.OpenAPI},
	}, append(append(append(authRoutes(ah), selfRoutes(sh)...), adminRoutes(adm)...), publicRoutes(pub)...)...)
}

// publicRoutes builds the anonymous /public/* route set. When pub is nil the
// handlers are 501 stubs; otherwise they delegate to the public handler. All
// routes are anonymous and tenant-scoped via the tenant middleware.
func publicRoutes(pub *v1public.Handler) []Route {
	profile, keys, proofs := stub(), stub(), stub()
	if pub != nil {
		profile, keys, proofs = pub.Profile, pub.Keys, pub.Proofs
	}
	return []Route{
		{Method: http.MethodGet, Path: "/api/v1/public/profile", Anonymous: true, Timeout: 5 * time.Second, Handler: profile},
		{Method: http.MethodGet, Path: "/api/v1/public/keys", Anonymous: true, Timeout: 5 * time.Second, Handler: keys},
		{Method: http.MethodGet, Path: "/api/v1/public/proofs", Anonymous: true, Timeout: 5 * time.Second, Handler: proofs},
	}
}

// authRoutes builds the auth/session/webauthn route set. When ah is nil the
// handlers are 501 stubs; otherwise they delegate to the auth handler.
func authRoutes(ah *v1auth.Handler) []Route {
	// Resolve the handlers once; referencing a method value on a nil receiver
	// panics, so only bind when ah is non-nil.
	redeem, getSess, delSess, refresh, regBegin, regFinish, loginBegin, loginFinish, inviteGet := stub(), stub(), stub(), stub(), stub(), stub(), stub(), stub(), stub()
	if ah != nil {
		redeem, getSess, delSess, refresh = ah.RedeemInvite, ah.GetSession, ah.DeleteSession, ah.RefreshSession
		regBegin, regFinish = ah.RegisterBegin, ah.RegisterFinish
		loginBegin, loginFinish = ah.LoginBegin, ah.LoginFinish
		inviteGet = ah.InviteGet
	}
	return []Route{
		{Method: http.MethodPost, Path: "/api/v1/auth/invite/redeem", Anonymous: true, Idempotent: true, Timeout: 10 * time.Second, Handler: redeem},
		{Method: http.MethodGet, Path: "/api/v1/auth/session", Scope: "self", Timeout: 5 * time.Second, Handler: getSess},
		{Method: http.MethodDelete, Path: "/api/v1/auth/session", Scope: "self", Timeout: 5 * time.Second, Handler: delSess},
		{Method: http.MethodPost, Path: "/api/v1/auth/session/refresh", Scope: "self", Timeout: 5 * time.Second, Handler: refresh},
		{Method: http.MethodPost, Path: "/api/v1/auth/webauthn/register/begin", Scope: "self", Timeout: 10 * time.Second, Handler: regBegin},
		{Method: http.MethodPost, Path: "/api/v1/auth/webauthn/register/finish", Scope: "self", Timeout: 10 * time.Second, Handler: regFinish},
		{Method: http.MethodPost, Path: "/api/v1/auth/webauthn/login/begin", Anonymous: true, Timeout: 10 * time.Second, Handler: loginBegin},
		{Method: http.MethodPost, Path: "/api/v1/auth/webauthn/login/finish", Anonymous: true, Timeout: 10 * time.Second, Handler: loginFinish},
		// Anonymous browser entry point (M1): redeem a magic link into a session
		// cookie and redirect to /panel. Token-in-URL leaks are acknowledged.
		{Method: http.MethodGet, Path: "/invite/{token}", Anonymous: true, Timeout: 10 * time.Second, Handler: inviteGet},
	}
}

// selfRoutes builds the /me/* self-service route set. When sh is nil the
// handlers are 501 stubs; otherwise they delegate to the self handler. GET
// routes get a 5s timeout; mutations get 10s. None are anonymous.
func selfRoutes(sh *self.Handler) []Route {
	// Resolve the handlers once; referencing a method value on a nil receiver
	// panics, so only bind when sh is non-nil.
	identityGet, identityUpdate, identityDelete, identityOnboarding, identityToS, identityExport := stub(), stub(), stub(), stub(), stub(), stub()
	profileGet, profilePut, profileDelete, profilePublish, profileUnpublish, profileAvatar := stub(), stub(), stub(), stub(), stub(), stub()
	linksList, linksAdd, linksUpdate, linksDelete, linksReorder := stub(), stub(), stub(), stub(), stub()
	keysList, keysGet, keysCreate, keysDelete, keysRevoke := stub(), stub(), stub(), stub(), stub()
	proofsList, proofsGet, proofsCreate, proofsDelete, proofsVerify := stub(), stub(), stub(), stub(), stub()
	sessList, sessRevoke, sessRevokeAll := stub(), stub(), stub()
	tokList, tokCreate, tokRevoke := stub(), stub(), stub()
	credList, credDelete := stub(), stub()
	if sh != nil {
		identityGet, identityUpdate, identityDelete = sh.Identity.Get, sh.Identity.Update, sh.Identity.RequestDeletion
		identityOnboarding, identityToS, identityExport = sh.Identity.OnboardingState, sh.Identity.AcceptToS, sh.Identity.Export
		profileGet, profilePut, profileDelete = sh.Profile.Get, sh.Profile.Put, sh.Profile.Delete
		profilePublish, profileUnpublish = sh.Profile.Publish, sh.Profile.Unpublish
		profileAvatar = sh.Profile.UploadAvatar
		linksList, linksAdd, linksUpdate, linksDelete, linksReorder = sh.Profile.ListLinks, sh.Profile.AddLink, sh.Profile.UpdateLink, sh.Profile.DeleteLink, sh.Profile.ReorderLinks
		keysList, keysGet, keysCreate, keysDelete, keysRevoke = sh.Keys.List, sh.Keys.Get, sh.Keys.Create, sh.Keys.Delete, sh.Keys.Revoke
		proofsList, proofsGet, proofsCreate, proofsDelete, proofsVerify = sh.Proofs.List, sh.Proofs.Get, sh.Proofs.Create, sh.Proofs.Delete, sh.Proofs.Verify
		sessList, sessRevoke, sessRevokeAll = sh.Sessions.List, sh.Sessions.Revoke, sh.Sessions.RevokeAll
		tokList, tokCreate, tokRevoke = sh.Tokens.List, sh.Tokens.Create, sh.Tokens.Revoke
		credList, credDelete = sh.Credentials.List, sh.Credentials.Delete
	}
	return []Route{
		{Method: http.MethodGet, Path: "/api/v1/me", Scope: "self:read", Timeout: 5 * time.Second, Handler: identityGet},
		{Method: http.MethodPatch, Path: "/api/v1/me", Scope: "self:write", Timeout: 10 * time.Second, Handler: identityUpdate},
		{Method: http.MethodDelete, Path: "/api/v1/me", Scope: "account:delete", Timeout: 10 * time.Second, Handler: identityDelete},
		{Method: http.MethodGet, Path: "/api/v1/me/onboarding", Scope: "self:read", Timeout: 5 * time.Second, Handler: identityOnboarding},
		{Method: http.MethodPost, Path: "/api/v1/me/tos", Scope: "self:write", Timeout: 10 * time.Second, Handler: identityToS},
		{Method: http.MethodGet, Path: "/api/v1/me/export", Scope: "export:read", Timeout: 5 * time.Second, Handler: identityExport},
		{Method: http.MethodGet, Path: "/api/v1/me/profile", Scope: "profile:read", Timeout: 5 * time.Second, Handler: profileGet},
		{Method: http.MethodPut, Path: "/api/v1/me/profile", Scope: "profile:write", Timeout: 10 * time.Second, Handler: profilePut},
		{Method: http.MethodDelete, Path: "/api/v1/me/profile", Scope: "profile:write", Timeout: 10 * time.Second, Handler: profileDelete},
		{Method: http.MethodPost, Path: "/api/v1/me/profile:publish", Scope: "profile:publish", Timeout: 10 * time.Second, Handler: profilePublish},
		{Method: http.MethodPost, Path: "/api/v1/me/profile:unpublish", Scope: "profile:publish", Timeout: 10 * time.Second, Handler: profileUnpublish},
		{Method: http.MethodPut, Path: "/api/v1/me/profile/avatar", Scope: "profile:write", Timeout: 10 * time.Second, Handler: profileAvatar},
		{Method: http.MethodGet, Path: "/api/v1/me/profile/links", Scope: "profile:read", Timeout: 5 * time.Second, Handler: linksList},
		{Method: http.MethodPost, Path: "/api/v1/me/profile/links", Scope: "profile:write", Timeout: 10 * time.Second, Handler: linksAdd},
		{Method: http.MethodPatch, Path: "/api/v1/me/profile/links/{id}", Scope: "profile:write", Timeout: 10 * time.Second, Handler: linksUpdate},
		{Method: http.MethodDelete, Path: "/api/v1/me/profile/links/{id}", Scope: "profile:write", Timeout: 10 * time.Second, Handler: linksDelete},
		{Method: http.MethodPost, Path: "/api/v1/me/profile/links:reorder", Scope: "profile:write", Timeout: 10 * time.Second, Handler: linksReorder},
		{Method: http.MethodGet, Path: "/api/v1/me/keys", Scope: "keys:read", Timeout: 5 * time.Second, Handler: keysList},
		{Method: http.MethodPost, Path: "/api/v1/me/keys", Scope: "keys:write", Timeout: 10 * time.Second, Handler: keysCreate},
		{Method: http.MethodGet, Path: "/api/v1/me/keys/{id}", Scope: "keys:read", Timeout: 5 * time.Second, Handler: keysGet},
		{Method: http.MethodDelete, Path: "/api/v1/me/keys/{id}", Scope: "keys:write", Timeout: 10 * time.Second, Handler: keysDelete},
		{Method: http.MethodPost, Path: "/api/v1/me/keys/{id}/revoke", Scope: "keys:write", Timeout: 10 * time.Second, Handler: keysRevoke},
		{Method: http.MethodGet, Path: "/api/v1/me/proofs", Scope: "proofs:read", Timeout: 5 * time.Second, Handler: proofsList},
		{Method: http.MethodPost, Path: "/api/v1/me/proofs", Scope: "proofs:write", Timeout: 10 * time.Second, Handler: proofsCreate},
		{Method: http.MethodGet, Path: "/api/v1/me/proofs/{id}", Scope: "proofs:read", Timeout: 5 * time.Second, Handler: proofsGet},
		{Method: http.MethodDelete, Path: "/api/v1/me/proofs/{id}", Scope: "proofs:write", Timeout: 10 * time.Second, Handler: proofsDelete},
		{Method: http.MethodPost, Path: "/api/v1/me/proofs/{id}/verify", Scope: "proofs:verify", Timeout: 10 * time.Second, Handler: proofsVerify},
		{Method: http.MethodGet, Path: "/api/v1/me/sessions", Scope: "sessions:read", Timeout: 5 * time.Second, Handler: sessList},
		{Method: http.MethodDelete, Path: "/api/v1/me/sessions/{id}", Scope: "sessions:revoke", Timeout: 10 * time.Second, Handler: sessRevoke},
		{Method: http.MethodDelete, Path: "/api/v1/me/sessions", Scope: "sessions:revoke", Timeout: 10 * time.Second, Handler: sessRevokeAll},
		// Programmatic API tokens (create is show-once: the raw token is returned
		// exactly once; list/revoke expose metadata only).
		{Method: http.MethodGet, Path: "/api/v1/me/tokens", Scope: "tokens:read", Timeout: 5 * time.Second, Handler: tokList},
		{Method: http.MethodPost, Path: "/api/v1/me/tokens", Scope: "tokens:write", Timeout: 10 * time.Second, Handler: tokCreate},
		{Method: http.MethodDelete, Path: "/api/v1/me/tokens/{family_id}", Scope: "tokens:revoke", Timeout: 10 * time.Second, Handler: tokRevoke},
		// WebAuthn credentials.
		{Method: http.MethodGet, Path: "/api/v1/me/credentials", Scope: "credentials:read", Timeout: 5 * time.Second, Handler: credList},
		{Method: http.MethodDelete, Path: "/api/v1/me/credentials/{id}", Scope: "credentials:write", Timeout: 10 * time.Second, Handler: credDelete},
	}
}

// adminRoutes builds the /admin/* instance-admin route set. When adm is nil
// the handlers are 501 stubs; otherwise they delegate to the admin handler.
// All admin routes declare an admin:* coarse scope (enforced by the scope
// middleware alongside IsAdmin). GET routes get a 5s timeout; mutations get
// 10s. Backup run/restore triggers are LongRunning (exempt from the per-route
// timeout) and Idempotent (an Idempotency-Key is required so a replay does
// not double-run). None are anonymous.
func adminRoutes(adm *admin.Handler) []Route {
	// Resolve the handlers once; referencing a method value on a nil receiver
	// panics, so only bind when adm is non-nil.
	tenantsList, tenantsGet, tenantsCreate, tenantsDelete := stub(), stub(), stub(), stub()
	clientsList, clientsGet, clientsCreate, clientsDelete, clientsRotate := stub(), stub(), stub(), stub(), stub()
	modList, modCreate, modGet, modDelete := stub(), stub(), stub(), stub()
	cfgGet, cfgPut, runsList, runsTrigger, runGet := stub(), stub(), stub(), stub(), stub()
	restoresList, restoreTrigger := stub(), stub()
	auditList := stub()
	deletionsList, deletionsApprove, deletionsReject := stub(), stub(), stub()
	systemInfo := stub()
	usersList, usersCreate, usersGet, usersUpdate, usersDelete, usersInvite, usersCredentials, usersRevoke := stub(), stub(), stub(), stub(), stub(), stub(), stub(), stub()
	ipfsList, ipfsAdd, ipfsGet := stub(), stub(), stub()
	tosGet, tosPut := stub(), stub()
	if adm != nil {
		tenantsList, tenantsGet, tenantsCreate, tenantsDelete = adm.Tenants.List, adm.Tenants.GetByID, adm.Tenants.Create, adm.Tenants.Delete
		clientsList, clientsGet, clientsCreate, clientsDelete, clientsRotate = adm.Clients.ListClients, adm.Clients.ClientByID, adm.Clients.CreateClient, adm.Clients.DeleteClient, adm.Clients.RotateSecret
		modList, modCreate, modGet, modDelete = adm.Moderation.List, adm.Moderation.Create, adm.Moderation.GetByID, adm.Moderation.Delete
		cfgGet, cfgPut, runsList, runsTrigger, runGet = adm.Backup.GetConfig, adm.Backup.PutConfig, adm.Backup.ListRuns, adm.Backup.TriggerRun, adm.Backup.RunByID
		restoresList, restoreTrigger = adm.Backup.ListRestores, adm.Backup.Restore
		auditList = adm.Audit.List
		deletionsList, deletionsApprove, deletionsReject = adm.Deletions.List, adm.Deletions.Approve, adm.Deletions.Reject
		systemInfo = adm.System.Info
		usersList, usersCreate, usersGet, usersUpdate, usersDelete = adm.Users.List, adm.Users.Create, adm.Users.GetByID, adm.Users.Update, adm.Users.Delete
		usersInvite, usersCredentials, usersRevoke = adm.Users.CreateInvite, adm.Users.ListCredentials, adm.Users.RevokeSessions
		ipfsList, ipfsAdd, ipfsGet = adm.IPFS.List, adm.IPFS.Add, adm.IPFS.GetByCID
		tosGet, tosPut = adm.ToS.Get, adm.ToS.Put
	}
	return []Route{
		// Tenants.
		{Method: http.MethodGet, Path: "/api/v1/admin/tenants", Scope: "admin:tenants:read", Timeout: 5 * time.Second, Handler: tenantsList},
		{Method: http.MethodPost, Path: "/api/v1/admin/tenants", Scope: "admin:tenants:write", Timeout: 10 * time.Second, Handler: tenantsCreate},
		{Method: http.MethodGet, Path: "/api/v1/admin/tenants/{id}", Scope: "admin:tenants:read", Timeout: 5 * time.Second, Handler: tenantsGet},
		{Method: http.MethodDelete, Path: "/api/v1/admin/tenants/{id}", Scope: "admin:tenants:write", Timeout: 10 * time.Second, Handler: tenantsDelete},
		// OIDC clients.
		{Method: http.MethodGet, Path: "/api/v1/admin/clients", Scope: "admin:clients:read", Timeout: 5 * time.Second, Handler: clientsList},
		{Method: http.MethodPost, Path: "/api/v1/admin/clients", Scope: "admin:clients:write", Timeout: 10 * time.Second, Handler: clientsCreate},
		{Method: http.MethodGet, Path: "/api/v1/admin/clients/{id}", Scope: "admin:clients:read", Timeout: 5 * time.Second, Handler: clientsGet},
		{Method: http.MethodDelete, Path: "/api/v1/admin/clients/{id}", Scope: "admin:clients:write", Timeout: 10 * time.Second, Handler: clientsDelete},
		{Method: http.MethodPost, Path: "/api/v1/admin/clients/{id}/secret/rotate", Scope: "admin:clients:write", Timeout: 10 * time.Second, Handler: clientsRotate},
		// Moderation takedowns.
		{Method: http.MethodGet, Path: "/api/v1/admin/moderation/takedowns", Scope: "admin:moderation:read", Timeout: 5 * time.Second, Handler: modList},
		{Method: http.MethodPost, Path: "/api/v1/admin/moderation/takedowns", Scope: "admin:moderation:write", Timeout: 10 * time.Second, Handler: modCreate},
		{Method: http.MethodGet, Path: "/api/v1/admin/moderation/takedowns/{id}", Scope: "admin:moderation:read", Timeout: 5 * time.Second, Handler: modGet},
		{Method: http.MethodDelete, Path: "/api/v1/admin/moderation/takedowns/{id}", Scope: "admin:moderation:write", Timeout: 10 * time.Second, Handler: modDelete},
		// Backup config.
		{Method: http.MethodGet, Path: "/api/v1/admin/backup/config", Scope: "admin:backup:read", Timeout: 5 * time.Second, Handler: cfgGet},
		{Method: http.MethodPut, Path: "/api/v1/admin/backup/config", Scope: "admin:backup:write", Timeout: 10 * time.Second, Handler: cfgPut},
		// Backup runs.
		{Method: http.MethodGet, Path: "/api/v1/admin/backup/runs", Scope: "admin:backup:read", Timeout: 5 * time.Second, Handler: runsList},
		{Method: http.MethodPost, Path: "/api/v1/admin/backup/runs", Scope: "admin:backup:write", LongRunning: true, Idempotent: true, Handler: runsTrigger},
		{Method: http.MethodGet, Path: "/api/v1/admin/backup/runs/{id}", Scope: "admin:backup:read", Timeout: 5 * time.Second, Handler: runGet},
		// Backup restores.
		{Method: http.MethodGet, Path: "/api/v1/admin/backup/restores", Scope: "admin:backup:read", Timeout: 5 * time.Second, Handler: restoresList},
		{Method: http.MethodPost, Path: "/api/v1/admin/backup/restores", Scope: "admin:backup:write", LongRunning: true, Idempotent: true, Handler: restoreTrigger},
		// Audit log (instance-wide).
		{Method: http.MethodGet, Path: "/api/v1/admin/audit", Scope: "admin:audit:read", Timeout: 5 * time.Second, Handler: auditList},
		// Deletion requests.
		{Method: http.MethodGet, Path: "/api/v1/admin/deletion-requests", Scope: "admin:users:read", Timeout: 5 * time.Second, Handler: deletionsList},
		{Method: http.MethodPost, Path: "/api/v1/admin/deletion-requests/{id}/approve", Scope: "admin:users:write", Timeout: 10 * time.Second, Handler: deletionsApprove},
		{Method: http.MethodPost, Path: "/api/v1/admin/deletion-requests/{id}/reject", Scope: "admin:users:write", Timeout: 10 * time.Second, Handler: deletionsReject},
		// Users (instance-wide). Create and invite are idempotent so a replayed
		// request does not create a duplicate user or send a second email.
		{Method: http.MethodGet, Path: "/api/v1/admin/users", Scope: "admin:users:read", Timeout: 5 * time.Second, Handler: usersList},
		{Method: http.MethodPost, Path: "/api/v1/admin/users", Scope: "admin:users:write", Idempotent: true, Timeout: 10 * time.Second, Handler: usersCreate},
		{Method: http.MethodGet, Path: "/api/v1/admin/users/{id}", Scope: "admin:users:read", Timeout: 5 * time.Second, Handler: usersGet},
		{Method: http.MethodPatch, Path: "/api/v1/admin/users/{id}", Scope: "admin:users:write", Timeout: 10 * time.Second, Handler: usersUpdate},
		{Method: http.MethodDelete, Path: "/api/v1/admin/users/{id}", Scope: "admin:users:write", Timeout: 10 * time.Second, Handler: usersDelete},
		{Method: http.MethodPost, Path: "/api/v1/admin/users/{id}/invites", Scope: "admin:users:write", Idempotent: true, Timeout: 10 * time.Second, Handler: usersInvite},
		{Method: http.MethodGet, Path: "/api/v1/admin/users/{id}/credentials", Scope: "admin:users:read", Timeout: 5 * time.Second, Handler: usersCredentials},
		{Method: http.MethodPost, Path: "/api/v1/admin/users/{id}/sessions:revoke", Scope: "admin:users:write", Timeout: 10 * time.Second, Handler: usersRevoke},
		// IPFS pins (NOT idempotent).
		{Method: http.MethodGet, Path: "/api/v1/admin/ipfs/pins", Scope: "admin:ipfs:read", Timeout: 5 * time.Second, Handler: ipfsList},
		{Method: http.MethodPost, Path: "/api/v1/admin/ipfs/pins", Scope: "admin:ipfs:write", Timeout: 10 * time.Second, Handler: ipfsAdd},
		{Method: http.MethodGet, Path: "/api/v1/admin/ipfs/pins/{cid}", Scope: "admin:ipfs:read", Timeout: 5 * time.Second, Handler: ipfsGet},
		// Terms of Service.
		{Method: http.MethodGet, Path: "/api/v1/admin/tos", Scope: "admin:system:read", Timeout: 5 * time.Second, Handler: tosGet},
		{Method: http.MethodPut, Path: "/api/v1/admin/tos", Scope: "admin:system:write", Timeout: 10 * time.Second, Handler: tosPut},
		// System.
		{Method: http.MethodGet, Path: "/api/v1/admin/system/info", Scope: "admin:system:read", Timeout: 5 * time.Second, Handler: systemInfo},
	}
}

// stub returns a 501 stub handler.
func stub() http.HandlerFunc { return notImplemented() }

// ToRouteInfo adapts the api.Route table to the middleware.RouteInfo slice
// that NewHandler consumes, attaching the real handler from each Route.Handler.
// Deriving the middleware table from api.Routes() guarantees the authn/scope
// decisions use the exact same route set the mux registers: they can never
// diverge.
func ToRouteInfo(routes []Route) []middleware.RouteInfo {
	infos := make([]middleware.RouteInfo, len(routes))
	for i, r := range routes {
		infos[i] = middleware.RouteInfo{
			Method:      r.Method,
			Path:        r.Path,
			Scope:       r.Scope,
			Timeout:     r.Timeout,
			Anonymous:   r.Anonymous,
			LongRunning: r.LongRunning,
			Idempotent:  r.Idempotent,
			Handler:     r.Handler,
		}
	}
	return infos
}
