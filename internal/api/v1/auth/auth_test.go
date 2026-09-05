package auth_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"

	"github.com/selfagency/sovereign/internal/api"
	"github.com/selfagency/sovereign/internal/api/dto"
	"github.com/selfagency/sovereign/internal/api/middleware"
	v1auth "github.com/selfagency/sovereign/internal/api/v1/auth"
	"github.com/selfagency/sovereign/internal/api/v1/meta"
	apiauth "github.com/selfagency/sovereign/internal/auth"
	"github.com/selfagency/sovereign/internal/store"
)

// --- harness ---

const (
	testIssuer = "https://id.example.com"
	testRPID   = "id.example.com"
	testOrigin = "https://id.example.com"
	testDomain = "example.com"
)

func testStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func testKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// seedTenantUser creates a tenant + user and returns the user.
func seedTenantUser(t *testing.T, s *store.Store, tenantID, handle string) *store.User {
	t.Helper()
	ctx := context.Background()
	if err := s.CreateTenant(ctx, &store.Tenant{ID: tenantID, Handle: handle + ".example.com", DIDMethod: "web"}); err != nil && !errors.Is(err, store.ErrDuplicateTenant) {
		t.Fatal(err)
	}
	u := &store.User{ID: "user-" + tenantID + "-" + handle, TenantID: tenantID, Handle: handle, DisplayName: handle}
	if err := s.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	return u
}

// seedInvite creates a redeemable invite token for the user and returns the raw token.
func seedInvite(t *testing.T, s *store.Store, userID string) string {
	t.Helper()
	raw := "invite-" + userID
	if err := s.CreateInviteToken(context.Background(), &store.InviteToken{
		ID:        "inv-" + userID,
		TokenHash: hashToken(raw),
		UserID:    userID,
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	return raw
}

// testAPI builds a fully-wired auth handler behind the middleware chain.
type testAPI struct {
	s   *store.Store
	key *rsa.PrivateKey
	wh  *apiauth.WebAuthnHandler
	mux http.Handler
}

func newTestAPI(t *testing.T) *testAPI {
	t.Helper()
	s := testStore(t)
	key := testKey(t)
	wh, err := apiauth.NewWebAuthnHandler(testRPID, "Sovereign", testOrigin, s)
	if err != nil {
		t.Fatalf("NewWebAuthnHandler: %v", err)
	}
	ah := v1auth.New(s, key, testIssuer, wh, slog.New(slog.NewTextHandler(io.Discard, nil)))
	h := meta.New()
	life := middleware.NewHandler(&middleware.ChainConfig{
		Routes:        api.ToRouteInfo(api.RoutesForAPI(h, ah)),
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		SigningKey:    key,
		Issuer:        testIssuer,
		SessionCookie: v1auth.SessionCookie,
		Sessions:      s,
		Users:         s,
		DualRead:      true,
		BodyLimit:     middleware.DefaultMaxBodyBytes,
	})
	t.Cleanup(life.Close)
	return &testAPI{s: s, key: key, wh: wh, mux: life}
}

// req builds an httptest request against the API with the given Host.
func (ta *testAPI) req(method, path string) *http.Request {
	r := httptest.NewRequest(method, path, http.NoBody)
	r.Host = testDomain
	return r
}

// do runs a request through the chain and returns the recorder.
func (ta *testAPI) do(r *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	ta.mux.ServeHTTP(rec, r)
	return rec
}

// cookieReq adds a session cookie (and CSRF for unsafe methods).
func (ta *testAPI) cookieReq(method, path, sessionToken string) *http.Request {
	r := ta.req(method, path)
	r.AddCookie(&http.Cookie{Name: v1auth.SessionCookie, Value: sessionToken})
	if method != http.MethodGet {
		// Cookie-authenticated unsafe requests require the double-submit CSRF token.
		tok := "csrf-token"
		r.AddCookie(&http.Cookie{Name: "__Host-csrf", Value: tok})
		r.Header.Set("X-CSRF-Token", tok)
	}
	return r
}

// bearerReq adds an Authorization Bearer header.
func bearerReq(r *http.Request, token string) *http.Request {
	r.Header.Set("Authorization", "Bearer "+token)
	return r
}

// createSession creates a server-side session row for the user and returns the raw token.
func createSession(t *testing.T, s *store.Store, userID string, ttl time.Duration) string {
	t.Helper()
	tok, err := store.GenerateSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateSession(context.Background(), userID, store.HashSessionToken(tok), ttl, "", ""); err != nil {
		t.Fatal(err)
	}
	return tok
}

func hashToken(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])
}

// --- tests ---

func TestRedeemInviteProgrammatic(t *testing.T) {
	ta := newTestAPI(t)
	u := seedTenantUser(t, ta.s, "identity", "alice")
	raw := seedInvite(t, ta.s, u.ID)

	body := strings.NewReader(`{"token":"` + raw + `"}`)
	r := ta.req(http.MethodPost, "/api/v1/auth/invite/redeem")
	r.Body = io.NopCloser(body)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Idempotency-Key", "key-1")
	rec := ta.do(r)
	if rec.Code != http.StatusOK {
		t.Fatalf("redeem = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	var resp struct {
		Session dto.Session `json:"session"`
		Token   string      `json:"token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode redeem: %v", err)
	}
	if resp.Token == "" {
		t.Fatal("redeem returned no session token")
	}
	if resp.Session.UserID != u.ID {
		t.Fatalf("session user = %q, want %q", resp.Session.UserID, u.ID)
	}
	// The raw token must be resolvable as a Bearer credential (exchange-only:
	// it authenticates, but is NOT a cookie).
	get := ta.do(bearerReq(ta.req(http.MethodGet, "/api/v1/auth/session"), resp.Token))
	if get.Code != http.StatusOK {
		t.Fatalf("bearer get session = %d, want 200 (body %s)", get.Code, get.Body.String())
	}
	// Exchange-only: the token cannot drive cookie-only endpoints (refresh).
	refresh := ta.do(bearerReq(ta.req(http.MethodPost, "/api/v1/auth/session/refresh"), resp.Token))
	if refresh.Code != http.StatusUnauthorized {
		t.Fatalf("bearer refresh = %d, want 401 (exchange-only)", refresh.Code)
	}
	// No cookie must be set by the programmatic redeem.
	if got := rec.Result().Cookies(); len(got) != 0 {
		t.Fatalf("programmatic redeem set cookies: %v", got)
	}
}

func TestBrowserInviteSessionFlow(t *testing.T) {
	ta := newTestAPI(t)
	u := seedTenantUser(t, ta.s, "identity", "alice")
	raw := seedInvite(t, ta.s, u.ID)

	// Anonymous GET /invite/{token} redeems into a session cookie and 303s.
	rec := ta.do(ta.req(http.MethodGet, "/invite/"+raw))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("invite GET = %d, want 303 (body %s)", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "/panel") {
		t.Fatalf("Location = %q, want /panel", loc)
	}
	var sessionCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == v1auth.SessionCookie {
			sessionCookie = c
		}
	}
	if sessionCookie == nil || sessionCookie.Value == "" {
		t.Fatal("no session cookie set")
	}
	if !sessionCookie.HttpOnly {
		t.Error("session cookie not HttpOnly")
	}

	// The cookie authenticates GET /auth/session.
	authReq := ta.cookieReq(http.MethodGet, "/api/v1/auth/session", sessionCookie.Value)
	authRec := ta.do(authReq)
	if authRec.Code != http.StatusOK {
		t.Fatalf("session with invite cookie = %d, want 200 (body %s)", authRec.Code, authRec.Body.String())
	}
	var p dto.Principal
	if err := json.Unmarshal(authRec.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	if p.UserID != u.ID {
		t.Fatalf("session user = %q, want %q", p.UserID, u.ID)
	}
	if !p.IsCookie {
		t.Fatal("invite-created session should be a cookie principal")
	}
}

func TestGetSession(t *testing.T) {
	ta := newTestAPI(t)
	u := seedTenantUser(t, ta.s, "identity", "alice")
	tok := createSession(t, ta.s, u.ID, time.Hour)

	rec := ta.do(ta.cookieReq(http.MethodGet, "/api/v1/auth/session", tok))
	if rec.Code != http.StatusOK {
		t.Fatalf("get session = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	var p dto.Principal
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	if p.UserID != u.ID || p.TenantID != "identity" || !p.IsCookie {
		t.Fatalf("principal = %+v", p)
	}
	if p.ToSAccepted {
		t.Error("tos_accepted should be false for a fresh user")
	}
}

func TestGetSessionUnauthenticated(t *testing.T) {
	ta := newTestAPI(t)
	rec := ta.do(ta.req(http.MethodGet, "/api/v1/auth/session"))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated get session = %d, want 401", rec.Code)
	}
}

func TestRefreshSessionSlidingRenewal(t *testing.T) {
	ta := newTestAPI(t)
	u := seedTenantUser(t, ta.s, "identity", "alice")
	// Start with a short TTL so the extension is measurable.
	tok := createSession(t, ta.s, u.ID, time.Minute)
	sess, err := ta.s.GetSessionByTokenHash(context.Background(), store.HashSessionToken(tok))
	if err != nil {
		t.Fatal(err)
	}
	before := sess.ExpiresAt

	rec := ta.do(ta.cookieReq(http.MethodPost, "/api/v1/auth/session/refresh", tok))
	if rec.Code != http.StatusOK {
		t.Fatalf("refresh = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	var got dto.Session
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !got.ExpiresAt.After(before) {
		t.Fatalf("expiry not extended: before=%v after=%v", before, got.ExpiresAt)
	}
	// The cookie must be re-set with the new expiry.
	var found bool
	for _, c := range rec.Result().Cookies() {
		if c.Name == v1auth.SessionCookie && c.Value == tok {
			found = true
		}
	}
	if !found {
		t.Error("refresh did not re-set the session cookie")
	}
}

func TestDeleteSessionRevokesAndClearsCookie(t *testing.T) {
	ta := newTestAPI(t)
	u := seedTenantUser(t, ta.s, "identity", "alice")
	tok := createSession(t, ta.s, u.ID, time.Hour)

	rec := ta.do(ta.cookieReq(http.MethodDelete, "/api/v1/auth/session", tok))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete session = %d, want 204 (body %s)", rec.Code, rec.Body.String())
	}
	// Session row revoked.
	sess, err := ta.s.GetSessionByTokenHash(context.Background(), store.HashSessionToken(tok))
	if err != nil || sess.RevokedAt == nil {
		t.Fatalf("session not revoked: err=%v sess=%+v", err, sess)
	}
	// Cookie cleared.
	var cleared bool
	for _, c := range rec.Result().Cookies() {
		if c.Name == v1auth.SessionCookie && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Error("session cookie not cleared (no MaxAge<0 cookie)")
	}
	// Revoked token no longer authenticates.
	after := ta.do(ta.cookieReq(http.MethodGet, "/api/v1/auth/session", tok))
	if after.Code != http.StatusUnauthorized {
		t.Fatalf("session after revoke = %d, want 401", after.Code)
	}
}

func TestWrongAudienceAndIssuerRejected(t *testing.T) {
	ta := newTestAPI(t)
	u := seedTenantUser(t, ta.s, "identity", "alice")
	// Mint JWTs with wrong audience and wrong issuer; both must be 401.
	for name, mint := range map[string]func() string{
		"wrong-audience": func() string { return mintToken(t, ta.key, u.ID, "wrong-audience", testIssuer) },
		"wrong-issuer":   func() string { return mintToken(t, ta.key, u.ID, "sovereign-api", "https://evil.example") },
	} {
		t.Run(name, func(t *testing.T) {
			rec := ta.do(bearerReq(ta.req(http.MethodGet, "/api/v1/auth/session"), mint()))
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("%s token = %d, want 401", name, rec.Code)
			}
		})
	}
}

func TestCrossTenantSessionIsolation(t *testing.T) {
	ta := newTestAPI(t)
	a := seedTenantUser(t, ta.s, "tenant-a", "alice")
	b := seedTenantUser(t, ta.s, "tenant-b", "bob")
	tokA := createSession(t, ta.s, a.ID, time.Hour)
	tokB := createSession(t, ta.s, b.ID, time.Hour)

	pa := ta.do(ta.cookieReq(http.MethodGet, "/api/v1/auth/session", tokA))
	pb := ta.do(ta.cookieReq(http.MethodGet, "/api/v1/auth/session", tokB))
	if pa.Code != http.StatusOK || pb.Code != http.StatusOK {
		t.Fatalf("session codes = %d/%d", pa.Code, pb.Code)
	}
	var ga, gb dto.Principal
	_ = json.Unmarshal(pa.Body.Bytes(), &ga)
	_ = json.Unmarshal(pb.Body.Bytes(), &gb)
	if ga.TenantID != "tenant-a" || gb.TenantID != "tenant-b" {
		t.Fatalf("tenant mapping wrong: a=%+v b=%+v", ga, gb)
	}
	if ga.UserID == gb.UserID {
		t.Fatal("sessions must resolve to distinct users")
	}
	// Revoking A's session must not affect B.
	if err := ta.s.RevokeSession(context.Background(), mustSessionID(t, ta.s, tokA)); err != nil {
		t.Fatal(err)
	}
	if rb := ta.do(ta.cookieReq(http.MethodGet, "/api/v1/auth/session", tokB)); rb.Code != http.StatusOK {
		t.Fatalf("tenant B session after A revoke = %d, want 200", rb.Code)
	}
}

// --- WebAuthn tests ---

func TestRegisterBeginDerivesUserFromSession(t *testing.T) {
	ta := newTestAPI(t)
	// Two users in the identity tenant so a ?handle= collision is detectable.
	u := seedTenantUser(t, ta.s, "identity", "alice")
	_ = seedTenantUser(t, ta.s, "identity", "bob")
	tok := createSession(t, ta.s, u.ID, time.Hour)

	// Pass ?handle=bob but authenticate as alice: the session's user wins (B11).
	req := ta.cookieReq(http.MethodPost, "/api/v1/auth/webauthn/register/begin?handle=bob", tok)
	req.URL.RawQuery = "handle=bob"
	rec := ta.do(req)
	if rec.Code != http.StatusOK {
		t.Fatalf("register begin = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	// The creation options must reference alice's user ID (the session user),
	// not bob's. go-webauthn nests the user object under "publicKey.user".
	var creation map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &creation); err != nil {
		t.Fatal(err)
	}
	pk, ok := creation["publicKey"].(map[string]any)
	if !ok {
		t.Fatalf("creation.publicKey missing: %s", rec.Body.String())
	}
	user, ok := pk["user"].(map[string]any)
	if !ok {
		t.Fatalf("publicKey.user missing: %s", rec.Body.String())
	}
	// The user object's "id" is base64url(user.WebAuthnID()) = the store user ID.
	uid, _ := user["id"].(string)
	if uid != base64.RawURLEncoding.EncodeToString([]byte(u.ID)) {
		t.Fatalf("registration bound to user id=%q, want session user %q", uid, u.ID)
	}
}

func TestRegisterFinishStoresCredentialAndSetsPasskey(t *testing.T) {
	ta := newTestAPI(t)
	u := seedTenantUser(t, ta.s, "identity", "alice")
	tok := createSession(t, ta.s, u.ID, time.Hour)

	// Begin registration (session user).
	begin := ta.do(ta.cookieReq(http.MethodPost, "/api/v1/auth/webauthn/register/begin", tok))
	if begin.Code != http.StatusOK {
		t.Fatalf("register begin = %d", begin.Code)
	}
	var creation protocol.CredentialCreation
	if err := json.Unmarshal(begin.Body.Bytes(), &creation); err != nil {
		t.Fatal(err)
	}
	challenge := creation.Response.Challenge.String()

	// Complete the registration with a mock authenticator.
	auth := newTestAuthenticator()
	finishBody := auth.registrationResponse(challenge, testRPID, testOrigin)
	req := ta.cookieReq(http.MethodPost, "/api/v1/auth/webauthn/register/finish?challenge="+challenge, tok)
	req.Body = io.NopCloser(strings.NewReader(string(finishBody)))
	req.Header.Set("Content-Type", "application/json")
	fin := ta.do(req)
	if fin.Code != http.StatusOK {
		t.Fatalf("register finish = %d, want 200 (body %s)", fin.Code, fin.Body.String())
	}
	// Passkey setup must be marked server-side.
	got, err := ta.s.UserByID(context.Background(), u.ID)
	if err != nil || !got.PasskeySetup {
		t.Fatalf("passkey_setup not set: err=%v user=%+v", err, got)
	}
	// Credential persisted.
	creds, err := ta.s.ListWebAuthnCredentials(context.Background(), u.ID)
	if err != nil || len(creds) != 1 {
		t.Fatalf("credentials = %d, %v, want 1", len(creds), err)
	}
}

func TestLoginBeginUniformForUnknownHandle(t *testing.T) {
	ta := newTestAPI(t)
	u := seedTenantUser(t, ta.s, "identity", "alice")

	// A known handle and an unknown handle must produce IDENTICAL response shape.
	known := ta.do(ta.req(http.MethodPost, "/api/v1/auth/webauthn/login/begin"))
	unknown := ta.do(ta.req(http.MethodPost, "/api/v1/auth/webauthn/login/begin"))
	if known.Code != http.StatusOK || unknown.Code != http.StatusOK {
		t.Fatalf("login begin codes = %d/%d", known.Code, unknown.Code)
	}
	var ka, ua protocol.CredentialAssertion
	if err := json.Unmarshal(known.Body.Bytes(), &ka); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(unknown.Body.Bytes(), &ua); err != nil {
		t.Fatal(err)
	}
	// Both are discoverable (passkey) logins: no user, no allowedCredentials.
	if ka.Response.AllowedCredentials != nil || ua.Response.AllowedCredentials != nil {
		t.Fatalf("login begin must be discoverable (no allowed credentials): known=%v unknown=%v",
			ka.Response.AllowedCredentials, ua.Response.AllowedCredentials)
	}
	if ka.Response.Challenge.String() == "" || ua.Response.Challenge.String() == "" {
		t.Fatal("login begin returned no challenge")
	}
	// The response bodies must have the same top-level keys.
	var km, um map[string]any
	_ = json.Unmarshal(known.Body.Bytes(), &km)
	_ = json.Unmarshal(unknown.Body.Bytes(), &um)
	if len(km) != len(um) {
		t.Fatalf("login begin shape differs: known keys=%d unknown keys=%d", len(km), len(um))
	}
	_ = u // user is only used to seed the tenant
}

func TestLoginFinishMintsSession(t *testing.T) {
	ta := newTestAPI(t)
	u := seedTenantUser(t, ta.s, "identity", "alice")
	tok := createSession(t, ta.s, u.ID, time.Hour)

	// Register a credential for alice first.
	begin := ta.do(ta.cookieReq(http.MethodPost, "/api/v1/auth/webauthn/register/begin", tok))
	if begin.Code != http.StatusOK {
		t.Fatalf("register begin = %d", begin.Code)
	}
	var creation protocol.CredentialCreation
	_ = json.Unmarshal(begin.Body.Bytes(), &creation)
	challenge := creation.Response.Challenge.String()
	auth := newTestAuthenticator()
	regBody := auth.registrationResponse(challenge, testRPID, testOrigin)
	regReq := ta.cookieReq(http.MethodPost, "/api/v1/auth/webauthn/register/finish?challenge="+challenge, tok)
	regReq.Body = io.NopCloser(strings.NewReader(string(regBody)))
	regReq.Header.Set("Content-Type", "application/json")
	if rr := ta.do(regReq); rr.Code != http.StatusOK {
		t.Fatalf("register finish = %d (body %s)", rr.Code, rr.Body.String())
	}

	// Anonymous discoverable login begin.
	lb := ta.do(ta.req(http.MethodPost, "/api/v1/auth/webauthn/login/begin"))
	if lb.Code != http.StatusOK {
		t.Fatalf("login begin = %d", lb.Code)
	}
	var assertion protocol.CredentialAssertion
	_ = json.Unmarshal(lb.Body.Bytes(), &assertion)
	lchallenge := assertion.Response.Challenge.String()

	// Complete the login with the same authenticator (assertion over stored key).
	loginBody := auth.assertionResponse(lchallenge, testRPID, testOrigin, u.ID, 1)
	lf := ta.req(http.MethodPost, "/api/v1/auth/webauthn/login/finish?challenge="+lchallenge)
	lf.Body = io.NopCloser(strings.NewReader(string(loginBody)))
	lf.Header.Set("Content-Type", "application/json")
	lfRec := ta.do(lf)
	if lfRec.Code != http.StatusOK {
		t.Fatalf("login finish = %d, want 200 (body %s)", lfRec.Code, lfRec.Body.String())
	}
	// A session cookie must be set.
	var sessionCookie *http.Cookie
	for _, c := range lfRec.Result().Cookies() {
		if c.Name == v1auth.SessionCookie {
			sessionCookie = c
		}
	}
	if sessionCookie == nil || sessionCookie.Value == "" {
		t.Fatal("login finish did not set a session cookie")
	}
	// The new cookie authenticates and resolves to alice.
	sessRec := ta.do(ta.cookieReq(http.MethodGet, "/api/v1/auth/session", sessionCookie.Value))
	if sessRec.Code != http.StatusOK {
		t.Fatalf("session after login = %d (body %s)", sessRec.Code, sessRec.Body.String())
	}
	var p dto.Principal
	_ = json.Unmarshal(sessRec.Body.Bytes(), &p)
	if p.UserID != u.ID {
		t.Fatalf("login session user = %q, want %q", p.UserID, u.ID)
	}
}

// --- mock authenticator ---

type testAuthenticator struct {
	key    *ecdsa.PrivateKey
	credID []byte
}

func newTestAuthenticator() *testAuthenticator {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	credID := make([]byte, 16)
	_, _ = rand.Read(credID)
	return &testAuthenticator{key: key, credID: credID}
}

// cosePublicKey encodes the EC2 (ES256) public key in COSE/CBOR form.
func (ta *testAuthenticator) cosePublicKey() []byte {
	// PublicKey.Bytes returns the SEC1 uncompressed point (0x04 || X || Y).
	raw, err := ta.key.PublicKey.Bytes()
	if err != nil {
		panic("testAuthenticator: encode public key: " + err.Error())
	}
	x := raw[1 : 1+32]
	y := raw[1+32:]
	pk := webauthncose.EC2PublicKeyData{
		PublicKeyData: webauthncose.PublicKeyData{KeyType: 2, Algorithm: -7}, // EC2, ES256
		Curve:         1,                                                     // P-256
		XCoord:        x,
		YCoord:        y,
	}
	b, _ := webauthncbor.Marshal(pk)
	return b
}

// rawAuthData builds the authenticator data (RPID hash + flags + counter, plus
// attested credential data for registration).
func (ta *testAuthenticator) rawAuthData(rpID string, withAttested bool, counter uint32) []byte {
	rpHash := sha256.Sum256([]byte(rpID))
	var out []byte
	out = append(out, rpHash[:]...)
	flags := byte(0x01) // UP
	if withAttested {
		flags |= 0x40 // AT
	}
	out = append(out, flags)
	var cnt [4]byte
	binary.BigEndian.PutUint32(cnt[:], counter)
	out = append(out, cnt[:]...)
	if withAttested {
		out = append(out, make([]byte, 16)...) // AAGUID
		var idLen [2]byte
		binary.BigEndian.PutUint16(idLen[:], uint16(len(ta.credID)))
		out = append(out, idLen[:]...)
		out = append(out, ta.credID...)
		out = append(out, ta.cosePublicKey()...)
	}
	return out
}

// registrationResponse builds a valid webauthn.create attestation response for
// the "none" attestation format.
func (ta *testAuthenticator) registrationResponse(challenge, rpID, origin string) []byte {
	authData := ta.rawAuthData(rpID, true, 1)
	attObj := protocol.AttestationObject{
		RawAuthData: authData,
		Format:      "none",
	}
	attBytes, _ := webauthncbor.Marshal(attObj)
	ccd, _ := json.Marshal(protocol.CollectedClientData{
		Type:      protocol.CreateCeremony,
		Challenge: challenge,
		Origin:    origin,
	})
	return marshalCredentialResponse(ta.credID, map[string]any{
		"attestationObject": base64.RawURLEncoding.EncodeToString(attBytes),
		"clientDataJSON":    base64.RawURLEncoding.EncodeToString(ccd),
	})
}

// assertionResponse builds a valid webauthn.get assertion response signed by
// the credential private key.
func (ta *testAuthenticator) assertionResponse(challenge, rpID, origin, userID string, counter uint32) []byte {
	authData := ta.rawAuthData(rpID, false, counter)
	ccd, _ := json.Marshal(protocol.CollectedClientData{
		Type:      protocol.AssertCeremony,
		Challenge: challenge,
		Origin:    origin,
	})
	ccdHash := sha256.Sum256(ccd)
	sigData := append(append([]byte{}, authData...), ccdHash[:]...)
	h := sha256.Sum256(sigData)
	r, s, _ := ecdsa.Sign(rand.Reader, ta.key, h[:])
	sig, _ := asn1.Marshal(webauthncose.ECDSASignature{R: r, S: s})
	return marshalCredentialResponse(ta.credID, map[string]any{
		"clientDataJSON":    base64.RawURLEncoding.EncodeToString(ccd),
		"authenticatorData": base64.RawURLEncoding.EncodeToString(authData),
		"signature":         base64.RawURLEncoding.EncodeToString(sig),
		"userHandle":        base64.RawURLEncoding.EncodeToString([]byte(userID)),
	})
}

// marshalCredentialResponse wraps a public-key credential JSON body.
func marshalCredentialResponse(credID []byte, response map[string]any) []byte {
	b, _ := json.Marshal(map[string]any{
		"id":       base64.RawURLEncoding.EncodeToString(credID),
		"rawId":    base64.RawURLEncoding.EncodeToString(credID),
		"type":     "public-key",
		"response": response,
	})
	return b
}

// --- misc helpers ---

func mintToken(t *testing.T, key *rsa.PrivateKey, sub, aud, issuer string) string {
	t.Helper()
	tok, err := apiauth.MintAccessToken(key, sub, []string{"self"}, time.Minute, issuer, aud)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func mustSessionID(t *testing.T, s *store.Store, token string) string {
	t.Helper()
	sess, err := s.GetSessionByTokenHash(context.Background(), store.HashSessionToken(token))
	if err != nil {
		t.Fatal(err)
	}
	return sess.ID
}
