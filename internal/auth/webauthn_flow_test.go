package auth

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/selfagency/sovereign/internal/store"
)

// --- mock authenticator (mirrors the control-plane test harness) ---

type mockAuthn struct {
	key    *ecdsa.PrivateKey
	credID []byte
}

func newMockAuthn() *mockAuthn {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	credID := make([]byte, 16)
	_, _ = rand.Read(credID)
	return &mockAuthn{key: key, credID: credID}
}

func (m *mockAuthn) cosePublicKey() []byte {
	raw, err := m.key.PublicKey.Bytes()
	if err != nil {
		panic("mockAuthn: public key: " + err.Error())
	}
	x := raw[1 : 1+32]
	y := raw[1+32:]
	pk := webauthncose.EC2PublicKeyData{
		PublicKeyData: webauthncose.PublicKeyData{KeyType: 2, Algorithm: -7},
		Curve:         1,
		XCoord:        x,
		YCoord:        y,
	}
	b, _ := webauthncbor.Marshal(pk)
	return b
}

func (m *mockAuthn) rawAuthData(rpID string, withAttested bool, counter uint32) []byte {
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
		binary.BigEndian.PutUint16(idLen[:], uint16(len(m.credID)))
		out = append(out, idLen[:]...)
		out = append(out, m.credID...)
		out = append(out, m.cosePublicKey()...)
	}
	return out
}

func (m *mockAuthn) registrationResponse(challenge, rpID, origin string) []byte {
	authData := m.rawAuthData(rpID, true, 1)
	attObj := protocol.AttestationObject{RawAuthData: authData, Format: "none"}
	attBytes, _ := webauthncbor.Marshal(attObj)
	ccd, _ := json.Marshal(protocol.CollectedClientData{Type: protocol.CreateCeremony, Challenge: challenge, Origin: origin})
	return marshalCredResponse(m.credID, map[string]any{
		"attestationObject": base64.RawURLEncoding.EncodeToString(attBytes),
		"clientDataJSON":    base64.RawURLEncoding.EncodeToString(ccd),
	})
}

func (m *mockAuthn) assertionResponse(challenge, rpID, origin, userID string, counter uint32) []byte {
	authData := m.rawAuthData(rpID, false, counter)
	ccd, _ := json.Marshal(protocol.CollectedClientData{Type: protocol.AssertCeremony, Challenge: challenge, Origin: origin})
	ccdHash := sha256.Sum256(ccd)
	sigData := append(append([]byte{}, authData...), ccdHash[:]...)
	h := sha256.Sum256(sigData)
	r, s, _ := ecdsa.Sign(rand.Reader, m.key, h[:])
	sig, _ := asn1.Marshal(webauthncose.ECDSASignature{R: r, S: s})
	return marshalCredResponse(m.credID, map[string]any{
		"clientDataJSON":    base64.RawURLEncoding.EncodeToString(ccd),
		"authenticatorData": base64.RawURLEncoding.EncodeToString(authData),
		"signature":         base64.RawURLEncoding.EncodeToString(sig),
		"userHandle":        base64.RawURLEncoding.EncodeToString([]byte(userID)),
	})
}

func marshalCredResponse(credID []byte, response map[string]any) []byte {
	b, _ := json.Marshal(map[string]any{
		"id":       base64.RawURLEncoding.EncodeToString(credID),
		"rawId":    base64.RawURLEncoding.EncodeToString(credID),
		"type":     "public-key",
		"response": response,
	})
	return b
}

// --- harness ---

const (
	testRPID   = "id.example.com"
	testOrigin = "https://id.example.com"
)

// newFlowStore opens a temp store with a seeded identity tenant + user.
func newFlowStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	ctx := context.Background()
	if err := s.CreateTenant(ctx, &store.Tenant{ID: "identity", Handle: "id.example.com", DIDMethod: "web"}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateUser(ctx, &store.User{ID: "u1", TenantID: "identity", Handle: "alice", DisplayName: "Alice"}); err != nil {
		t.Fatal(err)
	}
	return s
}

func newFlowHandler(t *testing.T, st *store.Store) *WebAuthnHandler {
	t.Helper()
	h, err := NewWebAuthnHandler(testRPID, "Sovereign", testOrigin, st)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// registerCredential drives a full session-derived register ceremony and
// returns the authenticator so the same key can assert in a later login.
func registerCredential(t *testing.T, h *WebAuthnHandler, st *store.Store) *mockAuthn {
	t.Helper()
	auth := newMockAuthn()
	_, session, err := h.BeginRegistrationUser("u1")
	if err != nil {
		t.Fatalf("register begin: %v", err)
	}
	challenge := session.Challenge
	body := auth.registrationResponse(challenge, testRPID, testOrigin)
	fin := httptest.NewRequest(http.MethodPost, "/webauthn/register/finish?challenge="+challenge, io.NopCloser(strings.NewReader(string(body))))
	fin.Header.Set("Content-Type", "application/json")
	if err := h.FinishRegistrationUser("u1", fin); err != nil {
		t.Fatalf("register finish: %v", err)
	}
	creds, err := st.ListWebAuthnCredentials(context.Background(), "u1")
	if err != nil || len(creds) != 1 {
		t.Fatalf("credentials = %d, err=%v, want 1", len(creds), err)
	}
	return auth
}

// --- webauthn.go tests ---

// TestNewWebAuthnRejectsInvalidRPID verifies config validation rejects an RPID
// with a scheme + path component.
func TestNewWebAuthnRejectsInvalidRPID(t *testing.T) {
	if _, err := NewWebAuthn("https://evil.example/x", "Sovereign", testOrigin); err == nil {
		t.Fatal("expected error for invalid RPID")
	}
}

// TestWebAuthnRegistrationRoundTrip drives a full registration through the
// library wrapper.
func TestWebAuthnRegistrationRoundTrip(t *testing.T) {
	wa, err := NewWebAuthn(testRPID, "Sovereign", testOrigin)
	if err != nil {
		t.Fatal(err)
	}
	u := &User{ID: "u1", Handle: "alice", DisplayName: "Alice"}

	creation, session, err := wa.BeginRegistration(u)
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	if creation.Response.Challenge.String() == "" {
		t.Fatal("no challenge in creation options")
	}
	auth := newMockAuthn()
	body := auth.registrationResponse(creation.Response.Challenge.String(), testRPID, testOrigin)
	req := httptest.NewRequest(http.MethodPost, "/x", io.NopCloser(strings.NewReader(string(body))))
	req.Header.Set("Content-Type", "application/json")
	cred, err := wa.FinishRegistration(u, session, req)
	if err != nil {
		t.Fatalf("FinishRegistration: %v", err)
	}
	if len(cred.ID) == 0 {
		t.Fatal("empty credential ID after finish")
	}
}

// TestWebAuthnLoginRoundTrip verifies begin/finish login for a user with a
// stored credential.
func TestWebAuthnLoginRoundTrip(t *testing.T) {
	st := newFlowStore(t)
	wa, err := NewWebAuthn(testRPID, "Sovereign", testOrigin)
	if err != nil {
		t.Fatal(err)
	}
	auth := newMockAuthn()
	// Seed one credential directly via the library registration path.
	u := &User{ID: "u1", Handle: "alice", DisplayName: "Alice"}
	creation, session, err := wa.BeginRegistration(u)
	if err != nil {
		t.Fatal(err)
	}
	regBody := auth.registrationResponse(creation.Response.Challenge.String(), testRPID, testOrigin)
	regReq := httptest.NewRequest(http.MethodPost, "/x", io.NopCloser(strings.NewReader(string(regBody))))
	regReq.Header.Set("Content-Type", "application/json")
	cred, err := wa.FinishRegistration(u, session, regReq)
	if err != nil {
		t.Fatalf("seed registration: %v", err)
	}
	// Store the credential so BeginLogin can find it.
	data, _ := json.Marshal(cred)
	if err := st.AddWebAuthnCredential(context.Background(), &store.WebAuthnCredential{
		ID: string(cred.ID), UserID: "u1", CredentialID: cred.ID, PublicKey: cred.PublicKey,
		SignCount: cred.Authenticator.SignCount, Data: data,
	}); err != nil {
		t.Fatal(err)
	}
	u.Credentials = append(u.Credentials, *cred)

	assertion, lsess, err := wa.BeginLogin(u)
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	if assertion.Response.Challenge.String() == "" {
		t.Fatal("no challenge in assertion")
	}
	loginBody := auth.assertionResponse(assertion.Response.Challenge.String(), testRPID, testOrigin, "u1", 2)
	loginReq := httptest.NewRequest(http.MethodPost, "/x", io.NopCloser(strings.NewReader(string(loginBody))))
	loginReq.Header.Set("Content-Type", "application/json")
	got, err := wa.FinishLogin(u, lsess, loginReq)
	if err != nil {
		t.Fatalf("FinishLogin: %v", err)
	}
	if !bytes.Equal(got.ID, cred.ID) {
		t.Fatalf("login credential id = %q, want %q", got.ID, cred.ID)
	}
}

// TestWebAuthnDiscoverableRoundTrip verifies the discoverable login path used
// by the anonymous login/begin endpoint, including the user resolver.
func TestWebAuthnDiscoverableRoundTrip(t *testing.T) {
	st := newFlowStore(t)
	wa, err := NewWebAuthn(testRPID, "Sovereign", testOrigin)
	if err != nil {
		t.Fatal(err)
	}
	auth := newMockAuthn()
	// Seed a credential + sign count via the store so login can resolve it.
	u := &User{ID: "u1", Handle: "alice", DisplayName: "Alice"}
	creation, session, err := wa.BeginRegistration(u)
	if err != nil {
		t.Fatal(err)
	}
	regBody := auth.registrationResponse(creation.Response.Challenge.String(), testRPID, testOrigin)
	regReq := httptest.NewRequest(http.MethodPost, "/x", io.NopCloser(strings.NewReader(string(regBody))))
	regReq.Header.Set("Content-Type", "application/json")
	cred, err := wa.FinishRegistration(u, session, regReq)
	if err != nil {
		t.Fatalf("seed registration: %v", err)
	}
	data, _ := json.Marshal(cred)
	if err := st.AddWebAuthnCredential(context.Background(), &store.WebAuthnCredential{
		ID: string(cred.ID), UserID: "u1", CredentialID: cred.ID, PublicKey: cred.PublicKey,
		SignCount: cred.Authenticator.SignCount, Data: data,
	}); err != nil {
		t.Fatal(err)
	}

	assertion, dsess, err := wa.BeginDiscoverableLogin()
	if err != nil {
		t.Fatalf("BeginDiscoverableLogin: %v", err)
	}
	if assertion.Response.AllowedCredentials != nil {
		t.Fatal("discoverable login must not pre-select credentials")
	}
	loginBody := auth.assertionResponse(assertion.Response.Challenge.String(), testRPID, testOrigin, "u1", 2)
	loginReq := httptest.NewRequest(http.MethodPost, "/x", io.NopCloser(strings.NewReader(string(loginBody))))
	loginReq.Header.Set("Content-Type", "application/json")

	resolver := func(rawID, userHandle []byte) (*User, error) {
		rec, err := st.GetWebAuthnCredential(context.Background(), rawID)
		if err != nil {
			return nil, err
		}
		su, err := st.UserByID(context.Background(), rec.UserID)
		if err != nil {
			return nil, err
		}
		return &User{ID: su.ID, Handle: su.Handle, DisplayName: su.DisplayName, Credentials: []webauthn.Credential{*cred}}, nil
	}
	gotUser, gotCred, err := wa.FinishPasskeyLogin(resolver, dsess, loginReq)
	if err != nil {
		t.Fatalf("FinishPasskeyLogin: %v", err)
	}
	if gotUser.ID != "u1" || gotUser.Handle != "alice" {
		t.Fatalf("resolved user = %+v, want u1/alice", gotUser)
	}
	if !bytes.Equal(gotCred.ID, cred.ID) {
		t.Fatalf("credential id = %q, want %q", gotCred.ID, cred.ID)
	}
}

// TestFinishPasskeyLoginResolverError verifies a resolver error propagates.
func TestFinishPasskeyLoginResolverError(t *testing.T) {
	wa, err := NewWebAuthn(testRPID, "Sovereign", testOrigin)
	if err != nil {
		t.Fatal(err)
	}
	assertion, dsess, err := wa.BeginDiscoverableLogin()
	if err != nil {
		t.Fatal(err)
	}
	auth := newMockAuthn()
	body := auth.assertionResponse(assertion.Response.Challenge.String(), testRPID, testOrigin, "u1", 1)
	req := httptest.NewRequest(http.MethodPost, "/x", io.NopCloser(strings.NewReader(string(body))))
	req.Header.Set("Content-Type", "application/json")
	resolver := func(_, _ []byte) (*User, error) {
		return nil, ErrNoCredentials
	}
	if _, _, err := wa.FinishPasskeyLogin(resolver, dsess, req); err == nil {
		t.Fatal("expected resolver error to propagate")
	}
}

// --- webauthn_handler.go tests ---

// TestWebAuthnHandlerLoginFinishRoundTrip drives the full session-derived login
// flow: register a credential then complete login/finish and resolve the user.
func TestWebAuthnHandlerLoginFinishRoundTrip(t *testing.T) {
	st := newFlowStore(t)
	h := newFlowHandler(t, st)
	auth := registerCredential(t, h, st)

	assertion, session, err := h.BeginLoginUniform()
	if err != nil {
		t.Fatalf("login begin: %v", err)
	}
	challenge := assertion.Response.Challenge.String()
	body := auth.assertionResponse(challenge, testRPID, testOrigin, "u1", 2)
	fin := httptest.NewRequest(http.MethodPost, "/webauthn/login/finish?challenge="+session.Challenge, io.NopCloser(strings.NewReader(string(body))))
	fin.Header.Set("Content-Type", "application/json")
	uid, err := h.FinishLoginUniform(fin)
	if err != nil {
		t.Fatalf("login finish: %v", err)
	}
	if uid != "u1" {
		t.Fatalf("login finish resolved user = %q, want u1", uid)
	}
}

// TestLoadUserByID verifies loading a user by ID populates credentials.
func TestLoadUserByID(t *testing.T) {
	st := newFlowStore(t)
	h := newFlowHandler(t, st)
	u, err := h.loadUserByID("u1")
	if err != nil {
		t.Fatalf("loadUserByID: %v", err)
	}
	if u.ID != "u1" || u.Handle != "alice" {
		t.Fatalf("user = %+v", u)
	}
	if _, err := h.loadUserByID("does-not-exist"); err == nil {
		t.Fatal("expected error loading unknown user")
	}
}

// TestBeginRegistrationUser verifies session-derived registration begin.
func TestBeginRegistrationUser(t *testing.T) {
	st := newFlowStore(t)
	h := newFlowHandler(t, st)
	creation, session, err := h.BeginRegistrationUser("u1")
	if err != nil {
		t.Fatalf("BeginRegistrationUser: %v", err)
	}
	if session.Challenge == "" || creation.Response.Challenge.String() == "" {
		t.Fatal("missing challenge in begin response")
	}
	if _, _, err := h.BeginRegistrationUser("nope"); err == nil {
		t.Fatal("expected error for unknown user")
	}
}

// TestFinishRegistrationUserRoundTrip drives the session-derived finish path
// and verifies the credential persists + session is deleted.
func TestFinishRegistrationUserRoundTrip(t *testing.T) {
	st := newFlowStore(t)
	h := newFlowHandler(t, st)
	auth := newMockAuthn()
	_, session, err := h.BeginRegistrationUser("u1")
	if err != nil {
		t.Fatal(err)
	}
	body := auth.registrationResponse(session.Challenge, testRPID, testOrigin)
	req := httptest.NewRequest(http.MethodPost, "/x?challenge="+session.Challenge, io.NopCloser(strings.NewReader(string(body))))
	req.Header.Set("Content-Type", "application/json")
	if err := h.FinishRegistrationUser("u1", req); err != nil {
		t.Fatalf("FinishRegistrationUser: %v", err)
	}
	creds, err := st.ListWebAuthnCredentials(context.Background(), "u1")
	if err != nil || len(creds) != 1 {
		t.Fatalf("credentials = %d, err=%v, want 1", len(creds), err)
	}
	if _, ok := h.session.Get(session.Challenge); ok {
		t.Fatal("session not deleted after finish")
	}
}

// TestFinishRegistrationUserError verifies finish error paths: unknown user and
// bad challenge.
func TestFinishRegistrationUserError(t *testing.T) {
	st := newFlowStore(t)
	h := newFlowHandler(t, st)
	if err := h.FinishRegistrationUser("nope", httptest.NewRequest(http.MethodPost, "/x", http.NoBody)); err == nil {
		t.Fatal("expected error for unknown user")
	}
	if err := h.FinishRegistrationUser("u1", httptest.NewRequest(http.MethodPost, "/x?challenge=missing", http.NoBody)); err == nil {
		t.Fatal("expected error for missing session")
	}
}

// TestBeginLoginUniform verifies uniform discoverable login begin.
func TestBeginLoginUniform(t *testing.T) {
	st := newFlowStore(t)
	h := newFlowHandler(t, st)
	assertion, session, err := h.BeginLoginUniform()
	if err != nil {
		t.Fatalf("BeginLoginUniform: %v", err)
	}
	if session.Challenge == "" || assertion.Response.Challenge.String() == "" {
		t.Fatal("missing challenge")
	}
	if assertion.Response.AllowedCredentials != nil {
		t.Fatal("uniform login must be discoverable")
	}
}

// TestFinishLoginUniformRoundTrip drives discoverable login finish and returns
// the authenticated user ID.
func TestFinishLoginUniformRoundTrip(t *testing.T) {
	st := newFlowStore(t)
	h := newFlowHandler(t, st)
	auth := registerCredential(t, h, st)

	assertion, session, err := h.BeginLoginUniform()
	if err != nil {
		t.Fatal(err)
	}
	body := auth.assertionResponse(assertion.Response.Challenge.String(), testRPID, testOrigin, "u1", 2)
	req := httptest.NewRequest(http.MethodPost, "/x?challenge="+session.Challenge, io.NopCloser(strings.NewReader(string(body))))
	req.Header.Set("Content-Type", "application/json")
	uid, err := h.FinishLoginUniform(req)
	if err != nil {
		t.Fatalf("FinishLoginUniform: %v", err)
	}
	if uid != "u1" {
		t.Fatalf("uid = %q, want u1", uid)
	}
	if _, ok := h.session.Get(session.Challenge); ok {
		t.Fatal("session not deleted after login finish")
	}
}

// TestFinishLoginUniformMissingSession verifies finish without a session fails.
func TestFinishLoginUniformMissingSession(t *testing.T) {
	st := newFlowStore(t)
	h := newFlowHandler(t, st)
	if _, err := h.FinishLoginUniform(httptest.NewRequest(http.MethodPost, "/x", http.NoBody)); err == nil {
		t.Fatal("expected error without challenge")
	}
	if _, err := h.FinishLoginUniform(httptest.NewRequest(http.MethodPost, "/x?challenge=nope", http.NoBody)); err == nil {
		t.Fatal("expected error for unknown challenge")
	}
}

// TestNewWebAuthnHandlerRejectsBadConfig verifies handler construction fails on
// an invalid RPID.
func TestNewWebAuthnHandlerRejectsBadConfig(t *testing.T) {
	st := newFlowStore(t)
	if _, err := NewWebAuthnHandler("https://evil.example/x", "Sovereign", testOrigin, st); err == nil {
		t.Fatal("expected error for invalid RPID")
	}
}

// TestSessionStoreTTLRoundTrip covers Put/Get/Delete with a real TTL window.
func TestSessionStoreTTLRoundTrip(t *testing.T) {
	s := NewSessionStore(10 * time.Minute)
	s.Put("c", &webauthn.SessionData{Challenge: "c"})
	if got, ok := s.Get("c"); !ok || got.Challenge != "c" {
		t.Fatalf("get = %v, %v", got, ok)
	}
}

// TestSessionStoreEvictsOldest verifies the maxEntries cap evicts the oldest
// entry once the store is at capacity.
func TestSessionStoreEvictsOldest(t *testing.T) {
	s := NewSessionStoreWithMax(10*time.Minute, 2)
	s.Put("c1", &webauthn.SessionData{Challenge: "c1"})
	s.Put("c2", &webauthn.SessionData{Challenge: "c2"})
	// c1 is the oldest; a third put must evict it.
	s.Put("c3", &webauthn.SessionData{Challenge: "c3"})
	if _, ok := s.Get("c1"); ok {
		t.Fatal("oldest entry not evicted at capacity")
	}
	if _, ok := s.Get("c2"); !ok {
		t.Fatal("c2 should remain")
	}
	if _, ok := s.Get("c3"); !ok {
		t.Fatal("c3 should remain")
	}
}

// TestSessionStoreUnbounded verifies a zero cap leaves the store unbounded.
func TestSessionStoreUnbounded(t *testing.T) {
	s := NewSessionStoreWithMax(10*time.Minute, 0)
	s.Put("a", &webauthn.SessionData{Challenge: "a"})
	s.Put("b", &webauthn.SessionData{Challenge: "b"})
	if _, ok := s.Get("a"); !ok {
		t.Fatal("unbounded store should keep all entries")
	}
	if _, ok := s.Get("b"); !ok {
		t.Fatal("unbounded store should keep all entries")
	}
}
