package atproto

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bluesky-social/indigo/atproto/identity"
)

// mockPLCServer serves a did:plc document.
func mockPLCServer(t *testing.T, did string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/"+did, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{
			"id":"` + did + `",
			"alsoKnownAs":["at://alice.example.com"],
			"verificationMethod":[{"id":"#atproto","type":"Multikey","controller":"` + did + `","publicKeyMultibase":"zDnae..."}],
			"service":[{"id":"#atproto_pds","type":"AtprotoPersonalDataServer","serviceEndpoint":"https://pds.example.com"}]
		}`))
	})
	return httptest.NewServer(mux)
}

// TestResolveDID verifies did:plc resolution via a mock PLC server.
func TestResolveDID(t *testing.T) {
	did := "did:plc:abc123"
	srv := mockPLCServer(t, did)
	defer srv.Close()

	base := &identity.BaseDirectory{PLCURL: srv.URL}
	dir := NewDirectoryWithBase(base)
	ident, err := dir.ResolveDID(context.Background(), did)
	if err != nil {
		t.Fatalf("ResolveDID: %v", err)
	}
	if ident.DID.String() != did {
		t.Fatalf("did = %s, want %s", ident.DID, did)
	}
	if pds := PDSEndpoint(ident); pds != "https://pds.example.com" {
		t.Fatalf("pds endpoint = %q", pds)
	}
}

// TestResolveDIDInvalid verifies an invalid DID is rejected.
func TestResolveDIDInvalid(t *testing.T) {
	dir := NewDirectory()
	if _, err := dir.ResolveDID(context.Background(), "not-a-did"); err == nil {
		t.Fatal("expected error for invalid DID")
	}
}

// TestResolveHandleInvalid verifies an invalid handle is rejected.
func TestResolveHandleInvalid(t *testing.T) {
	dir := NewDirectory()
	if _, err := dir.ResolveHandle(context.Background(), "not a handle"); err == nil {
		t.Fatal("expected error for invalid handle")
	}
	if _, err := dir.ResolveHandleToDID(context.Background(), "not a handle"); err == nil {
		t.Fatal("expected error for invalid handle")
	}
}

// TestResolveHandleToDIDLookupError verifies ResolveHandleToDID surfaces a
// lookup failure for a well-formed but unresolvable handle.
func TestResolveHandleToDIDLookupError(t *testing.T) {
	dir := NewDirectory()
	if _, err := dir.ResolveHandleToDID(context.Background(), "nonexistent.example.com"); err == nil {
		t.Fatal("expected error for unresolvable handle")
	}
}
