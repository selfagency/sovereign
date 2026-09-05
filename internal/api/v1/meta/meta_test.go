package meta

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/selfagency/sovereign/internal/api/dto"
	"github.com/selfagency/sovereign/openapi"
)

// serve runs a handler against a fresh GET request and returns the recorder.
func serve(h http.HandlerFunc) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "http://sovereign.example/api/v1/meta", http.NoBody)
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec
}

func TestCapabilitiesHonest(t *testing.T) {
	// Only Phase-1-wired features are true; data-plane features are false.
	h := New(WithCapabilities(dto.Capabilities{WebAuthn: true, OIDC: true}))
	rec := serve(h.Capabilities)

	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	want := dto.Capabilities{Backup: false, Atproto: false, Solid: false, IPFS: false, Proofs: false, WebAuthn: true, OIDC: true}
	var got dto.Capabilities
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal capabilities: %v", err)
	}
	if got != want {
		t.Errorf("capabilities mismatch\n got %+v\nwant %+v", got, want)
	}
}

func TestCapabilitiesAllOff(t *testing.T) {
	// A zero-value capability set reports everything false.
	h := New()
	rec := serve(h.Capabilities)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var got dto.Capabilities
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got != (dto.Capabilities{}) {
		t.Errorf("expected all-false capabilities, got %+v", got)
	}
}

func TestVersion(t *testing.T) {
	h := New(WithVersion(VersionInfo{Version: "v1.2.3", Commit: "c172cf2", GoVersion: "go1.27"}))
	rec := serve(h.Version)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	var got dto.Version
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Version != "v1.2.3" || got.Commit != "c172cf2" || got.GoVersion != "go1.27" {
		t.Errorf("version = %+v, want version=v1.2.3 commit=c172cf2 go_version=go1.27", got)
	}
}

func TestVersionFillsGoRuntime(t *testing.T) {
	// When GoVersion is not stamped, the handler reports runtime.Version().
	h := New(WithVersion(VersionInfo{Version: "dev"}))
	rec := serve(h.Version)
	var got dto.Version
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.GoVersion == "" {
		t.Error("expected go_version to be filled from runtime, got empty")
	}
}

func TestHealth(t *testing.T) {
	h := New()
	rec := serve(h.Health)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	var got dto.Health
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Status != "ok" {
		t.Errorf("status field = %q, want ok", got.Status)
	}
}

func TestReadyOK(t *testing.T) {
	h := New(WithPing(func(context.Context) error { return nil }))
	rec := serve(h.Ready)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var got dto.Health
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Status != "ok" {
		t.Errorf("status field = %q, want ok", got.Status)
	}
}

func TestReadyFailsOnPingError(t *testing.T) {
	h := New(WithPing(func(context.Context) error { return errors.New("db down") }))
	rec := serve(h.Ready)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Errorf("Content-Type = %q, want application/problem+json", ct)
	}
	if body := rec.Body.String(); !strings.Contains(body, "service-unavailable") {
		t.Errorf("body %q should reference the service-unavailable problem type", body)
	}
}

func TestReadyFailsClosedWithoutPing(t *testing.T) {
	// No ping wired -> fail closed with 503.
	h := New()
	rec := serve(h.Ready)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

func TestOpenAPIServesJSON(t *testing.T) {
	h := New()
	rec := serve(h.OpenAPI)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	// Must be valid JSON.
	var doc map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("openapi body is not valid JSON: %v", err)
	}
	if doc["openapi"] == nil {
		t.Error("openapi document missing the openapi version field")
	}
	// Must carry the documented paths.
	paths, ok := doc["paths"].(map[string]any)
	if !ok {
		t.Fatalf("openapi document missing paths object, got %T", doc["paths"])
	}
	for _, p := range []string{"/meta/capabilities", "/health", "/ready", "/openapi.json"} {
		if _, ok := paths[p]; !ok {
			t.Errorf("openapi document missing documented path %s", p)
		}
	}
}

func TestOpenAPIMatchesSourceOfTruth(t *testing.T) {
	// The served spec must equal the embedded source of truth (JSON-ified), so
	// the endpoint can never drift from the file the drift test validates.
	want, err := openapi.SpecJSON()
	if err != nil {
		t.Fatalf("SpecJSON: %v", err)
	}
	h := New()
	rec := serve(h.OpenAPI)
	if got := rec.Body.Bytes(); !bytes.Equal(got, want) {
		t.Error("served openapi.json differs from the embedded source of truth")
	}
}
