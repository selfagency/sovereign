package openapi

import (
	"bytes"
	"encoding/json"
	"sync"
	"testing"
)

// TestSpecJSONValid verifies the embedded spec converts to valid JSON and is
// not empty. The meta handler serves exactly this document.
func TestSpecJSONValid(t *testing.T) {
	spec, err := SpecJSON()
	if err != nil {
		t.Fatalf("SpecJSON: %v", err)
	}
	if len(spec) == 0 {
		t.Fatal("SpecJSON returned empty document")
	}
	var doc map[string]any
	if err := json.Unmarshal(spec, &doc); err != nil {
		t.Fatalf("SpecJSON is not valid JSON: %v", err)
	}
	if doc["openapi"] == nil {
		t.Error("document missing openapi version field")
	}
	if doc["paths"] == nil {
		t.Error("document missing paths object")
	}
}

// TestSpecJSONIsStable verifies repeated calls return the same cached bytes.
func TestSpecJSONIsStable(t *testing.T) {
	a, err := SpecJSON()
	if err != nil {
		t.Fatalf("SpecJSON: %v", err)
	}
	b, err := SpecJSON()
	if err != nil {
		t.Fatalf("SpecJSON: %v", err)
	}
	if !bytes.Equal(a, b) {
		t.Error("SpecJSON returned different bytes across calls")
	}
}

// TestSpecJSONBadYAML verifies an invalid embedded YAML surfaces an error (and
// the error is cached, not recomputed).
func TestSpecJSONBadYAML(t *testing.T) {
	orig := specYAML
	defer func() { specYAML = orig }()

	// Reset the sync.Once so the poisoned specYAML is parsed fresh.
	once = sync.Once{}
	specYAML = []byte("not: [valid: yaml: :::")
	if _, err := SpecJSON(); err == nil {
		t.Fatal("expected error from invalid YAML")
	}
	// The error is cached: a second call returns the same error.
	if _, err := SpecJSON(); err == nil {
		t.Fatal("expected cached error from invalid YAML")
	}

	// Restore a valid spec and confirm the next call works after the cache is
	// reset again.
	specYAML = orig
	spec = nil
	errVal = nil
	once = sync.Once{}
	if _, err := SpecJSON(); err != nil {
		t.Fatalf("SpecJSON after restore: %v", err)
	}
}
