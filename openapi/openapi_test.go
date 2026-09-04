package openapi

import (
	"bytes"
	"encoding/json"
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
