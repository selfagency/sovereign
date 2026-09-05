// Package openapi embeds the hand-written OpenAPI 3.1 source of truth
// (sovereign.v1.yaml) so the server can serve it at /api/v1/openapi.json.
//
// The embed is co-located with the YAML it embeds, which keeps the served
// document identical to the source of truth the OpenAPI drift test validates.
// It is converted to JSON at init so /openapi.json can serve
// application/json with no per-request parsing.
package openapi

import (
	_ "embed"
	"encoding/json"
	"sync"

	"gopkg.in/yaml.v3"
)

//go:embed sovereign.v1.yaml
var specYAML []byte

var (
	once   sync.Once
	spec   []byte
	errVal error
)

// SpecJSON returns the embedded OpenAPI document converted to JSON. The
// result is cached after the first call and safe for concurrent use.
func SpecJSON() ([]byte, error) {
	once.Do(func() {
		var doc any
		if err := yaml.Unmarshal(specYAML, &doc); err != nil {
			errVal = err
			return
		}
		out, err := json.Marshal(doc)
		if err != nil {
			errVal = err
			return
		}
		spec = out
	})
	return spec, errVal
}
