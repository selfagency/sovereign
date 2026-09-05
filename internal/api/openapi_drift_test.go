package api

import (
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

// specPath is the hand-written OpenAPI 3.1 source of truth (D-5).
const specPath = "../../openapi/sovereign.v1.yaml"

// apiBase is the versioned API prefix carried by route-table paths. The spec
// declares it as the server base URL, so spec paths omit it.
const apiBase = "/api/v1"

// loadSpec loads and validates the OpenAPI spec from disk.
func loadSpec(t *testing.T) *openapi3.T {
	t.Helper()
	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromFile(specPath)
	if err != nil {
		t.Fatalf("load spec %s: %v", specPath, err)
	}
	if err := doc.Validate(loader.Context); err != nil {
		t.Fatalf("validate spec %s: %v", specPath, err)
	}
	return doc
}

// routeKey normalizes a route-table path to the spec's path form by stripping
// the /api/v1 base prefix.
func routeKey(routePath string) string {
	return strings.TrimPrefix(routePath, apiBase)
}

// specKeys returns the set of "METHOD path" keys present in the spec.
func specKeys(doc *openapi3.T) map[string]bool {
	keys := make(map[string]bool)
	for p, item := range doc.Paths.Map() {
		for method := range item.Operations() {
			keys[method+" "+p] = true
		}
	}
	return keys
}

// routeKeys returns the set of "METHOD path" keys present in a route set.
func routeKeys(routes []Route) map[string]bool {
	keys := make(map[string]bool)
	for _, r := range routes {
		keys[r.Method+" "+routeKey(r.Path)] = true
	}
	return keys
}

// driftError reports a parity mismatch between the spec and the route set.
type driftError struct{ msg string }

func (e *driftError) Error() string { return e.msg }

// checkDrift returns an error if the spec and route set disagree in either
// direction. It is the shared gate used by both the happy-path test and the
// deliberately-omitted-route test.
func checkDrift(doc *openapi3.T, routes []Route) error {
	spec := specKeys(doc)
	routesSet := routeKeys(routes)

	// Direction 1: every spec path+method must have a matching route.
	for k := range spec {
		if !routesSet[k] {
			return &driftError{msg: "spec documents " + k + " but no route implements it"}
		}
	}
	// Direction 2: every route must have a matching spec path+method.
	for k := range routesSet {
		if !spec[k] {
			return &driftError{msg: "route " + k + " is not documented in the spec"}
		}
	}
	return nil
}

// TestOpenAPIDrift asserts bidirectional parity between the route table and
// the OpenAPI spec for the current route set.
func TestOpenAPIDrift(t *testing.T) {
	doc := loadSpec(t)
	if err := checkDrift(doc, Routes()); err != nil {
		t.Fatal(err)
	}
}

// TestOpenAPIDriftFailsOnOmittedRoute proves the gate fails when a route is
// added to the table but not documented in the spec.
func TestOpenAPIDriftFailsOnOmittedRoute(t *testing.T) {
	doc := loadSpec(t)

	// Temporarily add an undocumented route to the table.
	extra := append(Routes(), Route{
		Method: "GET",
		Path:   apiBase + "/meta/undocumented",
	})

	if err := checkDrift(doc, extra); err == nil {
		t.Fatal("expected drift gate to fail on an omitted route, but it passed")
	}
}
