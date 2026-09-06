package api

import (
	"reflect"
	"testing"
)

// TestToRouteInfoHandlerPresent verifies every RouteInfo derived from Routes()
// carries a non-nil handler, so the middleware chain and the mux can never
// register a nil-handler route.
func TestToRouteInfoHandlerPresent(t *testing.T) {
	infos := ToRouteInfo(Routes())
	if len(infos) == 0 {
		t.Fatal("ToRouteInfo returned no routes")
	}
	for _, ri := range infos {
		if ri.Handler == nil {
			t.Errorf("route %s %s has a nil handler", ri.Method, ri.Path)
		}
	}
}

// TestToRouteInfoFieldsMatch verifies the adapter copies every middleware-driving
// field faithfully (authn/scope/timeout/idempotency), so the chain's decisions
// mirror the api.Route table exactly.
func TestToRouteInfoFieldsMatch(t *testing.T) {
	routes := Routes()
	infos := ToRouteInfo(routes)
	if len(routes) != len(infos) {
		t.Fatalf("len = %d infos, want %d", len(infos), len(routes))
	}
	for i, r := range routes {
		ri := infos[i]
		if ri.Method != r.Method || ri.Path != r.Path || ri.Scope != r.Scope ||
			ri.Timeout != r.Timeout || ri.Anonymous != r.Anonymous ||
			ri.LongRunning != r.LongRunning || ri.Idempotent != r.Idempotent {
			t.Errorf("route %d fields mismatch\n route: %+v\n  info: %+v", i, r, ri)
		}
		// Handler must be the very same function, not a wrapper.
		if reflect.ValueOf(ri.Handler).Pointer() != reflect.ValueOf(r.Handler).Pointer() {
			t.Errorf("route %d handler not preserved through adapter", i)
		}
	}
}

// TestToRouteInfoPreservesAnonymousAuthz verifies anonymous routes stay
// anonymous and scoped routes keep their scope through the adapter (the
// authn/scope decision the chain makes).
func TestToRouteInfoPreservesAnonymousAuthz(t *testing.T) {
	infos := ToRouteInfo(Routes())
	for _, ri := range infos {
		if ri.Anonymous && ri.Scope != "" {
			t.Errorf("route %s %s is anonymous but declares scope %q", ri.Method, ri.Path, ri.Scope)
		}
	}
}
