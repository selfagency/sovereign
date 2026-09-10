package capabilities

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestREADMEClaimsSubsetCapabilities is the capabilities_truth gate (T4.2):
// every machine-readable claim in the README status table must map to a
// capability entry in the derived feature set. A README row marketing a
// capability that the provider does not know about fails the build.
func TestREADMEClaimsSubsetCapabilities(t *testing.T) {
	readme, err := os.ReadFile("../../../../../README.md")
	if err != nil {
		t.Fatalf("read README: %v", err)
	}

	// Extract the claims block between <!-- claims and claims -->.
	block := extractClaimsBlock(string(readme))
	if block == "" {
		t.Fatal("no claims block found in README")
	}

	// The provider's feature set is the universe of known capabilities.
	p := New(Config{}, testStore(t))
	known := p.Features()

	// claimSlugToCapability maps each README claim slug to the capability
	// name it represents. The README table rows are prose; the claims block
	// slugs are the machine anchors. Every slug must resolve.
	slugToCap := map[string]string{
		"multi-tenant-host-derived":     "tenants",
		"tenant-isolated-blob-storage":  "identity",
		"single-binary-sqlite":          "identity",
		"versioned-migrations-accounts": "identity",
		"signed-access-tokens":          "oidc",
		"webfinger":                     "webfinger",
		"nodeinfo":                      "nodeinfo",
		"public-key-hosting":            "keys",
		"identity-proofs":               "proofs",
		"remotestorage":                 "remotestorage",
		"profile":                       "profile",
		"oidc-provider":                 "oidc",
		"webauthn-passkeys":             "webauthn",
		"admin-user-invites":            "identity",
		"magic-link-panel":              "sessions",
		"admin-moderation":              "moderation",
		"indieauth":                     "identity",
	}

	for _, line := range strings.Split(block, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) < 3 {
			t.Errorf("malformed claim line: %q", line)
			continue
		}
		slug := strings.TrimSpace(parts[0])
		capName, ok := slugToCap[slug]
		if !ok {
			t.Errorf("claim slug %q has no capability mapping; add it to slugToCap", slug)
			continue
		}
		if _, ok := known[capName]; !ok {
			t.Errorf("claim %q maps to capability %q which is not in the derived feature set", slug, capName)
		}
	}
}

// extractClaimsBlock returns the text between the README claims markers.
func extractClaimsBlock(readme string) string {
	re := regexp.MustCompile(`(?s)<!-- claims\n(.*?)\nclaims -->`)
	m := re.FindStringSubmatch(readme)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}
