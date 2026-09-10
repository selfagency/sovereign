package capabilities

import (
	"path/filepath"
	"testing"

	"github.com/selfagency/sovereign/internal/store"
)

// testStore opens a throwaway SQLite store for the store-backed cases.
func testStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// TestFeaturesTruth is the "truth" test: a capability must not claim wired
// when the backend/config that backs it is absent, and must claim wired when
// it is present.
func TestFeaturesTruth(t *testing.T) {
	tests := []struct {
		name       string
		cfg        Config
		store      *store.Store
		capability string
		wantWired  bool
	}{
		// Store-backed features: wired only when the store is present.
		{name: "identity wired with store", cfg: Config{}, store: testStore(t), capability: "identity", wantWired: true},
		{name: "identity not wired without store", cfg: Config{}, store: nil, capability: "identity", wantWired: false},
		{name: "profile wired with store", cfg: Config{}, store: testStore(t), capability: "profile", wantWired: true},
		{name: "profile not wired without store", cfg: Config{}, store: nil, capability: "profile", wantWired: false},
		{name: "keys wired with store", cfg: Config{}, store: testStore(t), capability: "keys", wantWired: true},
		{name: "keys not wired without store", cfg: Config{}, store: nil, capability: "keys", wantWired: false},
		{name: "proofs wired with store", cfg: Config{}, store: testStore(t), capability: "proofs", wantWired: true},
		{name: "proofs not wired without store", cfg: Config{}, store: nil, capability: "proofs", wantWired: false},
		{name: "sessions wired with store", cfg: Config{}, store: testStore(t), capability: "sessions", wantWired: true},
		{name: "sessions not wired without store", cfg: Config{}, store: nil, capability: "sessions", wantWired: false},
		{name: "tenants wired with store", cfg: Config{}, store: testStore(t), capability: "tenants", wantWired: true},
		{name: "tenants not wired without store", cfg: Config{}, store: nil, capability: "tenants", wantWired: false},
		{name: "clients wired with store", cfg: Config{}, store: testStore(t), capability: "clients", wantWired: true},
		{name: "clients not wired without store", cfg: Config{}, store: nil, capability: "clients", wantWired: false},
		{name: "backup wired with store", cfg: Config{}, store: testStore(t), capability: "backup", wantWired: true},
		{name: "backup not wired without store", cfg: Config{}, store: nil, capability: "backup", wantWired: false},
		{name: "moderation wired with store", cfg: Config{}, store: testStore(t), capability: "moderation", wantWired: true},
		{name: "moderation not wired without store", cfg: Config{}, store: nil, capability: "moderation", wantWired: false},
		{name: "audit wired with store", cfg: Config{}, store: testStore(t), capability: "audit", wantWired: true},
		{name: "audit not wired without store", cfg: Config{}, store: nil, capability: "audit", wantWired: false},

		// Config-driven features: wired only when the config enables them.
		{name: "ipfs wired when enabled", cfg: Config{IPFSEnabled: true}, store: testStore(t), capability: "ipfs", wantWired: true},
		{name: "ipfs not wired when disabled", cfg: Config{IPFSEnabled: false}, store: testStore(t), capability: "ipfs", wantWired: false},
		{name: "smtp wired when enabled", cfg: Config{SMTPEnabled: true}, store: testStore(t), capability: "smtp", wantWired: true},
		{name: "smtp not wired when disabled", cfg: Config{SMTPEnabled: false}, store: testStore(t), capability: "smtp", wantWired: false},

		// Always-wired protocol surfaces.
		{name: "atproto always wired", cfg: Config{}, store: testStore(t), capability: "atproto", wantWired: true},
		{name: "solid always wired", cfg: Config{}, store: testStore(t), capability: "solid", wantWired: true},
		{name: "remotestorage always wired", cfg: Config{}, store: testStore(t), capability: "remotestorage", wantWired: true},
		{name: "activitypub always wired", cfg: Config{}, store: testStore(t), capability: "activitypub", wantWired: true},
		{name: "webfinger always wired", cfg: Config{}, store: testStore(t), capability: "webfinger", wantWired: true},
		{name: "nodeinfo always wired", cfg: Config{}, store: testStore(t), capability: "nodeinfo", wantWired: true},
		{name: "webauthn always wired", cfg: Config{}, store: testStore(t), capability: "webauthn", wantWired: true},
		{name: "oidc always wired", cfg: Config{}, store: testStore(t), capability: "oidc", wantWired: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := New(tt.cfg, tt.store)
			feat, ok := p.Features()[tt.capability]
			if !ok {
				t.Fatalf("capability %q not present in derived set", tt.capability)
			}
			if feat.Wired != tt.wantWired {
				t.Errorf("capability %q wired = %v, want %v", tt.capability, feat.Wired, tt.wantWired)
			}
			if feat.Description == "" {
				t.Errorf("capability %q has empty description", tt.capability)
			}
		})
	}
}

// TestFeaturesAlwaysDescribe ensures every derived feature carries a
// non-empty description (the README status table sources from these).
func TestFeaturesAlwaysDescribe(t *testing.T) {
	p := New(Config{}, testStore(t))
	for name, f := range p.Features() {
		if f.Description == "" {
			t.Errorf("capability %q has empty description", name)
		}
	}
}
