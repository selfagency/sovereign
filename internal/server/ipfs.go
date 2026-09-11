package server

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/ipfs/go-cid"

	"github.com/selfagency/sovereign/internal/protocols/ipfspin"
	"github.com/selfagency/sovereign/internal/store"
)

// ipfsBroker serves the IPFS pinning broker HTTP surface. It persists the
// pin set in the store and calls the configured Kubo RPC backend.
type ipfsBroker struct {
	store   *store.Store
	backend ipfspin.Backend
}

// newIPFSBroker builds a broker. If no backend is configured, pin operations
// are no-ops that still record the pin set in the store.
func newIPFSBroker(st *store.Store, backend ipfspin.Backend) *ipfsBroker {
	return &ipfsBroker{store: st, backend: backend}
}

// pin handles POST /ipfs/pin?cid=<cid>.
func (b *ipfsBroker) pin(w http.ResponseWriter, r *http.Request) {
	cidStr := r.URL.Query().Get("cid")
	if cidStr == "" {
		http.Error(w, "cid is required", http.StatusBadRequest)
		return
	}
	if b.backend != nil {
		if err := b.backend.Pin(r.Context(), mustCID(cidStr)); err != nil {
			internalError(w, "ipfs: backend pin", err)
			return
		}
	}
	if err := b.store.AddIPFSPin(r.Context(), cidStr, "pinned"); err != nil {
		internalError(w, "ipfs: store pin", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"cid": cidStr, "status": "pinned"})
}

// status handles GET /ipfs/pin/{cid}.
func (b *ipfsBroker) status(w http.ResponseWriter, r *http.Request) {
	cidStr := strings.TrimPrefix(r.URL.Path, "/ipfs/pin/")
	if cidStr == "" {
		http.Error(w, "cid is required", http.StatusBadRequest)
		return
	}
	p, err := b.store.GetIPFSPin(r.Context(), cidStr)
	if err != nil {
		http.Error(w, "pin not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"cid": p.CID, "status": p.Status})
}

// mustCID parses a CID string, returning a zero CID on error (the backend
// call will fail harmlessly). The store persists the raw string regardless.
func mustCID(s string) (c cid.Cid) {
	c, _ = cid.Decode(s)
	return c
}

// writeJSON writes a JSON response with the given status.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
