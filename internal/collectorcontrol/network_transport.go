package collectorcontrol

import (
	"context"
	"net/http"

	"github.com/verticalcomputer/sherlock/internal/networkmonitor"
)

type NetworkCycleRecorder interface {
	RecordNetworkCycle(context.Context, string, string, networkmonitor.Cycle) error
}

// Exact durable enrollment is checked by the recorder; mTLS capability alone
// cannot publish another cluster's ports or extend the reviewed inventory.
func (t *Transport) ConfigureNetworkMonitoring(store NetworkCycleRecorder) {
	t.mux.HandleFunc("POST /collector/v2/network/polls", func(w http.ResponseWriter, r *http.Request) {
		id, ok := validateProtocolVersion(w, r, 2)
		if !ok {
			return
		}
		identity, ok := t.authenticate(w, r, id)
		if !ok {
			return
		}
		var cycle networkmonitor.Cycle
		if !decodeJSONLimit(w, r, &cycle, 128<<10) {
			writeProblem(w, 400, "INVALID_INPUT", "invalid network cycle", id)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), defaultRequestTimeout)
		defer cancel()
		if err := store.RecordNetworkCycle(ctx, string(identity.ClusterID), string(identity.CollectorID), cycle); err != nil {
			writeProblem(w, 409, "NETWORK_CYCLE_REJECTED", "network cycle not accepted", id)
			return
		}
		writeJSON(w, 200, map[string]bool{"accepted": true})
	})
}
