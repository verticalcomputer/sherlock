package prometheus

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func fleetQueryProfile(slot time.Time) domain.CoolingUploadProfile {
	p := domain.CoolingUploadProfile{Version: 3, ProfileID: "fleet", Revision: 1, CollectorID: "collector", ClusterID: "cluster", SourceID: "source", InventoryRevision: "inventory", StartsAt: slot.Add(-time.Hour), State: "ENABLED"}
	for i := range 128 {
		p.Assets = append(p.Assets, domain.CoolingUploadAsset{NodeID: domain.StableNodeID(fmt.Sprintf("node.%02d", i/8)), GPUUUID: domain.PhysicalGPUUUID(fmt.Sprintf("GPU-x.%03d", i))})
	}
	return p
}
func TestFleetCoolingQueryCountExactPairsAndAliases(t *testing.T) {
	slot := time.Now().UTC().Truncate(15 * time.Second).Add(15 * time.Second)
	p := fleetQueryProfile(slot)
	for _, kind := range []string{"complete", "wrong-pair", "ambiguous-alias"} {
		t.Run(kind, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				q := r.URL.Query().Get("query")
				if !strings.Contains(q, `Hostname=~`) && !strings.Contains(q, `hostname=~`) {
					t.Error("missing bounded node regex")
				}
				if !strings.Contains(q, `node\\.00`) || !strings.Contains(q, `GPU-x\\.000`) {
					t.Error("label regex metacharacters unescaped")
				}
				entries := []any{}
				if strings.Contains(q, `Hostname=~`) && strings.Contains(q, `,UUID=~`) {
					for _, a := range p.Assets {
						labels := map[string]string{"__name__": "DCGM_FI_DEV_GPU_TEMP", "Hostname": string(a.NodeID), "UUID": string(a.GPUUUID)}
						if len(entries) == 0 && kind == "wrong-pair" {
							labels["Hostname"] = "node.01"
						}
						if len(entries) == 0 && kind == "ambiguous-alias" {
							labels["hostname"] = "other-node"
						}
						entries = append(entries, map[string]any{"metric": labels, "values": [][]any{{float64(slot.Unix()), "70"}}})
					}
				}
				json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": map[string]any{"resultType": "matrix", "result": entries}})
			}))
			defer server.Close()
			client, e := NewClient(Config{BaseURL: server.URL, Timeout: time.Second, MaxSeries: 128, MaxBytes: domain.CoolingUploadMaxBytes})
			if e != nil {
				t.Fatal(e)
			}
			result, e := client.CoolingInstant(t.Context(), p, domain.QueryGPUTemperature, slot)
			if kind == "complete" {
				if e != nil || len(result.Samples) != 128 || calls.Load() != 4 {
					t.Fatalf("samples%d requests%d error%v", len(result.Samples), calls.Load(), e)
				}
			} else if e == nil {
				t.Fatal("unauthorized/ambiguous node UUID pair accepted")
			}
		})
	}
	v2 := p
	v2.Version = 2
	v2.State = ""
	v2.EndsAt = slot.Add(time.Hour)
	v2.Assets = []domain.CoolingUploadAsset{p.Assets[0], p.Assets[8]}
	queries := coolingSelectors(v2, "DCGM_FI_DEV_GPU_TEMP")
	if len(queries) != 8 || strings.Contains(queries[0], "Hostname=~") {
		t.Fatal("V2 selector behavior changed")
	}
}
func TestFleetCoolingAggregateBytesAndCancellation(t *testing.T) {
	slot := time.Now().UTC().Truncate(15 * time.Second).Add(15 * time.Second)
	p := fleetQueryProfile(slot)
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		fmt.Fprint(w, `{"status":"success","data":{"resultType":"matrix","result":[]}}`)
	}))
	defer server.Close()
	c, e := NewClient(Config{BaseURL: server.URL, Timeout: time.Second, MaxSeries: 128, MaxBytes: 100})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = c.CoolingInstant(t.Context(), p, domain.QueryGPUPower, slot); e == nil {
		t.Fatal("aggregate response byte cap reset per selector")
	}
	if calls.Load() > 2 {
		t.Fatal("continued reading after byte exhaustion")
	}
	before := calls.Load()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, e = c.CoolingInstant(ctx, p, domain.QueryGPUPower, slot); e == nil {
		t.Fatal("cancelled query accepted")
	}
	if calls.Load() != before {
		t.Fatal("cancelled context issued source reads")
	}
	// The eight-second deadline is anchored to the scheduled slot, not the
	// start of each selector or a fresh retry.
	expired := slot.Add(-30 * time.Second)
	if _, e = c.CoolingInstant(t.Context(), p, domain.QueryGPUPower, expired); e == nil {
		t.Fatal("expired source deadline accepted")
	}
	if calls.Load() != before {
		t.Fatal("expired slot issued source reads")
	}
}
