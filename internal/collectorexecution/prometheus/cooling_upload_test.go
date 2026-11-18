package prometheus

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	adapter "github.com/verticalcomputer/sherlock/internal/adapters/prometheus"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/platform"
)

type coolingTestClock struct{ at time.Time }

func (f coolingTestClock) Now() time.Time { return f.at }

func TestExecuteCoolingUsesScopedRawSamples(t *testing.T) {
	slot := time.Now().UTC().Truncate(domain.CoolingUploadInterval).Add(domain.CoolingUploadInterval)
	profile := domain.CoolingUploadProfile{
		Version: 2, ProfileID: "pilot", Revision: 1, CollectorID: "collector", SourceID: "dcgm", ClusterID: "cluster",
		InventoryRevision: "inventory", StartsAt: slot.Add(-time.Minute), EndsAt: slot.Add(time.Minute),
		Assets: []domain.CoolingUploadAsset{{NodeID: "node-a", GPUUUID: "GPU-a"}, {NodeID: "node-b", GPUUUID: "GPU-b"}},
	}
	pointAt := slot.Add(-725 * time.Millisecond)
	old := slot.Add(-2250 * time.Millisecond)
	for _, scenario := range []struct {
		name   string
		status domain.ResultStatus
		gpus   int
	}{
		{name: "known points", status: domain.ResultSucceeded, gpus: 2},
		{name: "foreign point", status: domain.ResultPartial, gpus: 1},
		{name: "duplicate exporter", status: domain.ResultPartial, gpus: 0},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				query := r.URL.Query().Get("query")
				if r.URL.Path != "/api/v1/query" || r.URL.Query().Get("time") != slot.Format(time.RFC3339Nano) ||
					!strings.HasPrefix(query, "DCGM_FI_DEV_GPU_TEMP{") || !strings.HasSuffix(query, "}[15s]") {
					t.Errorf("unscoped source query %s %s", r.URL.Path, r.URL.RawQuery)
				}
				if (strings.Contains(query, "node-a") && !strings.Contains(query, "GPU-a")) ||
					(strings.Contains(query, "node-b") && !strings.Contains(query, "GPU-b")) ||
					(strings.Contains(query, "node-a") && strings.Contains(query, "GPU-b")) ||
					(strings.Contains(query, "node-b") && strings.Contains(query, "GPU-a")) {
					t.Errorf("query could read an unenrolled pair: %q", query)
				}
				series := ""
				switch query {
				case `DCGM_FI_DEV_GPU_TEMP{Hostname="node-a",UUID=~"GPU-a"}[15s]`:
					series = fmt.Sprintf(`{"metric":{"__name__":"DCGM_FI_DEV_GPU_TEMP","Hostname":"node-a","UUID":"GPU-a","job":"private"},"values":[[%d.%03d,"48"],[%d.%03d,"51"]]}`,
						old.Unix(), old.Nanosecond()/1e6, pointAt.Unix(), pointAt.Nanosecond()/1e6)
					if scenario.name == "duplicate exporter" {
						series += "," + strings.Replace(series, "private", "duplicate", 1)
					}
				case `DCGM_FI_DEV_GPU_TEMP{hostname="node-b",Hostname="",uuid=~"GPU-b",UUID=""}[15s]`:
					if scenario.name == "duplicate exporter" {
						break
					}
					gpu := "GPU-b"
					if scenario.name == "foreign point" {
						gpu = "GPU-foreign"
					}
					series = fmt.Sprintf(`{"metric":{"__name__":"DCGM_FI_DEV_GPU_TEMP","hostname":"node-b","uuid":"%s"},"values":[[%d.%03d,"55"]]}`,
						gpu, pointAt.Unix(), pointAt.Nanosecond()/1e6)
				}
				_, _ = fmt.Fprintf(w, `{"status":"success","data":{"resultType":"matrix","result":[%s]}}`, series)
			}))
			defer server.Close()
			client, err := adapter.NewClient(adapter.Config{BaseURL: server.URL, Timeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			executor, err := NewUpload(client, coolingTestClock{slot.Add(time.Second)}, platform.RandomIDGenerator{})
			if err != nil {
				t.Fatal(err)
			}
			result := executor.ExecuteCooling(t.Context(), profile, profile.Task(domain.QueryGPUTemperature, slot))
			if result.Status != scenario.status || len(result.Observations) != scenario.gpus || calls.Load() != 8 {
				t.Fatalf("scoped result = %+v, calls = %d", result, calls.Load())
			}
			for _, obs := range result.Observations {
				if !obs.ObservedAt.Equal(pointAt) || len(obs.Labels) != 2 || obs.SourceReference != domain.DCGMSourceReference(domain.QueryGPUTemperature) {
					t.Fatalf("source time or identity was substituted: %+v", obs)
				}
			}
			if scenario.gpus > 0 && result.Observations[0].Value != 51 {
				t.Fatalf("did not use latest actual point: %+v", result.Observations[0])
			}
			hash := domain.ChecksumSHA256([]byte("profile")).String()
			report := domain.CoolingUploadReport{Version: 2, ProfileID: profile.ProfileID, ProfileRevision: profile.Revision, ProfileHash: hash, Result: result}
			if err := report.Validate(profile, hash, slot.Add(time.Second)); err != nil {
				t.Fatal(err)
			}
		})
	}
}
