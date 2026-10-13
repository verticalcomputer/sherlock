package prometheus

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	adapter "github.com/verticalcomputer/sherlock/internal/adapters/prometheus"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/platform"
)

func TestExpandedDCGMResponseBoundsAndRedaction(t *testing.T) {
	good := `{"status":"success","data":{"resultType":"vector","result":[{"metric":{"__name__":"DCGM_FI_DEV_POWER_USAGE","Hostname":"node-a","UUID":"GPU-a","gpu":"0","token":"bearer-secret","url":"https://user:password@example.com"},"value":[1787133600,"42"]}]}}`
	for _, test := range []struct {
		name, body string
		bytes      int64
		status     domain.ResultStatus
		code       domain.FailureCode
	}{
		{"redacted", good, 10000, domain.ResultSucceeded, ""},
		{"empty", `{"status":"success","data":{"resultType":"vector","result":[]}}`, 10000, domain.ResultNoData, ""},
		{"malformed", `{"secret":"bearer-secret"}`, 10000, domain.ResultFailed, domain.FailureMalformedResponse},
		{"byte_limit", good, 32, domain.ResultFailed, domain.FailureResultLimit},
		{"nan", strings.Replace(good, `"42"`, `"NaN"`, 1), 10000, domain.ResultPartial, domain.FailurePartialData},
		{"foreign_metric", strings.Replace(good, "DCGM_FI_DEV_POWER_USAGE", "secret_metric", 1), 10000, domain.ResultPartial, domain.FailurePartialData},
		{"mig", strings.Replace(good, `"gpu":"0"`, `"GPU_I_ID":"0"`, 1), 10000, domain.ResultPartial, domain.FailurePartialData},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(test.body)) }))
			defer server.Close()
			client, _ := adapter.NewClient(adapter.Config{BaseURL: server.URL, Timeout: time.Second})
			executor, _ := New(client, platform.SystemClock{}, platform.RandomIDGenerator{})
			task := executionTask()
			task.Query = domain.QueryGPUPower
			task.MaxBytes = test.bytes
			r := executor.Execute(context.Background(), task)
			if r.Status != test.status || (test.code != "" && (len(r.Failures) == 0 || r.Failures[0].Code != test.code)) {
				t.Fatalf("%+v", r)
			}
			encoded, _ := json.Marshal(r)
			for _, secret := range []string{"bearer-secret", "password", "secret_metric"} {
				if strings.Contains(string(encoded), secret) {
					t.Fatalf("leaked %s", secret)
				}
			}
		})
	}
}

func TestExpandedDCGMRangeRetainsExistingContract(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/query_range" || r.URL.Query().Get("query") != "(DCGM_FI_DEV_POWER_USAGE or DCGM_FI_DEV_POWER_MGMT_LIMIT)" {
			t.Errorf("range contract changed: %s", r.URL)
		}
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"matrix","result":[{"metric":{"__name__":"DCGM_FI_DEV_POWER_USAGE","Hostname":"node-a","gpu":"0"},"values":[[1787133600,"42"],[1787133660,"43"]]}]}}`))
	}))
	defer server.Close()
	client, _ := adapter.NewClient(adapter.Config{BaseURL: server.URL, Timeout: time.Second})
	executor, _ := New(client, platform.SystemClock{}, platform.RandomIDGenerator{})
	task := executionTask()
	task.Query = domain.QueryGPUPower
	task.Range = &domain.CollectionRange{Start: time.Unix(1787133600, 0), End: time.Unix(1787133660, 0), Step: time.Minute}
	r := executor.Execute(context.Background(), task)
	if r.Status != domain.ResultSucceeded || len(r.Observations) != 2 || r.Observations[0].EntityKey != "node/node-a/gpu/0" || r.Observations[0].SourceReference != "prometheus:"+string(task.Query) {
		t.Fatalf("legacy range changed: %+v", r)
	}
	got := domain.NormalizeDCGMCollection(r, nil)
	if got.Status != r.Status || len(got.Observations) != 2 || len(got.Coverage.MetricFields) != 0 || got.Observations[0].Semantics != nil {
		t.Fatalf("range normalized as instant: %+v", got)
	}
}

func TestExpandedDCGMForeignClusterLabelIsIgnoredNotAmbiguous(t *testing.T) {
	body := `{"status":"success","data":{"resultType":"vector","result":[{"metric":{"__name__":"DCGM_FI_DEV_POWER_USAGE","Hostname":"node-a","UUID":"GPU-a","cluster":"synthetic-foreign-cluster"},"value":[1787133600,"42"]}]}}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(body)) }))
	defer server.Close()
	client, _ := adapter.NewClient(adapter.Config{BaseURL: server.URL, Timeout: time.Second})
	executor, _ := New(client, platform.SystemClock{}, platform.RandomIDGenerator{})
	task := executionTask()
	task.Query = domain.QueryGPUPower
	r := executor.Execute(context.Background(), task)
	if r.Status != domain.ResultSucceeded || len(r.Observations) != 1 {
		t.Fatalf("expected a foreign exporter cluster label to be ignored, not dropped: %+v", r)
	}
	labels := r.Observations[0].Labels
	if len(labels) != 3 {
		t.Fatalf("expected labels stripped to exactly __name__/Hostname/UUID, got %+v", labels)
	}
	want := map[string]string{"__name__": "DCGM_FI_DEV_POWER_USAGE", "Hostname": "node-a", "UUID": "GPU-a"}
	for _, l := range labels {
		if want[l.Name] != l.Value {
			t.Fatalf("unexpected label %+v, want %+v", l, want)
		}
	}
}
