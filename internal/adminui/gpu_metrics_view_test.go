package adminui

import (
	"context"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

// gpuMetricsFakeProvider adds the optional GPU metrics boundary to the shared
// fake data provider, exactly as a deployment adds it to the real client.
type gpuMetricsFakeProvider struct {
	*fakeProvider
	metrics GPUMetrics
	err     error
}

func (provider *gpuMetricsFakeProvider) GetClusterGPUMetrics(_ context.Context, _ string) (GPUMetrics, error) {
	return provider.metrics, provider.err
}

func gpuMetricsFixture(now time.Time) GPUMetrics {
	fresh := now.Add(-12 * time.Second)
	old := now.Add(-2 * time.Hour)
	ancient := now.Add(-21 * 24 * time.Hour)
	ahead := now.Add(2 * time.Hour)
	return GPUMetrics{
		ClusterID: "cluster-1", GeneratedAt: now,
		Fields: []GPUMetricsField{
			{Name: "DCGM_FI_DEV_POWER_USAGE", Unit: "watts", Semantics: "gauge"},
			{Name: "DCGM_FI_DEV_POWER_MGMT_LIMIT", Unit: "watts", Semantics: "gauge"},
			{Name: "DCGM_FI_DEV_ECC_SBE_VOL_TOTAL", Unit: "count", Semantics: "counter"},
			{Name: "DCGM_FI_DEV_GPU_TEMP", Unit: "celsius", Semantics: "gauge"},
		},
		Sources: []GPUMetricsSource{{SourceID: "source-1", DisplayName: "DCGM", Primary: true,
			Operations: []GPUMetricsOperation{{
				OperationID: "prometheus.gpu_power.v1", Enrolled: true, Enabled: true, Mode: "durable",
				IntervalSeconds: 30, Revision: 2, HasRun: true, RunID: "run-1", RunStatus: "PARTIAL",
				CompletedAt: fresh, Freshness: "FRESH", FreshWindowSeconds: 60,
				Fields: []GPUMetricsFieldSummary{
					{Field: "DCGM_FI_DEV_POWER_USAGE", Supported: 80, Unknown: 20, Assessed: 80, Expected: 100, UnassessedExpected: 20, Dominant: "SUPPORTED"},
					{Field: "DCGM_FI_DEV_POWER_MGMT_LIMIT", NotSupported: 80, Unknown: 20, Assessed: 80, Expected: 100, UnassessedExpected: 20, Dominant: "NOT_SUPPORTED"},
				},
			}, {
				OperationID: "prometheus.gpu_ecc.v1", Enrolled: true, Enabled: true, Mode: "durable",
				IntervalSeconds: 30, HasRun: true, RunID: "run-2", RunStatus: "FAILED",
				CompletedAt: fresh, Freshness: "FAILING", FreshWindowSeconds: 60,
				Fields: []GPUMetricsFieldSummary{{Field: "DCGM_FI_DEV_ECC_SBE_VOL_TOTAL", Dominant: "UNKNOWN"}},
			}, {
				OperationID: "prometheus.gpu_temperature.v1", Freshness: "NO_DATA", FreshWindowSeconds: 300,
				Fields: []GPUMetricsFieldSummary{{Field: "DCGM_FI_DEV_GPU_TEMP", Dominant: "UNKNOWN"}},
			}}}},
		OtherSources: []GPUMetricsOtherSource{{SourceID: "source-2", ObservedNodes: 3, ObservedGPUs: 24}},
		Truncated:    true,
		GPUs: []GPUMetricsRow{{
			SourceID: "source-1", NodeID: "node-1", GPUUUID: "GPU-0123456789abcdef-tail",
			Expected: true, Observed: true, ObservedAt: &fresh, ObservedState: "OBSERVED",
			Values: map[string]GPUMetricsCell{
				"DCGM_FI_DEV_POWER_USAGE":       {State: "SUPPORTED", Value: floatPointer(210), Unit: "watts", ObservedAt: &fresh},
				"DCGM_FI_DEV_POWER_MGMT_LIMIT":  {State: "NOT_SUPPORTED", Unit: "watts"},
				"DCGM_FI_DEV_ECC_SBE_VOL_TOTAL": {State: "STALE", Unit: "count", ObservedAt: &old},
				"DCGM_FI_DEV_GPU_TEMP":          {State: "NO_DATA", Unit: "celsius"},
			},
		}, {
			// Present in the never-pruned target cache, last seen three weeks
			// ago, with a non-finite sample and one from a clock ahead of ours.
			SourceID: "source-1", NodeID: "node-2", GPUUUID: "GPU-stale",
			Expected: true, Observed: true, ObservedAt: &ancient, ObservedState: "OBSERVED_STALE",
			Values: map[string]GPUMetricsCell{
				"DCGM_FI_DEV_POWER_USAGE":       {State: "SUPPORTED", Value: floatPointer(math.NaN()), Unit: "watts", ObservedAt: &fresh},
				"DCGM_FI_DEV_POWER_MGMT_LIMIT":  {State: "SUPPORTED", Value: floatPointer(180), Unit: "watts", ObservedAt: &ahead},
				"DCGM_FI_DEV_ECC_SBE_VOL_TOTAL": {State: "UNKNOWN", Unit: "count"},
				"DCGM_FI_DEV_GPU_TEMP":          {State: "NO_DATA", Unit: "celsius"},
			},
		}, {
			SourceID: "source-1", NodeID: "node-1", GPUUUID: "GPU-0123456789abcdef-tail",
			MIGIdentity: "mig-0", Expected: true, ObservedState: "NOT_OBSERVED",
			Values: map[string]GPUMetricsCell{
				"DCGM_FI_DEV_POWER_USAGE":       {State: "AMBIGUOUS_MIG", Unit: "watts"},
				"DCGM_FI_DEV_POWER_MGMT_LIMIT":  {State: "AMBIGUOUS_MIG", Unit: "watts"},
				"DCGM_FI_DEV_ECC_SBE_VOL_TOTAL": {State: "AMBIGUOUS_MIG", Unit: "count"},
				"DCGM_FI_DEV_GPU_TEMP":          {State: "AMBIGUOUS_MIG", Unit: "celsius"},
			},
		}},
		Inventory: GPUMetricsInventory{
			SourceID: "source-1", ExpectedNodes: 0, ObservedNodes: 1, ObservedGPUs: 2,
			FreshObservedGPUs: 1, StaleObservedGPUs: 1, ObservationWindowSeconds: 300,
			ExpectedNotObserved: []GPUMetricsEntityRef{{NodeID: "node-2", GPUUUID: "GPU-stale", Stale: true, ObservedAt: &ancient}},
			ObservedNotExpected: []GPUMetricsEntityRef{{NodeID: "node-1", GPUUUID: "GPU-ccc"}},
		},
	}
}

func newGPUMetricsTestServer(t *testing.T, provider *gpuMetricsFakeProvider) (*Server, *http.Cookie) {
	t.Helper()
	clock := &fakeClock{now: time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)}
	server, err := New(Options{Provider: provider, AccessVerifier: fakeAccessVerifier{}, Auditor: &fakeAuditor{}, ErrorReporter: &fakeErrorReporter{}, Clock: clock})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	_, cookie := authenticateWithAccess(t, server, testAssertion)
	return server, cookie
}

func TestGPUMetricsTabRendersExplicitStatesInsteadOfZero(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	provider := &gpuMetricsFakeProvider{fakeProvider: sampleProvider(), metrics: gpuMetricsFixture(now)}
	provider.metrics.GPUs[0].Conditions = []domain.HealthSignal{{Type: domain.HealthSignalECC, Severity: domain.HealthSeverityCritical,
		Metric: "DCGM_FI_DEV_ROW_REMAP_FAILURE", Reason: "row remap failure"},
		{Type: domain.HealthSignalPartial, Severity: domain.HealthSeverityUnknown, Reason: "collection coverage is incomplete"},
		{Type: domain.HealthSignalStale, Category: domain.HealthSignalThermal, Severity: domain.HealthSeverityUnknown, Reason: "temperature stale"}}
	server, cookie := newGPUMetricsTestServer(t, provider)
	response := doRequest(server, cookie, http.MethodGet, "/admin/clusters/cluster-1/gpu-metrics", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, want := range []string{
		"GPU metrics", "NOT SUPPORTED", "STALE", "NO DATA",
		"GPU conditions", "ECC · CRITICAL", "PARTIAL", "THERMAL · STALE", "UNMEASURED",
		"210 W", "ENROLLED · ENABLED", "NOT ENROLLED",
		"SUPPORTED 80 / NOT SUPPORTED 0 / UNKNOWN 20",
		"assessed 80 of 100 expected",
		"newest run PARTIAL", "FAILING",
		"OBSERVED · STALE 21 d", "AMBIGUOUS MIG",
		"source-2 (24 observed GPUs, 3 observed nodes)",
		"GPU table is bounded to 1024 rows",
		"No expected inventory revision",
		"NOT IN EXPECTED INVENTORY",
		`title="GPU-0123456789abcdef-tail"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("rendered page is missing %q", want)
		}
	}
	// An unsupported, stale, or absent field must never appear as a number in
	// the value table. Inventory counts elsewhere on the page may legitimately
	// be zero, so the check is scoped to the metric cells.
	for _, cell := range strings.Split(body, `<td class="metric-cell"`)[1:] {
		cell = cell[:strings.Index(cell, "</td>")]
		if strings.Contains(cell, "badge") && strings.Contains(cell, "<strong>") {
			t.Fatalf("a badge cell also rendered a value: %s", cell)
		}
		if strings.Contains(cell, "<strong>0<") {
			t.Fatalf("an absent value was rendered as zero: %s", cell)
		}
		if strings.Contains(cell, "<strong></strong>") {
			t.Fatalf("an unrenderable value produced an empty value element: %s", cell)
		}
	}
	if !strings.Contains(body, "DCGM_FI_DEV_POWER_MGMT_LIMIT") {
		t.Fatal("the unsupported field column is missing")
	}
}

func TestGPUMetricsTabStatesMissingProjectionAndBackendFailure(t *testing.T) {
	failing := &gpuMetricsFakeProvider{fakeProvider: sampleProvider(), err: errors.New("backend down")}
	server, cookie := newGPUMetricsTestServer(t, failing)
	response := doRequest(server, cookie, http.MethodGet, "/admin/clusters/cluster-1/gpu-metrics", nil)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "not interpreted as healthy") {
		t.Fatalf("failure page = %d %s", response.Code, response.Body.String())
	}

	plain, _, _, _ := newTestServer(t, sampleProvider(), 0)
	_, plainCookie := authenticateWithAccess(t, plain, testAssertion)
	disabled := doRequest(plain, plainCookie, http.MethodGet, "/admin/clusters/cluster-1/gpu-metrics", nil)
	if !strings.Contains(disabled.Body.String(), "not configured for this deployment") {
		t.Fatalf("missing provider page = %s", disabled.Body.String())
	}
}

func TestGPUMetricsTabRequiresCloudflareAccess(t *testing.T) {
	provider := &gpuMetricsFakeProvider{fakeProvider: sampleProvider(), metrics: gpuMetricsFixture(time.Now().UTC())}
	server, _ := newGPUMetricsTestServer(t, provider)
	request := httptest.NewRequest(http.MethodGet, "https://admin.example/admin/clusters/cluster-1/gpu-metrics", nil)
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized && response.Code != http.StatusForbidden {
		t.Fatalf("an unauthenticated GPU metrics request must not be served: %d", response.Code)
	}
	if strings.Contains(response.Body.String(), "DCGM_FI_DEV_POWER_USAGE") {
		t.Fatalf("evidence leaked to an unauthenticated request: %s", response.Body.String())
	}
}

func TestGPUMetricsPresentationNeverFormatsAnAbsentValue(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	metrics := presentGPUMetrics(gpuMetricsFixture(now), now)
	cells := map[string]GPUMetricsCell{}
	for _, cell := range metrics.GPUs[0].Cells {
		cells[cell.Field] = cell
	}
	if len(cells) != 4 {
		t.Fatalf("cells = %+v", cells)
	}
	if supported := cells["DCGM_FI_DEV_POWER_USAGE"]; !supported.Supported || supported.Display != "210 W" || supported.Age != "12 s ago" {
		t.Fatalf("supported cell = %+v", supported)
	}
	for _, field := range []string{"DCGM_FI_DEV_POWER_MGMT_LIMIT", "DCGM_FI_DEV_ECC_SBE_VOL_TOTAL", "DCGM_FI_DEV_GPU_TEMP"} {
		cell := cells[field]
		if cell.Supported || cell.Display != "" || cell.Value != nil || cell.Badge == "" {
			t.Fatalf("%s must render as a badge without a value: %+v", field, cell)
		}
	}
	if cells["DCGM_FI_DEV_POWER_MGMT_LIMIT"].Class != "unavailable" || cells["DCGM_FI_DEV_ECC_SBE_VOL_TOTAL"].Class != "stale" {
		t.Fatalf("state classes = %+v", cells)
	}
	if metrics.GPUs[0].ShortUUID == metrics.GPUs[0].GPUUUID {
		t.Fatalf("a long UUID should be shortened for the table: %q", metrics.GPUs[0].ShortUUID)
	}
}

func TestGPUMetricsPresentationRejectsSupportedValueWithoutTimestamp(t *testing.T) {
	cell := presentGPUMetricsCell(GPUMetricsCell{State: "SUPPORTED", Value: floatPointer(0)}, GPUMetricsField{Name: "DCGM_FI_DEV_ROW_REMAP_FAILURE", Unit: "boolean"}, time.Now().UTC())
	if cell.Supported || cell.Value != nil || cell.Display != "" || cell.Badge != "UNKNOWN" {
		t.Fatalf("missing observation time rendered as healthy zero: %+v", cell)
	}
}

func TestGPUMetricsPresentationNeverShowsAStaleObservationAsHealthy(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	metrics := presentGPUMetrics(gpuMetricsFixture(now), now)

	rows := map[string]GPUMetricsRow{}
	for _, row := range metrics.GPUs {
		key := row.GPUUUID
		if row.MIGIdentity != "" {
			key += "/" + row.MIGIdentity
		}
		rows[key] = row
	}
	if fresh := rows["GPU-0123456789abcdef-tail"]; fresh.ObservedBadge != "OBSERVED" || fresh.ObservedClass != "healthy" {
		t.Fatalf("a fresh observation = %q %q", fresh.ObservedBadge, fresh.ObservedClass)
	}
	stale := rows["GPU-stale"]
	if stale.ObservedBadge != "OBSERVED · STALE 21 d" || stale.ObservedClass != "stale" {
		t.Fatalf("a three-week-old observation must never read as healthy: %q %q", stale.ObservedBadge, stale.ObservedClass)
	}
	if mig := rows["GPU-0123456789abcdef-tail/mig-0"]; !mig.MIG {
		t.Fatalf("a MIG entity row must be marked as one: %+v", mig)
	}

	cells := map[string]GPUMetricsCell{}
	for _, cell := range stale.Cells {
		cells[cell.Field] = cell
	}
	// A non-finite sample and a sample from a clock ahead of ours are both
	// unrenderable: a badge, never an empty value element.
	for _, field := range []string{"DCGM_FI_DEV_POWER_USAGE"} {
		cell := cells[field]
		if cell.Supported || cell.Display != "" || cell.Badge != "UNKNOWN" {
			t.Fatalf("%s must render as UNKNOWN: %+v", field, cell)
		}
	}
	if skewed := cells["DCGM_FI_DEV_POWER_MGMT_LIMIT"]; skewed.Age != "in 2 h" {
		t.Fatalf("a future instant must be shown signed, not clamped: %+v", skewed)
	}
	if mig := rows["GPU-0123456789abcdef-tail/mig-0"].Cells[0]; mig.Supported || mig.Badge != "AMBIGUOUS MIG" {
		t.Fatalf("a MIG cell must carry no value: %+v", mig)
	}

	gap := metrics.Inventory.ExpectedNotObserved[0]
	if gap.Badge != "OBSERVATION STALE" || gap.BadgeClass != "stale" {
		t.Fatalf("a stale coverage gap must say so: %+v", gap)
	}
	if metrics.GoverningSource != "source-1" || metrics.OtherSourceNote == "" || metrics.BoundsNote == "" {
		t.Fatalf("the page must name its governing source and its bounds: %+v", metrics)
	}
	operations := metrics.Sources[0].Operations
	if operations[0].FreshnessDetail != "newest run PARTIAL" || operations[1].FreshnessClass != "unavailable" {
		t.Fatalf("a failing newest run must be visible and never healthy: %+v", operations)
	}
	if operations[2].FreshnessDetail != "no committed run" {
		t.Fatalf("an operation with no run must say so: %+v", operations[2])
	}
}
