package application

import (
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

func projectHealthTest(t *testing.T, result domain.CollectionResult, now time.Time) []domain.HealthSignal {
	t.Helper()
	signals, err := ProjectGPUHealth(result, now, DefaultGPUHealthThresholds())
	if err != nil {
		t.Fatal(err)
	}
	return signals
}

func TestGPUHealthRowRemapCountersAndFailureHaveDistinctSemantics(t *testing.T) {
	now := time.Now().UTC()
	for _, test := range []struct {
		metric, unit string
		value        float64
		kind         domain.HealthSignalType
		severity     domain.HealthSeverity
		reason       string
	}{
		{"DCGM_FI_DEV_CORRECTABLE_REMAPPED_ROWS", "count", 3, domain.HealthSignalECC, domain.HealthSeverityWarning, "historical"},
		{"DCGM_FI_DEV_UNCORRECTABLE_REMAPPED_ROWS", "count", 1, domain.HealthSignalECC, domain.HealthSeverityCritical, "epoch is unknown"},
		{"DCGM_FI_DEV_ROW_REMAP_FAILURE", "boolean", 1, domain.HealthSignalECC, domain.HealthSeverityCritical, "failure state is asserted"},
		{"DCGM_FI_DEV_ROW_REMAP_FAILURE", "boolean", 0, domain.HealthSignalNormal, domain.HealthSeverityInfo, "missing fields"},
		{"DCGM_FI_DEV_ROW_REMAP_FAILURE", "boolean", 2, domain.HealthSignalPartial, domain.HealthSeverityUnknown, "invalid"},
	} {
		t.Run(test.metric+test.reason, func(t *testing.T) {
			signals := projectHealthTest(t, healthResult(domain.ResultSucceeded, true, []domain.Observation{healthObservation("e", test.metric, test.value, test.unit, now)}), now)
			if len(signals) != 1 || signals[0].Type != test.kind || signals[0].Severity != test.severity || !strings.Contains(signals[0].Reason, test.reason) {
				t.Fatalf("unexpected remap semantics: %+v", signals)
			}
		})
	}
}

func TestGPUHealthTemperatureSensorsRemainIndependent(t *testing.T) {
	now := time.Now().UTC()
	result := healthResult(domain.ResultSucceeded, true, []domain.Observation{
		healthObservation("gpu", "DCGM_FI_DEV_GPU_TEMP", 87, "celsius", now),
		healthObservation("memory", "DCGM_FI_DEV_MEMORY_TEMP", 40, "celsius", now.Add(-3*time.Minute)),
	})
	signals := projectHealthTest(t, result, now)
	if len(signals) != 2 {
		t.Fatalf("GPU/memory sensors collapsed: %+v", signals)
	}
	for _, signal := range signals {
		if signal.Metric == "DCGM_FI_DEV_GPU_TEMP" && (signal.Type != domain.HealthSignalThermal || signal.Severity != domain.HealthSeverityCritical || !strings.Contains(signal.Reason, "gpu temperature")) {
			t.Fatalf("fresh GPU thermal condition lost: %+v", signal)
		}
		if signal.Metric == "DCGM_FI_DEV_MEMORY_TEMP" && signal.Type != domain.HealthSignalStale {
			t.Fatalf("stale memory sensor became normal: %+v", signal)
		}
	}
}

func TestGPUHealthExactNamesAndPowerCompanions(t *testing.T) {
	now := time.Now().UTC()
	for _, metric := range []string{"custom_POWER_USAGE", "GPU_TEMP_FAKE", "DCGM_FI_DEV_POWER_VIOLATION", "DCGM_FI_DEV_CLOCKS_EVENT_REASONS"} {
		signals := projectHealthTest(t, healthResult(domain.ResultSucceeded, true, []domain.Observation{healthObservation("e", metric, 99, "percent", now)}), now)
		if len(signals) != 1 || signals[0].Type != domain.HealthSignalNoData {
			t.Fatalf("unqualified sensor adopted health semantics: %+v", signals)
		}
	}
	for _, observations := range [][]domain.Observation{
		{healthObservation("power", "DCGM_FI_DEV_POWER_USAGE", 95, "percent", now)},
		{healthObservation("limit", "DCGM_FI_DEV_POWER_MGMT_LIMIT", 300, "watts", now)},
		{healthObservation("reserved", "DCGM_FI_DEV_FB_RESERVED", 100, "MiB", now)},
		{healthObservation("used", "DCGM_FI_DEV_FB_USED", 101, "MiB", now), healthObservation("total", "DCGM_FI_DEV_FB_TOTAL", 100, "MiB", now)},
	} {
		signals := projectHealthTest(t, healthResult(domain.ResultSucceeded, true, observations), now)
		if len(signals) != 1 || signals[0].Type != domain.HealthSignalPartial {
			t.Fatalf("missing/invalid companion evidence became healthy: %+v", signals)
		}
	}
}

func TestGPUHealthCanonicalLegacyBridgeRequiresPhysicalProof(t *testing.T) {
	now := time.Now().UTC()
	power := healthObservation("power", "DCGM_FI_DEV_POWER_USAGE", 270, "watts", now)
	power.EntityKey = "cluster-1/GPU/comp001/GPU-a/"
	limit := healthObservation("limit", "DCGM_FI_DEV_POWER_MGMT_LIMIT", 300, "watts", now)
	limit.Labels = []domain.Label{{Name: "UUID", Value: "GPU-a"}}
	result := healthResult(domain.ResultSucceeded, true, []domain.Observation{power, limit})
	before := append([]domain.Observation{}, result.Observations...)
	signals := projectHealthTest(t, result, now)
	if len(signals) != 1 || signals[0].EntityKey != power.EntityKey || signals[0].Type != domain.HealthSignalPower || signals[0].Severity != domain.HealthSeverityWarning {
		t.Fatalf("proven legacy/canonical GPU not reconciled: %+v", signals)
	}
	if !reflect.DeepEqual(result.Observations, before) {
		t.Fatal("pure health projector mutated persisted evidence")
	}
	result.Observations[1].Labels = nil
	signals = projectHealthTest(t, result, now)
	if len(signals) != 2 {
		t.Fatalf("unproven GPU index merged into UUID identity: %+v", signals)
	}
	for _, signal := range signals {
		if signal.Type != domain.HealthSignalPartial {
			t.Fatalf("cross-identity power ratio fabricated: %+v", signal)
		}
	}
}

func TestGPUHealthPreservesExpectedMissingAndUnsupportedFields(t *testing.T) {
	now := time.Now().UTC()
	observation := healthObservation("old-memory", "DCGM_FI_DEV_MEMORY_TEMP", 90, "celsius", now)
	observation.EntityKey = "cluster-1/GPU/comp001/GPU-a/"
	result := healthResult(domain.ResultSucceeded, true, []domain.Observation{observation})
	result.Coverage.MetricFields = []domain.DCGMFieldEvidence{
		{NodeID: "comp001", GPU: "GPU-a", Metric: "DCGM_FI_DEV_MEMORY_TEMP", State: "UNKNOWN"},
		{NodeID: "comp001", GPU: "GPU-a", Metric: "DCGM_FI_DEV_GPU_TEMP", State: "NOT_SUPPORTED"},
		{NodeID: "comp001", GPU: "GPU-b", Metric: "DCGM_FI_DEV_GPU_TEMP", State: "UNKNOWN"},
	}
	signals := projectHealthTest(t, result, now)
	missingGPU, unsupported := false, false
	for _, signal := range signals {
		if signal.Type == domain.HealthSignalNormal || signal.Type == domain.HealthSignalThermal {
			t.Fatalf("missing source field reused old projection: %+v", signals)
		}
		missingGPU = missingGPU || signal.EntityKey == "cluster-1/GPU/comp001/GPU-b/"
		unsupported = unsupported || strings.Contains(signal.Reason, "NOT_SUPPORTED")
	}
	if !missingGPU || !unsupported {
		t.Fatalf("expected missing device/support state dropped: %+v", signals)
	}
	result.Observations = nil
	signals = projectHealthTest(t, result, now)
	if len(signals) != 3 {
		t.Fatalf("missing observations erased expected field states: %+v", signals)
	}
}

func TestGPUHealthCounterResetLateAndFutureEvidenceStayExplicit(t *testing.T) {
	now := time.Now().UTC()
	prior := healthObservation("prior", "DCGM_FI_DEV_CORRECTABLE_REMAPPED_ROWS", 10, "count", now.Add(-time.Minute))
	current := healthObservation("current", prior.Metric, 0, "count", now)
	result := healthResult(domain.ResultSucceeded, true, []domain.Observation{current, prior})
	signals := projectHealthTest(t, result, now)
	if len(signals) != 1 || signals[0].Type != domain.HealthSignalPartial || !strings.Contains(signals[0].Reason, "counter reset") {
		t.Fatalf("counter reset manufactured healthy zero/delta: %+v", signals)
	}
	result.Observations = []domain.Observation{prior, current}
	if reordered := projectHealthTest(t, result, now); !reflect.DeepEqual(signals, reordered) {
		t.Fatalf("late arrival changed deterministic health: %+v %+v", signals, reordered)
	}
	result.Observations[1].Value = 2
	result.Observations[1].Semantics = &domain.MetricSemantics{Kind: "counter", ResetObserved: true}
	signals = projectHealthTest(t, result, now)
	if signals[0].Type != domain.HealthSignalECC || !strings.Contains(signals[0].Reason, "historical") || !strings.Contains(signals[0].Reason, "counter reset") {
		t.Fatalf("positive reset-epoch history misreported: %+v", signals)
	}
	result.Observations[1].ObservedAt = now.Add(time.Second)
	signals = projectHealthTest(t, result, now)
	if signals[0].Type != domain.HealthSignalPartial || signals[0].Freshness != domain.FreshnessUnknown {
		t.Fatalf("future sample became current evidence: %+v", signals)
	}
}

func TestGPUHealthInvalidCurrentEvidenceCannotFallBackToHealthy(t *testing.T) {
	now := time.Now().UTC()
	for _, change := range []func(*domain.Observation){
		func(o *domain.Observation) { o.Value = math.NaN() },
		func(o *domain.Observation) { o.ObservedAt = time.Time{} },
		func(o *domain.Observation) { o.ObservedAt = now.Add(time.Second) },
		func(o *domain.Observation) { o.CollectedAt = now.Add(time.Second) },
		func(o *domain.Observation) { o.Unit = "watts" },
	} {
		observation := healthObservation("bad", "DCGM_FI_DEV_GPU_TEMP", 40, "celsius", now)
		change(&observation)
		signals := projectHealthTest(t, healthResult(domain.ResultSucceeded, true, []domain.Observation{observation}), now)
		if len(signals) != 1 || signals[0].Type != domain.HealthSignalPartial {
			t.Fatalf("invalid current evidence projected all-clear: %+v", signals)
		}
	}
	result := healthResult(domain.ResultSucceeded, true, []domain.Observation{healthObservation("a", "DCGM_FI_DEV_GPU_TEMP", 40, "celsius", now), healthObservation("b", "DCGM_FI_DEV_GPU_TEMP", 90, "celsius", now)})
	if signals := projectHealthTest(t, result, now); signals[0].Type != domain.HealthSignalPartial {
		t.Fatalf("conflicting timestamp values chose arbitrary fault/clear: %+v", signals)
	}
}

func TestGPUHealthUncertainECCFieldDoesNotHideIndependentFault(t *testing.T) {
	now := time.Now().UTC()
	for _, bad := range []domain.Observation{
		healthObservation("bad", "DCGM_FI_DEV_CORRECTABLE_REMAPPED_ROWS", math.NaN(), "count", now),
		healthObservation("bad", "DCGM_FI_DEV_CORRECTABLE_REMAPPED_ROWS", 0, "count", now.Add(time.Second)),
		healthObservation("bad", "DCGM_FI_DEV_CORRECTABLE_REMAPPED_ROWS", 0, "count", now.Add(-3*time.Minute)),
	} {
		fault := healthObservation("failure", "DCGM_FI_DEV_ROW_REMAP_FAILURE", 1, "boolean", now)
		signals := projectHealthTest(t, healthResult(domain.ResultSucceeded, true, []domain.Observation{bad, fault}), now)
		if len(signals) != 2 {
			t.Fatalf("field uncertainty and independent fault were conflated: %+v", signals)
		}
		critical := findSignal(signals, domain.HealthSignalECC)
		if critical == nil || critical.Severity != domain.HealthSeverityCritical || len(critical.Evidence) != 1 || critical.Evidence[0] != "failure" {
			t.Fatalf("uncertain unrelated ECC field suppressed asserted failure: %+v", signals)
		}
	}
	zero := healthObservation("zero", "DCGM_FI_DEV_ECC_DBE_VOL_TOTAL", 0, "count", now)
	failure := healthObservation("failure", "DCGM_FI_DEV_ROW_REMAP_FAILURE", 1, "boolean", now)
	signals := projectHealthTest(t, healthResult(domain.ResultSucceeded, true, []domain.Observation{zero, failure}), now)
	if strings.Contains(signals[0].Reason, "historical ECC/remapped-row count is positive") {
		t.Fatalf("zero counter invented positive history: %+v", signals)
	}
}

func TestGPUHealthTiedMalformedEvidenceCannotChooseHealthByID(t *testing.T) {
	now := time.Now().UTC()
	for _, value := range []float64{40, 90} {
		for _, change := range []struct {
			name string
			edit func(*domain.Observation)
		}{
			{"unit", func(o *domain.Observation) { o.Unit = "watts" }},
			{"kind", func(o *domain.Observation) {
				o.Semantics = &domain.MetricSemantics{Kind: "counter", Reset: "not_applicable"}
			}},
			{"reset", func(o *domain.Observation) {
				o.Semantics = &domain.MetricSemantics{Kind: "gauge", Reset: "source_reset"}
			}},
			{"reset_observed", func(o *domain.Observation) {
				o.Semantics = &domain.MetricSemantics{Kind: "gauge", Reset: "not_applicable", ResetObserved: true}
			}},
		} {
			t.Run(fmt.Sprintf("%s/%g", change.name, value), func(t *testing.T) {
				good := healthObservation("a", "DCGM_FI_DEV_GPU_TEMP", value, "celsius", now)
				good.Semantics = &domain.MetricSemantics{Kind: "gauge", Reset: "not_applicable"}
				bad := good
				bad.ID = "b"
				change.edit(&bad)
				for _, swapIDs := range []bool{false, true} {
					if swapIDs {
						good.ID, bad.ID = bad.ID, good.ID
					}
					for _, observations := range [][]domain.Observation{{good, bad}, {bad, good}} {
						signals := projectHealthTest(t, healthResult(domain.ResultSucceeded, true, observations), now)
						if len(signals) != 1 || signals[0].Type != domain.HealthSignalPartial || signals[0].Severity != domain.HealthSeverityUnknown {
							t.Fatalf("tied malformed evidence chose healthy/fault by ID or arrival: %+v", signals)
						}
					}
				}
				// A third historical row with no metadata must not hide the
				// contradiction between two explicit contracts if its ID wins.
				legacy := good
				legacy.ID, legacy.Semantics = "z", nil
				for _, observations := range [][]domain.Observation{{good, bad, legacy}, {legacy, bad, good}} {
					signals := projectHealthTest(t, healthResult(domain.ResultSucceeded, true, observations), now)
					if len(signals) != 1 || signals[0].Type != domain.HealthSignalPartial || signals[0].Severity != domain.HealthSeverityUnknown {
						t.Fatalf("metadata-free tie hid incompatible explicit contracts: %+v", signals)
					}
				}
			})
		}
	}
	good := healthObservation("a", "DCGM_FI_DEV_UNCORRECTABLE_REMAPPED_ROWS", 1, "count", now)
	bad := good
	bad.ID, bad.Semantics = "b", &domain.MetricSemantics{Kind: "gauge"}
	for _, observations := range [][]domain.Observation{{good, bad}, {bad, good}} {
		signals := projectHealthTest(t, healthResult(domain.ResultSucceeded, true, observations), now)
		if len(signals) != 1 || signals[0].Type != domain.HealthSignalPartial || signals[0].Severity != domain.HealthSeverityUnknown {
			t.Fatalf("tied malformed ECC evidence arbitrarily asserted fault: %+v", signals)
		}
	}
}

func TestGPUHealthTiedCompatibleLegacyUnitAndMissingMetadataRemainUsable(t *testing.T) {
	now := time.Now().UTC()
	good := healthObservation("a", "DCGM_FI_DEV_XID_ERRORS", 79, "count", now)
	good.Semantics = &domain.MetricSemantics{Kind: "gauge", Reset: "not_applicable"}
	legacy := good
	legacy.ID, legacy.Unit, legacy.Semantics = "b", "xid_code", nil
	for _, observations := range [][]domain.Observation{{good, legacy}, {legacy, good}} {
		signals := projectHealthTest(t, healthResult(domain.ResultSucceeded, true, observations), now)
		if len(signals) != 1 || signals[0].Type != domain.HealthSignalXID || signals[0].Severity != domain.HealthSeverityCritical {
			t.Fatalf("documented legacy alias or absent metadata became conflict: %+v", signals)
		}
	}
}

func TestGPUHealthAcceptsPersistedLegacyXIDCodeUnit(t *testing.T) {
	now := time.Now().UTC()
	observation := healthObservation("xid", "DCGM_FI_DEV_XID_ERRORS", 79, "xid_code", now)
	signals := projectHealthTest(t, healthResult(domain.ResultSucceeded, true, []domain.Observation{observation}), now)
	if len(signals) != 1 || signals[0].Type != domain.HealthSignalXID || signals[0].Severity != domain.HealthSeverityCritical {
		t.Fatalf("persisted XID code unit lost health interpretation: %+v", signals)
	}
}

func TestGPUHealthFailedSensorDoesNotHideOtherSourceCondition(t *testing.T) {
	now := time.Now().UTC()
	observation := healthObservation("temp", "DCGM_FI_DEV_GPU_TEMP", 90, "celsius", now)
	observation.EntityKey = "cluster-1/GPU/comp001/GPU-a/"
	result := healthResult(domain.ResultPartial, false, []domain.Observation{observation})
	result.Coverage.MetricFields = []domain.DCGMFieldEvidence{
		{NodeID: "comp001", GPU: "GPU-a", Metric: observation.Metric, State: "SUPPORTED"},
		{NodeID: "comp001", GPU: "GPU-a", Metric: "DCGM_FI_DEV_XID_ERRORS", State: "UNKNOWN", Reason: "collection_failed"},
	}
	signals := projectHealthTest(t, result, now)
	if findSignal(signals, domain.HealthSignalUnavailable) == nil || findSignal(signals, domain.HealthSignalThermal) == nil {
		t.Fatalf("failed dimension masked valid independent condition: %+v", signals)
	}
}
