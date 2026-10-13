package application

import (
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

func TestProjectGPUHealthCollectionStates(t *testing.T) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name   string
		result domain.CollectionResult
		want   domain.HealthSignalType
	}{
		{name: "unavailable", result: healthResult(domain.ResultFailed, true, nil, domain.CollectionFailure{Code: domain.FailureSourceUnavailable}), want: domain.HealthSignalUnavailable},
		{name: "no data", result: healthResult(domain.ResultNoData, true, nil), want: domain.HealthSignalNoData},
		{name: "unsupported observations are not normal", result: healthResult(domain.ResultSucceeded, true, []domain.Observation{healthObservation("identity", "DCGM_FI_DEV_UUID", 1, "", now)}), want: domain.HealthSignalNoData},
		{name: "partial", result: healthResult(domain.ResultPartial, false, []domain.Observation{healthObservation("util", "DCGM_FI_DEV_GPU_UTIL", 50, "percent", now)}), want: domain.HealthSignalPartial},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signals, err := ProjectGPUHealth(tt.result, now, DefaultGPUHealthThresholds())
			if err != nil {
				t.Fatal(err)
			}
			if len(signals) != 1 || signals[0].Type != tt.want {
				t.Fatalf("signals = %#v, want one %s signal", signals, tt.want)
			}
			if signals[0].Type == domain.HealthSignalNormal {
				t.Fatal("missing or incomplete evidence must not project normal health")
			}
		})
	}
}

func TestProjectGPUHealthStaleSuppressesIncidentConclusion(t *testing.T) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	result := healthResult(domain.ResultSucceeded, true, []domain.Observation{
		healthObservation("xid", "DCGM_FI_DEV_XID_ERRORS", 79, "count", now.Add(-3*time.Minute)),
	})
	signals, err := ProjectGPUHealth(result, now, DefaultGPUHealthThresholds())
	if err != nil {
		t.Fatal(err)
	}
	if len(signals) != 1 || signals[0].Type != domain.HealthSignalStale || signals[0].Category != domain.HealthSignalXID {
		t.Fatalf("signals = %#v, want stale XID evidence", signals)
	}
	if signals[0].Severity != domain.HealthSeverityUnknown {
		t.Fatalf("severity = %s, want UNKNOWN", signals[0].Severity)
	}
}

func TestProjectGPUHealthStaleCompanionEvidenceSuppressesDerivedConclusion(t *testing.T) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	result := healthResult(domain.ResultSucceeded, true, []domain.Observation{
		healthObservation("power", "DCGM_FI_DEV_POWER_USAGE", 270, "watts", now),
		healthObservation("limit", "DCGM_FI_DEV_POWER_MGMT_LIMIT", 300, "watts", now.Add(-3*time.Minute)),
	})
	signals, err := ProjectGPUHealth(result, now, DefaultGPUHealthThresholds())
	if err != nil {
		t.Fatal(err)
	}
	if len(signals) != 1 || signals[0].Type != domain.HealthSignalStale || signals[0].Category != domain.HealthSignalPower {
		t.Fatalf("signals = %#v, want stale power evidence", signals)
	}
}

func TestProjectGPUHealthMetricRules(t *testing.T) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name          string
		observations  []domain.Observation
		wantType      domain.HealthSignalType
		wantCategory  domain.HealthSignalType
		wantSeverity  domain.HealthSeverity
		wantThreshold float64
	}{
		{name: "normal temperature", observations: []domain.Observation{healthObservation("temp", "DCGM_FI_DEV_GPU_TEMP", 70, "celsius", now)}, wantType: domain.HealthSignalNormal, wantCategory: domain.HealthSignalThermal, wantSeverity: domain.HealthSeverityInfo, wantThreshold: 80},
		{name: "XID", observations: []domain.Observation{healthObservation("xid", "DCGM_FI_DEV_XID_ERRORS", 79, "count", now)}, wantType: domain.HealthSignalXID, wantCategory: domain.HealthSignalXID, wantSeverity: domain.HealthSeverityCritical, wantThreshold: 1},
		{name: "single bit ECC", observations: []domain.Observation{healthObservation("sbe", "DCGM_FI_DEV_ECC_SBE_VOL_TOTAL", 2, "count", now), healthObservation("dbe0", "DCGM_FI_DEV_ECC_DBE_VOL_TOTAL", 0, "count", now)}, wantType: domain.HealthSignalECC, wantCategory: domain.HealthSignalECC, wantSeverity: domain.HealthSeverityWarning, wantThreshold: 1},
		{name: "double bit ECC", observations: []domain.Observation{healthObservation("sbe0", "DCGM_FI_DEV_ECC_SBE_VOL_TOTAL", 0, "count", now), healthObservation("dbe", "DCGM_FI_DEV_ECC_DBE_VOL_TOTAL", 1, "count", now)}, wantType: domain.HealthSignalECC, wantCategory: domain.HealthSignalECC, wantSeverity: domain.HealthSeverityCritical, wantThreshold: 1},
		{name: "thermal warning", observations: []domain.Observation{healthObservation("temp", "DCGM_FI_DEV_GPU_TEMP", 82, "celsius", now)}, wantType: domain.HealthSignalThermal, wantCategory: domain.HealthSignalThermal, wantSeverity: domain.HealthSeverityWarning, wantThreshold: 80},
		{name: "thermal critical", observations: []domain.Observation{healthObservation("temp", "DCGM_FI_DEV_GPU_TEMP", 85, "celsius", now)}, wantType: domain.HealthSignalThermal, wantCategory: domain.HealthSignalThermal, wantSeverity: domain.HealthSeverityCritical, wantThreshold: 85},
		{name: "memory derived percentage", observations: []domain.Observation{healthObservation("used", "DCGM_FI_DEV_FB_USED", 95, "MiB", now), healthObservation("free", "DCGM_FI_DEV_FB_FREE", 5, "MiB", now)}, wantType: domain.HealthSignalMemory, wantCategory: domain.HealthSignalMemory, wantSeverity: domain.HealthSeverityCritical, wantThreshold: 95},
		{name: "power derived percentage", observations: []domain.Observation{healthObservation("power", "DCGM_FI_DEV_POWER_USAGE", 270, "watts", now), healthObservation("limit", "DCGM_FI_DEV_POWER_MGMT_LIMIT", 300, "watts", now)}, wantType: domain.HealthSignalPower, wantCategory: domain.HealthSignalPower, wantSeverity: domain.HealthSeverityWarning, wantThreshold: 90},
		{name: "high utilization is not critical", observations: []domain.Observation{healthObservation("util", "DCGM_FI_DEV_GPU_UTIL", 99, "percent", now)}, wantType: domain.HealthSignalUtilization, wantCategory: domain.HealthSignalUtilization, wantSeverity: domain.HealthSeverityWarning, wantThreshold: 95},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signals, err := ProjectGPUHealth(healthResult(domain.ResultSucceeded, true, tt.observations), now, DefaultGPUHealthThresholds())
			if err != nil {
				t.Fatal(err)
			}
			if len(signals) != 1 {
				t.Fatalf("got %d signals: %#v", len(signals), signals)
			}
			got := signals[0]
			if got.Type != tt.wantType || got.Category != tt.wantCategory || got.Severity != tt.wantSeverity {
				t.Fatalf("signal = (%s, %s, %s), want (%s, %s, %s)", got.Type, got.Category, got.Severity, tt.wantType, tt.wantCategory, tt.wantSeverity)
			}
			if got.Threshold == nil || got.Threshold.Operator != ">=" || got.Threshold.Value != tt.wantThreshold {
				t.Fatalf("threshold = %#v, want >= %v", got.Threshold, tt.wantThreshold)
			}
		})
	}
}

func TestProjectGPUHealthPreservesIncidentUnderPartialCoverage(t *testing.T) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	result := healthResult(domain.ResultPartial, false, []domain.Observation{
		healthObservation("xid", "DCGM_FI_DEV_XID_ERRORS", 79, "count", now),
	})
	signals, err := ProjectGPUHealth(result, now, DefaultGPUHealthThresholds())
	if err != nil {
		t.Fatal(err)
	}
	if len(signals) != 2 || findSignal(signals, domain.HealthSignalPartial) == nil || findSignal(signals, domain.HealthSignalXID) == nil {
		t.Fatalf("signals = %#v, want partial state plus proven XID", signals)
	}
}

func TestProjectGPUHealthRequiresCompanionEvidence(t *testing.T) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	result := healthResult(domain.ResultSucceeded, true, []domain.Observation{
		healthObservation("used", "DCGM_FI_DEV_FB_USED", 95, "MiB", now),
	})
	signals, err := ProjectGPUHealth(result, now, DefaultGPUHealthThresholds())
	if err != nil {
		t.Fatal(err)
	}
	if len(signals) != 1 || signals[0].Type != domain.HealthSignalPartial || signals[0].Category != domain.HealthSignalMemory {
		t.Fatalf("signals = %#v, want partial memory evidence", signals)
	}
}

func TestProjectGPUHealthRecordsCounterEvidence(t *testing.T) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	result := healthResult(domain.ResultSucceeded, true, []domain.Observation{
		healthObservation("sbe", "DCGM_FI_DEV_ECC_SBE_VOL_TOTAL", 0, "count", now),
		healthObservation("dbe", "DCGM_FI_DEV_ECC_DBE_VOL_TOTAL", 1, "count", now),
	})
	signals, err := ProjectGPUHealth(result, now, DefaultGPUHealthThresholds())
	if err != nil {
		t.Fatal(err)
	}
	if got := signals[0].Evidence; len(got) != 1 || got[0] != "dbe" {
		t.Fatalf("evidence = %v, want [dbe]", got)
	}
	if got := signals[0].CounterEvidence; len(got) != 1 || got[0] != "sbe" {
		t.Fatalf("counter evidence = %v, want [sbe]", got)
	}
}

func healthResult(status domain.ResultStatus, complete bool, observations []domain.Observation, failures ...domain.CollectionFailure) domain.CollectionResult {
	return domain.CollectionResult{
		Task:   domain.CollectionTask{ClusterID: "cluster-1", SourceID: "source-1", Node: "comp001"},
		Status: status, Coverage: domain.Coverage{SeriesReturned: len(observations), Complete: complete},
		Observations: observations, Failures: failures,
	}
}

func healthObservation(id domain.ObservationID, metric string, value float64, unit string, observedAt time.Time) domain.Observation {
	return domain.Observation{ID: id, ClusterID: "cluster-1", SourceID: "source-1", EntityKey: "node/comp001/gpu/0", Metric: metric, Value: value, Unit: unit, ObservedAt: observedAt}
}

func findSignal(signals []domain.HealthSignal, signalType domain.HealthSignalType) *domain.HealthSignal {
	for i := range signals {
		if signals[i].Type == signalType {
			return &signals[i]
		}
	}
	return nil
}
