package domain

import (
	"bytes"
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"
)

func dcgmFixture(q QueryKind) (CollectionResult, []EntityIdentity) {
	now := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	r := CollectionResult{Task: CollectionTask{RunID: "r", ClusterID: "c", SourceID: "s", Query: q, ScheduledFor: now, Deadline: now.Add(time.Minute), MaxSeries: 100, MaxBytes: 10000}, Status: ResultSucceeded, StartedAt: now, CompletedAt: now.Add(time.Second), Coverage: Coverage{Complete: true}}
	for i, f := range DCGMFields(q) {
		r.Observations = append(r.Observations, Observation{ID: ObservationID(string(rune('a' + i))), ClusterID: "c", SourceID: "s", Metric: f.Name, Labels: []Label{{Name: "Hostname", Value: "node-a"}, {Name: "UUID", Value: "GPU-a"}, {Name: "token", Value: "secret"}}, Value: 1, ObservedAt: now, CollectedAt: r.CompletedAt, Unit: "forged", SourceReference: DCGMSourceReference(q)})
	}
	r.Coverage.SeriesReturned = len(r.Observations)
	return r, []EntityIdentity{{ClusterID: "c", Kind: EntityGPU, NodeID: "node-a", PhysicalGPUUUID: "GPU-a"}}
}

func TestDCGMExactSemanticsAndCompleteFieldCoverage(t *testing.T) {
	for _, q := range ExpandedDCGMQueries() {
		t.Run(string(q), func(t *testing.T) {
			r, entities := dcgmFixture(q)
			r = NormalizeDCGMCollection(r, entities)
			if !r.Coverage.Complete || r.Status != ResultSucceeded || len(r.Observations) != len(DCGMFields(q)) {
				t.Fatalf("%+v", r)
			}
			for i, o := range r.Observations {
				f := DCGMFields(q)[i]
				if o.Unit != f.Unit || o.Semantics.Kind != f.Kind || o.Semantics.Reset != f.Reset || o.EntityKey != "c/GPU/node-a/GPU-a/" || len(o.Labels) != 2 || strings.Contains(o.SourceReference, "secret") {
					t.Fatalf("%+v", o)
				}
			}
		})
	}
}

func TestDCGMRowRemapFieldSemantics(t *testing.T) {
	fields := map[string]DCGMField{}
	for _, field := range DCGMFields(QueryGPUECC) {
		fields[field.Name] = field
	}
	for _, name := range []string{"DCGM_FI_DEV_CORRECTABLE_REMAPPED_ROWS", "DCGM_FI_DEV_UNCORRECTABLE_REMAPPED_ROWS"} {
		field, ok := fields[name]
		if !ok || field.Kind != "counter" || field.Unit != "count" || field.Boolean || !strings.Contains(field.Reset, "epoch_unknown") {
			t.Fatalf("row counter %s = %+v", name, field)
		}
	}
	failure, ok := fields["DCGM_FI_DEV_ROW_REMAP_FAILURE"]
	if !ok || failure.Kind != "gauge" || failure.Unit != "boolean" || !failure.Boolean || failure.Reset != "not_applicable" {
		t.Fatalf("row-remap failure = %+v", failure)
	}
}

func TestDCGMSupportIsPerFieldAndMissingNeverUnsupported(t *testing.T) {
	tests := []struct {
		name         string
		query        QueryKind
		change       func(*CollectionResult, *[]EntityIdentity)
		state        string
		observations int
	}{
		{"confirmed_double_unsupported", QueryGPUPower, func(r *CollectionResult, _ *[]EntityIdentity) { r.Observations[0].Value = 140737488355330 }, "NOT_SUPPORTED", 1},
		{"old_collector_contract", QueryGPUPower, func(r *CollectionResult, _ *[]EntityIdentity) {
			r.Observations[0].SourceReference = "prometheus:" + string(r.Task.Query)
		}, "UNKNOWN", 1},
		{"credential_identity", QueryGPUPower, func(r *CollectionResult, _ *[]EntityIdentity) {
			r.Observations[0].Labels[0].Value = "https://user:secret@example.com"
		}, "UNKNOWN", 1},
		{"integer_float_sentinel_is_unknown", QueryGPUTemperature, func(r *CollectionResult, _ *[]EntityIdentity) { r.Observations[0].Value = 140737488355330 }, "UNKNOWN", 1},
		{"rounded_integer_sentinel", QueryGPUECC, func(r *CollectionResult, _ *[]EntityIdentity) { r.Observations[0].Value = 9223372036854775794 }, "UNKNOWN", len(DCGMFields(QueryGPUECC)) - 1},
		{"blank", QueryGPUPower, func(r *CollectionResult, _ *[]EntityIdentity) { r.Observations[0].Value = 140737488355328 }, "UNKNOWN", 1},
		{"nan", QueryGPUPower, func(r *CollectionResult, _ *[]EntityIdentity) { r.Observations[0].Value = math.NaN() }, "UNKNOWN", 1},
		{"stale", QueryGPUPower, func(r *CollectionResult, _ *[]EntityIdentity) {
			r.Observations[0].ObservedAt = r.Task.ScheduledFor.Add(-3 * time.Minute)
		}, "UNKNOWN", 1},
		{"delayed_result", QueryGPUPower, func(r *CollectionResult, _ *[]EntityIdentity) { r.CompletedAt = r.CompletedAt.Add(time.Hour) }, "UNKNOWN", 0},
		{"future", QueryGPUPower, func(r *CollectionResult, _ *[]EntityIdentity) {
			r.Observations[0].ObservedAt = r.Task.ScheduledFor.Add(time.Minute)
		}, "UNKNOWN", 1},
		{"disappearing", QueryGPUPower, func(r *CollectionResult, _ *[]EntityIdentity) {
			r.Observations = r.Observations[1:]
			r.Coverage.SeriesReturned = 1
		}, "UNKNOWN", 1},
		{"empty", QueryGPUPower, func(r *CollectionResult, _ *[]EntityIdentity) {
			r.Observations = nil
			r.Status = ResultNoData
			r.Coverage.SeriesReturned = 0
		}, "UNKNOWN", 0},
		{"failed", QueryGPUPower, func(r *CollectionResult, _ *[]EntityIdentity) {
			r.Status = ResultFailed
			r.Coverage.Complete = false
			r.Failures = []CollectionFailure{{Code: FailureSourceUnavailable, Target: "secret", Message: "secret"}}
		}, "UNKNOWN", 0},
		{"foreign_node", QueryGPUPower, func(r *CollectionResult, _ *[]EntityIdentity) { r.Observations[0].Labels[0].Value = "foreign" }, "UNKNOWN", 1},
		{"foreign_gpu", QueryGPUPower, func(r *CollectionResult, _ *[]EntityIdentity) { r.Observations[0].Labels[1].Value = "GPU-foreign" }, "UNKNOWN", 1},
		{"foreign_cluster", QueryGPUPower, func(r *CollectionResult, _ *[]EntityIdentity) { r.Observations[0].ClusterID = "foreign" }, "UNKNOWN", 1},
		{"foreign_source", QueryGPUPower, func(r *CollectionResult, _ *[]EntityIdentity) { r.Observations[0].SourceID = "foreign" }, "UNKNOWN", 1},
		{"index_is_not_uuid", QueryGPUPower, func(r *CollectionResult, _ *[]EntityIdentity) {
			r.Observations[0].Labels = []Label{{Name: "Hostname", Value: "node-a"}, {Name: "gpu", Value: "0"}}
		}, "UNKNOWN", 1},
		{"conflicting_alias", QueryGPUPower, func(r *CollectionResult, _ *[]EntityIdentity) {
			r.Observations[0].Labels = append(r.Observations[0].Labels, Label{Name: "hostname", Value: "foreign"})
		}, "UNKNOWN", 1},
		{"mig_label", QueryGPUPower, func(r *CollectionResult, _ *[]EntityIdentity) {
			r.Observations[0].Labels = append(r.Observations[0].Labels, Label{Name: "GPU_I_ID", Value: "0"})
		}, "UNKNOWN", 1},
		{"mig_inventory", QueryGPUPower, func(_ *CollectionResult, e *[]EntityIdentity) {
			*e = append(*e, EntityIdentity{ClusterID: "c", Kind: EntityMIG, NodeID: "node-a", PhysicalGPUUUID: "GPU-a", MIGIdentity: "MIG-a"})
		}, "UNKNOWN", 0},
		{"ambiguous_inventory", QueryGPUPower, func(_ *CollectionResult, e *[]EntityIdentity) {
			*e = append(*e, EntityIdentity{ClusterID: "c", Kind: EntityGPU, NodeID: "node-b", PhysicalGPUUUID: "GPU-a"})
		}, "UNKNOWN", 0},
		{"duplicate_field", QueryGPUPower, func(r *CollectionResult, _ *[]EntityIdentity) {
			r.Observations = append(r.Observations, r.Observations[0])
			r.Coverage.SeriesReturned++
		}, "UNKNOWN", 1},
		{"limits", QueryGPUPower, func(r *CollectionResult, _ *[]EntityIdentity) { r.Task.MaxSeries = 1 }, "UNKNOWN", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, e := dcgmFixture(tt.query)
			tt.change(&r, &e)
			r = NormalizeDCGMCollection(r, e)
			if r.Coverage.Complete || r.Status == ResultSucceeded || len(r.Observations) != tt.observations || r.Coverage.MetricFields[0].State != tt.state {
				t.Fatalf("%+v", r)
			}
			encoded, _ := json.Marshal(r)
			if bytes.Contains(encoded, []byte("secret")) {
				t.Fatalf("unsanitized result %s", encoded)
			}
		})
	}
}

func TestDCGMRowRemapFailureRejectsValuesOutsideBooleanDomain(t *testing.T) {
	r, entities := dcgmFixture(QueryGPUECC)
	for i := range r.Observations {
		if r.Observations[i].Metric == "DCGM_FI_DEV_ROW_REMAP_FAILURE" {
			r.Observations[i].Value = 2
		}
	}
	r = NormalizeDCGMCollection(r, entities)
	if r.Status != ResultPartial || r.Coverage.Complete || len(r.Observations) != len(DCGMFields(QueryGPUECC))-1 {
		t.Fatalf("invalid boolean result: %+v", r)
	}
	for _, field := range r.Coverage.MetricFields {
		if field.Metric == "DCGM_FI_DEV_ROW_REMAP_FAILURE" && (field.State != "UNKNOWN" || field.Reason != "invalid_or_blank_value") {
			t.Fatalf("invalid boolean assessment: %+v", field)
		}
	}
}

func TestDCGMUnknownInventoryAndMetadataNeverAlterWire(t *testing.T) {
	r, _ := dcgmFixture(QueryGPUPower)
	base, _ := json.Marshal(r)
	r.Observations[0].Semantics = &MetricSemantics{Kind: "forged"}
	r.Coverage.MetricFields = []DCGMFieldEvidence{{State: "NOT_SUPPORTED"}}
	encoded, _ := json.Marshal(r)
	if !bytes.Equal(base, encoded) {
		t.Fatal("server metadata changed canonical collector result encoding")
	}
	r = NormalizeDCGMCollection(r, nil)
	if r.Coverage.Complete || len(r.Observations) != 0 || r.Coverage.SeriesExpected != nil || len(r.Coverage.MetricFields) != 0 {
		t.Fatalf("unknown inventory: %+v", r)
	}
}

func TestDCGMIdentityIgnoresFreeFormClusterLabel(t *testing.T) {
	task := CollectionTask{ClusterID: "pilot-cluster"}
	labels := []Label{{Name: "Hostname", Value: "node-a"}, {Name: "UUID", Value: "GPU-a"}, {Name: "cluster", Value: "synthetic-foreign-cluster"}}
	node, gpu, valid := DCGMIdentity(labels, task)
	if !valid || node != "node-a" || gpu != "GPU-a" {
		t.Fatalf("expected valid identity ignoring foreign cluster label, got node=%q gpu=%q valid=%v", node, gpu, valid)
	}
}
