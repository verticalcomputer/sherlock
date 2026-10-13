package monitoring

import (
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

var testAt = time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)

func thermalPolicy() Policy {
	return Policy{ID: "thermal-a", Revision: 1, ClusterID: "cluster", SourceID: "source", EntityKey: "cluster/GPU/node/GPU-a/", Rule: RuleGPUThermal, RuleVersion: 1,
		Metric: "DCGM_FI_DEV_GPU_TEMP", Unit: "celsius", Binding: Binding{Operation: domain.OperationPrometheusGPUTemperature, Scope: domain.CollectionScope{Nodes: []domain.StableNodeID{"node"}}, ScheduleRevision: 3, InventoryRevisionID: "inventory-1"},
		EnrolledAt: testAt.Add(-10 * time.Minute), StartupGraceSeconds: 30, FreshForSeconds: 300, ConfirmCount: 2, ConfirmWindowSeconds: 180, ConfirmMinDurationSeconds: 60,
		RecoverCount: 2, RecoverWindowSeconds: 180, RecoverMinDurationSeconds: 60, MaxSampleGapSeconds: 30, OpenThreshold: 80, RecoverBelow: 70, Severity: domain.HealthSeverityCritical}
}

func counterPolicy() Policy {
	p := thermalPolicy()
	p.ID, p.Rule, p.Metric, p.Unit = "counter-a", RuleECCHistorical, "DCGM_FI_DEV_UNCORRECTABLE_REMAPPED_ROWS", "count"
	p.Binding.Operation = domain.OperationPrometheusGPUECC
	p.ConfirmCount, p.ConfirmMinDurationSeconds, p.RecoverMinDurationSeconds, p.OpenThreshold, p.RecoverBelow = 1, 0, 0, 1, 0
	return p
}

func telemetryPolicy() Policy {
	p := thermalPolicy()
	p.ID, p.EntityKey, p.Rule, p.Metric, p.Unit = "loss-a", "source/source", RuleTelemetryLoss, "", ""
	p.EnrolledAt = testAt
	p.ConfirmCount, p.ConfirmMinDurationSeconds, p.RecoverMinDurationSeconds, p.OpenThreshold, p.RecoverBelow = 1, 0, 30, 0, 0
	p.FreshForSeconds, p.MaxSampleGapSeconds = 60, 60
	return p
}

func sample(policy Policy, id string, seconds int, value float64) Sample {
	at := testAt.Add(time.Duration(seconds) * time.Second)
	return Sample{Observation: domain.Observation{ID: domain.ObservationID(id), ClusterID: policy.ClusterID, SourceID: policy.SourceID, EntityKey: policy.EntityKey, Metric: policy.Metric, Value: value, Unit: policy.Unit, ObservedAt: at, CollectedAt: at}, RunID: domain.RunID("run-" + id), CollectionCompletedAt: at, Status: domain.ResultSucceeded, Supported: true, CoverageComplete: true}
}

func sensorInput(policy Policy, at time.Time, samples ...Sample) Input {
	input := Input{At: at, AuthorityValid: true, Samples: samples}
	for _, s := range samples {
		input.Runs = append(input.Runs, RunEvidence{RunID: s.RunID, ClusterID: policy.ClusterID, SourceID: policy.SourceID, Binding: policy.Binding, CompletedAt: s.CollectionCompletedAt, Status: s.Status, CoverageComplete: s.CoverageComplete, Count: 1, FieldState: "SUPPORTED"})
	}
	return input
}

func evaluate(t *testing.T, policy Policy, state State, input Input) Decision {
	t.Helper()
	d, err := Evaluate(policy, state, input)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestThermalSustainedDurationAndRecoveryHold(t *testing.T) {
	p := thermalPolicy()
	state := State{}
	for _, seconds := range []int{0, 1} {
		d := evaluate(t, p, state, sensorInput(p, testAt.Add(time.Duration(seconds)*time.Second), sample(p, fmt.Sprint(seconds), seconds, 80)))
		if d.Transition != nil {
			t.Fatal("two immediate high samples satisfied advertised 60-second condition")
		}
		state = d.State
	}
	state = evaluate(t, p, state, sensorInput(p, testAt.Add(2*time.Second), sample(p, "spike-ended", 2, 40))).State
	if state.PendingCount != 0 {
		t.Fatal("ended spike retained sustained confirmation")
	}
	for _, seconds := range []int{30, 60, 90} {
		d := evaluate(t, p, state, sensorInput(p, testAt.Add(time.Duration(seconds)*time.Second), sample(p, fmt.Sprint(seconds), seconds, 80)))
		if (d.Transition != nil) != (seconds == 90) {
			t.Fatalf("sustained boundary %d: %+v", seconds, d)
		}
		state = d.State
	}
	for _, seconds := range []int{100, 101, 130, 160} {
		d := evaluate(t, p, state, sensorInput(p, testAt.Add(time.Duration(seconds)*time.Second), sample(p, fmt.Sprint(seconds), seconds, 69)))
		if (d.Transition != nil) != (seconds == 160) {
			t.Fatalf("recovery hold boundary %d: %+v", seconds, d)
		}
		state = d.State
	}
	if state.Open || state.Occurrence != 1 {
		t.Fatalf("incorrect recovered occurrence: %+v", state)
	}
}

func TestThermalGapWindowHysteresisAndReplay(t *testing.T) {
	p := thermalPolicy()
	first := sample(p, "first", 0, 85)
	state := evaluate(t, p, State{}, sensorInput(p, testAt, first)).State
	for i := 1; i <= 20; i++ {
		d := evaluate(t, p, state, sensorInput(p, testAt.Add(time.Duration(i)*time.Second), first))
		if d.Transition != nil || d.State.PendingCount != 1 {
			t.Fatal("repeated immutable observation confirmed on clock ticks")
		}
		state = d.State
	}
	state = evaluate(t, p, state, sensorInput(p, testAt.Add(31*time.Second), sample(p, "gap", 31, 85))).State
	if state.PendingCount != 1 || !state.Pending[0].ObservedAt.Equal(testAt.Add(31*time.Second)) {
		t.Fatalf("maximum sample gap did not restart sequence: %+v", state)
	}
	d := evaluate(t, p, state, sensorInput(p, testAt.Add(91*time.Second), sample(p, "next", 61, 85), sample(p, "last", 91, 85)))
	if d.Transition == nil || d.Transition.Kind != TransitionOpen {
		t.Fatal("fresh gap-bounded 60-second evidence did not confirm")
	}
	state = d.State
	state = evaluate(t, p, state, sensorInput(p, testAt.Add(100*time.Second), sample(p, "cool", 100, 69))).State
	state = evaluate(t, p, state, sensorInput(p, testAt.Add(120*time.Second), sample(p, "boundary", 120, 70))).State
	if state.RecoveryCount != 0 || !state.Open {
		t.Fatal("hysteresis boundary improperly recovered or kept prior hold")
	}
	late := evaluate(t, p, state, sensorInput(p, testAt.Add(130*time.Second), first))
	if late.Transition != nil || !late.State.SourceCursor.ObservedAt.Equal(testAt.Add(120*time.Second)) {
		t.Fatal("late evidence moved cursor or cleared condition")
	}
}

func TestDenseConfirmationBoundsRetainedEvidenceHonestly(t *testing.T) {
	p := thermalPolicy()
	p.ConfirmMinDurationSeconds, p.MaxSampleGapSeconds = 90, 2
	var samples []Sample
	for i := 0; i <= 90; i++ {
		samples = append(samples, sample(p, fmt.Sprintf("sample-%03d", i), i, 90))
	}
	input := sensorInput(p, testAt.Add(90*time.Second), samples...)
	before, _ := json.Marshal(input)
	d := evaluate(t, p, State{}, input)
	if d.Transition == nil || d.Transition.QualifyingSampleCount != 91 || len(d.Transition.Evidence) != 32 || d.Transition.OmittedEvidenceCount != 59 || !d.Transition.Evidence[0].ObservedAt.Equal(testAt) || !d.Transition.Evidence[31].ObservedAt.Equal(testAt.Add(90*time.Second)) {
		t.Fatalf("bounded evidence claimed complete retention or invented counts: %+v", d)
	}
	after, _ := json.Marshal(input)
	if string(before) != string(after) {
		t.Fatal("evaluator mutated immutable input")
	}
}

func TestInvalidSensorEvidenceCannotConfirmOrRecover(t *testing.T) {
	p := thermalPolicy()
	p.ConfirmCount, p.ConfirmMinDurationSeconds = 1, 0
	opened := evaluate(t, p, State{}, sensorInput(p, testAt, sample(p, "open", 0, 90))).State
	for _, test := range []struct {
		name string
		edit func(*Input)
	}{
		{"foreign_source", func(i *Input) { i.Samples[0].Observation.SourceID = "foreign" }},
		{"foreign_gpu", func(i *Input) { i.Samples[0].Observation.EntityKey = "cluster/GPU/node/GPU-b/" }},
		{"foreign_operation", func(i *Input) { i.Runs[0].Binding.Operation = domain.OperationPrometheusGPUUtilization }},
		{"wrong_schedule_revision", func(i *Input) { i.Runs[0].Binding.ScheduleRevision++ }},
		{"missing_run", func(i *Input) { i.Runs = nil }},
		{"unsupported", func(i *Input) { i.Samples[0].Supported = false }},
		{"future", func(i *Input) { i.At = testAt }},
		{"invalid_value", func(i *Input) { i.Samples[0].Observation.Value = math.NaN() }},
		{"wrong_unit", func(i *Input) { i.Samples[0].Observation.Unit = "watts" }},
		{"stale", func(i *Input) { i.At = testAt.Add(400 * time.Second) }},
		{"authority", func(i *Input) { i.AuthorityValid = false }},
		{"missing", func(i *Input) { i.Samples = nil }},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := sensorInput(p, testAt.Add(10*time.Second), sample(p, "bad", 10, 0))
			test.edit(&input)
			d := evaluate(t, p, opened, input)
			if !d.State.Open || d.Transition != nil || d.State.RecoveryCount != 0 || d.State.LastGap == "" {
				t.Fatalf("invalid evidence recovered existing condition: %+v", d)
			}
		})
	}
}

func TestSensorTiesFailClosedAndLegacyUnitAliasesRemainCompatible(t *testing.T) {
	p := thermalPolicy()
	p.ConfirmCount, p.ConfirmMinDurationSeconds = 1, 0
	good := sample(p, "a", 0, 90)
	good.Observation.Semantics = &domain.MetricSemantics{Kind: "gauge", Reset: "not_applicable"}
	bad := sample(p, "b", 0, 90)
	bad.Observation.Semantics = &domain.MetricSemantics{Kind: "gauge", Reset: "source_reset"}
	legacy := sample(p, "0", 0, 90)
	for _, samples := range [][]Sample{{good, bad, legacy}, {legacy, bad, good}} {
		d := evaluate(t, p, State{}, sensorInput(p, testAt, samples...))
		if d.Transition != nil || d.State.LastGap != ReasonConflict {
			t.Fatalf("metadata-free tie concealed incompatible contracts: %+v", d)
		}
	}
	legacy.Observation.Unit = "C"
	d := evaluate(t, p, State{}, sensorInput(p, testAt, good, legacy))
	if d.Transition == nil || d.Transition.Kind != TransitionOpen || d.Transition.QualifyingSampleCount != 1 {
		t.Fatal("compatible legacy unit alias rejected or counted twice")
	}
}

func TestNewerRequiredAttemptCannotUncoverOlderRecoveryOrConfirmations(t *testing.T) {
	p := thermalPolicy()
	p.ConfirmCount, p.ConfirmMinDurationSeconds = 1, 0
	opened := evaluate(t, p, State{}, sensorInput(p, testAt, sample(p, "open", 0, 90))).State
	for _, failure := range []struct {
		status domain.ResultStatus
		field  string
	}{
		{domain.ResultFailed, "UNKNOWN"},
		{domain.ResultNoData, "UNKNOWN"},
		{domain.ResultPartial, "UNKNOWN"},
		{domain.ResultPartial, "NOT_SUPPORTED"},
	} {
		input := sensorInput(p, testAt.Add(70*time.Second), sample(p, "old-cool-1", 1, 60), sample(p, "old-cool-2", 61, 60))
		newest := goodRun(p, "newer-gap", 70)
		newest.Status, newest.FieldState, newest.Count = failure.status, failure.field, 0
		input.Runs = append(input.Runs, newest)
		d := evaluate(t, p, opened, input)
		if !d.State.Open || d.Transition != nil || d.State.RecoveryCount != 0 || d.State.LastGap == "" {
			t.Fatalf("newer gap uncovered old fresh cooling evidence: %+v", d)
		}
		pendingPolicy := p
		pendingPolicy.ConfirmCount, pendingPolicy.ConfirmMinDurationSeconds = 2, 60
		pending := evaluate(t, pendingPolicy, State{}, sensorInput(pendingPolicy, testAt, sample(pendingPolicy, "pending", 0, 90))).State
		input.Samples = nil
		input = sensorInput(pendingPolicy, input.At, sample(pendingPolicy, "old-high", 60, 90))
		input.Runs = append(input.Runs, newest)
		d = evaluate(t, pendingPolicy, pending, input)
		if d.Transition != nil || d.State.PendingCount != 0 {
			t.Fatal("newer failed attempt completed an old confirmation sequence")
		}
	}
}

func TestIntermediateAttemptGapRestartsConfirmationButIndependentSupportedFieldQualifies(t *testing.T) {
	p := thermalPolicy()
	state := evaluate(t, p, State{}, sensorInput(p, testAt, sample(p, "before-gap", 0, 90))).State
	input := sensorInput(p, testAt.Add(60*time.Second), sample(p, "after-gap", 60, 90))
	gap := goodRun(p, "middle-gap", 30)
	gap.Status, gap.FieldState = domain.ResultFailed, "UNKNOWN"
	input.Runs = append(input.Runs, gap)
	d := evaluate(t, p, state, input)
	if d.Transition != nil || d.State.PendingCount != 1 || d.State.Pending[0].RunID != "run-after-gap" {
		t.Fatal("confirmation bridged failed operation evidence")
	}
	p.ConfirmCount, p.ConfirmMinDurationSeconds = 1, 0
	partial := sample(p, "partial-supported", 90, 90)
	partial.Status, partial.CoverageComplete = domain.ResultPartial, false
	d = evaluate(t, p, State{}, sensorInput(p, testAt.Add(90*time.Second), partial))
	if d.Transition == nil || d.Transition.Kind != TransitionOpen {
		t.Fatal("independent supported fault was hidden by unrelated partial coverage")
	}
}

func TestEmptyFetchPreservesFreshPendingWithoutCountingTicks(t *testing.T) {
	p := thermalPolicy()
	state := evaluate(t, p, State{}, sensorInput(p, testAt, sample(p, "first", 0, 90))).State
	d := evaluate(t, p, state, Input{At: testAt.Add(10 * time.Second), AuthorityValid: true})
	if d.Transition != nil || d.State.PendingCount != 1 || d.State.LastGap != "" {
		t.Fatal("empty fetch erased fresh persisted confirmation or counted a sample")
	}
	d = evaluate(t, p, d.State, Input{At: testAt.Add(301 * time.Second), AuthorityValid: true})
	if d.Transition != nil || d.State.PendingCount != 0 || d.State.LastGap != ReasonStale {
		t.Fatal("stale persisted source evidence retained active confirmation")
	}
}

func TestHistoricalCounterReviewIsNotMeasuredRecoveryAndPinsBaseline(t *testing.T) {
	p := counterPolicy()
	d := evaluate(t, p, State{}, sensorInput(p, testAt, sample(p, "history", 0, 120)))
	if d.Transition == nil || d.Transition.Reason != ReasonHistoricalCounter || d.State.LastHistoricalValue == nil {
		t.Fatal("positive historical counter did not preserve attention evidence")
	}
	zero := sample(p, "reset", 10, 0)
	zero.Observation.Semantics = &domain.MetricSemantics{Kind: "counter", ResetObserved: true}
	d = evaluate(t, p, d.State, sensorInput(p, testAt.Add(10*time.Second), zero))
	if !d.State.Open || d.Transition != nil || d.State.LastGap != ReasonCounterReset {
		t.Fatal("zero/reset falsely recovered historical condition")
	}
	review := RecoveryDisposition{ID: "review-1", PolicyID: p.ID, EnrollmentRevision: 1, Occurrence: 1, Actor: "operator", EvidenceID: "review-evidence", ReviewedAt: testAt.Add(20 * time.Second)}
	d = evaluate(t, p, d.State, Input{At: review.ReviewedAt, AuthorityValid: false, RecoveryDisposition: &review})
	if d.State.Open || d.Transition == nil || d.Transition.Reason != ReasonReviewedDisposition || d.State.LastGap != ReasonCounterReset || d.Transition.QualifyingSampleCount != 0 || *d.State.ReviewedCounterValue != 120 {
		t.Fatalf("reviewed closure implied measured recovery or lost baseline: %+v", d)
	}
	again, err := ApplyReviewedDisposition(p, d.State, review, review.ReviewedAt)
	if err != nil || again.Transition != nil {
		t.Fatal("replayed review duplicated transition")
	}
	d = evaluate(t, p, d.State, sensorInput(p, testAt.Add(30*time.Second), sample(p, "same-value", 30, 120)))
	if d.Transition != nil || d.State.Open {
		t.Fatal("fresh unchanged historical counter reopened reviewed attention")
	}
	d = evaluate(t, p, d.State, sensorInput(p, testAt.Add(40*time.Second), sample(p, "changed-value", 40, 121)))
	if d.Transition == nil || !d.State.Open || d.State.Occurrence != 2 || d.Transition.Reason != ReasonHistoricalCounter {
		t.Fatal("changed positive history lost new attention occurrence")
	}
}

func TestRowRemapBooleanUsesDistinctFreshZeroRecovery(t *testing.T) {
	p := counterPolicy()
	p.Rule, p.Metric, p.Unit = RuleRemapFailure, "DCGM_FI_DEV_ROW_REMAP_FAILURE", "boolean"
	p.RecoverMinDurationSeconds = 30
	d := evaluate(t, p, State{}, sensorInput(p, testAt, sample(p, "failure", 0, 1)))
	if d.Transition == nil || d.Transition.Reason != ReasonRemapFailure {
		t.Fatal("boolean failure did not assert")
	}
	zero := sample(p, "zero-1", 1, 0)
	d = evaluate(t, p, d.State, sensorInput(p, testAt.Add(time.Second), zero))
	d = evaluate(t, p, d.State, sensorInput(p, testAt.Add(10*time.Second), zero))
	if d.Transition != nil || d.State.RecoveryCount != 1 {
		t.Fatal("replayed zero counted twice")
	}
	d = evaluate(t, p, d.State, sensorInput(p, testAt.Add(31*time.Second), sample(p, "zero-2", 31, 0)))
	if d.Transition == nil || d.Transition.Kind != TransitionRecover || d.State.Open {
		t.Fatal("distinct fresh zero samples failed held recovery")
	}
}

func goodRun(p Policy, id string, seconds int) RunEvidence {
	return RunEvidence{RunID: domain.RunID(id), ClusterID: p.ClusterID, SourceID: p.SourceID, Binding: p.Binding, CompletedAt: testAt.Add(time.Duration(seconds) * time.Second), Status: domain.ResultSucceeded, CoverageComplete: true, Count: 1, FieldState: "SUPPORTED"}
}

func TestClockSilenceWithoutNewSamplesAndExactRunRecovery(t *testing.T) {
	p := telemetryPolicy()
	d := evaluate(t, p, State{}, Input{At: testAt.Add(29 * time.Second), AuthorityValid: true})
	if d.Transition != nil || d.State.LastGap != ReasonStartupGrace {
		t.Fatal("startup grace not respected")
	}
	d = evaluate(t, p, d.State, Input{At: testAt.Add(30 * time.Second), AuthorityValid: true})
	if d.Transition == nil || d.Transition.Reason != ReasonSourceDeadline || len(d.Transition.Evidence) != 0 {
		t.Fatal("silent enrolled source failed deadline or manufactured observations")
	}
	heartbeat := goodRun(p, "unrelated-heartbeat", 31)
	heartbeat.Binding.Operation = domain.OperationPrometheusSourceHealth
	empty := goodRun(p, "empty", 32)
	empty.Count = 0
	d = evaluate(t, p, d.State, Input{At: testAt.Add(32 * time.Second), AuthorityValid: true, Runs: []RunEvidence{heartbeat, empty}})
	if d.Transition != nil || !d.State.Open || !d.State.LastRelevantSuccessAt.IsZero() {
		t.Fatal("heartbeat/empty GPU result falsely cleared source loss")
	}
	first := goodRun(p, "recovery-1", 40)
	d = evaluate(t, p, d.State, Input{At: first.CompletedAt, AuthorityValid: true, Runs: []RunEvidence{first}})
	d = evaluate(t, p, d.State, Input{At: testAt.Add(50 * time.Second), AuthorityValid: true, Runs: []RunEvidence{first}})
	if d.Transition != nil || d.State.RecoveryCount != 1 {
		t.Fatal("same successful run counted twice")
	}
	second := goodRun(p, "recovery-2", 70)
	d = evaluate(t, p, d.State, Input{At: second.CompletedAt, AuthorityValid: true, Runs: []RunEvidence{second}})
	if d.Transition == nil || d.State.Open {
		t.Fatal("distinct exact runs failed recovery")
	}
	d = evaluate(t, p, d.State, Input{At: testAt.Add(129 * time.Second), AuthorityValid: true})
	if d.Transition != nil {
		t.Fatal("source expired before freshness deadline")
	}
	d = evaluate(t, p, d.State, Input{At: testAt.Add(130 * time.Second), AuthorityValid: true})
	if d.Transition == nil || d.State.Occurrence != 2 {
		t.Fatal("source silence after recovery failed recurrence")
	}
}

func TestRequiredRunFailureNoDataAndSameTimeConflict(t *testing.T) {
	p := telemetryPolicy()
	for _, status := range []domain.ResultStatus{domain.ResultFailed, domain.ResultNoData} {
		run := goodRun(p, "failed", 1)
		run.Status, run.Count = status, 0
		d := evaluate(t, p, State{}, Input{At: run.CompletedAt, AuthorityValid: true, Runs: []RunEvidence{run}})
		if d.Transition == nil || len(d.Transition.Evidence) != 1 || d.Transition.Evidence[0].ObservationID != "" {
			t.Fatal("required run failure lost actual run evidence")
		}
	}
	a, b := goodRun(p, "a", 1), goodRun(p, "b", 1)
	b.Status, b.Count = domain.ResultFailed, 0
	for _, runs := range [][]RunEvidence{{a, b}, {b, a}} {
		d := evaluate(t, p, State{}, Input{At: testAt.Add(time.Second), AuthorityValid: true, Runs: runs})
		if d.Transition != nil || !d.State.LastRelevantSuccessAt.IsZero() || d.State.LastGap != ReasonConflict {
			t.Fatal("same-time conflicting runs selected arbitrary source health")
		}
	}
}

func TestTelemetrySameInstantConflictIgnoresTimestampRepresentation(t *testing.T) {
	p := telemetryPolicy()
	p.RecoverCount, p.RecoverMinDurationSeconds = 1, 0
	opened := evaluate(t, p, State{}, Input{At: testAt.Add(30 * time.Second), AuthorityValid: true}).State
	for _, alreadyOpen := range []bool{false, true} {
		prior, seconds := State{}, 1
		if alreadyOpen {
			prior, seconds = opened, 40
		}
		for _, failedID := range []string{"a", "z"} {
			failed, success := goodRun(p, failedID, seconds), goodRun(p, "m", seconds)
			failed.Status, failed.Count = domain.ResultFailed, 0
			success.CompletedAt = success.CompletedAt.In(time.FixedZone("same-instant", 19800))
			for _, runs := range [][]RunEvidence{{failed, success}, {success, failed}} {
				d := evaluate(t, p, prior, Input{At: testAt.Add(time.Duration(seconds) * time.Second), AuthorityValid: true, Runs: runs})
				wantGap := ReasonConflict
				if alreadyOpen {
					// Existing source silence remains independently established.
					wantGap = ReasonSourceDeadline
				}
				if d.Transition != nil || d.State.Open != alreadyOpen || !d.State.LastRelevantSuccessAt.IsZero() || d.State.LastGap != wantGap {
					t.Fatalf("equal instant chose health from timezone/ID order: %+v", d)
				}
			}
		}
	}
}

func TestEvidenceAtExactFreshnessExpiryCannotRecoverAndReopen(t *testing.T) {
	p := telemetryPolicy()
	p.RecoverCount, p.RecoverMinDurationSeconds = 1, 0
	opened := evaluate(t, p, State{}, Input{At: testAt.Add(30 * time.Second), AuthorityValid: true}).State
	run := goodRun(p, "at-expiry", 40)
	d := evaluate(t, p, opened, Input{At: testAt.Add(100 * time.Second), AuthorityValid: true, Runs: []RunEvidence{run}})
	if d.Transition != nil || !d.State.Open || !d.State.LastRelevantSuccessAt.IsZero() {
		t.Fatal("run at its exact expiry recovered before reopening on next tick")
	}
	sensor := thermalPolicy()
	sensor.ConfirmCount, sensor.ConfirmMinDurationSeconds = 1, 0
	d = evaluate(t, sensor, State{}, sensorInput(sensor, testAt.Add(300*time.Second), sample(sensor, "sensor-at-expiry", 0, 90)))
	if d.Transition != nil || d.State.LastGap != ReasonStale {
		t.Fatal("sensor freshness boundary differs from the declared exclusive expiry")
	}
}

func TestLatestTelemetryAttemptBlocksOlderSuccessfulRecovery(t *testing.T) {
	p := telemetryPolicy()
	p.RecoverCount, p.RecoverMinDurationSeconds = 1, 0
	opened := evaluate(t, p, State{}, Input{At: testAt.Add(30 * time.Second), AuthorityValid: true}).State
	for _, status := range []domain.ResultStatus{domain.ResultFailed, domain.ResultNoData, domain.ResultPartial} {
		old := goodRun(p, "old-success", 40)
		latest := goodRun(p, "newer-gap", 50)
		latest.Status, latest.CoverageComplete, latest.Count = status, false, 0
		for _, runs := range [][]RunEvidence{{old, latest}, {latest, old}} {
			d := evaluate(t, p, opened, Input{At: testAt.Add(50 * time.Second), AuthorityValid: true, Runs: runs})
			if d.Transition != nil || !d.State.Open || d.State.RecoveryCount != 0 {
				t.Fatalf("known newer required-source gap falsely recovered: %+v", d)
			}
		}
	}
	badPolicy := p
	badPolicy.ConfirmMinDurationSeconds = 1
	if ValidatePolicy(badPolicy) == nil {
		t.Fatal("telemetry accepted an unused advertised confirmation hold")
	}
}

func TestReviewedCounterBaselineCannotCrossResetOrDecrease(t *testing.T) {
	p := counterPolicy()
	for _, reset := range []struct {
		value    float64
		explicit bool
	}{
		{0, true}, {0, false}, {4, false}, {5, true},
	} {
		d := evaluate(t, p, State{}, sensorInput(p, testAt, sample(p, "history", 0, 5)))
		review := RecoveryDisposition{ID: "review", PolicyID: p.ID, EnrollmentRevision: 1, Occurrence: 1, Actor: "operator", EvidenceID: "proof", ReviewedAt: testAt.Add(time.Second)}
		d = evaluate(t, p, d.State, Input{At: review.ReviewedAt, RecoveryDisposition: &review})
		s := sample(p, "reset", 10, reset.value)
		s.Observation.Semantics = &domain.MetricSemantics{Kind: "counter", ResetObserved: reset.explicit}
		d = evaluate(t, p, d.State, sensorInput(p, testAt.Add(10*time.Second), s))
		if d.State.ReviewedCounterValue != nil {
			t.Fatal("unknown counter epoch retained old reviewed baseline")
		}
		if !d.State.Open {
			d = evaluate(t, p, d.State, sensorInput(p, testAt.Add(20*time.Second), sample(p, "same-numeric-new-epoch", 20, 5)))
		}
		if !d.State.Open || d.State.Occurrence != 2 || d.Transition == nil || d.Transition.Reason != ReasonHistoricalCounter {
			t.Fatalf("new unknown epoch reused old numeric disposition: %+v", d)
		}
	}
}

func TestPendingEvidenceCapSurvivesRestartWithActualCounts(t *testing.T) {
	p := thermalPolicy()
	p.ConfirmMinDurationSeconds, p.MaxSampleGapSeconds = 120, 2
	var first []Sample
	for i := 0; i <= 90; i++ {
		first = append(first, sample(p, fmt.Sprintf("sample-%03d", i), i, 90))
	}
	d := evaluate(t, p, State{}, sensorInput(p, testAt.Add(90*time.Second), first...))
	if d.Transition != nil || d.State.PendingCount != 91 || len(d.State.Pending) != 32 || d.State.PendingOmittedEvidence != 59 {
		t.Fatal("bounded pending state lost actual sample count or omitted coverage")
	}
	encoded, _ := json.Marshal(d.State)
	var restored State
	if err := json.Unmarshal(encoded, &restored); err != nil {
		t.Fatal(err)
	}
	var last []Sample
	for i := 91; i <= 120; i++ {
		last = append(last, sample(p, fmt.Sprintf("sample-%03d", i), i, 90))
	}
	d = evaluate(t, p, restored, sensorInput(p, testAt.Add(120*time.Second), last...))
	if d.Transition == nil || d.Transition.QualifyingSampleCount != 121 || d.Transition.OmittedEvidenceCount != 89 || len(d.Transition.Evidence) != 32 {
		t.Fatal("restart manufactured confirmations or forgot retained first/last hold")
	}
}

func TestKnownRequiredFailureOpensDespiteInvalidFutureContact(t *testing.T) {
	p := telemetryPolicy()
	for _, status := range []domain.ResultStatus{domain.ResultFailed, domain.ResultNoData} {
		known := goodRun(p, "known-fault", 10)
		known.Status, known.Count = status, 0
		future := goodRun(p, "impossible-future-contact", 100)
		d := evaluate(t, p, State{}, Input{At: testAt.Add(10 * time.Second), AuthorityValid: true, Runs: []RunEvidence{known, future}})
		if d.Transition == nil || d.Transition.Kind != TransitionOpen || d.Transition.Reason == ReasonSourceDeadline || d.Transition.Evidence[0].RunID != known.RunID || !d.State.LastRelevantSuccessAt.IsZero() {
			t.Fatal("invalid future contact suppressed independent known required failure")
		}
	}
}

func TestPhysicalAttemptCursorAdvancesThroughGapsAndPreservesRemainingSamples(t *testing.T) {
	p := thermalPolicy()
	p.ConfirmCount, p.ConfirmMinDurationSeconds = 1, 0
	p.RecoverCount, p.RecoverMinDurationSeconds = 1, 0
	var state State
	for i := 0; i < 300; i++ {
		run := goodRun(p, fmt.Sprintf("failed-%d", i), i)
		run.Status, run.FieldState = domain.ResultFailed, "UNKNOWN"
		d := evaluate(t, p, state, Input{At: run.CompletedAt, AuthorityValid: true, Runs: []RunEvidence{run}})
		if d.State.RunCursor == nil || d.State.RunCursor.RunID != run.RunID || d.State.SourceCursor != nil || d.State.LastGap != ReasonCollectionFailed {
			t.Fatal("failed physical attempts accumulated without durable cursor progress")
		}
		state = d.State
	}
	input := sensorInput(p, testAt.Add(320*time.Second), sample(p, "open", 310, 90), sample(p, "recover", 320, 60))
	d := evaluate(t, p, state, input)
	if d.Transition == nil || d.Transition.Kind != TransitionOpen || d.State.RunCursor.CompletedAt.After(testAt.Add(320*time.Second)) {
		t.Fatal("transition skipped unconsumed recovery evidence")
	}
	// The loader's inclusive run-time cursor must replay the boundary attempt.
	var replay Input
	replay.At, replay.AuthorityValid = input.At, true
	for _, run := range input.Runs {
		if !run.CompletedAt.Before(d.State.RunCursor.CompletedAt) {
			replay.Runs = append(replay.Runs, run)
		}
	}
	for _, s := range input.Samples {
		if !s.CollectionCompletedAt.Before(d.State.RunCursor.CompletedAt) {
			replay.Samples = append(replay.Samples, s)
		}
	}
	d = evaluate(t, p, d.State, replay)
	if d.Transition == nil || d.Transition.Kind != TransitionRecover || d.State.RunCursor.RunID != "run-recover" {
		t.Fatal("physical progress cursor lost remaining immutable recovery sample")
	}
}

func TestKnownRemapFailureAliasRetainsOriginalImmutableMetric(t *testing.T) {
	p := counterPolicy()
	p.Rule, p.Metric, p.Unit = RuleRemapFailure, "DCGM_FI_DEV_ROW_REMAP_FAILURE", "boolean"
	observed := sample(p, "known-alias", 0, 1)
	observed.Observation.Metric = "DCGM_FI_DEV_ROW_REMAP_FAILED"
	input := sensorInput(p, testAt, observed)
	d := evaluate(t, p, State{}, input)
	if d.Transition == nil || d.Transition.Reason != ReasonRemapFailure || input.Samples[0].Observation.Metric != "DCGM_FI_DEV_ROW_REMAP_FAILED" {
		t.Fatal("known alias rejected or original observation rewritten")
	}
	aliasPolicy := p
	aliasPolicy.ID, aliasPolicy.Metric = "duplicate-alias-policy", "DCGM_FI_DEV_ROW_REMAP_FAILED"
	if ValidatePolicy(aliasPolicy) == nil {
		t.Fatal("read alias could enroll a duplicate rule for the same physical fault")
	}
	rule, _ := LookupRule(RuleRemapFailure, 1)
	if !reflect.DeepEqual(rule.Metrics, []string{"DCGM_FI_DEV_ROW_REMAP_FAILURE"}) || !reflect.DeepEqual(rule.ReadAliases, []string{"DCGM_FI_DEV_ROW_REMAP_FAILED"}) {
		t.Fatal("registry advertised read alias as independent policy metric")
	}
}

func TestSensorTimestampOrderingStrictAndVerifiedLegacyTolerance(t *testing.T) {
	p := thermalPolicy()
	p.ConfirmCount, p.ConfirmMinDurationSeconds = 1, 0
	for _, test := range []struct {
		name          string
		observedSkew  time.Duration
		collectedSkew time.Duration
		legacy        bool
		provenance    bool
		valid         bool
	}{
		{"strict_equal", 0, 0, false, false, true},
		{"strict_source_after_collection", time.Millisecond, 0, false, true, false},
		{"collection_after_run", 0, time.Millisecond, false, true, false},
		{"collection_before_run", 0, -time.Millisecond, true, true, false},
		{"legacy_exact_one_second", time.Second, 0, true, true, true},
		{"legacy_beyond_one_second", time.Second + time.Nanosecond, 0, true, true, false},
		{"unverified_legacy_reference", time.Second, 0, true, false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := sample(p, "sensor", 0, 90)
			s.Observation.ObservedAt = s.Observation.ObservedAt.Add(test.observedSkew)
			s.Observation.CollectedAt = s.Observation.CollectedAt.Add(test.collectedSkew)
			if test.provenance {
				s.Observation.SourceReference = domain.DCGMSourceReference(domain.QueryGPUTemperature)
			}
			input := sensorInput(p, testAt.Add(2*time.Second), s)
			input.Runs[0].LegacySourceClockTolerance = test.legacy
			d := evaluate(t, p, State{}, input)
			if (d.Transition != nil) != test.valid {
				t.Fatalf("timestamp contract admitted malformed or rejected reviewed legacy boundary: %+v", d)
			}
		})
	}
}

func TestUnrelatedFutureEvidenceCannotSuppressIndependentCounterFault(t *testing.T) {
	p := counterPolicy()
	proof := sample(p, "known-dbe", 0, 5)
	for _, foreignSource := range []bool{false, true} {
		foreign := sample(p, "unrelated-future", 0, 5)
		foreign.Observation.CollectedAt, foreign.CollectionCompletedAt = testAt.Add(100*time.Second), testAt.Add(100*time.Second)
		input := sensorInput(p, testAt, proof, foreign)
		if foreignSource {
			input.Samples[1].Observation.SourceID, input.Runs[1].SourceID = "foreign", "foreign"
		} else {
			input.Samples[1].Observation.Metric = "DCGM_FI_DEV_POWER_VIOLATION"
			input.Runs[1].Binding.Operation = domain.OperationPrometheusGPUPower
		}
		d := evaluate(t, p, State{}, input)
		if d.Transition == nil || d.Transition.Reason != ReasonHistoricalCounter || len(d.Transition.Evidence) != 1 || d.Transition.Evidence[0].ObservationID != proof.Observation.ID {
			t.Fatal("unrelated future field/source suppressed independently admitted counter proof")
		}
	}
}

func TestStatePersistenceAndPolicyBoundsFailClosed(t *testing.T) {
	p := thermalPolicy()
	d := evaluate(t, p, State{}, sensorInput(p, testAt, sample(p, "first", 0, 90)))
	encoded, err := json.Marshal(d.State)
	if err != nil {
		t.Fatal(err)
	}
	var restored State
	if err = json.Unmarshal(encoded, &restored); err != nil || !reflect.DeepEqual(d.State, restored) {
		t.Fatal("durable state lost evidence cursor/counts")
	}
	if _, err = Evaluate(p, restored, Input{At: testAt.Add(-time.Second), AuthorityValid: true}); err == nil {
		t.Fatal("database clock regression accepted")
	}
	for _, edit := range []func(*Policy){
		func(p *Policy) { p.RuleVersion = 2 },
		func(p *Policy) { p.AllowEmptySuccess = true },
		func(p *Policy) { p.ConfirmMinDurationSeconds = p.ConfirmWindowSeconds + 1 },
		func(p *Policy) { p.MaxSampleGapSeconds = 0 },
		func(p *Policy) { p.Binding.Scope.Nodes = []domain.StableNodeID{"z", "node"} },
		func(p *Policy) { p.Binding.Operation = domain.OperationPrometheusGPUPower },
	} {
		bad := p
		edit(&bad)
		if ValidatePolicy(bad) == nil {
			t.Fatal("invalid enrollment policy accepted")
		}
	}
	request := p
	request.Revision, request.EnrolledAt = 0, time.Time{}
	if ValidateEnrollmentRequest(request) != nil || ValidateEnrollmentRequest(p) == nil {
		t.Fatal("server-owned enrollment revision/time not fenced")
	}
}
