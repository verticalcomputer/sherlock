package monitoring

import (
	"fmt"
	"math"
	"reflect"
	"slices"
	"sort"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

const MaxInputEvidence = 256
const MaxRetainedEvidence = 32

// Evaluate is deterministic and emits at most one transition. On transition it
// stops at that evidence cursor; replay supplies remaining evidence next pass.
// It never reads a clock, mutates input slices, or substitutes source heartbeat.
func Evaluate(policy Policy, prior State, input Input) (decision Decision, err error) {
	defer func() {
		if err == nil {
			normalizeWindows(&decision.State)
		}
	}()
	if err := ValidatePolicy(policy); err != nil {
		return Decision{}, err
	}
	if input.At.IsZero() || len(input.Samples) > MaxInputEvidence || len(input.Runs) > MaxInputEvidence {
		return Decision{}, fmt.Errorf("invalid monitoring time or evidence bound")
	}
	state := prior
	if state.Version == 0 {
		if !reflect.DeepEqual(state, State{}) {
			return Decision{}, fmt.Errorf("unversioned monitoring state is not empty")
		}
		state = State{Version: StateVersion, PolicyID: policy.ID, EnrollmentRevision: policy.Revision}
	}
	if state.Version != StateVersion || state.PolicyID != policy.ID || state.EnrollmentRevision != policy.Revision || state.Occurrence < 0 || state.Occurrence == math.MaxInt64 ||
		state.LastEvaluatedAt.After(input.At) || state.LastRelevantSuccessAt.After(input.At) || len(state.Pending) > MaxRetainedEvidence || len(state.RecoveryPending) > MaxRetainedEvidence ||
		state.PendingCount < int64(len(state.Pending)) || state.RecoveryCount < int64(len(state.RecoveryPending)) || state.PendingCount > 1_000_000_000 || state.RecoveryCount > 1_000_000_000 ||
		state.Open && len(state.Pending) > 0 || !state.Open && len(state.RecoveryPending) > 0 ||
		state.Open && (state.Occurrence == 0 || state.OpenedAt.IsZero() || state.FaultAt.IsZero()) {
		return Decision{}, fmt.Errorf("invalid monitoring state or clock regression")
	}
	state.Pending = append([]EvidenceRef(nil), state.Pending...)
	state.RecoveryPending = append([]EvidenceRef(nil), state.RecoveryPending...)
	state.LastEvaluatedAt = input.At
	if policy.Rule == RuleECCHistorical && state.Open && input.RecoveryDisposition != nil {
		return ApplyReviewedDisposition(policy, state, *input.RecoveryDisposition, input.At)
	}
	if !input.AuthorityValid {
		state.LastGap, state.Pending, state.RecoveryPending = ReasonAuthority, nil, nil
		return Decision{State: state}, nil
	}
	if policy.EnrolledAt.After(input.At) {
		state.LastGap = ReasonFuture
		return Decision{State: state}, nil
	}
	runs, conflictingRun := indexedRuns(input.Runs)
	if conflictingRun {
		state.LastGap, state.Pending, state.RecoveryPending = ReasonConflict, nil, nil
		return Decision{State: state}, nil
	}
	if policy.Rule == RuleTelemetryLoss {
		return evaluateTelemetry(policy, state, input, runs), nil
	}
	return evaluateSensors(policy, state, input, runs), nil
}

func normalizeWindows(state *State) {
	if len(state.Pending) == 0 {
		state.PendingCount = 0
	}
	if len(state.RecoveryPending) == 0 {
		state.RecoveryCount = 0
	}
	state.PendingOmittedEvidence = state.PendingCount - int64(len(state.Pending))
	state.RecoveryOmittedEvidence = state.RecoveryCount - int64(len(state.RecoveryPending))
}

func indexedRuns(input []RunEvidence) (map[domain.RunID]RunEvidence, bool) {
	runs := map[domain.RunID]RunEvidence{}
	for _, run := range input {
		if prior, found := runs[run.RunID]; found && !reflect.DeepEqual(prior, run) {
			return nil, true
		}
		runs[run.RunID] = run
	}
	return runs, false
}

func sameBinding(a, b Binding) bool {
	return a.Operation == b.Operation && a.ScheduleRevision == b.ScheduleRevision && a.InventoryRevisionID == b.InventoryRevisionID && slices.Equal(a.Scope.Nodes, b.Scope.Nodes)
}

func exactRun(policy Policy, run RunEvidence) bool {
	return validID(string(run.RunID)) && run.ClusterID == policy.ClusterID && run.SourceID == policy.SourceID && sameBinding(run.Binding, policy.Binding) && run.Count >= 0 && run.Count <= 10000
}

func runRef(run RunEvidence) EvidenceRef {
	return EvidenceRef{RunID: run.RunID, CompletedAt: run.CompletedAt}
}

func sampleRef(sample Sample) EvidenceRef {
	return EvidenceRef{ObservationID: sample.Observation.ID, RunID: sample.RunID, ObservedAt: sample.Observation.ObservedAt, CollectedAt: sample.Observation.CollectedAt, CompletedAt: sample.CollectionCompletedAt}
}

func refTime(ref EvidenceRef, source bool) time.Time {
	if source {
		return ref.ObservedAt
	}
	return ref.CompletedAt
}

func expireWindow(refs []EvidenceRef, now time.Time, seconds int64, source bool) []EvidenceRef {
	if len(refs) > 0 && now.Sub(refTime(refs[0], source)) > time.Duration(seconds)*time.Second {
		return nil
	}
	return refs
}

func extendWindow(refs []EvidenceRef, count int64, ref EvidenceRef, window, gap int64, source bool) ([]EvidenceRef, int64) {
	if len(refs) == 0 || refTime(ref, source).Sub(refTime(refs[0], source)) > time.Duration(window)*time.Second ||
		refTime(ref, source).Sub(refTime(refs[len(refs)-1], source)) > time.Duration(gap)*time.Second {
		refs, count = nil, 0
	}
	refs, count = append(refs, ref), count+1
	if len(refs) > MaxRetainedEvidence {
		refs = append([]EvidenceRef{refs[0]}, refs[len(refs)-(MaxRetainedEvidence-1):]...)
	}
	return refs, count
}

func windowReady(refs []EvidenceRef, count int64, minimumCount int, minDuration int64, source bool) bool {
	return len(refs) > 0 && count >= int64(minimumCount) && refTime(refs[len(refs)-1], source).Sub(refTime(refs[0], source)) >= time.Duration(minDuration)*time.Second
}

func openState(state State, at, faultAt time.Time, reason Reason, refs []EvidenceRef, count int64, severity domain.HealthSeverity) Decision {
	state.Open, state.Occurrence = true, state.Occurrence+1
	state.OpenedAt, state.FaultAt, state.LastGap = at, faultAt, ""
	state.Pending, state.RecoveryPending = nil, nil
	if len(refs) > 0 {
		first, last := refs[0], refs[len(refs)-1]
		state.FirstQualifying, state.LastQualifying = &first, &last
	} else {
		state.FirstQualifying, state.LastQualifying = nil, nil
	}
	return Decision{State: state, Transition: &Transition{Kind: TransitionOpen, Occurrence: state.Occurrence, At: at, Reason: reason, Severity: severity, Evidence: append([]EvidenceRef(nil), refs...), QualifyingSampleCount: count, OmittedEvidenceCount: count - int64(len(refs))}}
}

func recoverState(state State, at time.Time, reason Reason, refs []EvidenceRef, count int64, severity domain.HealthSeverity) Decision {
	state.Open, state.LastGap = false, ""
	state.Pending, state.RecoveryPending = nil, nil
	return Decision{State: state, Transition: &Transition{Kind: TransitionRecover, Occurrence: state.Occurrence, At: at, Reason: reason, Severity: severity, Evidence: append([]EvidenceRef(nil), refs...), QualifyingSampleCount: count, OmittedEvidenceCount: count - int64(len(refs))}}
}

func evaluateTelemetry(policy Policy, state State, input Input, indexed map[domain.RunID]RunEvidence) Decision {
	state.RecoveryPending = expireWindow(state.RecoveryPending, input.At, policy.RecoverWindowSeconds, false)
	runs := make([]RunEvidence, 0, len(indexed))
	for _, run := range indexed {
		if exactRun(policy, run) {
			runs = append(runs, run)
		}
	}
	sort.Slice(runs, func(i, j int) bool {
		if !runs[i].CompletedAt.Equal(runs[j].CompletedAt) {
			return runs[i].CompletedAt.Before(runs[j].CompletedAt)
		}
		return runs[i].RunID < runs[j].RunID
	})
	conflictedTimes := map[time.Time]bool{}
	// Equal instants may carry different locations or monotonic clock metadata.
	// Normalize map keys so every member of a conflicting tie remains uncertain.
	for i := 1; i < len(runs); i++ {
		a, b := runs[i-1], runs[i]
		if a.CompletedAt.Equal(b.CompletedAt) && (a.Status != b.Status || a.Count != b.Count || a.CoverageComplete != b.CoverageComplete || a.FieldState != b.FieldState) {
			conflictedTimes[a.CompletedAt.Round(0).UTC()] = true
		}
	}
	var barrier, latestKnown *RunEvidence
	for i := range runs {
		run := &runs[i]
		if !run.CompletedAt.IsZero() && !run.CompletedAt.After(input.At) {
			latestKnown = run
		}
		if conflictedTimes[run.CompletedAt.Round(0).UTC()] || run.CompletedAt.IsZero() || run.CompletedAt.After(input.At) || run.Status != domain.ResultSucceeded || !run.CoverageComplete || run.Count < 1 {
			barrier = run
		}
	}
	if barrier != nil && len(state.RecoveryPending) > 0 && !state.RecoveryPending[0].CompletedAt.After(barrier.CompletedAt) {
		state.RecoveryPending = nil
	}
	state.LastGap = ""
	for _, run := range runs {
		if conflictedTimes[run.CompletedAt.Round(0).UTC()] {
			state.LastGap, state.RecoveryPending = ReasonConflict, nil
			continue
		}
		if run.CompletedAt.IsZero() || run.CompletedAt.After(input.At) {
			state.LastGap = ReasonFuture
			continue
		}
		if run.CompletedAt.Before(policy.EnrolledAt) {
			continue
		}
		if state.RunCursor != nil {
			if run.RunID == state.RunCursor.RunID && !run.CompletedAt.Equal(state.RunCursor.CompletedAt) {
				state.LastGap, state.RecoveryPending = ReasonConflict, nil
				continue
			}
			if !run.CompletedAt.After(state.RunCursor.CompletedAt) {
				continue
			}
		}
		ref := runRef(run)
		state.RunCursor = &ref
		fresh := input.At.Sub(run.CompletedAt) < time.Duration(policy.FreshForSeconds)*time.Second
		if !fresh {
			state.LastGap, state.RecoveryPending = ReasonStale, nil
			continue
		}
		if run.Status == domain.ResultFailed || run.Status == domain.ResultNoData {
			reason := ReasonCollectionFailed
			if run.Status == domain.ResultNoData {
				reason = ReasonCollectionNoData
			}
			state.LastGap, state.RecoveryPending = reason, nil
			state.LastQualifying = &ref
			if !state.Open && (latestKnown == nil || !latestKnown.CompletedAt.After(run.CompletedAt)) {
				return openState(state, input.At, run.CompletedAt, reason, []EvidenceRef{ref}, 1, policy.Severity)
			}
			continue
		}
		if run.Status != domain.ResultSucceeded || !run.CoverageComplete || run.Count < 1 {
			state.LastGap, state.RecoveryPending = ReasonMissing, nil
			continue
		}
		state.LastRelevantSuccessAt = run.CompletedAt
		state.LastGap = ""
		if state.Open && run.CompletedAt.After(state.FaultAt) && (barrier == nil || run.CompletedAt.After(barrier.CompletedAt)) {
			state.RecoveryPending, state.RecoveryCount = extendWindow(state.RecoveryPending, state.RecoveryCount, ref, policy.RecoverWindowSeconds, policy.MaxSampleGapSeconds, false)
		}
	}
	if state.Open && windowReady(state.RecoveryPending, state.RecoveryCount, policy.RecoverCount, policy.RecoverMinDurationSeconds, false) &&
		(barrier == nil || state.LastRelevantSuccessAt.After(barrier.CompletedAt)) && input.At.Sub(state.LastRelevantSuccessAt) < time.Duration(policy.FreshForSeconds)*time.Second {
		return recoverState(state, input.At, ReasonFreshRecovery, state.RecoveryPending, state.RecoveryCount, policy.Severity)
	}
	deadline := policy.EnrolledAt.Add(time.Duration(policy.StartupGraceSeconds) * time.Second)
	if !state.LastRelevantSuccessAt.IsZero() {
		deadline = state.LastRelevantSuccessAt.Add(time.Duration(policy.FreshForSeconds) * time.Second)
	}
	if !input.At.Before(deadline) {
		state.LastGap, state.RecoveryPending = ReasonSourceDeadline, nil
		if !state.Open {
			return openState(state, input.At, deadline, ReasonSourceDeadline, nil, 0, policy.Severity)
		}
	} else if state.LastRelevantSuccessAt.IsZero() && state.LastGap == "" {
		state.LastGap = ReasonStartupGrace
	}
	return Decision{State: state}
}

func sampleGap(policy Policy, sample Sample, input Input, runs map[domain.RunID]RunEvidence) Reason {
	o := sample.Observation
	if !validID(string(o.ID)) || o.ClusterID != policy.ClusterID || o.SourceID != policy.SourceID || !metricMatchesPolicy(policy, o.Metric) {
		return ReasonInvalid
	}
	identity, ok := domain.ResolveGPUObservationIdentity(policy.ClusterID, policy.SourceID, o)
	if !ok || !identity.Canonical || identity.EntityKey != policy.EntityKey {
		return ReasonInvalid
	}
	run, found := runs[sample.RunID]
	if !found || !exactRun(policy, run) || !run.CompletedAt.Equal(sample.CollectionCompletedAt) || run.Status != sample.Status || run.Count < 1 {
		return ReasonInvalid
	}
	if !sample.Supported {
		return ReasonUnsupported
	}
	if run.FieldState != "SUPPORTED" {
		return ReasonMissing
	}
	if run.Status != domain.ResultSucceeded && run.Status != domain.ResultPartial {
		return ReasonMissing
	}
	if o.ObservedAt.IsZero() || o.CollectedAt.IsZero() || run.CompletedAt.IsZero() || o.ObservedAt.After(input.At) || o.CollectedAt.After(input.At) || run.CompletedAt.After(input.At) {
		return ReasonFuture
	}
	tolerance := time.Duration(0)
	operation, _ := domain.ReviewedCollectionOperation(policy.Binding.Operation)
	if run.LegacySourceClockTolerance && o.SourceReference == domain.DCGMSourceReference(operation.Query) {
		tolerance = time.Second
	}
	if !o.CollectedAt.Equal(run.CompletedAt) || o.ObservedAt.After(o.CollectedAt.Add(tolerance)) {
		return ReasonInvalid
	}
	if !domain.ValidGPUHealthObservation(o) {
		return ReasonInvalid
	}
	if input.At.Sub(o.ObservedAt) >= time.Duration(policy.FreshForSeconds)*time.Second {
		return ReasonStale
	}
	return ""
}

func metricMatchesPolicy(policy Policy, metric string) bool {
	if metric == policy.Metric {
		return true
	}
	return policy.Rule == RuleRemapFailure && policy.Metric == "DCGM_FI_DEV_ROW_REMAP_FAILURE" && metric == "DCGM_FI_DEV_ROW_REMAP_FAILED"
}

func evaluateSensors(policy Policy, state State, input Input, runs map[domain.RunID]RunEvidence) (decision Decision) {
	var remaining []Sample
	defer func() {
		advancePhysicalRunCursor(&decision.State, policy, runs, input.At, remaining)
	}()
	state.Pending = expireWindow(state.Pending, input.At, policy.ConfirmWindowSeconds, true)
	state.RecoveryPending = expireWindow(state.RecoveryPending, input.At, policy.RecoverWindowSeconds, true)
	barrier, barrierReason, latest := sensorAttemptBarrier(policy, runs, input.At)
	if barrier != nil {
		if len(state.Pending) > 0 && !state.Pending[0].CompletedAt.After(barrier.CompletedAt) {
			state.Pending = nil
		}
		if len(state.RecoveryPending) > 0 && !state.RecoveryPending[0].CompletedAt.After(barrier.CompletedAt) {
			state.RecoveryPending = nil
		}
		if latest == nil || !latest.CompletedAt.After(barrier.CompletedAt) {
			state.LastGap, state.Pending, state.RecoveryPending = barrierReason, nil, nil
			return Decision{State: state}
		}
	}
	samples := make([]Sample, 0, len(input.Samples))
	for _, sample := range input.Samples {
		o := sample.Observation
		if o.ClusterID != policy.ClusterID || o.SourceID != policy.SourceID || !metricMatchesPolicy(policy, o.Metric) {
			continue
		}
		identity, valid := domain.ResolveGPUObservationIdentity(policy.ClusterID, policy.SourceID, o)
		if !valid || !identity.Canonical || identity.EntityKey != policy.EntityKey {
			continue
		}
		if barrier == nil || sample.CollectionCompletedAt.After(barrier.CompletedAt) {
			samples = append(samples, sample)
		}
	}
	remaining = samples
	sort.Slice(samples, func(i, j int) bool {
		if !samples[i].Observation.ObservedAt.Equal(samples[j].Observation.ObservedAt) {
			return samples[i].Observation.ObservedAt.Before(samples[j].Observation.ObservedAt)
		}
		return samples[i].Observation.ID < samples[j].Observation.ID
	})
	seen := map[domain.ObservationID]Sample{}
	for _, sample := range samples {
		if prior, found := seen[sample.Observation.ID]; found && !reflect.DeepEqual(prior, sample) {
			state.LastGap, state.Pending, state.RecoveryPending = ReasonConflict, nil, nil
			return Decision{State: state}
		}
		seen[sample.Observation.ID] = sample
	}
	if len(samples) == 0 {
		// A fetch with no distinct rows is normal. Existing fresh admitted
		// evidence remains authoritative until an actual newer run gap or stale
		// source time establishes missing coverage.
		if state.SourceCursor != nil && input.At.Sub(state.SourceCursor.ObservedAt) < time.Duration(policy.FreshForSeconds)*time.Second &&
			(latest == nil || !latest.CompletedAt.After(state.SourceCursor.CompletedAt)) {
			return Decision{State: state}
		}
		reason := ReasonMissing
		if state.SourceCursor != nil && input.At.Sub(state.SourceCursor.ObservedAt) >= time.Duration(policy.FreshForSeconds)*time.Second {
			reason = ReasonStale
		}
		state.LastGap, state.Pending, state.RecoveryPending = reason, nil, nil
		return Decision{State: state}
	}
	for start := 0; start < len(samples); {
		end := start + 1
		for end < len(samples) && samples[end].Observation.ObservedAt.Equal(samples[start].Observation.ObservedAt) {
			end++
		}
		tied := samples[start:end]
		sample := tied[0]
		gap := sampleGap(policy, sample, input, runs)
		explicit := sample.Observation.Semantics
		for _, other := range tied[1:] {
			otherGap := sampleGap(policy, other, input, runs)
			if gap == "" && otherGap != "" {
				gap = otherGap
			}
			if other.Observation.Value != sample.Observation.Value || explicit != nil && other.Observation.Semantics != nil && *explicit != *other.Observation.Semantics {
				gap = ReasonConflict
			}
			if other.Observation.Semantics != nil {
				explicit = other.Observation.Semantics
			}
		}
		ref := sampleRef(sample)
		start = end
		remaining = samples[start:]
		if state.SourceCursor != nil {
			if ref.ObservationID == state.SourceCursor.ObservationID && !ref.ObservedAt.Equal(state.SourceCursor.ObservedAt) {
				state.LastGap, state.Pending, state.RecoveryPending = ReasonConflict, nil, nil
				continue
			}
			if !ref.ObservedAt.After(state.SourceCursor.ObservedAt) {
				if gap != "" && ref.ObservedAt.Equal(state.SourceCursor.ObservedAt) {
					state.LastGap, state.Pending, state.RecoveryPending = gap, nil, nil
				}
				continue
			}
		}
		if gap != "" {
			state.LastGap, state.Pending, state.RecoveryPending = gap, nil, nil
			// Future and foreign evidence must never move the admitted cursor.
			continue
		}
		state.SourceCursor, state.LastGap = &ref, ""
		bad := sample.Observation.Value >= policy.OpenThreshold
		recovered := sample.Observation.Value < policy.RecoverBelow
		if policy.Rule == RuleRemapFailure {
			recovered = sample.Observation.Value == 0
		}
		if policy.Rule == RuleECCHistorical {
			recovered = false
			if sample.Observation.Semantics != nil && sample.Observation.Semantics.ResetObserved || state.LastHistoricalValue != nil && sample.Observation.Value < *state.LastHistoricalValue {
				state.ReviewedCounterValue = nil
			}
			if bad {
				value := sample.Observation.Value
				state.LastHistoricalValue = &value
				if state.ReviewedCounterValue != nil && value == *state.ReviewedCounterValue {
					bad = false
				}
			}
			if !bad {
				state.LastGap = ReasonCounterReset
			}
		}
		if bad {
			state.LastQualifying = &ref
			state.RecoveryPending = nil
			if !state.Open {
				state.Pending, state.PendingCount = extendWindow(state.Pending, state.PendingCount, ref, policy.ConfirmWindowSeconds, policy.MaxSampleGapSeconds, true)
				if windowReady(state.Pending, state.PendingCount, policy.ConfirmCount, policy.ConfirmMinDurationSeconds, true) {
					reason := ReasonThermalThreshold
					if policy.Rule == RuleECCHistorical {
						reason = ReasonHistoricalCounter
					} else if policy.Rule == RuleRemapFailure {
						reason = ReasonRemapFailure
					}
					return openState(state, input.At, ref.ObservedAt, reason, state.Pending, state.PendingCount, policy.Severity)
				}
			}
		} else {
			state.Pending = nil
			if state.Open && recovered && ref.ObservedAt.After(state.FaultAt) {
				state.RecoveryPending, state.RecoveryCount = extendWindow(state.RecoveryPending, state.RecoveryCount, ref, policy.RecoverWindowSeconds, policy.MaxSampleGapSeconds, true)
				if windowReady(state.RecoveryPending, state.RecoveryCount, policy.RecoverCount, policy.RecoverMinDurationSeconds, true) {
					return recoverState(state, input.At, ReasonFreshRecovery, state.RecoveryPending, state.RecoveryCount, policy.Severity)
				}
			} else {
				state.RecoveryPending = nil
			}
		}
	}
	return Decision{State: state}
}

func advancePhysicalRunCursor(state *State, policy Policy, runs map[domain.RunID]RunEvidence, at time.Time, remaining []Sample) {
	limit := at
	for _, sample := range remaining {
		if !sample.CollectionCompletedAt.IsZero() && sample.CollectionCompletedAt.Before(limit) {
			limit = sample.CollectionCompletedAt
		}
	}
	for _, run := range runs {
		if !exactRun(policy, run) || run.CompletedAt.IsZero() || run.CompletedAt.After(limit) || run.CompletedAt.After(at) {
			continue
		}
		if state.RunCursor == nil || run.CompletedAt.After(state.RunCursor.CompletedAt) || run.CompletedAt.Equal(state.RunCursor.CompletedAt) && run.RunID > state.RunCursor.RunID {
			ref := runRef(run)
			state.RunCursor = &ref
		}
	}
}

// A newer required-operation failure or field-local gap cannot uncover older
// still-fresh readings as recovery. Successful later independent field support
// permits a new sequence, but confirmations cannot bridge the gap.
func sensorAttemptBarrier(policy Policy, runs map[domain.RunID]RunEvidence, at time.Time) (*RunEvidence, Reason, *RunEvidence) {
	var barrier, latest *RunEvidence
	var reason Reason
	for _, run := range runs {
		if !exactRun(policy, run) {
			continue
		}
		if latest == nil || run.CompletedAt.After(latest.CompletedAt) || run.CompletedAt.Equal(latest.CompletedAt) && run.RunID > latest.RunID {
			copy := run
			latest = &copy
		}
		gap := Reason("")
		switch {
		case run.CompletedAt.IsZero() || run.CompletedAt.After(at):
			gap = ReasonFuture
		case run.Status == domain.ResultFailed:
			gap = ReasonCollectionFailed
		case run.Status == domain.ResultNoData:
			gap = ReasonCollectionNoData
		case run.FieldState == "NOT_SUPPORTED":
			gap = ReasonUnsupported
		case run.FieldState != "SUPPORTED" || run.Count < 1 || run.Status != domain.ResultSucceeded && run.Status != domain.ResultPartial:
			gap = ReasonMissing
		}
		if gap != "" && (barrier == nil || run.CompletedAt.After(barrier.CompletedAt) || run.CompletedAt.Equal(barrier.CompletedAt) && run.RunID > barrier.RunID) {
			copy := run
			barrier, reason = &copy, gap
		}
	}
	return barrier, reason, latest
}
