package monitoring

import (
	"fmt"
	"math"
	"time"
)

// ApplyReviewedDisposition is a reviewed closure, not a measured recovery.
// Store invokes it under exact episode/control fencing and audited actor proof;
// current source authority may be unavailable or the policy may be disabled.
func ApplyReviewedDisposition(policy Policy, state State, disposition RecoveryDisposition, at time.Time) (Decision, error) {
	if err := ValidatePolicy(policy); err != nil {
		return Decision{}, err
	}
	if policy.Rule != RuleECCHistorical || state.Version != StateVersion || state.PolicyID != policy.ID || state.EnrollmentRevision != policy.Revision || state.Occurrence < 1 || at.IsZero() || state.LastEvaluatedAt.After(at) ||
		!validID(disposition.ID) || !validID(disposition.Actor) || !validID(disposition.EvidenceID) || disposition.PolicyID != policy.ID || disposition.EnrollmentRevision != policy.Revision || disposition.Occurrence != state.Occurrence ||
		disposition.ReviewedAt.IsZero() || disposition.ReviewedAt.After(at) || disposition.ReviewedAt.Before(state.OpenedAt) {
		return Decision{}, fmt.Errorf("invalid reviewed counter disposition")
	}
	if !state.Open {
		if state.DispositionID == disposition.ID {
			return Decision{State: state}, nil
		}
		return Decision{}, fmt.Errorf("reviewed disposition requires exact open occurrence")
	}
	if state.LastHistoricalValue == nil || math.IsNaN(*state.LastHistoricalValue) || math.IsInf(*state.LastHistoricalValue, 0) || *state.LastHistoricalValue < 1 || math.Trunc(*state.LastHistoricalValue) != *state.LastHistoricalValue {
		return Decision{}, fmt.Errorf("reviewed disposition requires cached historical attention value")
	}
	value := *state.LastHistoricalValue
	state.ReviewedCounterValue, state.ReviewedAt, state.DispositionID = &value, disposition.ReviewedAt, disposition.ID
	state.LastEvaluatedAt = at
	decision := recoverState(state, at, ReasonReviewedDisposition, nil, 0, policy.Severity)
	decision.State.LastGap = ReasonCounterReset
	decision.Transition.DispositionID = disposition.ID
	normalizeWindows(&decision.State)
	return decision, nil
}
