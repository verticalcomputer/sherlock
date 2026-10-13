package domain

import (
	"fmt"
	"slices"
	"strings"
	"time"
)

const DiagnosticEvidenceDefinitionVersion = "diagnostic-execution-evidence-v1"

// MaximumDiagnosticObservationLookback bounds how much history one diagnostic
// may claim to have observed, so a misdeclared binding cannot assert coverage
// of an arbitrary past.
const MaximumDiagnosticObservationLookback = 30 * 24 * time.Hour

// DiagnosticEvidenceSourceKind marks a source row as standing for diagnostic
// executions rather than a polled system. The context loader keys on this kind
// to read the probe's own output instead of the observations table, which a
// diagnostic never writes.
const DiagnosticEvidenceSourceKind = "diagnostic"

// DiagnosticEvidenceSourceID names the synthetic source for one cluster's
// diagnostic executions.
//
// It must be derived from the cluster, not from the pack: source_id is a global
// primary key, so a pack-derived identifier would collide the moment a second
// cluster ran the same reviewed pack, and that cluster's evidence would be
// refused as an attribution conflict. The definition is already carried by the
// envelope's operation and reference, so nothing is lost by naming the source
// per cluster, which is how model-payload evidence names its own.
func DiagnosticEvidenceSourceID(clusterID ClusterID) SourceID {
	return SourceID("diagnostic-" + ChecksumSHA256([]byte(clusterID)).String()[:24])
}

// DiagnosticEvidenceForAttempt projects one completed diagnostic execution
// into an ordinary evidence envelope.
//
// This projection is the whole of M12's evidence story. Citations, coverage
// projection, periodic-sample coalescing, redundancy reduction, the context
// builder, the replay harness, and the admin report all operate on evidence
// envelopes; a parallel diagnostic-result type would require reimplementing
// every one of them. Nothing downstream may need to know that this envelope
// came from a remote execution rather than from a collector.
//
// The observed time range is what the command actually reports on. A probe of
// live state reports as of when it ran, so [started, completed] is the honest
// interval: it is short by construction, and it is what makes the result
// comparable with a metric sample over the same period. That is the case for a
// zero observationLookback.
//
// A command that reads history is different. A journal read returns days of
// events, and stamping it with the execution instant understates it twice
// over: coverage projection reports the investigated window as uninterrogated
// even though the read spanned it, and a reader takes a week of events for a
// one-second sample. Such a definition declares its lookback in its reviewed
// binding, and its evidence observes [completed-lookback, completed].
//
// The lookback is never derived from the command's output or its arguments. It
// is reviewed configuration that must match the signed argv, so evidence
// cannot claim coverage the command did not read.
func DiagnosticEvidenceForAttempt(request DiagnosticRequest, attempt DiagnosticAttemptResult, observationLookback time.Duration) (EvidenceEnvelope, error) {
	if err := request.Validate(); err != nil {
		return EvidenceEnvelope{}, fmt.Errorf("diagnostic evidence request is invalid: %w", err)
	}
	if err := attempt.Validate(request.Targets); err != nil {
		return EvidenceEnvelope{}, fmt.Errorf("diagnostic evidence attempt is invalid: %w", err)
	}
	if attempt.RunID != request.RunID {
		return EvidenceEnvelope{}, fmt.Errorf("diagnostic evidence attempt belongs to a different run")
	}
	if observationLookback < 0 || observationLookback > MaximumDiagnosticObservationLookback {
		return EvidenceEnvelope{}, fmt.Errorf("diagnostic observation lookback is outside the reviewed bound")
	}
	observedStart := attempt.StartedAt
	if observationLookback > 0 {
		observedStart = attempt.CompletedAt.Add(-observationLookback)
	}
	cluster := EvidenceTarget{Kind: EvidenceTargetCluster, ID: EvidenceTargetID(request.ClusterID)}
	expected := make([]EvidenceTarget, 0, len(request.Targets)+1)
	expected = append(expected, cluster)
	for _, target := range request.Targets {
		expected = append(expected, EvidenceTarget{Kind: EvidenceTargetNode, ID: EvidenceTargetID(target)})
	}
	covered := make([]EvidenceTarget, 0, len(expected))
	succeeded, emptyOutput := 0, 0
	for _, result := range attempt.Targets {
		if result.Status != DiagnosticTargetSucceeded {
			continue
		}
		succeeded++
		if result.StdoutBytes == 0 {
			emptyOutput++
		}
		covered = append(covered, EvidenceTarget{Kind: EvidenceTargetNode, ID: EvidenceTargetID(result.Target)})
	}
	// A host that answered is covered; the cluster is covered only when every
	// host did. This is the same rule collection evidence applies, so coverage
	// projection reads a diagnostic exactly as it reads a metric.
	status := EvidencePartial
	switch {
	case succeeded == 0:
		status, covered = EvidenceUnavailable, nil
	case succeeded == len(request.Targets):
		status = EvidenceComplete
		if emptyOutput == succeeded {
			// Every host answered and none had anything to report. That is a real
			// observation, not a failure: it is how "no retired pages" looks.
			status = EvidenceNoData
		}
		covered = append(covered, cluster)
	}
	sortEvidenceTargets(expected)
	sortEvidenceTargets(covered)
	digest := ChecksumSHA256([]byte("diagnostic-evidence-v1\x00" + string(request.ClusterID) + "\x00" + string(request.RunID) + "\x00" +
		string(request.Definition.DefinitionID) + "\x00" + request.Definition.DefinitionVersion + "\x00" + attempt.PlanDigest.String()))
	envelope, err := CreateEvidenceEnvelope(NewEvidenceEnvelope{
		ID: EvidenceID("diagnostic-" + digest.String()), SchemaVersion: EvidenceSchemaVersion,
		ClusterID: request.ClusterID, Status: status,
		Source: EvidenceSourceReference{
			// The definition is the source: a diagnostic is not attributable to a
			// polled system, and the operation identifier is the reviewed
			// definition so evidence policy can allow-list it by exact name.
			SourceID: DiagnosticEvidenceSourceID(request.ClusterID), DiagnosticRunID: request.RunID,
			Operation: EvidenceOperationID(request.Definition.DefinitionID), DefinitionVersion: DiagnosticEvidenceDefinitionVersion,
			Reference: EvidenceSourceLocator("commandpack:" + request.Definition.PackID + "@" + request.Definition.PackVersion + ":" + string(request.Definition.DefinitionID) + "@" + request.Definition.DefinitionVersion),
		},
		TimeRange:   EvidenceTimeRange{Start: observedStart, End: attempt.CompletedAt},
		CollectedAt: attempt.CompletedAt,
		Coverage:    EvidenceCoverage{Expected: expected, Covered: covered},
	})
	if err != nil {
		return EvidenceEnvelope{}, fmt.Errorf("build diagnostic evidence: %w", err)
	}
	return envelope, nil
}

func sortEvidenceTargets(targets []EvidenceTarget) {
	slices.SortFunc(targets, func(left, right EvidenceTarget) int {
		if left.Kind != right.Kind {
			return strings.Compare(string(left.Kind), string(right.Kind))
		}
		return strings.Compare(string(left.ID), string(right.ID))
	})
}
