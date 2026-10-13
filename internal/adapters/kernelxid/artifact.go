package kernelxid

import (
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

// ErrArtifactScreeningFailed means a typed result cannot be transformed into
// the fixed GP-06d representation. Callers must record the explicit screening
// gap; they must never retain or substitute a raw journal excerpt.
var ErrArtifactScreeningFailed = errors.New("kernel XID artifact screening failed")

// ScreeningFailureArtifact is the only durable substitute for a rejected
// source transformation. It keeps no source field from the rejected value and
// records a PARTIAL coverage gap instead of falling back to a raw excerpt.
func ScreeningFailureArtifact(observedFrom, observedTo time.Time, binding domain.KernelXIDArtifactBinding) (domain.KernelXIDArtifact, error) {
	artifact, err := domain.NewKernelXIDArtifact(domain.KernelXIDArtifactInput{
		ObservedFrom: observedFrom, ObservedTo: observedTo, Disposition: domain.KernelXIDArtifactPartial,
		DeclaredLimits: []string{string(LimitFixedWindow), string(LimitLineCap), string(LimitOutputCap)},
		Gaps:           []domain.KernelXIDArtifactGap{domain.KernelXIDArtifactGapScreeningFailure}, Binding: &binding,
	})
	if err != nil {
		return domain.KernelXIDArtifact{}, fmt.Errorf("create kernel XID screening-failure artifact: %w", err)
	}
	return artifact, nil
}

// BuildArtifact retains only the reviewed structured fields. In particular it
// does not accept raw lines, target hostnames from journal text, labels, paths,
// credentials, or trailing driver messages.
func BuildArtifact(source TargetEvidence, binding domain.KernelXIDArtifactBinding) (domain.KernelXIDArtifact, error) {
	if source.ParserVersion != ParserVersion || source.SourceDefinition != string(DefinitionID) || source.SourceDefinitionVersion != DefinitionVersion {
		return domain.KernelXIDArtifact{}, fmt.Errorf("%w: kernel XID source definition drift", ErrArtifactScreeningFailed)
	}
	if source.Target == "" || domain.DiagnosticTarget(source.Target) != binding.Target {
		return domain.KernelXIDArtifact{}, fmt.Errorf("%w: target does not match diagnostic binding", ErrArtifactScreeningFailed)
	}
	gaps := make([]domain.KernelXIDArtifactGap, 0, len(source.Gaps)+1)
	for _, gap := range source.Gaps {
		converted := domain.KernelXIDArtifactGap(gap)
		if !artifactGapAllowed(converted) {
			return domain.KernelXIDArtifact{}, fmt.Errorf("%w: unrecognized source gap", ErrArtifactScreeningFailed)
		}
		gaps = append(gaps, converted)
	}
	events := make([]domain.KernelXIDArtifactEvent, 0, min(len(source.Events), domain.MaxKernelXIDArtifactEvents))
	for index, event := range source.Events {
		if index == domain.MaxKernelXIDArtifactEvents {
			gaps = append(gaps, domain.KernelXIDArtifactGapArtifactLimit)
			break
		}
		events = append(events, domain.KernelXIDArtifactEvent{ObservedAt: event.ObservedAt, XIDCode: event.XIDCode, PCIBDF: event.PCIBDF})
	}
	disposition := domain.KernelXIDArtifactDisposition(source.Disposition)
	if slices.Contains(gaps, domain.KernelXIDArtifactGapArtifactLimit) {
		disposition = domain.KernelXIDArtifactPartial
	}
	artifact, err := domain.NewKernelXIDArtifact(domain.KernelXIDArtifactInput{
		ObservedFrom: source.ObservedFrom, ObservedTo: source.ObservedTo, Disposition: disposition,
		DeclaredLimits: artifactLimits(source.DeclaredLimits), Gaps: gaps, Events: events, Binding: &binding,
	})
	if err != nil {
		return domain.KernelXIDArtifact{}, fmt.Errorf("%w: %v", ErrArtifactScreeningFailed, err)
	}
	return artifact, nil
}

func artifactLimits(limits []DeclaredLimit) []string {
	result := make([]string, len(limits))
	for index, limit := range limits {
		result[index] = string(limit)
	}
	return result
}

func artifactGapAllowed(gap domain.KernelXIDArtifactGap) bool {
	switch gap {
	case domain.KernelXIDArtifactGapTargetUnavailable, domain.KernelXIDArtifactGapTargetFailed, domain.KernelXIDArtifactGapTargetTimedOut,
		domain.KernelXIDArtifactGapTargetRejected, domain.KernelXIDArtifactGapOutputTruncated, domain.KernelXIDArtifactGapOutputTransformed,
		domain.KernelXIDArtifactGapOutputUnknown, domain.KernelXIDArtifactGapMalformedRecord, domain.KernelXIDArtifactGapOutsideWindow,
		domain.KernelXIDArtifactGapNormalizedLimit, domain.KernelXIDArtifactGapLineCap, domain.KernelXIDArtifactGapOutputInvalid:
		return true
	default:
		return false
	}
}
