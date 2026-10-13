package investigationapi

import (
	"context"
	"fmt"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

// EvidenceEnvelopeStore commits an immutable envelope. Creation is idempotent
// on the envelope identity, which is derived from the run and plan, so
// re-recording the same execution cannot produce a second envelope.
type EvidenceEnvelopeStore interface {
	CreateEvidence(context.Context, domain.EvidenceEnvelope) (bool, error)
	// EnsureDiagnosticSource provisions the synthetic source the envelope
	// refers to. A diagnostic's source is the reviewed pack rather than a
	// polled system, so nothing else creates it.
	EnsureDiagnosticSource(context.Context, domain.ClusterID, domain.SourceID) error
}

// CommittingEvidenceSink writes a projected diagnostic envelope through the
// ordinary evidence path and returns the investigation-scoped reference the
// controller appends to the ledger. Diagnostic results enter durable storage
// exactly where collection results do; nothing downstream can tell them apart.
type CommittingEvidenceSink struct {
	store EvidenceEnvelopeStore
}

func NewCommittingEvidenceSink(store EvidenceEnvelopeStore) (*CommittingEvidenceSink, error) {
	if store == nil {
		return nil, fmt.Errorf("evidence envelope store is required")
	}
	return &CommittingEvidenceSink{store: store}, nil
}

func (sink *CommittingEvidenceSink) RecordDiagnosticEvidence(ctx context.Context, investigationID domain.InvestigationID, envelope domain.EvidenceEnvelope) (domain.InvestigationEvidence, error) {
	if err := sink.store.EnsureDiagnosticSource(ctx, envelope.ClusterID(), envelope.Source().SourceID); err != nil {
		return domain.InvestigationEvidence{}, fmt.Errorf("provision diagnostic evidence source: %w", err)
	}
	if _, err := sink.store.CreateEvidence(ctx, envelope); err != nil {
		return domain.InvestigationEvidence{}, fmt.Errorf("commit diagnostic evidence envelope: %w", err)
	}
	// The ledger entry names the hosts the observation actually covers, which is
	// what citation validation and coverage projection read.
	entities := make([]string, 0, len(envelope.Coverage().Expected))
	for _, target := range envelope.Coverage().Expected {
		if target.Kind == domain.EvidenceTargetNode {
			entities = append(entities, string(target.ID))
		}
	}
	if len(entities) == 0 {
		return domain.InvestigationEvidence{}, fmt.Errorf("diagnostic evidence names no node target")
	}
	return domain.InvestigationEvidence{
		EvidenceID: envelope.ID(), InvestigationID: investigationID, ClusterID: envelope.ClusterID(),
		EntityIDs: entities, Status: envelope.Status(),
		ObservedStart: envelope.TimeRange().Start, ObservedEnd: envelope.TimeRange().End,
		RecordedAt: envelope.CollectedAt(),
	}, nil
}

var _ DiagnosticEvidenceSink = (*CommittingEvidenceSink)(nil)
