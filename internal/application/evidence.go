package application

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

// ArtifactReconciliationCandidate contains only the immutable metadata needed
// to verify an artifact. Raw evidence never passes through the reconciliation
// ledger or its telemetry.
type ArtifactReconciliationCandidate struct {
	EvidenceID domain.EvidenceID
	Reference  domain.ArtifactReference
	Condition  domain.ArtifactAvailability
}

type ArtifactReconciliationStore interface {
	ListArtifactReconciliationCandidates(context.Context, time.Time, int) ([]ArtifactReconciliationCandidate, error)
	SetArtifactAvailability(context.Context, domain.EvidenceID, domain.ArtifactID, domain.ArtifactAvailability) error
}

type ArtifactChecker interface {
	Check(context.Context, domain.ArtifactReference) (domain.ArtifactAvailability, error)
}

type ArtifactReconciliationResult struct {
	Checked     int
	Available   int
	Unavailable int
	Corrupt     int
	Changed     int
	Failures    int
}

type ArtifactReconciler struct {
	store   ArtifactReconciliationStore
	checker ArtifactChecker
	minAge  time.Duration
	limit   int
}

func NewArtifactReconciler(store ArtifactReconciliationStore, checker ArtifactChecker, minAge time.Duration, limit int) (*ArtifactReconciler, error) {
	if store == nil || checker == nil {
		return nil, fmt.Errorf("artifact reconciliation dependencies are required")
	}
	if minAge < 0 || limit < 1 || limit > 10_000 {
		return nil, fmt.Errorf("artifact reconciliation bounds are invalid")
	}
	return &ArtifactReconciler{store: store, checker: checker, minAge: minAge, limit: limit}, nil
}

func (reconciler *ArtifactReconciler) Run(ctx context.Context, now time.Time) (ArtifactReconciliationResult, error) {
	if reconciler == nil {
		return ArtifactReconciliationResult{}, fmt.Errorf("artifact reconciler is unavailable")
	}
	if now.IsZero() {
		return ArtifactReconciliationResult{}, fmt.Errorf("artifact reconciliation time is required")
	}
	candidates, err := reconciler.store.ListArtifactReconciliationCandidates(ctx, now.UTC().Add(-reconciler.minAge), reconciler.limit)
	if err != nil {
		if ctx.Err() != nil {
			return ArtifactReconciliationResult{}, ctx.Err()
		}
		return ArtifactReconciliationResult{Failures: 1}, fmt.Errorf("list artifact reconciliation candidates: %w", err)
	}
	result := ArtifactReconciliationResult{}
	var failures []error
	for _, candidate := range candidates {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		if candidate.EvidenceID == "" {
			result.Failures++
			failures = append(failures, fmt.Errorf("artifact reconciliation candidate is missing its evidence identifier"))
			continue
		}
		if err := domain.ValidateArtifactReference(candidate.Reference); err != nil {
			result.Failures++
			failures = append(failures, fmt.Errorf("invalid artifact reconciliation candidate: %w", err))
			continue
		}
		condition, err := reconciler.checker.Check(ctx, candidate.Reference)
		if err != nil {
			if ctx.Err() != nil {
				return result, ctx.Err()
			}
			result.Failures++
			failures = append(failures, fmt.Errorf("check artifact content: %w", err))
			continue
		}
		switch condition {
		case domain.ArtifactAvailable:
			result.Available++
		case domain.ArtifactUnavailable:
			result.Unavailable++
		case domain.ArtifactCorrupt:
			result.Corrupt++
		default:
			result.Failures++
			failures = append(failures, fmt.Errorf("artifact checker returned invalid condition %q", condition))
			continue
		}
		result.Checked++
		if err := reconciler.store.SetArtifactAvailability(ctx, candidate.EvidenceID, candidate.Reference.ArtifactID, condition); err != nil {
			if ctx.Err() != nil {
				return result, ctx.Err()
			}
			result.Failures++
			failures = append(failures, fmt.Errorf("record artifact reconciliation: %w", err))
			continue
		}
		if condition != candidate.Condition {
			result.Changed++
		}
	}
	return result, errors.Join(failures...)
}

var (
	ErrEvidenceConflict           = errors.New("evidence conflicts with its immutable prior record")
	ErrArtifactTooLarge           = errors.New("artifact exceeds its byte limit")
	ErrArtifactChecksumMismatch   = errors.New("artifact checksum does not match its payload")
	ErrArtifactConflict           = errors.New("artifact conflicts with immutable stored content")
	ErrArtifactUnavailable        = errors.New("artifact is unavailable")
	ErrArtifactCorrupt            = errors.New("artifact failed stored-content verification")
	ErrKernelXIDArtifactNotFound  = errors.New("kernel XID artifact is unavailable in the requested diagnostic scope")
	ErrKernelXIDArtifactBinding   = errors.New("kernel XID artifact does not match its signed diagnostic binding")
	ErrKernelXIDArtifactConflict  = errors.New("kernel XID artifact conflicts with immutable stored content")
	ErrKernelXIDArtifactScreening = errors.New("kernel XID artifact failed canonical screening")
)

type EvidenceStore interface {
	// CreateEvidence returns false only for an exact idempotent replay. A store
	// must return ErrEvidenceConflict when the ID exists with different content.
	// Artifact-bearing envelopes are created with PENDING availability.
	CreateEvidence(context.Context, domain.EvidenceEnvelope) (bool, error)
	// MarkArtifactAvailable performs an idempotent PENDING -> AVAILABLE
	// transition and rejects a mismatched artifact identity.
	MarkArtifactAvailable(context.Context, domain.EvidenceID, domain.ArtifactID) error
}

type EvidenceArtifactReader interface {
	ArtifactAvailability(context.Context, domain.EvidenceID) (domain.EvidenceArtifactAvailability, bool, error)
}

type ArtifactStageID string

type StagedArtifact struct {
	ID         ArtifactStageID
	EvidenceID domain.EvidenceID
	Reference  domain.ArtifactReference
}

type ArtifactStore interface {
	Stage(context.Context, domain.EvidenceID, domain.ArtifactReference, []byte) (StagedArtifact, error)
	Promote(context.Context, StagedArtifact) error
	Discard(context.Context, StagedArtifact) error
}

type EvidenceRecorder struct {
	evidence  EvidenceStore
	artifacts ArtifactStore
	maxBytes  int64
}

func NewEvidenceRecorder(evidence EvidenceStore, artifacts ArtifactStore, maxBytes int64) (*EvidenceRecorder, error) {
	if evidence == nil || artifacts == nil {
		return nil, fmt.Errorf("evidence and artifact stores are required")
	}
	if maxBytes < 1 || maxBytes > 100<<20 {
		return nil, fmt.Errorf("evidence artifact limit must be between 1 byte and 100 MiB")
	}
	return &EvidenceRecorder{evidence: evidence, artifacts: artifacts, maxBytes: maxBytes}, nil
}

type RecordEvidence struct {
	Envelope    domain.EvidenceEnvelope
	RawArtifact []byte
}

type RecordEvidenceOutcome struct {
	PreviouslyRecorded bool
	ArtifactAvailable  bool
}

func (recorder *EvidenceRecorder) Record(ctx context.Context, input RecordEvidence) (RecordEvidenceOutcome, error) {
	if err := input.Envelope.Validate(); err != nil {
		return RecordEvidenceOutcome{}, fmt.Errorf("validate evidence envelope: %w", err)
	}
	reference, hasArtifact := input.Envelope.Artifact()
	if !hasArtifact {
		if len(input.RawArtifact) != 0 {
			return RecordEvidenceOutcome{}, fmt.Errorf("raw artifact requires envelope artifact metadata")
		}
		created, err := recorder.evidence.CreateEvidence(ctx, input.Envelope)
		if err != nil {
			return RecordEvidenceOutcome{}, fmt.Errorf("create evidence %s: %w", input.Envelope.ID(), err)
		}
		return RecordEvidenceOutcome{PreviouslyRecorded: !created}, nil
	}
	if int64(len(input.RawArtifact)) > recorder.maxBytes || reference.Bytes > recorder.maxBytes {
		return RecordEvidenceOutcome{}, ErrArtifactTooLarge
	}
	if int64(len(input.RawArtifact)) != reference.Bytes || domain.ChecksumSHA256(input.RawArtifact) != reference.SHA256 {
		return RecordEvidenceOutcome{}, ErrArtifactChecksumMismatch
	}
	staged, err := recorder.artifacts.Stage(ctx, input.Envelope.ID(), reference, input.RawArtifact)
	if err != nil {
		return RecordEvidenceOutcome{}, fmt.Errorf("stage artifact for evidence %s: %w", input.Envelope.ID(), err)
	}
	created, err := recorder.evidence.CreateEvidence(ctx, input.Envelope)
	if err != nil {
		_ = recorder.artifacts.Discard(ctx, staged)
		return RecordEvidenceOutcome{}, fmt.Errorf("create evidence %s: %w", input.Envelope.ID(), err)
	}
	outcome := RecordEvidenceOutcome{PreviouslyRecorded: !created}
	if err := recorder.artifacts.Promote(ctx, staged); err != nil {
		// The immutable envelope intentionally remains recorded. Its artifact
		// absence is visible and a retry/reconciler can promote it later.
		return outcome, fmt.Errorf("promote artifact for evidence %s: %w", input.Envelope.ID(), err)
	}
	if err := recorder.evidence.MarkArtifactAvailable(ctx, input.Envelope.ID(), reference.ArtifactID); err != nil {
		return outcome, fmt.Errorf("mark artifact available for evidence %s: %w", input.Envelope.ID(), err)
	}
	outcome.ArtifactAvailable = true
	return outcome, nil
}

type EvidenceArtifactLookup struct {
	reader EvidenceArtifactReader
}

func NewEvidenceArtifactLookup(reader EvidenceArtifactReader) (*EvidenceArtifactLookup, error) {
	if reader == nil {
		return nil, fmt.Errorf("evidence artifact reader is required")
	}
	return &EvidenceArtifactLookup{reader: reader}, nil
}

func (lookup *EvidenceArtifactLookup) Get(ctx context.Context, evidenceID domain.EvidenceID) (domain.EvidenceArtifactAvailability, bool, error) {
	if evidenceID == "" {
		return domain.EvidenceArtifactAvailability{}, false, fmt.Errorf("evidence identifier is required")
	}
	availability, found, err := lookup.reader.ArtifactAvailability(ctx, evidenceID)
	if err != nil {
		return domain.EvidenceArtifactAvailability{}, false, fmt.Errorf("load artifact availability for evidence %s: %w", evidenceID, err)
	}
	if !found {
		return domain.EvidenceArtifactAvailability{}, false, nil
	}
	if err := availability.Validate(); err != nil {
		return domain.EvidenceArtifactAvailability{}, false, fmt.Errorf("stored artifact availability for evidence %s: %w", evidenceID, err)
	}
	if availability.EvidenceID != evidenceID {
		return domain.EvidenceArtifactAvailability{}, false, fmt.Errorf("stored artifact availability has mismatched evidence identity")
	}
	return availability, true, nil
}
