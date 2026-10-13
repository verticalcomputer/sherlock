package investigationcontext

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

type ContextRecord struct {
	Checkpoint Checkpoint
	Delta      *Delta
	Selected   []string
	Exclusions []EvidenceExclusion
}

type CheckpointStore interface {
	LoadLatestCheckpoint(context.Context, string, int) (Checkpoint, bool, error)
	RecordContextCheckpoint(context.Context, ContextRecord) error
}

type EngineConfig struct {
	EvidenceAllowanceTokens int64
	MaximumPerClass         int
	MaximumPerSource        int
	PolicyVersion           string
	ToolSchemaVersion       string
	// MaxSummaryBytes and MaxExcerptBytes must match the context builder's
	// limits so selection prices the block the builder will actually emit.
	MaxSummaryBytes int
	MaxExcerptBytes int
}

func DefaultEngineConfig() EngineConfig {
	limits := DefaultLimits()
	return EngineConfig{EvidenceAllowanceTokens: 4_000, MaximumPerClass: 8, MaximumPerSource: 8, PolicyVersion: "investigation-policy-v1", ToolSchemaVersion: "catalog-v1", MaxSummaryBytes: limits.MaxSummaryBytes, MaxExcerptBytes: limits.MaxExcerptBytes}
}

type Engine struct {
	config EngineConfig
	store  CheckpointStore
}

func NewEngine(config EngineConfig, store CheckpointStore) (*Engine, error) {
	if config.EvidenceAllowanceTokens < 256 || config.EvidenceAllowanceTokens > 100_000 || config.MaximumPerClass < 1 || config.MaximumPerClass > 256 || config.MaximumPerSource < 1 || config.MaximumPerSource > 256 || config.PolicyVersion == "" || config.ToolSchemaVersion == "" || store == nil {
		return nil, fmt.Errorf("investigation context engine configuration is invalid")
	}
	return &Engine{config: config, store: store}, nil
}

func (engine *Engine) Prepare(ctx context.Context, snapshot application.InvestigationSnapshot, input Input) (Input, ContextRecord, error) {
	if engine == nil {
		return Input{}, ContextRecord{}, fmt.Errorf("investigation context engine is unavailable")
	}
	request := snapshot.Investigation.Request()
	queryText := request.Question
	classes := []string{}
	for _, hypothesis := range snapshot.Hypotheses.Entries() {
		queryText += " " + hypothesis.Statement + " " + strings.Join(hypothesis.UnresolvedTests, " ")
		classes = append(classes, hypothesis.UnresolvedTests...)
	}
	// Coalesce before selection, not after. Selection is where mandatory evidence
	// that exceeds the allowance fails the transition outright, so it has to see
	// one block per observation rather than one per collector scrape; merging
	// downstream in the builder would shrink the prompt but never prevent the
	// failure.
	orderedEvidence := slices.Clone(input.Evidence)
	slices.SortFunc(orderedEvidence, compareEvidence)
	coalescedEvidence, merged := coalesceEvidence(orderedEvidence)
	input.Evidence = coalescedEvidence
	selection, err := SelectEvidence(input.Evidence, RetrievalQuery{
		ClusterID: request.ClusterID, EntityIDs: request.Scope.EntityIDs, Start: request.Scope.Start, End: request.Scope.End,
		CommittedBefore: request.RequestedAt, Text: queryText, EvidenceClasses: classes,
		AllowanceTokens: engine.config.EvidenceAllowanceTokens, MaximumPerClass: engine.config.MaximumPerClass, MaximumPerSource: engine.config.MaximumPerSource,
		MaxSummaryBytes: engine.config.MaxSummaryBytes, MaxExcerptBytes: engine.config.MaxExcerptBytes,
	})
	if err != nil {
		return Input{}, ContextRecord{}, err
	}
	checkpoint, err := ProjectCheckpoint(snapshot, input, engine.config.PolicyVersion, engine.config.ToolSchemaVersion)
	if err != nil {
		return Input{}, ContextRecord{}, err
	}
	// Retrieval's capacity exclusions are losses in exactly the sense the
	// builder's omissions are, so they travel with the context instead of
	// resting only in the checkpoint where no report can reach them.
	input.SelectionLosses = selectionLosses(selection, input.Evidence)
	record := ContextRecord{Checkpoint: checkpoint, Exclusions: slices.Clone(selection.Exclusions)}
	for _, id := range merged {
		record.Exclusions = append(record.Exclusions, EvidenceExclusion{EvidenceID: id, Reason: ExcludeCoalesced})
	}
	for _, item := range selection.Selected {
		record.Selected = append(record.Selected, string(item.EvidenceID))
	}
	prior, found, err := engine.store.LoadLatestCheckpoint(ctx, string(request.ID), checkpoint.Projection.LedgerVersion)
	if err != nil {
		return Input{}, ContextRecord{}, fmt.Errorf("load prior context checkpoint: %w", err)
	}
	if found {
		delta, deltaErr := BuildDelta(prior, checkpoint)
		if deltaErr != nil {
			return Input{}, ContextRecord{}, deltaErr
		}
		applied, applyErr := Apply(prior, delta)
		if applyErr != nil || applied.Digest != checkpoint.Digest {
			return Input{}, ContextRecord{}, fmt.Errorf("%w: delta verification failed", ErrCheckpointMismatch)
		}
		record.Delta = &delta
	}
	if err := engine.store.RecordContextCheckpoint(ctx, record); err != nil {
		return Input{}, ContextRecord{}, fmt.Errorf("persist context checkpoint: %w", err)
	}
	input.Evidence = selection.Selected
	input.EvidenceAnchors = slices.Clone(selection.AnchorIDs)
	input.EvidenceAllocation = nil
	for _, item := range selection.Selected {
		input.EvidenceAllocation = append(input.EvidenceAllocation, item.EvidenceID)
	}
	input.CheckpointDigest = checkpoint.Digest
	if record.Delta != nil {
		input.DeltaFromVersion = record.Delta.FromVersion
	}
	return input, record, nil
}

// selectionLosses converts the capacity exclusions retrieval recorded into the
// builder's omission vocabulary, carrying the entities each one cost.
//
// A per-class cap is an item limit and a selection allowance is a size ceiling,
// so neither needs a reason of its own: what an operator has to know is that
// the evidence existed, was collected, and did not fit.
func selectionLosses(selection RetrievalResult, candidates []EvidenceInput) []SelectionLoss {
	entities := make(map[domain.EvidenceID][]string, len(candidates))
	for _, candidate := range candidates {
		entities[candidate.EvidenceID] = candidate.EntityIDs
	}
	var losses []SelectionLoss
	for _, exclusion := range selection.Exclusions {
		reason := ""
		switch exclusion.Reason {
		case ExcludeDiversity:
			reason = OmissionItemLimit
		case ExcludeTokenLimit:
			reason = OmissionEncodedSizeLimit
		default:
			continue
		}
		losses = append(losses, SelectionLoss{EvidenceID: exclusion.EvidenceID, EntityIDs: slices.Clone(entities[exclusion.EvidenceID]), Reason: reason})
	}
	return losses
}
