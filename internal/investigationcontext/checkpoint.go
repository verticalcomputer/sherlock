package investigationcontext

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

const CheckpointSchemaVersion = 1

var ErrCheckpointMismatch = errors.New("CONTEXT_CHECKPOINT_MISMATCH")

type TargetSet struct {
	Digest     string   `json:"digest"`
	EntityKind string   `json:"entity_kind"`
	EntityIDs  []string `json:"entity_ids"`
}

type CheckpointEvidence struct {
	EvidenceID     domain.EvidenceID     `json:"evidence_id"`
	Status         domain.EvidenceStatus `json:"status"`
	Source         string                `json:"source"`
	TargetSet      string                `json:"target_set"`
	ObservedFrom   string                `json:"observed_from"`
	ObservedTo     string                `json:"observed_to"`
	Coverage       string                `json:"coverage"`
	SummaryVersion string                `json:"summary_version"`
	SummaryQuality string                `json:"summary_quality"`
}

type CheckpointAction struct {
	Sequence    int                 `json:"sequence"`
	Digest      string              `json:"digest"`
	ToolID      string              `json:"tool_id"`
	Outcome     string              `json:"outcome"`
	Targets     []string            `json:"targets"`
	Start       string              `json:"start"`
	End         string              `json:"end"`
	EvidenceIDs []domain.EvidenceID `json:"evidence_ids"`
}

type CheckpointHypothesis struct {
	ID                    domain.HypothesisID     `json:"id"`
	Status                domain.HypothesisStatus `json:"status"`
	Confidence            float64                 `json:"confidence"`
	Statement             string                  `json:"statement"`
	SupportingEvidence    []domain.EvidenceID     `json:"supporting_evidence"`
	ContradictingEvidence []domain.EvidenceID     `json:"contradicting_evidence"`
	UnresolvedTests       []string                `json:"unresolved_tests"`
}

type CheckpointBudget struct {
	Decisions       int   `json:"decisions"`
	ToolCalls       int   `json:"tool_calls"`
	DiagnosticCalls int   `json:"diagnostic_calls"`
	PrivilegedCalls int   `json:"privileged_calls"`
	FanOut          int   `json:"fan_out"`
	ModelTokens     int64 `json:"model_tokens"`
	CostMicros      int64 `json:"cost_micros"`
}

type CheckpointProjection struct {
	SchemaVersion     int                    `json:"schema_version"`
	InvestigationID   domain.InvestigationID `json:"investigation_id"`
	LedgerVersion     int                    `json:"ledger_version"`
	ClusterID         domain.ClusterID       `json:"cluster_id"`
	Question          string                 `json:"question"`
	SuccessCriteria   []string               `json:"success_criteria"`
	TargetSet         TargetSet              `json:"target_set"`
	Status            string                 `json:"status"`
	StopReason        string                 `json:"stop_reason,omitempty"`
	Hypotheses        []CheckpointHypothesis `json:"hypotheses"`
	PriorActions      []CheckpointAction     `json:"prior_actions"`
	Evidence          []CheckpointEvidence   `json:"evidence"`
	RemainingBudget   CheckpointBudget       `json:"remaining_budget"`
	PolicyVersion     string                 `json:"policy_version"`
	ToolSchemaVersion string                 `json:"tool_schema_version"`
	HighestEvent      int                    `json:"highest_event"`
}

type Checkpoint struct {
	Projection    CheckpointProjection `json:"projection"`
	Digest        string               `json:"digest"`
	CanonicalJSON []byte               `json:"-"`
}

// ProjectCheckpoint is a pure projection. It contains no raw artifact,
// provider payload, credential, embedding, or model-authored recap.
func ProjectCheckpoint(snapshot application.InvestigationSnapshot, input Input, policyVersion, toolSchemaVersion string) (Checkpoint, error) {
	request := snapshot.Investigation.Request()
	if request.ID == "" || request.ID != input.InvestigationID || request.ClusterID != input.ClusterID || policyVersion == "" || toolSchemaVersion == "" {
		return Checkpoint{}, fmt.Errorf("checkpoint source identity or versions are invalid")
	}
	ids := slices.Clone(request.Scope.EntityIDs)
	slices.Sort(ids)
	targetJSON, _ := json.Marshal(struct {
		Kind string   `json:"kind"`
		IDs  []string `json:"ids"`
	}{request.Scope.EntityKind, ids})
	targetDigest := domain.ChecksumSHA256(targetJSON).String()
	budget, usage := request.Budget, snapshot.Investigation.Usage()
	projection := CheckpointProjection{
		SchemaVersion: CheckpointSchemaVersion, InvestigationID: request.ID,
		LedgerVersion: snapshot.Investigation.Version(), ClusterID: request.ClusterID,
		Question: request.Question, SuccessCriteria: slices.Clone(request.SuccessCriteria),
		TargetSet: TargetSet{Digest: targetDigest, EntityKind: request.Scope.EntityKind, EntityIDs: ids},
		Status:    string(snapshot.Investigation.Status()), StopReason: string(snapshot.Investigation.StopReason()),
		RemainingBudget: CheckpointBudget{
			Decisions: budget.MaxDecisions - usage.Decisions, ToolCalls: budget.MaxToolCalls - usage.ToolCalls,
			DiagnosticCalls: budget.MaxDiagnosticCalls - usage.DiagnosticCalls,
			PrivilegedCalls: budget.MaxPrivilegedCalls - usage.PrivilegedCalls,
			FanOut:          budget.MaxFanOut, ModelTokens: budget.MaxModelTokens - usage.ModelTokens,
			CostMicros: budget.MaxCostMicros - usage.CostMicros,
		},
		PolicyVersion: policyVersion, ToolSchemaVersion: toolSchemaVersion,
		HighestEvent: snapshot.Investigation.Version(),
	}
	for _, item := range snapshot.Hypotheses.Entries() {
		projection.Hypotheses = append(projection.Hypotheses, CheckpointHypothesis{
			ID: item.ID, Status: item.Status, Confidence: item.Confidence, Statement: item.Statement,
			SupportingEvidence: sortedEvidenceIDs(item.SupportingEvidence), ContradictingEvidence: sortedEvidenceIDs(item.ContradictingEvidence),
			UnresolvedTests: sortedStrings(item.UnresolvedTests),
		})
	}
	for sequence, action := range snapshot.PriorActions {
		projection.PriorActions = append(projection.PriorActions, CheckpointAction{
			Sequence: sequence + 1, Digest: action.Digest.String(), ToolID: action.ToolID, Outcome: action.Outcome,
			Targets: sortedStrings(action.Targets), Start: canonicalTime(action.Start), End: canonicalTime(action.End), EvidenceIDs: sortedEvidenceIDs(action.EvidenceIDs),
		})
	}
	for _, item := range input.Evidence {
		coverage := fmt.Sprintf("%d/%d", len(item.Coverage.Covered), len(item.Coverage.Expected))
		projection.Evidence = append(projection.Evidence, CheckpointEvidence{
			EvidenceID: item.EvidenceID, Status: item.Status, Source: item.Source, TargetSet: targetDigest,
			ObservedFrom: canonicalTime(item.ObservedFrom), ObservedTo: canonicalTime(item.ObservedTo), Coverage: coverage,
			SummaryVersion: summaryVersion(item),
			SummaryQuality: item.SummaryQuality,
		})
	}
	canonicalizeProjection(&projection)
	return sealCheckpoint(projection)
}

func sealCheckpoint(projection CheckpointProjection) (Checkpoint, error) {
	canonicalizeProjection(&projection)
	encoded, err := json.Marshal(projection)
	if err != nil {
		return Checkpoint{}, fmt.Errorf("encode context checkpoint: %w", err)
	}
	digest := domain.ChecksumSHA256(append([]byte("m11-checkpoint-v1\x00"), encoded...)).String()
	return Checkpoint{Projection: projection, Digest: digest, CanonicalJSON: encoded}, nil
}

func canonicalizeProjection(value *CheckpointProjection) {
	value.SuccessCriteria = slices.Clone(value.SuccessCriteria)
	value.TargetSet.EntityIDs = sortedStrings(value.TargetSet.EntityIDs)
	slices.SortFunc(value.Hypotheses, func(a, b CheckpointHypothesis) int { return strings.Compare(string(a.ID), string(b.ID)) })
	for index := range value.Hypotheses {
		value.Hypotheses[index].SupportingEvidence = sortedEvidenceIDs(value.Hypotheses[index].SupportingEvidence)
		value.Hypotheses[index].ContradictingEvidence = sortedEvidenceIDs(value.Hypotheses[index].ContradictingEvidence)
		value.Hypotheses[index].UnresolvedTests = sortedStrings(value.Hypotheses[index].UnresolvedTests)
	}
	slices.SortFunc(value.PriorActions, func(a, b CheckpointAction) int { return a.Sequence - b.Sequence })
	for index := range value.PriorActions {
		value.PriorActions[index].Targets = sortedStrings(value.PriorActions[index].Targets)
		value.PriorActions[index].EvidenceIDs = sortedEvidenceIDs(value.PriorActions[index].EvidenceIDs)
	}
	slices.SortFunc(value.Evidence, func(a, b CheckpointEvidence) int { return strings.Compare(string(a.EvidenceID), string(b.EvidenceID)) })
	if value.Hypotheses == nil {
		value.Hypotheses = []CheckpointHypothesis{}
	}
	if value.PriorActions == nil {
		value.PriorActions = []CheckpointAction{}
	}
	if value.Evidence == nil {
		value.Evidence = []CheckpointEvidence{}
	}
}

type Delta struct {
	SchemaVersion      int                    `json:"schema_version"`
	InvestigationID    domain.InvestigationID `json:"investigation_id"`
	ParentDigest       string                 `json:"parent_digest"`
	FromVersion        int                    `json:"from_version"`
	ToVersion          int                    `json:"to_version"`
	Status             string                 `json:"status"`
	StopReason         string                 `json:"stop_reason,omitempty"`
	HypothesesUpserted []CheckpointHypothesis `json:"hypotheses_upserted"`
	HypothesesRemoved  []domain.HypothesisID  `json:"hypotheses_removed"`
	ActionsAppended    []CheckpointAction     `json:"actions_appended"`
	EvidenceUpserted   []CheckpointEvidence   `json:"evidence_upserted"`
	EvidenceRemoved    []domain.EvidenceID    `json:"evidence_removed"`
	RemainingBudget    CheckpointBudget       `json:"remaining_budget"`
	HighestEvent       int                    `json:"highest_event"`
	ResultDigest       string                 `json:"result_digest"`
}

func BuildDelta(parent, next Checkpoint) (Delta, error) {
	if parent.Projection.InvestigationID != next.Projection.InvestigationID || next.Projection.LedgerVersion <= parent.Projection.LedgerVersion ||
		parent.Projection.ClusterID != next.Projection.ClusterID || parent.Projection.TargetSet.Digest != next.Projection.TargetSet.Digest ||
		parent.Projection.PolicyVersion != next.Projection.PolicyVersion || parent.Projection.ToolSchemaVersion != next.Projection.ToolSchemaVersion {
		return Delta{}, fmt.Errorf("%w: incompatible checkpoint lineage", ErrCheckpointMismatch)
	}
	delta := Delta{SchemaVersion: CheckpointSchemaVersion, InvestigationID: parent.Projection.InvestigationID, ParentDigest: parent.Digest,
		FromVersion: parent.Projection.LedgerVersion, ToVersion: next.Projection.LedgerVersion, Status: next.Projection.Status,
		StopReason: next.Projection.StopReason, RemainingBudget: next.Projection.RemainingBudget, HighestEvent: next.Projection.HighestEvent, ResultDigest: next.Digest}
	delta.HypothesesUpserted, delta.HypothesesRemoved = diffHypotheses(parent.Projection.Hypotheses, next.Projection.Hypotheses)
	delta.EvidenceUpserted, delta.EvidenceRemoved = diffEvidence(parent.Projection.Evidence, next.Projection.Evidence)
	if len(next.Projection.PriorActions) < len(parent.Projection.PriorActions) || !slices.EqualFunc(parent.Projection.PriorActions, next.Projection.PriorActions[:min(len(parent.Projection.PriorActions), len(next.Projection.PriorActions))], func(a, b CheckpointAction) bool { return equalJSON(a, b) }) {
		return Delta{}, fmt.Errorf("%w: action history is not append-only", ErrCheckpointMismatch)
	}
	delta.ActionsAppended = slices.Clone(next.Projection.PriorActions[len(parent.Projection.PriorActions):])
	return delta, nil
}

func Apply(parent Checkpoint, delta Delta) (Checkpoint, error) {
	if delta.SchemaVersion != CheckpointSchemaVersion || delta.InvestigationID != parent.Projection.InvestigationID || delta.ParentDigest != parent.Digest ||
		delta.FromVersion != parent.Projection.LedgerVersion || delta.ToVersion <= delta.FromVersion {
		return Checkpoint{}, fmt.Errorf("%w: parent or version mismatch", ErrCheckpointMismatch)
	}
	projection := parent.Projection
	projection.LedgerVersion, projection.Status, projection.StopReason = delta.ToVersion, delta.Status, delta.StopReason
	projection.RemainingBudget, projection.HighestEvent = delta.RemainingBudget, delta.HighestEvent
	projection.Hypotheses = applyHypotheses(projection.Hypotheses, delta.HypothesesUpserted, delta.HypothesesRemoved)
	projection.Evidence = applyEvidence(projection.Evidence, delta.EvidenceUpserted, delta.EvidenceRemoved)
	projection.PriorActions = append(slices.Clone(projection.PriorActions), delta.ActionsAppended...)
	result, err := sealCheckpoint(projection)
	if err != nil {
		return Checkpoint{}, err
	}
	if result.Digest != delta.ResultDigest {
		return Checkpoint{}, fmt.Errorf("%w: resulting digest mismatch", ErrCheckpointMismatch)
	}
	return result, nil
}

func diffHypotheses(old, next []CheckpointHypothesis) ([]CheckpointHypothesis, []domain.HypothesisID) {
	before := map[domain.HypothesisID]CheckpointHypothesis{}
	for _, item := range old {
		before[item.ID] = item
	}
	after := map[domain.HypothesisID]struct{}{}
	var upsert []CheckpointHypothesis
	for _, item := range next {
		after[item.ID] = struct{}{}
		if prior, ok := before[item.ID]; !ok || !equalJSON(prior, item) {
			upsert = append(upsert, item)
		}
	}
	var removed []domain.HypothesisID
	for _, item := range old {
		if _, ok := after[item.ID]; !ok {
			removed = append(removed, item.ID)
		}
	}
	return upsert, removed
}

func diffEvidence(old, next []CheckpointEvidence) ([]CheckpointEvidence, []domain.EvidenceID) {
	before := map[domain.EvidenceID]CheckpointEvidence{}
	for _, item := range old {
		before[item.EvidenceID] = item
	}
	after := map[domain.EvidenceID]struct{}{}
	var upsert []CheckpointEvidence
	for _, item := range next {
		after[item.EvidenceID] = struct{}{}
		if prior, ok := before[item.EvidenceID]; !ok || !equalJSON(prior, item) {
			upsert = append(upsert, item)
		}
	}
	var removed []domain.EvidenceID
	for _, item := range old {
		if _, ok := after[item.EvidenceID]; !ok {
			removed = append(removed, item.EvidenceID)
		}
	}
	return upsert, removed
}

func applyHypotheses(current, upsert []CheckpointHypothesis, removed []domain.HypothesisID) []CheckpointHypothesis {
	values := map[domain.HypothesisID]CheckpointHypothesis{}
	for _, item := range current {
		values[item.ID] = item
	}
	for _, id := range removed {
		delete(values, id)
	}
	for _, item := range upsert {
		values[item.ID] = item
	}
	result := make([]CheckpointHypothesis, 0, len(values))
	for _, item := range values {
		result = append(result, item)
	}
	return result
}

func applyEvidence(current, upsert []CheckpointEvidence, removed []domain.EvidenceID) []CheckpointEvidence {
	values := map[domain.EvidenceID]CheckpointEvidence{}
	for _, item := range current {
		values[item.EvidenceID] = item
	}
	for _, id := range removed {
		delete(values, id)
	}
	for _, item := range upsert {
		values[item.EvidenceID] = item
	}
	result := make([]CheckpointEvidence, 0, len(values))
	for _, item := range values {
		result = append(result, item)
	}
	return result
}

func equalJSON[T any](left, right T) bool {
	a, _ := json.Marshal(left)
	b, _ := json.Marshal(right)
	return slices.Equal(a, b)
}
func sortedStrings(values []string) []string {
	result := slices.Clone(values)
	slices.Sort(result)
	return result
}
func sortedEvidenceIDs(values []domain.EvidenceID) []domain.EvidenceID {
	result := slices.Clone(values)
	slices.Sort(result)
	return result
}
func canonicalTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}

func summaryVersion(item EvidenceInput) string {
	if item.SummaryVersion != "" {
		return item.SummaryVersion
	}
	return "legacy-v1"
}
