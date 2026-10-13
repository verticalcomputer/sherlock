// Package scheduleinvestigation supplies a deterministic, read-only
// investigation path for a durably proven collection-scheduling gap. It does
// not call a model, collector, diagnostic runner, or privileged executor.
package scheduleinvestigation

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

const SourceFreshnessToolID = "cluster.source_freshness.v1"

// Reader is implemented by the consumer that owns durable detector and
// evidence provenance. It must reconstruct one exact request from committed
// data; this package never turns a loosely matched incident or current job
// state into execution authority.
type Reader interface {
	ReadScheduleInvestigation(context.Context, domain.InvestigationID) (Snapshot, error)
}

// Snapshot is the pinned schedule-repair admission fact and the current
// controller state read by the same consumer. Evidence is a committed,
// investigation-scoped envelope; Eligible is true only for the reviewed
// schedule-dispatch-gap rule.
type Snapshot struct {
	ClusterID       domain.ClusterID
	IncidentID      domain.IncidentID
	InvestigationID domain.InvestigationID
	JobID           string
	SourceID        domain.SourceID
	Evidence        domain.InvestigationEvidence
	Eligible        bool
	Current         application.InvestigationSnapshot
}

// Planner implements all three controller extension points. Keeping planning,
// execution, and synthesis together ensures each boundary independently reads
// and verifies the pinned durable fact.
type Planner struct{ reader Reader }

func New(reader Reader) (*Planner, error) {
	if reader == nil {
		return nil, errors.New("schedule investigation reader is required")
	}
	return &Planner{reader: reader}, nil
}

func (planner *Planner) Decide(ctx context.Context, snapshot application.InvestigationSnapshot) (application.InvestigationDecision, error) {
	facts, err := planner.read(ctx, snapshot)
	if err != nil {
		return application.InvestigationDecision{}, err
	}
	if containsExactEvidence(snapshot.Evidence, facts.Evidence) {
		return application.InvestigationDecision{
			Stop: true, Outcome: domain.InvestigationCompleted, Reason: domain.StopSuccessCriteriaMet,
		}, nil
	}
	action := actionFor(facts, snapshot.Investigation.Request().Scope)
	return application.InvestigationDecision{Action: &action}, nil
}

// ExecuteInvestigationAction independently reloads durable provenance and
// requires the action to be byte-for-byte equivalent to the persisted proposal.
// Its only result is the already committed evidence supplied by Reader.
func (planner *Planner) ExecuteInvestigationAction(ctx context.Context, idempotencyKey string, action domain.InvestigationAction) (application.InvestigationExecutionResult, error) {
	id, err := idFromKey(idempotencyKey, action.ID)
	if err != nil {
		return application.InvestigationExecutionResult{}, err
	}
	facts, err := planner.reader.ReadScheduleInvestigation(ctx, id)
	if err != nil {
		return application.InvestigationExecutionResult{}, fmt.Errorf("read schedule investigation: %w", err)
	}
	if facts.InvestigationID != id {
		return application.InvestigationExecutionResult{}, errors.New("schedule investigation execution request does not match durable identity")
	}
	if err := validateFacts(facts, facts.Current); err != nil {
		return application.InvestigationExecutionResult{}, err
	}
	expected := actionFor(facts, facts.Current.Investigation.Request().Scope)
	if !reflect.DeepEqual(action, expected) || facts.Current.ProposedAction == nil || !reflect.DeepEqual(*facts.Current.ProposedAction, action) {
		return application.InvestigationExecutionResult{}, errors.New("schedule investigation action does not match durable request")
	}
	return application.InvestigationExecutionResult{Receipt: "schedule-evidence:" + string(facts.Evidence.EvidenceID), Evidence: []domain.InvestigationEvidence{facts.Evidence}}, nil
}

func (planner *Planner) Synthesize(ctx context.Context, snapshot application.InvestigationSnapshot) (application.InvestigationSynthesis, error) {
	facts, err := planner.read(ctx, snapshot)
	if err != nil {
		return application.InvestigationSynthesis{}, err
	}
	if !containsExactEvidence(snapshot.Evidence, facts.Evidence) {
		return application.InvestigationSynthesis{}, errors.New("schedule investigation evidence is not in the durable ledger")
	}
	request := snapshot.Investigation.Request()
	citation := []domain.EvidenceID{facts.Evidence.EvidenceID}
	observedAt := facts.Evidence.ObservedEnd.UTC()
	finding := domain.Finding{
		ID: domain.FindingID("schedule-source-freshness-" + string(request.ID)), InvestigationID: request.ID, Kind: domain.FindingObservation,
		Statement: "The committed source-freshness evidence covers the requested collection job.",
		EntityIDs: []string{facts.JobID}, Severity: string(domain.HealthSeverityInfo), EvidenceIDs: citation, Status: domain.FindingCurrent,
	}
	sections := []domain.ReportSection{
		{ID: domain.ReportSectionID("schedule-source-timeline-" + string(request.ID)), InvestigationID: request.ID, Kind: domain.ReportSectionTimeline, Ordinal: 0, Statement: "Source freshness was observed for the exact requested collection job.", ObservedAt: &observedAt, EvidenceIDs: citation},
		{ID: domain.ReportSectionID("schedule-source-coverage-" + string(request.ID)), InvestigationID: request.ID, Kind: domain.ReportSectionCoverage, Ordinal: 1, Statement: "The report is limited to the durably verified collection job and source-freshness evidence.", EvidenceIDs: citation},
	}
	card, err := domain.NewActionCard(domain.ActionCardID("schedule-action-"+string(request.ID)), snapshot.Investigation, snapshot.Evidence, domain.ActionCardInput{
		Owner: domain.ActionOwnerSherlock, Action: "Request one additional collection for the proven scheduling gap under separately evaluated standing policy.",
		Urgency: domain.ActionUrgencyMonitor, Targets: []string{facts.JobID},
		Rationale:   "The completed read-only source-freshness action returned the exact committed evidence selected by the durable schedule investigation request.",
		EvidenceIDs: citation, BlockingGaps: []string{},
		EscalationCondition: "Escalate only after a separately admitted remediation path establishes a current scheduling defect and its required effect authority.",
	})
	if err != nil {
		return application.InvestigationSynthesis{}, fmt.Errorf("build schedule action card: %w", err)
	}
	return application.InvestigationSynthesis{Findings: []domain.Finding{finding}, Sections: sections, ActionCard: &card, Disposition: application.SynthesisValidatedComplete}, nil
}

func (planner *Planner) read(ctx context.Context, snapshot application.InvestigationSnapshot) (Snapshot, error) {
	if planner == nil || planner.reader == nil {
		return Snapshot{}, errors.New("schedule investigation planner is not configured")
	}
	facts, err := planner.reader.ReadScheduleInvestigation(ctx, snapshot.Investigation.Request().ID)
	if err != nil {
		return Snapshot{}, fmt.Errorf("read schedule investigation: %w", err)
	}
	if err := validateFacts(facts, snapshot); err != nil {
		return Snapshot{}, err
	}
	return facts, nil
}

func validateFacts(facts Snapshot, expected application.InvestigationSnapshot) error {
	request := expected.Investigation.Request()
	if !facts.Eligible || facts.InvestigationID != request.ID || facts.ClusterID != request.ClusterID || facts.IncidentID != request.IncidentID || facts.JobID == "" || facts.SourceID == "" {
		return errors.New("schedule investigation admission is not eligible for the exact request")
	}
	if !sameRequest(facts.Current.Investigation.Request(), request) || !exactJobScope(request.Scope, facts.JobID) {
		return errors.New("schedule investigation scope does not match the durable request")
	}
	evidence := facts.Evidence
	if evidence.EvidenceID == "" || evidence.InvestigationID != request.ID || evidence.ClusterID != request.ClusterID || evidence.Status != domain.EvidenceComplete || !slices.Contains(evidence.EntityIDs, facts.JobID) || evidence.ObservedStart.IsZero() || evidence.ObservedEnd.IsZero() || evidence.RecordedAt.IsZero() || evidence.ObservedEnd.Before(evidence.ObservedStart) {
		return errors.New("schedule investigation evidence is not an exact complete job record")
	}
	return nil
}

func exactJobScope(scope domain.InvestigationScope, jobID string) bool {
	return scope.EntityKind == "collection_job" && len(scope.EntityIDs) == 1 && scope.EntityIDs[0] == jobID && !scope.Start.IsZero() && !scope.End.IsZero() && !scope.End.Before(scope.Start)
}

func sameRequest(left, right domain.InvestigationRequest) bool {
	return left.ID == right.ID && left.IncidentID == right.IncidentID && left.ClusterID == right.ClusterID && left.Scope.EntityKind == right.Scope.EntityKind && slices.Equal(left.Scope.EntityIDs, right.Scope.EntityIDs) && left.Scope.Start.Equal(right.Scope.Start) && left.Scope.End.Equal(right.Scope.End)
}

func actionFor(facts Snapshot, scope domain.InvestigationScope) domain.InvestigationAction {
	canonical := strings.Join([]string{"schedule-source-freshness-v1", string(facts.InvestigationID), string(facts.ClusterID), facts.JobID, string(facts.SourceID), string(facts.Evidence.EvidenceID), scope.Start.UTC().Format(time.RFC3339Nano), scope.End.UTC().Format(time.RFC3339Nano)}, "\x00")
	return domain.InvestigationAction{
		ID: domain.InvestigationActionID("schedule-source-freshness-" + string(facts.InvestigationID)), ToolID: SourceFreshnessToolID, Digest: domain.ChecksumSHA256([]byte(canonical)),
		FanOut: 1, Targets: []string{facts.JobID}, Start: scope.Start.UTC(), End: scope.End.UTC(),
		Arguments: []domain.InvestigationArgument{{Name: "cluster_id", Kind: "STRING", String: string(facts.ClusterID)}, {Name: "job_id", Kind: "STRING", String: facts.JobID}, {Name: "source_id", Kind: "STRING", String: string(facts.SourceID)}},
	}
}

func containsExactEvidence(ledger domain.EvidenceLedger, expected domain.InvestigationEvidence) bool {
	return slices.ContainsFunc(ledger.Entries(), func(entry domain.InvestigationEvidence) bool { return reflect.DeepEqual(entry, expected) })
}

func idFromKey(key string, actionID domain.InvestigationActionID) (domain.InvestigationID, error) {
	const prefix, separator = "investigation/", "/action/"
	if !strings.HasPrefix(key, prefix) {
		return "", errors.New("schedule investigation idempotency key is invalid")
	}
	parts := strings.Split(strings.TrimPrefix(key, prefix), separator)
	if len(parts) != 2 || parts[0] == "" || parts[1] != string(actionID) {
		return "", errors.New("schedule investigation idempotency key is invalid")
	}
	return domain.InvestigationID(parts[0]), nil
}

var (
	_ application.InvestigationPlanner     = (*Planner)(nil)
	_ application.InvestigationSynthesizer = (*Planner)(nil)
	_ application.InvestigationExecutor    = (*Planner)(nil)
)
