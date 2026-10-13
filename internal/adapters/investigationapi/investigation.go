package investigationapi

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	publicapi "github.com/verticalcomputer/sherlock/internal/api"
	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
	contract "github.com/verticalcomputer/sherlock/sdk/go"
)

func (service *Service) StartInvestigation(ctx context.Context, input publicapi.StartInvestigationInput) (publicapi.InvestigationResource, bool, error) {
	now := service.clock.Now().UTC()
	request := domain.InvestigationRequest{
		ID:         domain.InvestigationID(stableID("investigation-", input.ClusterID, input.IdempotencyKey)),
		IncidentID: domain.IncidentID(input.IncidentID), ClusterID: input.ClusterID, Question: input.Question,
		RequestedBy: input.ActorID, IdempotencyKey: input.IdempotencyKey, Purpose: input.Purpose,
		Scope:           domain.InvestigationScope{EntityKind: canonicalEntityKind(input.Scope.EntityKind), EntityIDs: input.Scope.EntityIDs, Start: input.Scope.Start, End: input.Scope.End},
		SuccessCriteria: input.SuccessCriteria,
		Budget:          domain.InvestigationBudget{MaxDecisions: input.Budget.MaxDecisions, MaxToolCalls: input.Budget.MaxToolCalls, MaxDiagnosticCalls: input.Budget.MaxDiagnosticCalls, MaxPrivilegedCalls: input.Budget.MaxPrivilegedCalls, MaxFanOut: input.Budget.MaxFanOut, MaxModelTokens: input.Budget.MaxModelTokens, MaxCostMicros: input.Budget.MaxCostMicros},
		RequestedAt:     now, Deadline: input.Deadline,
	}
	snapshot, created, err := service.controller.Start(ctx, application.StartInvestigationInput{Request: request})
	if err != nil {
		return publicapi.InvestigationResource{}, false, mapError(err)
	}
	item, err := service.mapInvestigation(ctx, snapshot)
	return item, !created, mapError(err)
}

// Public clients historically emitted upper-case entity kinds while the
// reviewed tool catalog uses lower-case identifiers. Canonicalize once at the
// application boundary so persisted authority and tool filtering cannot drift.
func canonicalEntityKind(value string) string { return strings.ToLower(value) }

func (service *Service) GetInvestigation(ctx context.Context, id string) (publicapi.InvestigationResource, bool, error) {
	snapshot, found, err := service.load(ctx, id)
	if err != nil || !found {
		return publicapi.InvestigationResource{}, found, mapError(err)
	}
	item, err := service.mapInvestigation(ctx, snapshot)
	return item, true, mapError(err)
}

func (service *Service) CancelInvestigation(ctx context.Context, input publicapi.CancelInvestigationInput) (publicapi.InvestigationResource, error) {
	snapshot, err := service.controller.CancelExpected(ctx, domain.InvestigationID(input.InvestigationID), input.ExpectedVersion)
	if err != nil {
		return publicapi.InvestigationResource{}, mapError(err)
	}
	return service.mapInvestigation(ctx, snapshot)
}

func (service *Service) ApproveInvestigation(ctx context.Context, input publicapi.ApproveInvestigationInput) (publicapi.InvestigationResource, error) {
	digest, err := domain.ParseSHA256(input.ActionSHA256)
	if err != nil {
		return publicapi.InvestigationResource{}, publicapi.ErrInvestigationInvalid
	}
	approval := domain.InvestigationApproval{ID: domain.InvestigationApprovalID(input.ApprovalID), InvestigationID: domain.InvestigationID(input.InvestigationID), ActionID: domain.InvestigationActionID(input.ActionID), ActionDigest: digest, InvestigationVersion: input.ExpectedVersion, ApprovedBy: input.ActorID, ApprovedAt: service.clock.Now().UTC(), ExpiresAt: input.ExpiresAt.UTC()}
	snapshot, err := service.controller.Approve(ctx, approval.InvestigationID, approval)
	if err != nil {
		return publicapi.InvestigationResource{}, mapError(err)
	}
	return service.mapInvestigation(ctx, snapshot)
}

func (service *Service) load(ctx context.Context, id string) (application.InvestigationSnapshot, bool, error) {
	return service.controllerSnapshot(ctx, domain.InvestigationID(id))
}

func (service *Service) controllerSnapshot(ctx context.Context, id domain.InvestigationID) (application.InvestigationSnapshot, bool, error) {
	// The controller intentionally exposes mutation only. Read paths use the
	// same durable store through this narrow adapter query.
	store, err := newSnapshotReader(service.pool)
	if err != nil {
		return application.InvestigationSnapshot{}, false, err
	}
	return store.LoadInvestigation(ctx, id)
}

func (service *Service) mapInvestigation(ctx context.Context, snapshot application.InvestigationSnapshot) (publicapi.InvestigationResource, error) {
	value := snapshot.Investigation
	request := value.Request()
	usage := value.Usage()
	item := publicapi.InvestigationResource{
		InvestigationID: string(request.ID), ClusterID: string(request.ClusterID), IncidentID: string(request.IncidentID), Question: request.Question,
		Scope:           publicapi.InvestigationScopeResource{EntityKind: request.Scope.EntityKind, EntityIDs: request.Scope.EntityIDs, Start: request.Scope.Start, End: request.Scope.End},
		SuccessCriteria: request.SuccessCriteria, Status: contract.InvestigationStatus(value.Status()), StopReason: string(value.StopReason()),
		Budget:    publicapi.InvestigationBudgetResource{MaxDecisions: request.Budget.MaxDecisions, MaxToolCalls: request.Budget.MaxToolCalls, MaxDiagnosticCalls: request.Budget.MaxDiagnosticCalls, MaxPrivilegedCalls: request.Budget.MaxPrivilegedCalls, MaxFanOut: request.Budget.MaxFanOut, MaxModelTokens: request.Budget.MaxModelTokens, MaxCostMicros: request.Budget.MaxCostMicros, DecisionsUsed: usage.Decisions, ToolCallsUsed: usage.ToolCalls, DiagnosticCallsUsed: usage.DiagnosticCalls, PrivilegedCallsUsed: usage.PrivilegedCalls, FanOutUsed: usage.FanOut, ModelTokensUsed: usage.ModelTokens, CostMicrosUsed: usage.CostMicros},
		CreatedBy: request.RequestedBy, CreatedAt: request.RequestedAt, Deadline: request.Deadline, Version: value.Version(), FindingIDs: []string{},
	}
	for _, finding := range snapshot.Findings {
		item.FindingIDs = append(item.FindingIDs, string(finding.ID))
	}
	if action, ok := value.PendingAction(); ok {
		item.PendingAction = &publicapi.InvestigationActionResource{ActionID: string(action.ID), ToolID: action.ToolID, ActionSHA256: action.Digest.String(), Privileged: action.Privileged, FanOut: action.FanOut}
	}
	var completed *time.Time
	if err := service.pool.QueryRow(ctx, `SELECT updated_at,completed_at FROM investigations WHERE investigation_id=$1`, request.ID).Scan(&item.UpdatedAt, &completed); err != nil {
		return publicapi.InvestigationResource{}, err
	}
	item.CompletedAt = completed
	return item, nil
}

func (service *Service) ListInvestigationEvents(ctx context.Context, id, lastEventID string, limit int) ([]publicapi.InvestigationEventResource, error) {
	after := int64(0)
	if lastEventID != "" {
		if strings.HasPrefix(lastEventID, "evt_") {
			parsed, err := strconv.ParseInt(strings.TrimPrefix(lastEventID, "evt_"), 10, 64)
			if err != nil {
				return nil, publicapi.ErrInvestigationInvalid
			}
			after = parsed
		} else if err := service.pool.QueryRow(ctx, `SELECT sequence FROM investigation_events WHERE investigation_id=$1 AND event_key=$2`, id, lastEventID).Scan(&after); err != nil {
			return nil, publicapi.ErrInvestigationInvalid
		}
	}
	rows, err := service.pool.Query(ctx, `SELECT event_key,cluster_id,sequence,event_type,COALESCE(from_status,''),COALESCE(to_status,''),payload,occurred_at FROM investigation_events WHERE investigation_id=$1 AND sequence>$2 ORDER BY sequence LIMIT $3`, id, after, limit)
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()
	var result []publicapi.InvestigationEventResource
	for rows.Next() {
		var item publicapi.InvestigationEventResource
		var payload []byte
		item.InvestigationID, item.SchemaVersion = id, domain.InvestigationSchemaVersion
		if err := rows.Scan(&item.EventID, &item.ClusterID, &item.Sequence, &item.Type, &item.FromStatus, &item.ToStatus, &payload, &item.OccurredAt); err != nil {
			return nil, mapError(err)
		}
		if err := json.Unmarshal(payload, &item.Attributes); err != nil {
			return nil, mapError(err)
		}
		result = append(result, item)
	}
	return result, mapError(rows.Err())
}

func (service *Service) ListInvestigationEvidence(ctx context.Context, id string) ([]publicapi.InvestigationEvidenceResource, error) {
	snapshot, found, err := service.load(ctx, id)
	if err != nil || !found {
		return nil, mapError(err)
	}
	values := snapshot.Evidence.Entries()
	result := make([]publicapi.InvestigationEvidenceResource, len(values))
	for index, value := range values {
		result[index] = publicapi.InvestigationEvidenceResource{InvestigationID: string(value.InvestigationID), EvidenceID: string(value.EvidenceID), ClusterID: string(value.ClusterID), EntityIDs: value.EntityIDs, RecordedAt: value.RecordedAt}
	}
	return result, nil
}

func (service *Service) ListInvestigationHypotheses(ctx context.Context, id string) ([]publicapi.HypothesisResource, error) {
	snapshot, found, err := service.load(ctx, id)
	if err != nil || !found {
		return nil, mapError(err)
	}
	values := snapshot.Hypotheses.Entries()
	result := make([]publicapi.HypothesisResource, len(values))
	for index, value := range values {
		result[index] = publicapi.HypothesisResource{HypothesisID: string(value.ID), InvestigationID: string(value.InvestigationID), Statement: value.Statement, Status: string(value.Status), Confidence: value.Confidence, SupportingEvidenceIDs: evidenceIDs(value.SupportingEvidence), CounterEvidenceIDs: evidenceIDs(value.ContradictingEvidence), UnresolvedTests: value.UnresolvedTests, Version: value.Version}
	}
	return result, nil
}

func (service *Service) ListInvestigationFindings(ctx context.Context, id string) ([]publicapi.FindingResource, error) {
	snapshot, found, err := service.load(ctx, id)
	if err != nil || !found {
		return nil, mapError(err)
	}
	result := make([]publicapi.FindingResource, len(snapshot.Findings))
	for index, value := range snapshot.Findings {
		result[index] = publicapi.FindingResource{FindingID: string(value.ID), InvestigationID: string(value.InvestigationID), Kind: string(value.Kind), Statement: value.Statement, EntityIDs: value.EntityIDs, Severity: value.Severity, Confidence: value.Confidence, EvidenceIDs: evidenceIDs(value.EvidenceIDs), CounterEvidenceIDs: evidenceIDs(value.CounterEvidenceIDs), Status: string(value.Status), ValidationStatus: "VALID", ValidationErrors: []string{}}
	}
	return result, nil
}

func evidenceIDs(values []domain.EvidenceID) []string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = string(value)
	}
	return result
}

var _ publicapi.InvestigationAPI = (*Service)(nil)
