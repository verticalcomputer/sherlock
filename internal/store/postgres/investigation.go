package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

type InvestigationStore struct{ pool *pgxpool.Pool }

func NewInvestigationStore(pool *pgxpool.Pool) (*InvestigationStore, error) {
	if pool == nil {
		return nil, fmt.Errorf("PostgreSQL pool is required")
	}
	return &InvestigationStore{pool: pool}, nil
}

func (store *InvestigationStore) HasInvestigationActionDigest(ctx context.Context, id domain.InvestigationID, digest domain.SHA256) (bool, error) {
	var exists bool
	err := store.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM investigation_actions WHERE investigation_id=$1 AND action_digest=$2)`, id, digest[:]).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check investigation action digest: %w", err)
	}
	return exists, nil
}

// maxDiagnosticFreshnessTargets matches the catalog's per-call target ceiling,
// so a well-formed proposal always fits and a malformed one fails closed.
const maxDiagnosticFreshnessTargets = 256

func (store *InvestigationStore) HasClusterInvestigationActionDigest(ctx context.Context, clusterID domain.ClusterID, digest domain.SHA256) (bool, error) {
	if clusterID == "" || digest == (domain.SHA256{}) {
		return false, fmt.Errorf("cluster action digest lookup is invalid")
	}
	var exists bool
	err := store.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM investigation_actions WHERE cluster_id=$1 AND action_digest=$2 AND status IN ('SUCCEEDED','FAILED','REJECTED'))`, clusterID, digest[:]).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check cluster investigation action digest: %w", err)
	}
	return exists, nil
}

// LatestInvestigationDiagnostics reports, per target, when this investigation
// last completed a successful execution of one diagnostic definition. It
// answers the recency question the freshness novelty rule asks; it never
// reports a failed, rejected, or still-dispatched attempt as a result.
func (store *InvestigationStore) LatestInvestigationDiagnostics(ctx context.Context, investigationID domain.InvestigationID, toolID string, targets []string, notBefore time.Time) (map[string]time.Time, error) {
	if investigationID == "" {
		return nil, fmt.Errorf("investigation diagnostic freshness lookup is invalid")
	}
	return store.latestDiagnostics(ctx, `investigation_id`, string(investigationID), toolID, targets, notBefore)
}

// LatestClusterDiagnostics is the cluster-scoped tier, matching the two-tier
// deduplication that already applies to evidence lookups: a probe another
// investigation ran moments ago on the same host is just as current.
func (store *InvestigationStore) LatestClusterDiagnostics(ctx context.Context, clusterID domain.ClusterID, toolID string, targets []string, notBefore time.Time) (map[string]time.Time, error) {
	if clusterID == "" {
		return nil, fmt.Errorf("cluster diagnostic freshness lookup is invalid")
	}
	return store.latestDiagnostics(ctx, `cluster_id`, string(clusterID), toolID, targets, notBefore)
}

func (store *InvestigationStore) latestDiagnostics(ctx context.Context, scopeColumn, scopeValue, toolID string, targets []string, notBefore time.Time) (map[string]time.Time, error) {
	if toolID == "" || len(targets) == 0 || len(targets) > maxDiagnosticFreshnessTargets || notBefore.IsZero() {
		return nil, fmt.Errorf("diagnostic freshness lookup is invalid")
	}
	// scopeColumn is a package-private literal, never a caller-supplied value.
	query := `SELECT target, max(a.completed_at) FROM investigation_actions a,
		LATERAL jsonb_array_elements_text(a.arguments->'targets') AS target
		WHERE a.` + scopeColumn + `=$1 AND a.tool_id=$2 AND a.operation='DIAGNOSTIC' AND a.status='SUCCEEDED'
		AND a.completed_at IS NOT NULL AND a.completed_at > $3 AND target = ANY($4)
		GROUP BY target`
	rows, err := store.pool.Query(ctx, query, scopeValue, toolID, notBefore.UTC(), targets)
	if err != nil {
		return nil, fmt.Errorf("query diagnostic freshness: %w", err)
	}
	defer rows.Close()
	result := make(map[string]time.Time, len(targets))
	for rows.Next() {
		var target string
		var at time.Time
		if err := rows.Scan(&target, &at); err != nil {
			return nil, fmt.Errorf("scan diagnostic freshness: %w", err)
		}
		result[target] = at.UTC()
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read diagnostic freshness: %w", err)
	}
	return result, nil
}

// FindInvestigationEvidence returns only immutable envelope references that
// were already committed when the investigation was requested. Artifact bodies
// and source credentials are deliberately outside this query boundary.
func (store *InvestigationStore) FindInvestigationEvidence(ctx context.Context, investigationID domain.InvestigationID, clusterID domain.ClusterID, targets []string, start, end, committedBefore time.Time, limit int) ([]domain.InvestigationEvidence, bool, error) {
	return store.findInvestigationEvidence(ctx, investigationID, clusterID, targets, start, end, committedBefore, nil, limit, false)
}

func (store *InvestigationStore) FindInvestigationEvidenceByOperations(ctx context.Context, investigationID domain.InvestigationID, clusterID domain.ClusterID, targets []string, start, end, committedBefore time.Time, operations []domain.EvidenceOperationID, limit int) ([]domain.InvestigationEvidence, bool, error) {
	if len(operations) == 0 || len(operations) > 32 {
		return nil, false, fmt.Errorf("investigation evidence operation filter is required")
	}
	seen := make(map[domain.EvidenceOperationID]struct{}, len(operations))
	for _, operation := range operations {
		if operation == "" {
			return nil, false, fmt.Errorf("investigation evidence operation filter is invalid")
		}
		if _, duplicate := seen[operation]; duplicate {
			return nil, false, fmt.Errorf("investigation evidence operation filter contains a duplicate")
		}
		seen[operation] = struct{}{}
	}
	return store.findInvestigationEvidence(ctx, investigationID, clusterID, targets, start, end, committedBefore, operations, limit, false)
}

func (store *InvestigationStore) findInvestigationEvidence(ctx context.Context, investigationID domain.InvestigationID, clusterID domain.ClusterID, targets []string, start, end, committedBefore time.Time, operations []domain.EvidenceOperationID, limit int, currentWarnings bool) ([]domain.InvestigationEvidence, bool, error) {
	return findInvestigationEvidence(ctx, store.pool, investigationID, clusterID, targets, start, end, committedBefore, operations, limit, currentWarnings, nil)
}

type investigationEvidenceQuerier interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

func findInvestigationEvidence(ctx context.Context, query investigationEvidenceQuerier, investigationID domain.InvestigationID, clusterID domain.ClusterID, targets []string, start, end, committedBefore time.Time, operations []domain.EvidenceOperationID, limit int, currentWarnings bool, frozenIDs []string) ([]domain.InvestigationEvidence, bool, error) {
	if investigationID == "" || clusterID == "" || len(targets) == 0 || start.IsZero() || end.Before(start) || committedBefore.IsZero() || limit < 1 || limit > 256 {
		return nil, false, fmt.Errorf("investigation evidence query is invalid")
	}
	prefix := "WITH ranked AS (SELECT e.*, 1 AS stream_rank FROM evidence_envelopes e) "
	if currentWarnings {
		prefix = `
		WITH ranked AS (
            SELECT e.*, row_number() OVER (
                PARTITION BY e.source_id,e.operation,
                CASE WHEN e.run_id IS NOT NULL THEN 'collection:' || coalesce(nullif(w.node_filter,''),'cluster') ELSE 'targets:' || e.coverage_expected::text END
                ORDER BY e.collected_at DESC,e.created_at DESC,e.evidence_id DESC
            ) AS stream_rank
            FROM evidence_envelopes e LEFT JOIN collector_work_items w ON w.run_id=e.run_id
            WHERE e.cluster_id=$1 AND e.created_at <= $4
        )
`
	}
	rows, err := query.Query(ctx, prefix+`
        SELECT evidence_id,status,observed_start,observed_end,collected_at,coverage_expected,coverage_covered
        FROM ranked evidence_envelopes
		WHERE cluster_id=$1 AND ($9 OR (observed_start <= $3 AND observed_end >= $2))
		  AND created_at <= $4
		  AND (($10::text[] IS NOT NULL AND evidence_id=ANY($10::text[])) OR ($10::text[] IS NULL AND (NOT $9 OR (stream_rank=1 AND (status <> 'COMPLETE' OR artifact_availability NOT IN ('NONE','AVAILABLE'))))))
		  AND operation NOT LIKE 'model\_%' ESCAPE '\'
		  AND (COALESCE(cardinality($7::text[]),0)=0 OR operation=ANY($7::text[]))
		  AND (NOT $11 OR EXISTS (
		    SELECT 1 FROM investigations current_investigation JOIN incident_evidence ie
		      ON ie.incident_id=current_investigation.incident_id
		    WHERE current_investigation.investigation_id=$8 AND current_investigation.cluster_id=$1
		      AND ie.evidence_id=evidence_envelopes.evidence_id
		  ))
		  AND ($10::text[] IS NOT NULL OR NOT EXISTS (
		    SELECT 1 FROM investigation_evidence attached
		    WHERE attached.investigation_id=$8 AND attached.evidence_id=evidence_envelopes.evidence_id
		  ))
		  AND ($9 OR EXISTS (
		    SELECT 1 FROM jsonb_array_elements(coverage_expected || coverage_covered) AS target
		    WHERE target->>'ID'=ANY($5::text[])
		  ))
		ORDER BY collected_at DESC,evidence_id DESC LIMIT $6`, clusterID, start.UTC(), end.UTC(), committedBefore.UTC(), targets, limit+1, operations, investigationID, currentWarnings, frozenIDs,
		len(operations) == 2 && slices.Contains(operations, domain.EvidenceOperationID("slurm.job_failures.v1")) && slices.Contains(operations, domain.EvidenceOperationID(slurmCorrelationOperation)))
	if err != nil {
		return nil, false, fmt.Errorf("query investigation evidence: %w", err)
	}
	defer rows.Close()
	entries := make([]domain.InvestigationEvidence, 0, limit+1)
	for rows.Next() {
		var entry domain.InvestigationEvidence
		var expectedJSON, coveredJSON []byte
		entry.InvestigationID, entry.ClusterID = investigationID, clusterID
		if err := rows.Scan(&entry.EvidenceID, &entry.Status, &entry.ObservedStart, &entry.ObservedEnd, &entry.RecordedAt, &expectedJSON, &coveredJSON); err != nil {
			return nil, false, fmt.Errorf("scan investigation evidence: %w", err)
		}
		var expected, covered []domain.EvidenceTarget
		if err := json.Unmarshal(expectedJSON, &expected); err != nil {
			return nil, false, fmt.Errorf("decode expected investigation evidence coverage: %w", err)
		}
		if err := json.Unmarshal(coveredJSON, &covered); err != nil {
			return nil, false, fmt.Errorf("decode covered investigation evidence coverage: %w", err)
		}
		for _, target := range targets {
			if currentWarnings || evidenceTargetsContain(expected, target) || evidenceTargetsContain(covered, target) {
				entry.EntityIDs = append(entry.EntityIDs, target)
			}
		}
		if len(entry.EntityIDs) != 0 {
			entry.ObservedStart = entry.ObservedStart.UTC()
			entry.ObservedEnd = entry.ObservedEnd.UTC()
			entry.RecordedAt = entry.RecordedAt.UTC()
			entries = append(entries, entry)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("iterate investigation evidence: %w", err)
	}
	more := len(entries) > limit
	if more {
		entries = entries[:limit]
	}
	return entries, more, nil
}

func evidenceTargetsContain(values []domain.EvidenceTarget, id string) bool {
	return slices.ContainsFunc(values, func(value domain.EvidenceTarget) bool { return string(value.ID) == id })
}

func (store *InvestigationStore) CreateInvestigation(ctx context.Context, snapshot application.InvestigationSnapshot, event domain.InvestigationEvent) (bool, error) {
	request := snapshot.Investigation.Request()
	if err := request.Validate(); err != nil {
		return false, err
	}
	scope, err := json.Marshal(struct {
		EntityKind string   `json:"entity_kind"`
		EntityIDs  []string `json:"entity_ids"`
	}{EntityKind: request.Scope.EntityKind, EntityIDs: request.Scope.EntityIDs})
	if err != nil {
		return false, fmt.Errorf("encode investigation scope: %w", err)
	}
	criteria, err := json.Marshal(request.SuccessCriteria)
	if err != nil {
		return false, fmt.Errorf("encode investigation success criteria: %w", err)
	}
	requestHash, err := investigationRequestHash(request)
	if err != nil {
		return false, err
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return false, fmt.Errorf("begin investigation creation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var priorID string
	var priorHash []byte
	err = tx.QueryRow(ctx, `SELECT resource_id,request_hash FROM investigation_idempotency_records WHERE cluster_id=$1 AND operation='CREATE_INVESTIGATION' AND idempotency_key=$2 AND status='COMPLETED'`, request.ClusterID, request.IdempotencyKey).Scan(&priorID, &priorHash)
	if err == nil {
		if priorID != string(request.ID) || !bytes.Equal(priorHash, requestHash[:]) {
			return false, application.ErrInvestigationConflict
		}
		return false, tx.Commit(ctx)
	}
	if err != pgx.ErrNoRows {
		return false, fmt.Errorf("load investigation idempotency record: %w", err)
	}
	// Repair purpose explicitly requests every current warning. Freeze the exact
	// ranked identities and normalize their window in this admission transaction;
	// a later warning (even backdated) must never change this proposal's scope.
	var repairIDs []string
	if request.Purpose == domain.InvestigationPurposeRepairPlan {
		entries, more, queryErr := findInvestigationEvidence(ctx, tx, request.ID, request.ClusterID, request.Scope.EntityIDs, request.Scope.Start, request.Scope.End, request.RequestedAt, nil, 256, true, nil)
		if queryErr != nil {
			return false, queryErr
		}
		if more {
			return false, application.ClassifyInvestigationFailure(fmt.Errorf("repair warning snapshot exceeds 256 items"), application.FailureRepairSnapshot)
		}
		repairIDs = make([]string, 0, len(entries))
		for _, entry := range entries {
			repairIDs = append(repairIDs, string(entry.EvidenceID))
			if entry.ObservedStart.Before(request.Scope.Start) {
				request.Scope.Start = entry.ObservedStart
			}
			if entry.ObservedEnd.After(request.Scope.End) {
				request.Scope.End = entry.ObservedEnd
			}
		}
		if err := request.Validate(); err != nil {
			return false, err
		}
	}
	completedAt := any(nil)
	if snapshot.Investigation.Status().Terminal() {
		completedAt = event.OccurredAt.UTC()
	}
	_, err = tx.Exec(ctx, `INSERT INTO investigations (investigation_id,cluster_id,incident_id,question,requested_by,scope,window_start,window_end,success_criteria,status,stop_reason,version,created_at,updated_at,completed_at,purpose) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$13,$14,$15)`,
		request.ID, request.ClusterID, request.IncidentID, request.Question, request.RequestedBy, scope, request.Scope.Start.UTC(), request.Scope.End.UTC(), criteria, snapshot.Investigation.Status(), snapshot.Investigation.StopReason(), snapshot.Investigation.Version(), request.RequestedAt.UTC(), completedAt, request.Purpose)
	if err != nil {
		return false, fmt.Errorf("insert investigation %s: %w", request.ID, err)
	}
	if repairIDs != nil {
		if _, err := tx.Exec(ctx, `UPDATE investigations SET repair_warning_ids=$2 WHERE investigation_id=$1`, request.ID, repairIDs); err != nil {
			return false, fmt.Errorf("freeze repair warnings: %w", err)
		}
	}
	b := request.Budget
	_, err = tx.Exec(ctx, `INSERT INTO investigation_budgets (investigation_id,cluster_id,deadline,max_decision_iterations,max_tool_calls,max_diagnostic_calls,max_privileged_calls,max_fan_out,max_model_tokens,max_cost_microunits) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, request.ID, request.ClusterID, request.Deadline.UTC(), b.MaxDecisions, b.MaxToolCalls, b.MaxDiagnosticCalls, b.MaxPrivilegedCalls, b.MaxFanOut, b.MaxModelTokens, b.MaxCostMicros)
	if err != nil {
		return false, fmt.Errorf("insert investigation budget: %w", err)
	}
	if err := appendInvestigationEvent(ctx, tx, request.ClusterID, snapshot.Investigation, event); err != nil {
		return false, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO investigation_idempotency_records (cluster_id,operation,idempotency_key,request_hash,status,resource_kind,resource_id,response_code,created_at,completed_at) VALUES ($1,'CREATE_INVESTIGATION',$2,$3,'COMPLETED','INVESTIGATION',$4,201,$5,$5)`, request.ClusterID, request.IdempotencyKey, requestHash[:], request.ID, event.OccurredAt.UTC())
	if err != nil {
		return false, fmt.Errorf("insert investigation idempotency record: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("commit investigation creation: %w", err)
	}
	return true, nil
}

func investigationRequestHash(request domain.InvestigationRequest) (domain.SHA256, error) {
	canonical := struct {
		Purpose         string                     `json:"purpose,omitempty"`
		IncidentID      domain.IncidentID          `json:"incident_id"`
		ClusterID       domain.ClusterID           `json:"cluster_id"`
		Question        string                     `json:"question"`
		RequestedBy     string                     `json:"requested_by"`
		Scope           domain.InvestigationScope  `json:"scope"`
		SuccessCriteria []string                   `json:"success_criteria"`
		Budget          domain.InvestigationBudget `json:"budget"`
		Deadline        time.Time                  `json:"deadline"`
	}{
		IncidentID: request.IncidentID, ClusterID: request.ClusterID, Question: request.Question, Purpose: request.Purpose,
		RequestedBy: request.RequestedBy, Scope: request.Scope, SuccessCriteria: request.SuccessCriteria,
		Budget: request.Budget, Deadline: request.Deadline.UTC(),
	}
	payload, err := json.Marshal(canonical)
	if err != nil {
		return domain.SHA256{}, fmt.Errorf("encode investigation idempotency request: %w", err)
	}
	return domain.ChecksumSHA256(payload), nil
}

func (store *InvestigationStore) LoadInvestigation(ctx context.Context, id domain.InvestigationID) (application.InvestigationSnapshot, bool, error) {
	var request domain.InvestigationRequest
	var scopeJSON, criteriaJSON []byte
	var status domain.InvestigationStatus
	var stop domain.InvestigationStopReason
	var version int
	request.ID = id
	var requestedOutcome domain.InvestigationStatus
	var requestedStop domain.InvestigationStopReason
	err := store.pool.QueryRow(ctx, `SELECT i.purpose,i.incident_id,i.cluster_id,i.question,i.requested_by,i.scope,i.window_start,i.window_end,i.success_criteria,i.status,i.stop_reason,i.requested_outcome,i.requested_stop_reason,i.version,i.created_at,b.deadline,b.max_decision_iterations,b.max_tool_calls,b.max_diagnostic_calls,b.max_privileged_calls,b.max_fan_out,b.max_model_tokens,b.max_cost_microunits FROM investigations i JOIN investigation_budgets b USING (investigation_id) WHERE i.investigation_id=$1`, id).Scan(
		&request.Purpose, &request.IncidentID, &request.ClusterID, &request.Question, &request.RequestedBy, &scopeJSON, &request.Scope.Start, &request.Scope.End, &criteriaJSON, &status, &stop, &requestedOutcome, &requestedStop, &version, &request.RequestedAt, &request.Deadline, &request.Budget.MaxDecisions, &request.Budget.MaxToolCalls, &request.Budget.MaxDiagnosticCalls, &request.Budget.MaxPrivilegedCalls, &request.Budget.MaxFanOut, &request.Budget.MaxModelTokens, &request.Budget.MaxCostMicros)
	if err == pgx.ErrNoRows {
		return application.InvestigationSnapshot{}, false, nil
	}
	if err != nil {
		return application.InvestigationSnapshot{}, false, fmt.Errorf("load investigation %s: %w", id, err)
	}
	var usage domain.InvestigationBudgetUsage
	// The final six scanned values are loaded separately to keep the row mapper
	// explicit and resilient to the domain request shape.
	err = store.pool.QueryRow(ctx, `SELECT used_decision_iterations,used_tool_calls,used_diagnostic_calls,used_privileged_calls,used_fan_out,used_model_tokens,used_cost_microunits FROM investigation_budgets WHERE investigation_id=$1`, id).Scan(&usage.Decisions, &usage.ToolCalls, &usage.DiagnosticCalls, &usage.PrivilegedCalls, &usage.FanOut, &usage.ModelTokens, &usage.CostMicros)
	if err != nil {
		return application.InvestigationSnapshot{}, false, fmt.Errorf("load investigation usage: %w", err)
	}
	var rawScope struct {
		EntityKind string   `json:"entity_kind"`
		EntityIDs  []string `json:"entity_ids"`
	}
	if err := json.Unmarshal(scopeJSON, &rawScope); err != nil {
		return application.InvestigationSnapshot{}, false, fmt.Errorf("decode investigation scope: %w", err)
	}
	request.Scope.EntityKind, request.Scope.EntityIDs = rawScope.EntityKind, rawScope.EntityIDs
	if err := json.Unmarshal(criteriaJSON, &request.SuccessCriteria); err != nil {
		return application.InvestigationSnapshot{}, false, fmt.Errorf("decode success criteria: %w", err)
	}
	// Idempotency is stored separately so the public key is never inferred from
	// identity. It is required to revalidate the aggregate.
	if err := store.pool.QueryRow(ctx, `SELECT idempotency_key FROM investigation_idempotency_records WHERE cluster_id=$1 AND operation='CREATE_INVESTIGATION' AND resource_id=$2 AND status='COMPLETED'`, request.ClusterID, id).Scan(&request.IdempotencyKey); err != nil {
		return application.InvestigationSnapshot{}, false, fmt.Errorf("load investigation idempotency key: %w", err)
	}

	var action *domain.InvestigationAction
	var actionValue domain.InvestigationAction
	var digest []byte
	var privilege string
	var operation string
	var actionStatus string
	var executionReceipt string
	var diagnosticRunID domain.DiagnosticRunID
	var actionArguments []byte
	err = store.pool.QueryRow(ctx, `SELECT action_id,tool_id,action_digest,privilege,operation,arguments,status,COALESCE(execution_receipt,''),COALESCE(diagnostic_run_id,'') FROM investigation_actions WHERE investigation_id=$1 AND status NOT IN ('FAILED','REJECTED','CANCELLED') ORDER BY created_at DESC LIMIT 1`, id).Scan(&actionValue.ID, &actionValue.ToolID, &digest, &privilege, &operation, &actionArguments, &actionStatus, &executionReceipt, &diagnosticRunID)
	if err != nil && err != pgx.ErrNoRows {
		return application.InvestigationSnapshot{}, false, fmt.Errorf("load investigation action: %w", err)
	}
	if err == nil {
		copy(actionValue.Digest[:], digest)
		actionValue.Privileged = privilege == "PRIVILEGED"
		actionValue.Diagnostic = operation == "DIAGNOSTIC"
		if err := decodeInvestigationActionArguments(actionArguments, &actionValue); err != nil {
			return application.InvestigationSnapshot{}, false, err
		}
		action = &actionValue
	}
	if (status == domain.InvestigationPlanning && actionStatus == "SUCCEEDED") || status == domain.InvestigationSynthesizing || status.Terminal() {
		action = nil
	}
	pending := action
	if status != domain.InvestigationAwaitingApproval {
		pending = nil
	}
	investigation, err := domain.ReconstituteInvestigation(request, status, stop, usage, pending, version)
	if err != nil {
		return application.InvestigationSnapshot{}, false, fmt.Errorf("reconstitute investigation: %w", err)
	}
	snapshot := application.InvestigationSnapshot{Investigation: investigation, ProposedAction: action, RequestedOutcome: requestedOutcome, RequestedStop: requestedStop, ExecutionReceipt: executionReceipt, DiagnosticRunID: diagnosticRunID}
	rows, err := store.pool.Query(ctx, `SELECT evidence_id,status,exact_scope,observed_start,observed_end,recorded_at FROM investigation_evidence WHERE investigation_id=$1 AND evidence_id IS NOT NULL ORDER BY sequence`, id)
	if err != nil {
		return application.InvestigationSnapshot{}, false, fmt.Errorf("load investigation evidence: %w", err)
	}
	defer rows.Close()
	var evidenceEntries []domain.InvestigationEvidence
	for rows.Next() {
		var entry domain.InvestigationEvidence
		var exact []byte
		entry.InvestigationID, entry.ClusterID = id, request.ClusterID
		if err := rows.Scan(&entry.EvidenceID, &entry.Status, &exact, &entry.ObservedStart, &entry.ObservedEnd, &entry.RecordedAt); err != nil {
			return application.InvestigationSnapshot{}, false, err
		}
		var value struct {
			EntityIDs []string `json:"entity_ids"`
		}
		if err := json.Unmarshal(exact, &value); err != nil {
			return application.InvestigationSnapshot{}, false, err
		}
		entry.EntityIDs = value.EntityIDs
		evidenceEntries = append(evidenceEntries, entry)
	}
	if err := rows.Err(); err != nil {
		return application.InvestigationSnapshot{}, false, err
	}
	snapshot.Evidence, err = domain.NewEvidenceLedger(evidenceEntries, investigation)
	if err != nil {
		return application.InvestigationSnapshot{}, false, err
	}
	snapshot.PriorActions, err = loadInvestigationActionHistory(ctx, store.pool, id)
	if err != nil {
		return application.InvestigationSnapshot{}, false, err
	}
	hypothesisRows, err := store.pool.Query(ctx, `SELECT hypothesis_id,statement,status,confidence,unresolved_tests,version FROM investigation_hypotheses WHERE investigation_id=$1 ORDER BY hypothesis_id`, id)
	if err != nil {
		return application.InvestigationSnapshot{}, false, fmt.Errorf("load investigation hypotheses: %w", err)
	}
	var hypotheses []domain.Hypothesis
	for hypothesisRows.Next() {
		var value domain.Hypothesis
		var unresolved []byte
		value.InvestigationID = id
		if err := hypothesisRows.Scan(&value.ID, &value.Statement, &value.Status, &value.Confidence, &unresolved, &value.Version); err != nil {
			hypothesisRows.Close()
			return application.InvestigationSnapshot{}, false, err
		}
		if err := json.Unmarshal(unresolved, &value.UnresolvedTests); err != nil {
			hypothesisRows.Close()
			return application.InvestigationSnapshot{}, false, err
		}
		citations, err := loadHypothesisCitations(ctx, store.pool, id, value.ID)
		if err != nil {
			hypothesisRows.Close()
			return application.InvestigationSnapshot{}, false, err
		}
		value.SupportingEvidence, value.ContradictingEvidence = citations.supporting, citations.contradicting
		hypotheses = append(hypotheses, value)
	}
	hypothesisRows.Close()
	if snapshot.Hypotheses, err = domain.NewHypothesisLedger(hypotheses, snapshot.Evidence, investigation); err != nil {
		return application.InvestigationSnapshot{}, false, err
	}
	findingRows, err := store.pool.Query(ctx, `SELECT finding_id,kind,statement,scope,severity,confidence,status FROM investigation_findings WHERE investigation_id=$1 AND validation_status='VALID' ORDER BY finding_id`, id)
	if err != nil {
		return application.InvestigationSnapshot{}, false, fmt.Errorf("load investigation findings: %w", err)
	}
	var findings []domain.Finding
	for findingRows.Next() {
		var value domain.Finding
		var scope []byte
		value.InvestigationID = id
		if err := findingRows.Scan(&value.ID, &value.Kind, &value.Statement, &scope, &value.Severity, &value.Confidence, &value.Status); err != nil {
			findingRows.Close()
			return application.InvestigationSnapshot{}, false, err
		}
		var decoded struct {
			EntityIDs []string `json:"entity_ids"`
		}
		if err := json.Unmarshal(scope, &decoded); err != nil {
			findingRows.Close()
			return application.InvestigationSnapshot{}, false, err
		}
		value.EntityIDs = decoded.EntityIDs
		evidence, counter, err := loadFindingCitations(ctx, store.pool, id, value.ID)
		if err != nil {
			findingRows.Close()
			return application.InvestigationSnapshot{}, false, err
		}
		value.EvidenceIDs, value.CounterEvidenceIDs = evidence, counter
		findings = append(findings, value)
	}
	findingRows.Close()
	ledger, err := domain.NewFindingLedger(findings, snapshot.Evidence, investigation)
	if err != nil {
		return application.InvestigationSnapshot{}, false, err
	}
	snapshot.Findings = ledger.Entries()
	if snapshot.ReportSections, err = loadInvestigationReportSections(ctx, store.pool, id); err != nil {
		return application.InvestigationSnapshot{}, false, err
	}
	if snapshot.ReportOmissions, err = loadInvestigationReportOmissions(ctx, store.pool, id); err != nil {
		return application.InvestigationSnapshot{}, false, err
	}
	if snapshot.PrimaryActionCard, err = loadInvestigationActionCard(ctx, store.pool, investigation, snapshot.Evidence); err != nil {
		return application.InvestigationSnapshot{}, false, err
	}
	return snapshot, true, nil
}

func loadInvestigationActionCard(ctx context.Context, pool *pgxpool.Pool, investigation domain.Investigation, ledger domain.EvidenceLedger) (*domain.ActionCard, error) {
	request := investigation.Request()
	var card domain.ActionCard
	card.InvestigationID = request.ID
	err := pool.QueryRow(ctx, `SELECT action_card_id,owner,action,urgency,targets,rationale,blocking_gaps,escalation_condition FROM investigation_action_cards WHERE investigation_id=$1`, request.ID).Scan(
		&card.ID, &card.Owner, &card.Action, &card.Urgency, &card.Targets, &card.Rationale, &card.BlockingGaps, &card.EscalationCondition)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("load investigation action card: %w", err)
	}
	rows, err := pool.Query(ctx, `SELECT e.evidence_id FROM investigation_action_card_citations c JOIN investigation_evidence e USING (cluster_id,investigation_id,ledger_entry_id) WHERE c.investigation_id=$1 AND c.action_card_id=$2 ORDER BY e.evidence_id`, request.ID, card.ID)
	if err != nil {
		return nil, fmt.Errorf("load investigation action-card citations: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id domain.EvidenceID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		card.EvidenceIDs = append(card.EvidenceIDs, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate investigation action-card citations: %w", err)
	}
	if err := card.Validate(ledger, investigation); err != nil {
		return nil, fmt.Errorf("validate investigation action card: %w", err)
	}
	return &card, nil
}

func loadInvestigationReportSections(ctx context.Context, pool *pgxpool.Pool, investigationID domain.InvestigationID) ([]domain.ReportSection, error) {
	rows, err := pool.Query(ctx, `SELECT section_id,kind,ordinal,statement,observed_at FROM investigation_report_sections WHERE investigation_id=$1 ORDER BY kind,ordinal,section_id`, investigationID)
	if err != nil {
		return nil, fmt.Errorf("load investigation report sections: %w", err)
	}
	defer rows.Close()
	var sections []domain.ReportSection
	for rows.Next() {
		section := domain.ReportSection{InvestigationID: investigationID}
		if err := rows.Scan(&section.ID, &section.Kind, &section.Ordinal, &section.Statement, &section.ObservedAt); err != nil {
			return nil, err
		}
		sections = append(sections, section)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate investigation report sections: %w", err)
	}
	for index := range sections {
		citations, err := loadReportSectionCitations(ctx, pool, investigationID, sections[index].ID)
		if err != nil {
			return nil, err
		}
		sections[index].EvidenceIDs = citations
	}
	return sections, nil
}

func loadInvestigationReportOmissions(ctx context.Context, pool *pgxpool.Pool, investigationID domain.InvestigationID) ([]domain.ReportOmission, error) {
	rows, err := pool.Query(ctx, `SELECT kind,reason,omitted_count FROM investigation_report_omissions WHERE investigation_id=$1 ORDER BY kind,reason`, investigationID)
	if err != nil {
		return nil, fmt.Errorf("load investigation report omissions: %w", err)
	}
	defer rows.Close()
	var omissions []domain.ReportOmission
	for rows.Next() {
		omission := domain.ReportOmission{InvestigationID: investigationID}
		if err := rows.Scan(&omission.Kind, &omission.Reason, &omission.Count); err != nil {
			return nil, err
		}
		omissions = append(omissions, omission)
	}
	return omissions, rows.Err()
}

func loadReportSectionCitations(ctx context.Context, pool *pgxpool.Pool, investigationID domain.InvestigationID, sectionID domain.ReportSectionID) ([]domain.EvidenceID, error) {
	rows, err := pool.Query(ctx, `SELECT e.evidence_id FROM investigation_report_section_citations c JOIN investigation_evidence e USING (cluster_id,investigation_id,ledger_entry_id) WHERE c.investigation_id=$1 AND c.section_id=$2 ORDER BY e.evidence_id`, investigationID, sectionID)
	if err != nil {
		return nil, fmt.Errorf("load investigation report section citations: %w", err)
	}
	defer rows.Close()
	var citations []domain.EvidenceID
	for rows.Next() {
		var id domain.EvidenceID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		citations = append(citations, id)
	}
	return citations, rows.Err()
}

func loadInvestigationActionHistory(ctx context.Context, pool *pgxpool.Pool, investigationID domain.InvestigationID) ([]application.InvestigationActionHistory, error) {
	rows, err := pool.Query(ctx, `
		SELECT a.tool_id,a.action_digest,
		       CASE
		         WHEN a.status='SUCCEEDED' AND count(e.evidence_id)=0 THEN 'NO_EVIDENCE'
		         WHEN a.status='SUCCEEDED' AND bool_and(e.status='NO_DATA') THEN 'NO_EVIDENCE'
		         WHEN a.status='SUCCEEDED' AND bool_and(e.status='UNAVAILABLE') THEN 'UNAVAILABLE'
		         ELSE a.status
		       END,
		       a.arguments,
		       COALESCE(array_agg(e.evidence_id::text ORDER BY e.evidence_id) FILTER (WHERE e.evidence_id IS NOT NULL),ARRAY[]::text[])
		FROM investigation_actions a
		LEFT JOIN investigation_evidence e
		  ON e.investigation_id=a.investigation_id AND e.action_id=a.action_id
		WHERE a.investigation_id=$1 AND a.status IN ('SUCCEEDED','FAILED','REJECTED','CANCELLED')
		GROUP BY a.action_id,a.tool_id,a.action_digest,a.status,a.arguments,a.created_at
		ORDER BY a.created_at,a.action_id`, investigationID)
	if err != nil {
		return nil, fmt.Errorf("load investigation action history: %w", err)
	}
	defer rows.Close()
	var result []application.InvestigationActionHistory
	for rows.Next() {
		var value application.InvestigationActionHistory
		var digest, arguments []byte
		var evidenceIDs []string
		var action domain.InvestigationAction
		if err := rows.Scan(&value.ToolID, &digest, &value.Outcome, &arguments, &evidenceIDs); err != nil {
			return nil, fmt.Errorf("scan investigation action history: %w", err)
		}
		if len(digest) != len(value.Digest) {
			return nil, fmt.Errorf("investigation action history digest is invalid")
		}
		copy(value.Digest[:], digest)
		if err := decodeInvestigationActionArguments(arguments, &action); err != nil {
			return nil, err
		}
		value.Targets, value.Start, value.End = action.Targets, action.Start, action.End
		for _, evidenceID := range evidenceIDs {
			value.EvidenceIDs = append(value.EvidenceIDs, domain.EvidenceID(evidenceID))
		}
		result = append(result, value)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate investigation action history: %w", err)
	}
	return result, nil
}

type hypothesisCitations struct{ supporting, contradicting []domain.EvidenceID }

func loadHypothesisCitations(ctx context.Context, pool *pgxpool.Pool, investigationID domain.InvestigationID, hypothesisID domain.HypothesisID) (hypothesisCitations, error) {
	rows, err := pool.Query(ctx, `SELECT e.evidence_id,c.relationship FROM investigation_hypothesis_evidence c JOIN investigation_evidence e USING (cluster_id,investigation_id,ledger_entry_id) WHERE c.investigation_id=$1 AND c.hypothesis_id=$2 ORDER BY e.evidence_id,c.relationship`, investigationID, hypothesisID)
	if err != nil {
		return hypothesisCitations{}, err
	}
	defer rows.Close()
	var result hypothesisCitations
	for rows.Next() {
		var id domain.EvidenceID
		var relationship string
		if err := rows.Scan(&id, &relationship); err != nil {
			return hypothesisCitations{}, err
		}
		if relationship == "SUPPORTS" {
			result.supporting = append(result.supporting, id)
		} else {
			result.contradicting = append(result.contradicting, id)
		}
	}
	return result, rows.Err()
}

func loadFindingCitations(ctx context.Context, pool *pgxpool.Pool, investigationID domain.InvestigationID, findingID domain.FindingID) ([]domain.EvidenceID, []domain.EvidenceID, error) {
	rows, err := pool.Query(ctx, `SELECT e.evidence_id,c.relationship FROM investigation_finding_citations c JOIN investigation_evidence e USING (cluster_id,investigation_id,ledger_entry_id) WHERE c.investigation_id=$1 AND c.finding_id=$2 ORDER BY e.evidence_id,c.relationship`, investigationID, findingID)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var evidence, counter []domain.EvidenceID
	for rows.Next() {
		var id domain.EvidenceID
		var relationship string
		if err := rows.Scan(&id, &relationship); err != nil {
			return nil, nil, err
		}
		if relationship == "EVIDENCE" {
			evidence = append(evidence, id)
		} else {
			counter = append(counter, id)
		}
	}
	return evidence, counter, rows.Err()
}

func (store *InvestigationStore) SaveInvestigation(ctx context.Context, expectedVersion int, snapshot application.InvestigationSnapshot, event domain.InvestigationEvent) error {
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := saveInvestigationSnapshot(ctx, tx, expectedVersion, snapshot, event); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (store *InvestigationStore) RecordInvestigationApproval(ctx context.Context, approval domain.InvestigationApproval, expectedVersion int, snapshot application.InvestigationSnapshot, event domain.InvestigationEvent) error {
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	request := snapshot.Investigation.Request()
	_, err = tx.Exec(ctx, `INSERT INTO investigation_approvals (approval_id,cluster_id,investigation_id,action_id,action_digest,investigation_version,status,requested_by,requested_at,resolved_by,resolved_at,expires_at,consumed_at) VALUES ($1,$2,$3,$4,$5,$6,'CONSUMED',$7,$8,$7,$8,$9,$8)`, approval.ID, request.ClusterID, request.ID, approval.ActionID, approval.ActionDigest[:], approval.InvestigationVersion, approval.ApprovedBy, approval.ApprovedAt.UTC(), approval.ExpiresAt.UTC())
	if err != nil {
		return fmt.Errorf("insert investigation approval: %w", err)
	}
	if err := saveInvestigationSnapshot(ctx, tx, expectedVersion, snapshot, event); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func saveInvestigationSnapshot(ctx context.Context, tx pgx.Tx, expectedVersion int, snapshot application.InvestigationSnapshot, event domain.InvestigationEvent) error {
	investigation := snapshot.Investigation
	request := investigation.Request()
	completedAt := any(nil)
	if investigation.Status().Terminal() {
		completedAt = event.OccurredAt.UTC()
	}
	command, err := tx.Exec(ctx, `UPDATE investigations SET status=$3,stop_reason=$4,requested_outcome=$5,requested_stop_reason=$6,version=$7,updated_at=$8,completed_at=$9 WHERE investigation_id=$1 AND cluster_id=$2 AND version=$10`, request.ID, request.ClusterID, investigation.Status(), investigation.StopReason(), snapshot.RequestedOutcome, snapshot.RequestedStop, investigation.Version(), event.OccurredAt.UTC(), completedAt, expectedVersion)
	if err != nil {
		return fmt.Errorf("update investigation: %w", err)
	}
	if command.RowsAffected() != 1 {
		return application.ErrInvestigationConflict
	}
	u := investigation.Usage()
	_, err = tx.Exec(ctx, `UPDATE investigation_budgets SET used_decision_iterations=$2,used_tool_calls=$3,used_diagnostic_calls=$4,used_privileged_calls=$5,used_fan_out=$6,used_model_tokens=$7,used_cost_microunits=$8,version=version+1 WHERE investigation_id=$1`, request.ID, u.Decisions, u.ToolCalls, u.DiagnosticCalls, u.PrivilegedCalls, u.FanOut, u.ModelTokens, u.CostMicros)
	if err != nil {
		return fmt.Errorf("update investigation budget: %w", err)
	}
	if snapshot.ProposedAction != nil {
		a := snapshot.ProposedAction
		stepID := "step-" + string(a.ID)
		stepStatus := "AVAILABLE"
		_, err = tx.Exec(ctx, `INSERT INTO investigation_steps (step_id,cluster_id,investigation_id,step_key,kind,status,investigation_version,available_at) VALUES ($1,$2,$3,$1,'EXECUTE',$4,$5,$6) ON CONFLICT (investigation_id,step_key) DO NOTHING`, stepID, request.ClusterID, request.ID, stepStatus, investigation.Version(), event.OccurredAt.UTC())
		if err != nil {
			return fmt.Errorf("persist investigation step: %w", err)
		}
		actionStatus := "PROPOSED"
		completed := any(nil)
		receipt := any(nil)
		diagnosticRunID := any(nil)
		switch investigation.Status() {
		case domain.InvestigationAwaitingApproval:
			actionStatus = "NEEDS_APPROVAL"
		case domain.InvestigationExecuting:
			actionStatus = "DISPATCHED"
		case domain.InvestigationRecordingEvidence, domain.InvestigationUpdatingLedger:
			actionStatus = "SUCCEEDED"
			completed = event.OccurredAt.UTC()
			receipt = snapshot.ExecutionReceipt
			if a.Diagnostic {
				diagnosticRunID = snapshot.DiagnosticRunID
			}
		}
		privilege := "UNPRIVILEGED"
		if a.Privileged {
			privilege = "PRIVILEGED"
		}
		operation := "READ_ONLY"
		if a.Diagnostic {
			operation = "DIAGNOSTIC"
		}
		arguments, err := encodeInvestigationActionArguments(*a)
		if err != nil {
			return fmt.Errorf("encode investigation action arguments: %w", err)
		}
		command, err := tx.Exec(ctx, `INSERT INTO investigation_actions (action_id,cluster_id,investigation_id,step_id,action_key,tool_id,arguments,purpose,expected_information,action_digest,privilege,operation,status,execution_idempotency_key,diagnostic_run_id,execution_receipt,completed_at,completion_recorded_at) VALUES ($1,$2,$3,$4,$1,$5,$6,'deterministic investigation step','bounded evidence',$7,$8,$9,$10,$11,NULLIF($12,''),$13,$14,CASE WHEN $10 IN ('SUCCEEDED','FAILED','REJECTED','CANCELLED') THEN clock_timestamp() END) ON CONFLICT (action_id) DO UPDATE SET status=EXCLUDED.status,diagnostic_run_id=COALESCE(investigation_actions.diagnostic_run_id,EXCLUDED.diagnostic_run_id),execution_receipt=EXCLUDED.execution_receipt,completed_at=CASE WHEN investigation_actions.completed_at IS NULL THEN EXCLUDED.completed_at WHEN EXCLUDED.completed_at IS NULL THEN investigation_actions.completed_at ELSE GREATEST(investigation_actions.completed_at,EXCLUDED.completed_at) END,completion_recorded_at=COALESCE(investigation_actions.completion_recorded_at,EXCLUDED.completion_recorded_at) WHERE EXCLUDED.diagnostic_run_id IS NULL OR investigation_actions.diagnostic_run_id IS NULL OR investigation_actions.diagnostic_run_id=EXCLUDED.diagnostic_run_id`, a.ID, request.ClusterID, request.ID, stepID, a.ToolID, arguments, a.Digest[:], privilege, operation, actionStatus, "investigation/"+string(request.ID)+"/action/"+string(a.ID), diagnosticRunID, receipt, completed)
		if err != nil {
			return fmt.Errorf("persist investigation action: %w", err)
		}
		if command.RowsAffected() != 1 {
			return fmt.Errorf("persist investigation action: diagnostic run attribution conflicts with the durable action")
		}
	}
	for index, entry := range snapshot.PendingEvidence {
		if snapshot.ProposedAction == nil {
			return fmt.Errorf("persist investigation evidence without a proposed action")
		}
		exact, err := json.Marshal(struct {
			EntityIDs []string `json:"entity_ids"`
		}{EntityIDs: entry.EntityIDs})
		if err != nil {
			return fmt.Errorf("encode investigation evidence scope: %w", err)
		}
		sequence := event.Sequence*1000 + int64(index+1)
		_, err = tx.Exec(ctx, `INSERT INTO investigation_evidence (ledger_entry_id,cluster_id,investigation_id,sequence,action_id,evidence_id,entry_kind,status,exact_scope,observed_start,observed_end,recorded_at) VALUES ($1,$2,$3,$4,$5,$6,'OBSERVATION',$7,$8,$9,$10,$11) ON CONFLICT (investigation_id,evidence_id) DO NOTHING`, "ledger-"+domain.ChecksumSHA256([]byte(string(request.ID)+"\x00"+string(entry.EvidenceID))).String(), request.ClusterID, request.ID, sequence, snapshot.ProposedAction.ID, entry.EvidenceID, entry.Status, exact, entry.ObservedStart.UTC(), entry.ObservedEnd.UTC(), entry.RecordedAt.UTC())
		if err != nil {
			return fmt.Errorf("persist investigation evidence: %w", err)
		}
	}
	for _, hypothesis := range snapshot.Hypotheses.Entries() {
		unresolved, err := json.Marshal(hypothesis.UnresolvedTests)
		if err != nil {
			return fmt.Errorf("encode unresolved hypothesis tests: %w", err)
		}
		_, err = tx.Exec(ctx, `INSERT INTO investigation_hypotheses (hypothesis_id,cluster_id,investigation_id,statement,status,confidence,unresolved_tests,version,created_at,updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$9) ON CONFLICT (hypothesis_id) DO UPDATE SET statement=EXCLUDED.statement,status=EXCLUDED.status,confidence=EXCLUDED.confidence,unresolved_tests=EXCLUDED.unresolved_tests,version=EXCLUDED.version,updated_at=EXCLUDED.updated_at`, hypothesis.ID, request.ClusterID, request.ID, hypothesis.Statement, hypothesis.Status, hypothesis.Confidence, unresolved, hypothesis.Version, event.OccurredAt.UTC())
		if err != nil {
			return fmt.Errorf("persist investigation hypothesis: %w", err)
		}
		if _, err = tx.Exec(ctx, `DELETE FROM investigation_hypothesis_evidence WHERE investigation_id=$1 AND hypothesis_id=$2`, request.ID, hypothesis.ID); err != nil {
			return err
		}
		for _, evidenceID := range hypothesis.SupportingEvidence {
			if _, err = tx.Exec(ctx, `INSERT INTO investigation_hypothesis_evidence (cluster_id,investigation_id,hypothesis_id,ledger_entry_id,relationship) VALUES ($1,$2,$3,(SELECT ledger_entry_id FROM investigation_evidence WHERE cluster_id=$1 AND investigation_id=$2 AND evidence_id=$4),'SUPPORTS')`, request.ClusterID, request.ID, hypothesis.ID, evidenceID); err != nil {
				return err
			}
		}
		for _, evidenceID := range hypothesis.ContradictingEvidence {
			if _, err = tx.Exec(ctx, `INSERT INTO investigation_hypothesis_evidence (cluster_id,investigation_id,hypothesis_id,ledger_entry_id,relationship) VALUES ($1,$2,$3,(SELECT ledger_entry_id FROM investigation_evidence WHERE cluster_id=$1 AND investigation_id=$2 AND evidence_id=$4),'CONTRADICTS')`, request.ClusterID, request.ID, hypothesis.ID, evidenceID); err != nil {
				return err
			}
		}
	}
	for _, finding := range snapshot.Findings {
		scope, err := json.Marshal(struct {
			EntityIDs []string `json:"entity_ids"`
		}{EntityIDs: finding.EntityIDs})
		if err != nil {
			return fmt.Errorf("encode investigation finding scope: %w", err)
		}
		_, err = tx.Exec(ctx, `INSERT INTO investigation_findings (finding_id,cluster_id,investigation_id,kind,statement,scope,severity,confidence,status,validation_status,validation_code,created_at,validated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'VALID','',$10,$10) ON CONFLICT (finding_id) DO UPDATE SET statement=EXCLUDED.statement,scope=EXCLUDED.scope,severity=EXCLUDED.severity,confidence=EXCLUDED.confidence,status=EXCLUDED.status,validation_status='VALID',validation_code='',validated_at=EXCLUDED.validated_at`, finding.ID, request.ClusterID, request.ID, finding.Kind, finding.Statement, scope, finding.Severity, finding.Confidence, finding.Status, event.OccurredAt.UTC())
		if err != nil {
			return fmt.Errorf("persist investigation finding: %w", err)
		}
		if _, err = tx.Exec(ctx, `DELETE FROM investigation_finding_citations WHERE investigation_id=$1 AND finding_id=$2`, request.ID, finding.ID); err != nil {
			return err
		}
		for _, evidenceID := range finding.EvidenceIDs {
			if _, err = tx.Exec(ctx, `INSERT INTO investigation_finding_citations (cluster_id,investigation_id,finding_id,ledger_entry_id,relationship) VALUES ($1,$2,$3,(SELECT ledger_entry_id FROM investigation_evidence WHERE cluster_id=$1 AND investigation_id=$2 AND evidence_id=$4),'EVIDENCE')`, request.ClusterID, request.ID, finding.ID, evidenceID); err != nil {
				return err
			}
		}
		for _, evidenceID := range finding.CounterEvidenceIDs {
			if _, err = tx.Exec(ctx, `INSERT INTO investigation_finding_citations (cluster_id,investigation_id,finding_id,ledger_entry_id,relationship) VALUES ($1,$2,$3,(SELECT ledger_entry_id FROM investigation_evidence WHERE cluster_id=$1 AND investigation_id=$2 AND evidence_id=$4),'COUNTER_EVIDENCE')`, request.ClusterID, request.ID, finding.ID, evidenceID); err != nil {
				return err
			}
		}
	}
	for _, section := range snapshot.ReportSections {
		var observedAt any
		if section.ObservedAt != nil {
			observedAt = section.ObservedAt.UTC()
		}
		if _, err := tx.Exec(ctx, `INSERT INTO investigation_report_sections (section_id,cluster_id,investigation_id,kind,ordinal,statement,observed_at,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (section_id) DO UPDATE SET kind=EXCLUDED.kind,ordinal=EXCLUDED.ordinal,statement=EXCLUDED.statement,observed_at=EXCLUDED.observed_at`, section.ID, request.ClusterID, request.ID, section.Kind, section.Ordinal, section.Statement, observedAt, event.OccurredAt.UTC()); err != nil {
			return fmt.Errorf("persist investigation report section: %w", err)
		}
		if _, err := tx.Exec(ctx, `DELETE FROM investigation_report_section_citations WHERE investigation_id=$1 AND section_id=$2`, request.ID, section.ID); err != nil {
			return err
		}
		for _, evidenceID := range section.EvidenceIDs {
			if _, err := tx.Exec(ctx, `INSERT INTO investigation_report_section_citations (cluster_id,investigation_id,section_id,ledger_entry_id) VALUES ($1,$2,$3,(SELECT ledger_entry_id FROM investigation_evidence WHERE cluster_id=$1 AND investigation_id=$2 AND evidence_id=$4))`, request.ClusterID, request.ID, section.ID, evidenceID); err != nil {
				return err
			}
		}
	}
	for _, omission := range snapshot.ReportOmissions {
		// Held to the same gate as the findings, sections and action card around
		// it. An omission row is the report's account of its own losses, and one
		// naming a reason outside the reviewed set would misreport them.
		if err := omission.Validate(investigation); err != nil {
			return fmt.Errorf("validate investigation report omission: %w", err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO investigation_report_omissions (cluster_id,investigation_id,kind,reason,omitted_count,created_at) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (investigation_id,kind,reason) DO UPDATE SET omitted_count=EXCLUDED.omitted_count`, request.ClusterID, request.ID, omission.Kind, omission.Reason, omission.Count, event.OccurredAt.UTC()); err != nil {
			return fmt.Errorf("persist investigation report omission: %w", err)
		}
	}
	if snapshot.PrimaryActionCard != nil {
		card := snapshot.PrimaryActionCard
		if err := card.Validate(snapshot.Evidence, investigation); err != nil {
			return fmt.Errorf("validate investigation action card: %w", err)
		}
		_, err := tx.Exec(ctx, `INSERT INTO investigation_action_cards (investigation_id,cluster_id,action_card_id,owner,action,urgency,targets,rationale,blocking_gaps,escalation_condition,created_at,updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$11) ON CONFLICT (investigation_id) DO UPDATE SET action_card_id=EXCLUDED.action_card_id,owner=EXCLUDED.owner,action=EXCLUDED.action,urgency=EXCLUDED.urgency,targets=EXCLUDED.targets,rationale=EXCLUDED.rationale,blocking_gaps=EXCLUDED.blocking_gaps,escalation_condition=EXCLUDED.escalation_condition,updated_at=EXCLUDED.updated_at`, request.ID, request.ClusterID, card.ID, card.Owner, card.Action, card.Urgency, card.Targets, card.Rationale, card.BlockingGaps, card.EscalationCondition, event.OccurredAt.UTC())
		if err != nil {
			return fmt.Errorf("persist investigation action card: %w", err)
		}
		if _, err := tx.Exec(ctx, `DELETE FROM investigation_action_card_citations WHERE investigation_id=$1`, request.ID); err != nil {
			return fmt.Errorf("replace investigation action-card citations: %w", err)
		}
		for _, evidenceID := range card.EvidenceIDs {
			if _, err := tx.Exec(ctx, `INSERT INTO investigation_action_card_citations (cluster_id,investigation_id,action_card_id,ledger_entry_id) VALUES ($1,$2,$3,(SELECT ledger_entry_id FROM investigation_evidence WHERE cluster_id=$1 AND investigation_id=$2 AND evidence_id=$4))`, request.ClusterID, request.ID, card.ID, evidenceID); err != nil {
				return fmt.Errorf("persist investigation action-card citation: %w", err)
			}
		}
	}
	return appendInvestigationEvent(ctx, tx, request.ClusterID, investigation, event)
}

type investigationActionArguments struct {
	FanOut    int                           `json:"fan_out"`
	Targets   []string                      `json:"targets,omitempty"`
	Start     *time.Time                    `json:"start,omitempty"`
	End       *time.Time                    `json:"end,omitempty"`
	Arguments []investigationActionArgument `json:"arguments,omitempty"`
}

type investigationActionArgument struct {
	Name       string     `json:"name"`
	Kind       string     `json:"kind"`
	String     string     `json:"string,omitempty"`
	Integer    int64      `json:"integer,omitempty"`
	Boolean    bool       `json:"boolean,omitempty"`
	Timestamp  *time.Time `json:"timestamp,omitempty"`
	StringList []string   `json:"string_list,omitempty"`
}

func encodeInvestigationActionArguments(action domain.InvestigationAction) ([]byte, error) {
	value := investigationActionArguments{FanOut: action.FanOut, Targets: slices.Clone(action.Targets)}
	if !action.Start.IsZero() {
		start := action.Start.UTC()
		value.Start = &start
	}
	if !action.End.IsZero() {
		end := action.End.UTC()
		value.End = &end
	}
	for _, argument := range action.Arguments {
		item := investigationActionArgument{Name: argument.Name, Kind: argument.Kind, String: argument.String, Integer: argument.Integer, Boolean: argument.Boolean, StringList: slices.Clone(argument.StringList)}
		if !argument.Timestamp.IsZero() {
			timestamp := argument.Timestamp.UTC()
			item.Timestamp = &timestamp
		}
		value.Arguments = append(value.Arguments, item)
	}
	return json.Marshal(value)
}

func decodeInvestigationActionArguments(encoded []byte, action *domain.InvestigationAction) error {
	var value investigationActionArguments
	if err := json.Unmarshal(encoded, &value); err != nil {
		return fmt.Errorf("decode investigation action arguments: %w", err)
	}
	action.FanOut, action.Targets = value.FanOut, slices.Clone(value.Targets)
	if action.FanOut == 0 {
		action.FanOut = 1
	}
	if value.Start != nil {
		action.Start = value.Start.UTC()
	}
	if value.End != nil {
		action.End = value.End.UTC()
	}
	for _, item := range value.Arguments {
		argument := domain.InvestigationArgument{Name: item.Name, Kind: item.Kind, String: item.String, Integer: item.Integer, Boolean: item.Boolean, StringList: slices.Clone(item.StringList)}
		if item.Timestamp != nil {
			argument.Timestamp = item.Timestamp.UTC()
		}
		action.Arguments = append(action.Arguments, argument)
	}
	return nil
}

func appendInvestigationEvent(ctx context.Context, tx pgx.Tx, clusterID domain.ClusterID, investigation domain.Investigation, event domain.InvestigationEvent) error {
	if err := event.Validate(); err != nil {
		return err
	}
	if event.Details.StopReason != "" && event.Details.StopReason != investigation.StopReason() {
		return fmt.Errorf("event stop reason differs from investigation")
	}
	payload, err := json.Marshal(event.Details)
	if err != nil {
		return err
	}
	typeValue := string(event.Kind)
	switch event.Kind {
	case domain.InvestigationEventStateChanged:
		typeValue = "STATE_TRANSITION"
	case domain.InvestigationEventApprovalGranted:
		typeValue = "APPROVAL_RESOLVED"
	case domain.InvestigationEventEvidenceAdded:
		typeValue = "EVIDENCE_RECORDED"
	case domain.InvestigationEventFindingAdded:
		typeValue = "FINDING_PUBLISHED"
	}
	from, to := any(nil), any(nil)
	if event.Kind == domain.InvestigationEventStateChanged {
		from, to = event.From, event.To
	}
	_, err = tx.Exec(ctx, `INSERT INTO investigation_events (cluster_id,investigation_id,sequence,event_key,event_type,from_status,to_status,investigation_version,actor_id,payload,occurred_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT (investigation_id,event_key) DO NOTHING`, clusterID, event.InvestigationID, event.Sequence, event.ID, typeValue, from, to, investigation.Version(), investigation.Request().RequestedBy, payload, event.OccurredAt.UTC())
	if err != nil {
		return fmt.Errorf("append investigation event: %w", err)
	}
	return nil
}

// FindCurrentRepairEvidence freezes the latest warning for every source/operation/scope
// as of request admission. Ranking before filtering excludes superseded failures.
func (store *InvestigationStore) FindCurrentRepairEvidence(ctx context.Context, id domain.InvestigationID, cluster domain.ClusterID, start, end, before time.Time, limit int) ([]domain.InvestigationEvidence, bool, error) {
	var frozenIDs []string
	var admittedStart, admittedEnd, admittedBefore time.Time
	err := store.pool.QueryRow(ctx, `SELECT repair_warning_ids,window_start,window_end,created_at FROM investigations WHERE investigation_id=$1 AND cluster_id=$2`, id, cluster).Scan(&frozenIDs, &admittedStart, &admittedEnd, &admittedBefore)
	if err != nil && err != pgx.ErrNoRows {
		return nil, false, err
	}
	if frozenIDs != nil && (!start.Equal(admittedStart) || !end.Equal(admittedEnd) || !before.Equal(admittedBefore)) {
		return nil, false, application.ClassifyInvestigationFailure(fmt.Errorf("repair warning query differs from admitted scope"), application.FailureRepairSnapshot)
	}
	entries, more, err := findInvestigationEvidence(ctx, store.pool, id, cluster, []string{string(cluster)}, start, end, before, nil, limit, true, frozenIDs)
	if err != nil {
		return nil, false, err
	}
	if frozenIDs != nil && !more && len(entries) != len(frozenIDs) {
		return nil, false, application.ClassifyInvestigationFailure(fmt.Errorf("admitted repair warning evidence is unavailable"), application.FailureRepairSnapshot)
	}
	for _, entry := range entries {
		if entry.ObservedEnd.Before(start) || entry.ObservedStart.After(end) {
			return nil, false, application.ClassifyInvestigationFailure(fmt.Errorf("a current repair warning lies outside the requested scope; refresh the warning snapshot"), application.FailureRepairSnapshot)
		}
	}
	return entries, more, nil
}
