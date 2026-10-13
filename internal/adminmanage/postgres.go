package adminmanage

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

const maxListLimit = 2000
const credentialRotationMaximumRecords = 1000

type PostgresStore struct {
	pool             *pgxpool.Pool
	payloads         ModelPayloadReader
	credentialCipher *credentialCipher
	// goodput is the canonical GP-02 fact writer. Expected inventory is only
	// ever recorded through it; leaving it unset disables import, it never
	// enables a second write path.
	goodput application.GoodputStore
}

type PostgresOption func(*PostgresStore) error

func WithModelPayloadReader(reader ModelPayloadReader) PostgresOption {
	return func(store *PostgresStore) error {
		if reader == nil {
			return fmt.Errorf("%w: model payload reader is required", ErrInvalid)
		}
		store.payloads = reader
		return nil
	}
}

// WithCredentialKeyring enables the bounded credential onboarding feature.
// Leaving it unset keeps credential operations disabled by default.
func WithCredentialKeyring(ring *CredentialKeyring) PostgresOption {
	return func(store *PostgresStore) error {
		cipher, err := newCredentialCipher(ring, rand.Reader)
		if err != nil {
			return fmt.Errorf("configure credential keyring: %w", err)
		}
		store.credentialCipher = cipher
		return nil
	}
}

func NewPostgresStore(pool *pgxpool.Pool, options ...PostgresOption) (*PostgresStore, error) {
	if pool == nil {
		return nil, fmt.Errorf("%w: PostgreSQL pool is required", ErrInvalid)
	}
	store := &PostgresStore{pool: pool}
	for _, option := range options {
		if option == nil {
			return nil, fmt.Errorf("%w: PostgreSQL store option is required", ErrInvalid)
		}
		if err := option(store); err != nil {
			return nil, err
		}
	}
	return store, nil
}

func (store *PostgresStore) ListClusters(ctx context.Context, includeRemoved bool, limit int) ([]Cluster, error) {
	if err := validateLimit(limit); err != nil {
		return nil, err
	}
	where := "WHERE removed_at IS NULL"
	if includeRemoved {
		where = ""
	}
	rows, err := store.pool.Query(ctx, `
		SELECT cluster_id, display_name, expected_collectors, created_at, removed_at
		FROM clusters `+where+`
		ORDER BY removed_at NULLS FIRST, display_name, cluster_id
		LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("list managed clusters: %w", err)
	}
	defer rows.Close()

	clusters := make([]Cluster, 0)
	for rows.Next() {
		var cluster Cluster
		if err := rows.Scan(&cluster.ID, &cluster.DisplayName, &cluster.ExpectedCollectors, &cluster.CreatedAt, &cluster.RemovedAt); err != nil {
			return nil, fmt.Errorf("scan managed cluster: %w", err)
		}
		clusters = append(clusters, cluster)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate managed clusters: %w", err)
	}
	return clusters, nil
}

func (store *PostgresStore) ListOperations(ctx context.Context, limit int) (Operations, error) {
	return store.listOperations(ctx, "", limit)
}

func (store *PostgresStore) ListClusterOperations(ctx context.Context, clusterID string, limit int) (Operations, error) {
	if err := validateClusterID(clusterID); err != nil {
		return Operations{}, err
	}
	return store.listOperations(ctx, clusterID, limit)
}

func (store *PostgresStore) listOperations(ctx context.Context, clusterID string, limit int) (Operations, error) {
	if err := validateLimit(limit); err != nil {
		return Operations{}, err
	}
	operations := Operations{
		Tickets:        make([]Ticket, 0),
		Investigations: make([]Investigation, 0),
	}
	rows, err := store.pool.Query(ctx, `
		SELECT i.incident_id, i.cluster_id, COALESCE(anomaly.rule_id,''), i.title, i.summary, i.severity, i.status,
			i.updated_at, COALESCE(anomaly.last_signal_at,i.updated_at), COALESCE(a.status,''), COALESCE(a.decision_code,''), a.updated_at
		FROM incidents i
		LEFT JOIN anomaly_incidents anomaly ON anomaly.incident_id=i.incident_id
		LEFT JOIN LATERAL (
			SELECT status, decision_code, updated_at
			FROM automatic_investigation_attempts
			WHERE incident_id=i.incident_id
			ORDER BY source_event_id DESC, created_at DESC
			LIMIT 1
		) a ON true
		WHERE i.status IN ('OPEN', 'INVESTIGATING', 'MONITORING')
		  AND ($2='' OR i.cluster_id=$2)
		ORDER BY i.updated_at DESC, i.incident_id
		LIMIT $1`, limit, clusterID)
	if err != nil {
		return Operations{}, fmt.Errorf("list live tickets: %w", err)
	}
	for rows.Next() {
		var ticket Ticket
		if err := rows.Scan(&ticket.ID, &ticket.ClusterID, &ticket.RuleID, &ticket.Title, &ticket.Summary,
			&ticket.Severity, &ticket.Status, &ticket.UpdatedAt, &ticket.LastSignalAt, &ticket.AutoStartStatus,
			&ticket.AutoStartDecision, &ticket.AutoStartUpdatedAt); err != nil {
			rows.Close()
			return Operations{}, fmt.Errorf("scan live ticket: %w", err)
		}
		operations.Tickets = append(operations.Tickets, ticket)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return Operations{}, fmt.Errorf("iterate live tickets: %w", err)
	}
	rows.Close()

	rows, err = store.pool.Query(ctx, `
		WITH selected AS (
			SELECT investigation_id, cluster_id, incident_id, question, status, scope, updated_at
			FROM investigations
			WHERE ($2='' OR cluster_id=$2)
			ORDER BY updated_at DESC, investigation_id
			LIMIT $1
		)
		SELECT i.investigation_id, i.cluster_id, COALESCE(i.incident_id, ''), i.question, i.status,
			i.scope, COALESCE(m.audited_tokens, 0), COALESCE(m.audited_cost_microunits, 0), i.updated_at
		FROM selected i
		LEFT JOIN LATERAL (
			SELECT COALESCE(sum(input_tokens + output_tokens), 0) AS audited_tokens,
				COALESCE(sum(cost_microunits), 0) AS audited_cost_microunits
			FROM investigation_model_calls
			WHERE investigation_id=i.investigation_id
		) m ON true
		ORDER BY i.updated_at DESC, i.investigation_id`, limit, clusterID)
	if err != nil {
		return Operations{}, fmt.Errorf("list investigations: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var investigation Investigation
		var scope []byte
		if err := rows.Scan(
			&investigation.ID,
			&investigation.ClusterID,
			&investigation.IncidentID,
			&investigation.Question,
			&investigation.Status,
			&scope,
			&investigation.AuditedTokens,
			&investigation.AuditedCostMicrounits,
			&investigation.UpdatedAt,
		); err != nil {
			return Operations{}, fmt.Errorf("scan investigation: %w", err)
		}
		var decodedScope struct {
			EntityKind string   `json:"entity_kind"`
			EntityIDs  []string `json:"entity_ids"`
		}
		if err := json.Unmarshal(scope, &decodedScope); err != nil {
			return Operations{}, fmt.Errorf("decode investigation scope: %w", err)
		}
		investigation.EntityKind = decodedScope.EntityKind
		investigation.EntityIDs = append([]string(nil), decodedScope.EntityIDs...)
		operations.Investigations = append(operations.Investigations, investigation)
	}
	if err := rows.Err(); err != nil {
		return Operations{}, fmt.Errorf("iterate investigations: %w", err)
	}
	rows.Close()
	operations.Repairs = store.repairOverview(ctx, clusterID)
	return operations, nil
}

func (store *PostgresStore) GetInvestigationReport(ctx context.Context, id string) (InvestigationReport, error) {
	id = strings.TrimSpace(id)
	if err := validateInvestigationID(id); err != nil {
		return InvestigationReport{}, err
	}
	var report InvestigationReport
	var scope, successCriteria []byte
	err := store.pool.QueryRow(ctx, `
		SELECT i.investigation_id, i.cluster_id, COALESCE(i.incident_id, ''), i.question,
			status, stop_reason, i.version, scope, window_start, window_end, success_criteria,
			created_at, updated_at, completed_at, b.max_model_tokens,
			b.used_model_tokens, b.max_cost_microunits, b.used_cost_microunits
		FROM investigations i JOIN investigation_budgets b USING (investigation_id)
		WHERE i.investigation_id=$1`, id).Scan(
		&report.ID, &report.ClusterID, &report.IncidentID, &report.Question,
		&report.Status, &report.StopReason, &report.Version, &scope, &report.WindowStart,
		&report.WindowEnd, &successCriteria, &report.CreatedAt,
		&report.UpdatedAt, &report.CompletedAt, &report.ModelUsage.MaxTokens,
		&report.ModelUsage.AdmittedTokens, &report.ModelUsage.MaxCostMicrounits,
		&report.ModelUsage.AdmittedCostMicrounits,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return InvestigationReport{}, fmt.Errorf("%w: investigation does not exist", ErrNotFound)
	}
	if err != nil {
		return InvestigationReport{}, fmt.Errorf("load investigation report: %w", err)
	}
	var decodedScope struct {
		EntityKind string   `json:"entity_kind"`
		EntityIDs  []string `json:"entity_ids"`
	}
	if err := json.Unmarshal(scope, &decodedScope); err != nil {
		return InvestigationReport{}, fmt.Errorf("decode investigation report scope: %w", err)
	}
	if err := json.Unmarshal(successCriteria, &report.SuccessCriteria); err != nil {
		return InvestigationReport{}, fmt.Errorf("decode investigation report success criteria: %w", err)
	}
	report.EntityKind = decodedScope.EntityKind
	report.EntityIDs = append([]string(nil), decodedScope.EntityIDs...)
	var action ReportActionCard
	err = store.pool.QueryRow(ctx, `
		SELECT a.action_card_id,a.owner,a.action,a.urgency,a.targets,a.rationale,a.blocking_gaps,a.escalation_condition,
			COALESCE(array_agg(COALESCE(e.evidence_id, substring(c.ledger_entry_id from 8)) ORDER BY e.evidence_id,c.ledger_entry_id)
				FILTER (WHERE c.ledger_entry_id IS NOT NULL), ARRAY[]::text[])
		FROM investigation_action_cards a
		LEFT JOIN investigation_action_card_citations c
			ON c.investigation_id=a.investigation_id AND c.action_card_id=a.action_card_id
		LEFT JOIN investigation_evidence e ON e.cluster_id=c.cluster_id AND e.investigation_id=c.investigation_id AND e.ledger_entry_id=c.ledger_entry_id
		WHERE a.investigation_id=$1
		GROUP BY a.investigation_id,a.action_card_id,a.owner,a.action,a.urgency,a.targets,a.rationale,a.blocking_gaps,a.escalation_condition`, id).Scan(
		&action.ID, &action.Owner, &action.Action, &action.Urgency, &action.Targets,
		&action.Rationale, &action.BlockingGaps, &action.EscalationCondition, &action.EvidenceIDs)
	if err == nil {
		report.PrimaryAction = &action
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return InvestigationReport{}, fmt.Errorf("load investigation report action card: %w", err)
	}
	report.Findings = make([]ReportFinding, 0)

	rows, err := store.pool.Query(ctx, `
		SELECT f.finding_id, f.kind, f.statement, f.scope, f.severity, f.confidence,
			COALESCE(array_agg(COALESCE(e.evidence_id, substring(c.ledger_entry_id from 8)) ORDER BY e.evidence_id,c.ledger_entry_id)
				FILTER (WHERE c.relationship='EVIDENCE'), ARRAY[]::text[]),
			COALESCE(array_agg(COALESCE(e.evidence_id, substring(c.ledger_entry_id from 8)) ORDER BY e.evidence_id,c.ledger_entry_id)
				FILTER (WHERE c.relationship='COUNTER_EVIDENCE'), ARRAY[]::text[])
		FROM investigation_findings f
		LEFT JOIN investigation_finding_citations c
			ON c.investigation_id=f.investigation_id AND c.finding_id=f.finding_id
		LEFT JOIN investigation_evidence e ON e.cluster_id=c.cluster_id AND e.investigation_id=c.investigation_id AND e.ledger_entry_id=c.ledger_entry_id
		WHERE f.investigation_id=$1 AND f.validation_status='VALID' AND f.status='CURRENT'
		GROUP BY f.finding_id, f.kind, f.statement, f.scope, f.severity, f.confidence
		ORDER BY f.kind, f.finding_id`, id)
	if err != nil {
		return InvestigationReport{}, fmt.Errorf("list investigation report findings: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var finding ReportFinding
		var findingScope []byte
		if err := rows.Scan(&finding.ID, &finding.Kind, &finding.Statement, &findingScope,
			&finding.Severity, &finding.Confidence, &finding.EvidenceIDs,
			&finding.CounterEvidenceIDs); err != nil {
			return InvestigationReport{}, fmt.Errorf("scan investigation report finding: %w", err)
		}
		var decoded struct {
			EntityIDs []string `json:"entity_ids"`
		}
		if err := json.Unmarshal(findingScope, &decoded); err != nil {
			return InvestigationReport{}, fmt.Errorf("decode investigation report finding scope: %w", err)
		}
		finding.EntityIDs = append([]string(nil), decoded.EntityIDs...)
		report.Findings = append(report.Findings, finding)
	}
	if err := rows.Err(); err != nil {
		return InvestigationReport{}, fmt.Errorf("iterate investigation report findings: %w", err)
	}

	report.ReportSections = make([]ReportSection, 0)
	sectionRows, err := store.pool.Query(ctx, `
		SELECT s.section_id, s.kind, s.ordinal, s.statement, s.observed_at,
			COALESCE(array_agg(COALESCE(e.evidence_id, substring(c.ledger_entry_id from 8)) ORDER BY e.evidence_id,c.ledger_entry_id)
				FILTER (WHERE c.ledger_entry_id IS NOT NULL), ARRAY[]::text[])
		FROM investigation_report_sections s
		LEFT JOIN investigation_report_section_citations c
			ON c.investigation_id=s.investigation_id AND c.section_id=s.section_id
		LEFT JOIN investigation_evidence e ON e.cluster_id=c.cluster_id AND e.investigation_id=c.investigation_id AND e.ledger_entry_id=c.ledger_entry_id
		WHERE s.investigation_id=$1
		GROUP BY s.section_id, s.kind, s.ordinal, s.statement, s.observed_at
		ORDER BY s.kind, s.ordinal, s.section_id`, id)
	if err != nil {
		return InvestigationReport{}, fmt.Errorf("list investigation report sections: %w", err)
	}
	for sectionRows.Next() {
		var section ReportSection
		if err := sectionRows.Scan(&section.ID, &section.Kind, &section.Ordinal, &section.Statement, &section.ObservedAt, &section.EvidenceIDs); err != nil {
			sectionRows.Close()
			return InvestigationReport{}, fmt.Errorf("scan investigation report section: %w", err)
		}
		report.ReportSections = append(report.ReportSections, section)
	}
	sectionRows.Close()
	if err := sectionRows.Err(); err != nil {
		return InvestigationReport{}, fmt.Errorf("iterate investigation report sections: %w", err)
	}

	report.ReportOmissions = make([]ReportOmission, 0)
	omissionRows, err := store.pool.Query(ctx, `
		SELECT kind, reason, omitted_count
		FROM investigation_report_omissions
		WHERE investigation_id=$1
		ORDER BY kind, reason`, id)
	if err != nil {
		return InvestigationReport{}, fmt.Errorf("list investigation report omissions: %w", err)
	}
	for omissionRows.Next() {
		var omission ReportOmission
		if err := omissionRows.Scan(&omission.Kind, &omission.Reason, &omission.Count); err != nil {
			omissionRows.Close()
			return InvestigationReport{}, fmt.Errorf("scan investigation report omission: %w", err)
		}
		report.ReportOmissions = append(report.ReportOmissions, omission)
	}
	omissionRows.Close()
	if err := omissionRows.Err(); err != nil {
		return InvestigationReport{}, fmt.Errorf("iterate investigation report omissions: %w", err)
	}

	report.Evidence = make([]ReportEvidence, 0)
	evidenceRows, err := store.pool.Query(ctx, `
		SELECT COALESCE(evidence_id, substring(ledger_entry_id from 8)), entry_kind,
			status, exact_scope, observed_start, observed_end, recorded_at
		FROM investigation_evidence
		WHERE investigation_id=$1
		ORDER BY sequence`, id)
	if err != nil {
		return InvestigationReport{}, fmt.Errorf("list investigation report evidence: %w", err)
	}
	defer evidenceRows.Close()
	for evidenceRows.Next() {
		var evidence ReportEvidence
		var exactScope []byte
		if err := evidenceRows.Scan(&evidence.ID, &evidence.Kind, &evidence.Status,
			&exactScope, &evidence.ObservedStart, &evidence.ObservedEnd,
			&evidence.RecordedAt); err != nil {
			return InvestigationReport{}, fmt.Errorf("scan investigation report evidence: %w", err)
		}
		evidence.ExactScope = string(exactScope)
		report.Evidence = append(report.Evidence, evidence)
	}
	if err := evidenceRows.Err(); err != nil {
		return InvestigationReport{}, fmt.Errorf("iterate investigation report evidence: %w", err)
	}

	report.ModelCalls = make([]ModelCall, 0)
	callRows, err := store.pool.Query(ctx, `
		SELECT call_id, call_kind, provider, model, model_config_version,
			prompt_schema_version, tool_schema_version, input_tokens, output_tokens,
			cost_microunits, latency_milliseconds, outcome, reason_code,
			input_evidence_id, output_evidence_id, occurred_at
		FROM investigation_model_calls
		WHERE investigation_id=$1
		ORDER BY occurred_at, call_id`, id)
	if err != nil {
		return InvestigationReport{}, fmt.Errorf("list investigation model calls: %w", err)
	}
	defer callRows.Close()
	for callRows.Next() {
		var call ModelCall
		var inputEvidenceID, outputEvidenceID *string
		if err := callRows.Scan(&call.ID, &call.Kind, &call.Provider, &call.Model,
			&call.ModelConfigVersion, &call.PromptSchemaVersion, &call.ToolSchemaVersion,
			&call.InputTokens, &call.OutputTokens, &call.CostMicrounits,
			&call.LatencyMilliseconds, &call.Outcome, &call.ReasonCode,
			&inputEvidenceID, &outputEvidenceID, &call.OccurredAt); err != nil {
			return InvestigationReport{}, fmt.Errorf("scan investigation model call: %w", err)
		}
		call.Input, err = store.readModelPayload(ctx, inputEvidenceID)
		if err != nil {
			return InvestigationReport{}, err
		}
		call.Output, err = store.readModelPayload(ctx, outputEvidenceID)
		if err != nil {
			return InvestigationReport{}, err
		}
		report.ModelCalls = append(report.ModelCalls, call)
		report.ModelUsage.AuditedTokens += call.InputTokens + call.OutputTokens
		report.ModelUsage.AuditedCostMicrounits += call.CostMicrounits
	}
	if err := callRows.Err(); err != nil {
		return InvestigationReport{}, fmt.Errorf("iterate investigation model calls: %w", err)
	}
	report.ContextManifests = make([]ContextManifest, 0)
	manifestRows, err := store.pool.Query(ctx, `SELECT call_key,call_kind,estimator_version,allowance_tokens,estimated_input_tokens,raw_estimated_input_tokens,calibration_factor_millionths,calibration_sample_count,fixed_margin_tokens,maximum_output_tokens,actual_input_tokens,estimator_underrun,memory_allowance_tokens,memory_candidate_count,selected_memory_ids,selected_evidence_ids,exclusion_reasons,section_tokens,retrieval_latency_milliseconds,index_version,fallback_state,context_mode,checkpoint_digest,delta_from_version,shadow_only,created_at FROM investigation_context_manifests WHERE investigation_id=$1 ORDER BY created_at,call_key`, id)
	if err != nil {
		return InvestigationReport{}, fmt.Errorf("list investigation context manifests: %w", err)
	}
	defer manifestRows.Close()
	for manifestRows.Next() {
		var item ContextManifest
		var selected, selectedEvidence, exclusions, sections []byte
		if err := manifestRows.Scan(&item.CallKey, &item.CallKind, &item.EstimatorVersion, &item.AllowanceTokens, &item.EstimatedInputTokens, &item.RawEstimatedInputTokens, &item.CalibrationFactorMillionths, &item.CalibrationSampleCount, &item.FixedMarginTokens, &item.MaximumOutputTokens, &item.ActualInputTokens, &item.EstimatorUnderrun, &item.MemoryAllowanceTokens, &item.MemoryCandidateCount, &selected, &selectedEvidence, &exclusions, &sections, &item.RetrievalLatencyMilliseconds, &item.IndexVersion, &item.FallbackState, &item.ContextMode, &item.CheckpointDigest, &item.DeltaFromVersion, &item.ShadowOnly, &item.CreatedAt); err != nil {
			return InvestigationReport{}, fmt.Errorf("scan investigation context manifest: %w", err)
		}
		if err := json.Unmarshal(selected, &item.SelectedMemoryIDs); err != nil {
			return InvestigationReport{}, fmt.Errorf("decode selected memory IDs: %w", err)
		}
		if err := json.Unmarshal(selectedEvidence, &item.SelectedEvidenceIDs); err != nil {
			return InvestigationReport{}, fmt.Errorf("decode selected evidence IDs: %w", err)
		}
		item.ExclusionReasons, item.SectionTokens = string(exclusions), string(sections)
		report.ContextManifests = append(report.ContextManifests, item)
	}
	if err := manifestRows.Err(); err != nil {
		return InvestigationReport{}, fmt.Errorf("iterate investigation context manifests: %w", err)
	}
	return report, nil
}

func (store *PostgresStore) readModelPayload(ctx context.Context, evidenceID *string) (ModelPayload, error) {
	if evidenceID == nil || *evidenceID == "" {
		return ModelPayload{Availability: PayloadNotRecorded}, nil
	}
	if store.payloads == nil {
		return ModelPayload{EvidenceID: *evidenceID, Availability: PayloadUnavailable}, nil
	}
	payload, err := store.payloads.ReadModelPayload(ctx, *evidenceID)
	if err != nil {
		return ModelPayload{}, fmt.Errorf("resolve investigation model payload: %w", err)
	}
	return payload, nil
}

func (store *PostgresStore) UpdateCluster(ctx context.Context, id, displayName string, expectedCollectors []string, audit MutationAudit) error {
	id = strings.TrimSpace(id)
	displayName = strings.TrimSpace(displayName)
	if err := validateClusterID(id); err != nil {
		return err
	}
	if displayName == "" || len(displayName) > 256 {
		return fmt.Errorf("%w: display name must contain 1 to 256 characters", ErrInvalid)
	}
	expectedCollectors, err := normalizeExpectedCollectors(expectedCollectors)
	if err != nil {
		return err
	}
	if err := validateMutationAudit(audit, EventClusterUpdated); err != nil {
		return err
	}

	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin cluster update: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	command, err := tx.Exec(ctx, `
		UPDATE clusters SET display_name=$2, expected_collectors=$3
		WHERE cluster_id=$1 AND removed_at IS NULL`, id, displayName, expectedCollectors)
	if err != nil {
		return classifyMutationError("update cluster", err)
	}
	if command.RowsAffected() == 0 {
		return classifyMissingCluster(ctx, tx, id)
	}
	if err := insertMutationAudit(ctx, tx, audit); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return classifyMutationError("commit cluster update", err)
	}
	return nil
}

func (store *PostgresStore) RemoveCluster(ctx context.Context, id string, now time.Time, audit MutationAudit) error {
	id = strings.TrimSpace(id)
	if err := validateClusterID(id); err != nil {
		return err
	}
	if now.IsZero() {
		return fmt.Errorf("%w: removal time is required", ErrInvalid)
	}
	if err := validateMutationAudit(audit, EventClusterRemoved); err != nil {
		return err
	}
	now = now.UTC()

	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin cluster removal: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var removedAt *time.Time
	if err := tx.QueryRow(ctx, `SELECT removed_at FROM clusters WHERE cluster_id=$1 FOR UPDATE`, id).Scan(&removedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w: cluster does not exist", ErrNotFound)
		}
		return fmt.Errorf("lock cluster for removal: %w", err)
	}
	if removedAt != nil {
		return fmt.Errorf("%w: cluster is already removed", ErrConflict)
	}

	statements := []struct {
		name string
		sql  string
		args []any
	}{
		{"mark cluster removed", `UPDATE clusters SET removed_at=$2 WHERE cluster_id=$1`, []any{id, now}},
		{"disable desired schedules", `UPDATE desired_schedules SET enabled=false WHERE cluster_id=$1 AND enabled`, []any{id}},
		{"deactivate collection jobs", `UPDATE collection_jobs SET active=false, lease_owner=NULL, lease_expires_at=NULL WHERE cluster_id=$1 AND active`, []any{id}},
		{"revoke collector identities", `UPDATE collector_identities i SET revoked_at=$2 FROM collectors c WHERE i.collector_id=c.collector_id AND c.cluster_id=$1 AND i.revoked_at IS NULL`, []any{id, now}},
		{"revoke collectors", `UPDATE collectors SET status='REVOKED', revoked_at=$2 WHERE cluster_id=$1 AND status <> 'REVOKED'`, []any{id, now}},
		{"revoke API keys", `UPDATE api_keys SET revoked_at=$2 WHERE cluster_id=$1 AND revoked_at IS NULL`, []any{id, now}},
	}
	for _, statement := range statements {
		if _, err := tx.Exec(ctx, statement.sql, statement.args...); err != nil {
			return classifyMutationError(statement.name, err)
		}
	}
	if err := insertMutationAudit(ctx, tx, audit); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return classifyMutationError("commit cluster removal", err)
	}
	return nil
}

// CredentialAdminAllowed is the authoritative cluster-scoped grant check.
// Access authentication alone never confers access to credential metadata.
func (store *PostgresStore) CredentialAdminAllowed(ctx context.Context, clusterID, subject string) (bool, error) {
	if err := validateClusterID(strings.TrimSpace(clusterID)); err != nil || !validAccessSubject(subject) {
		return false, ErrCredentialAccessDenied
	}
	var allowed bool
	err := store.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM admin_cluster_credential_grants g
			JOIN clusters c ON c.cluster_id=g.cluster_id
			WHERE g.cluster_id=$1 AND g.access_subject=$2 AND g.revoked_at IS NULL AND c.removed_at IS NULL
		)`, clusterID, subject).Scan(&allowed)
	if err != nil {
		return false, fmt.Errorf("check credential administrator grant: %w", err)
	}
	return allowed, nil
}

// GrantCredentialAdmin and RevokeCredentialAdmin are protected operator
// maintenance operations used to bootstrap the default-deny Access mapping.
// They are intentionally absent from the browser/API surface.
func (store *PostgresStore) GrantCredentialAdmin(ctx context.Context, clusterID, targetSubject, actorSubject string, now time.Time) error {
	return store.changeCredentialAdminGrant(ctx, clusterID, targetSubject, actorSubject, now, false)
}

func (store *PostgresStore) RevokeCredentialAdmin(ctx context.Context, clusterID, targetSubject, actorSubject string, now time.Time) error {
	return store.changeCredentialAdminGrant(ctx, clusterID, targetSubject, actorSubject, now, true)
}

func (store *PostgresStore) ListCredentialAdminGrants(ctx context.Context, clusterID string) ([]CredentialAdminGrant, error) {
	if validateClusterID(clusterID) != nil {
		return nil, fmt.Errorf("%w: cluster ID is invalid", ErrInvalid)
	}
	rows, err := store.pool.Query(ctx, `SELECT cluster_id,access_subject,granted_at,revoked_at FROM admin_cluster_credential_grants WHERE cluster_id=$1 ORDER BY access_subject`, clusterID)
	if err != nil {
		return nil, fmt.Errorf("list credential administrator grants: %w", err)
	}
	defer rows.Close()
	grants := make([]CredentialAdminGrant, 0)
	for rows.Next() {
		var grant CredentialAdminGrant
		if err := rows.Scan(&grant.ClusterID, &grant.AccessSubject, &grant.GrantedAt, &grant.RevokedAt); err != nil {
			return nil, err
		}
		grants = append(grants, grant)
	}
	return grants, rows.Err()
}

func (store *PostgresStore) changeCredentialAdminGrant(ctx context.Context, clusterID, targetSubject, actorSubject string, now time.Time, revoke bool) error {
	if validateClusterID(clusterID) != nil || !validAccessSubject(targetSubject) || !validAccessSubject(actorSubject) || now.IsZero() {
		return fmt.Errorf("%w: credential administrator grant is invalid", ErrInvalid)
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var locked string
	if err := tx.QueryRow(ctx, `SELECT cluster_id FROM clusters WHERE cluster_id=$1 AND removed_at IS NULL FOR UPDATE`, clusterID).Scan(&locked); errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	kind := EventCredentialAdminGranted
	if revoke {
		kind = EventCredentialAdminRevoked
	}
	if revoke {
		if _, err := tx.Exec(ctx, `UPDATE admin_cluster_credential_grants SET revoked_at=$3 WHERE cluster_id=$1 AND access_subject=$2 AND revoked_at IS NULL`, clusterID, targetSubject, now.UTC()); err != nil {
			return err
		}
	} else if _, err := tx.Exec(ctx, `INSERT INTO admin_cluster_credential_grants(cluster_id,access_subject,granted_at,revoked_at) VALUES($1,$2,$3,NULL) ON CONFLICT(cluster_id,access_subject) DO UPDATE SET granted_at=EXCLUDED.granted_at,revoked_at=NULL`, clusterID, targetSubject, now.UTC()); err != nil {
		return classifyMutationError("grant credential administrator", err)
	}
	eventID, err := newCredentialAuditID()
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO admin_credential_grant_audit_events(event_id,event_kind,actor_subject,target_subject,cluster_id,occurred_at) VALUES($1,$2,$3,$4,$5,$6)`, eventID, kind, actorSubject, targetSubject, clusterID, now.UTC()); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	return nil
}

func credentialAdminAllowedTx(ctx context.Context, tx pgx.Tx, clusterID, subject string) (bool, error) {
	if validateClusterID(strings.TrimSpace(clusterID)) != nil || !validAccessSubject(subject) {
		return false, ErrCredentialAccessDenied
	}
	var lockedCluster string
	if err := tx.QueryRow(ctx, `SELECT cluster_id FROM clusters WHERE cluster_id=$1 AND removed_at IS NULL FOR SHARE`, clusterID).Scan(&lockedCluster); errors.Is(err, pgx.ErrNoRows) {
		return false, ErrNotFound
	} else if err != nil {
		return false, fmt.Errorf("lock credential cluster scope: %w", err)
	}
	var allowed bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM admin_cluster_credential_grants WHERE cluster_id=$1 AND access_subject=$2 AND revoked_at IS NULL)`, clusterID, subject).Scan(&allowed); err != nil {
		return false, fmt.Errorf("check credential administrator grant: %w", err)
	}
	return allowed, nil
}

func (store *PostgresStore) ListCredentialMetadata(ctx context.Context, clusterID, subject string) ([]CredentialMetadata, error) {
	if !store.credentialsEnabled() {
		return nil, ErrCredentialKeyUnavailable
	}
	allowed, err := store.CredentialAdminAllowed(ctx, clusterID, subject)
	if err != nil {
		return nil, err
	}
	if !allowed {
		return nil, ErrCredentialAccessDenied
	}
	rows, err := store.pool.Query(ctx, `
		SELECT credential_id, cluster_id, host, purpose, username, key_version,
			credential_version, status, created_at, revoked_at, COALESCE(replaced_by,'')
		FROM cluster_credentials WHERE cluster_id=$1
		ORDER BY created_at DESC, credential_id DESC`, clusterID)
	if err != nil {
		return nil, fmt.Errorf("list cluster credentials: %w", err)
	}
	defer rows.Close()
	metadata := make([]CredentialMetadata, 0)
	for rows.Next() {
		var item CredentialMetadata
		if err := rows.Scan(&item.ID, &item.ClusterID, &item.Host, &item.Purpose, &item.Username, &item.KeyVersion, &item.Version, &item.Status, &item.CreatedAt, &item.RevokedAt, &item.ReplacedBy); err != nil {
			return nil, fmt.Errorf("scan cluster credential metadata: %w", err)
		}
		metadata = append(metadata, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate cluster credential metadata: %w", err)
	}
	return metadata, nil
}

// PutCredential atomically revokes the current credential for the same
// cluster/host/purpose and inserts its replacement. expectedVersion is zero
// for a first enrollment and otherwise prevents a stale form from restoring
// a revoked or replaced secret.
func (store *PostgresStore) PutCredential(ctx context.Context, clusterID, subject string, input CredentialInput, audit MutationAudit) (CredentialMetadata, error) {
	defer func() {
		clearBytes(input.SSHPassword)
		clearBytes(input.SudoPassword)
	}()
	if !store.credentialsEnabled() {
		return CredentialMetadata{}, ErrCredentialKeyUnavailable
	}
	if err := validateCredentialInput(clusterID, input); err != nil {
		return CredentialMetadata{}, err
	}
	if audit.EventKind != EventCredentialCreated && audit.EventKind != EventCredentialReplaced {
		return CredentialMetadata{}, fmt.Errorf("%w: credential audit kind is invalid", ErrInvalid)
	}
	if err := validateMutationAudit(audit, audit.EventKind); err != nil {
		return CredentialMetadata{}, err
	}
	credentialID, err := newCredentialID()
	if err != nil {
		clearBytes(input.SSHPassword)
		clearBytes(input.SudoPassword)
		return CredentialMetadata{}, err
	}

	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		clearBytes(input.SSHPassword)
		clearBytes(input.SudoPassword)
		return CredentialMetadata{}, fmt.Errorf("begin credential replacement: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT cluster_id FROM clusters WHERE cluster_id=$1 AND removed_at IS NULL FOR UPDATE`, clusterID); err != nil {
		clearBytes(input.SSHPassword)
		clearBytes(input.SudoPassword)
		return CredentialMetadata{}, fmt.Errorf("lock cluster for credential replacement: %w", err)
	}
	allowed, err := credentialAdminAllowedTx(ctx, tx, clusterID, subject)
	if err != nil {
		clearBytes(input.SSHPassword)
		clearBytes(input.SudoPassword)
		return CredentialMetadata{}, err
	}
	if !allowed {
		clearBytes(input.SSHPassword)
		clearBytes(input.SudoPassword)
		return CredentialMetadata{}, finishRejectedCredentialTx(ctx, tx, clusterID, subject, CredentialRejectAccessDenied, audit, ErrCredentialAccessDenied)
	}
	var priorID string
	var priorVersion int64
	var priorStatus string
	err = tx.QueryRow(ctx, `
		SELECT credential_id, credential_version, status FROM cluster_credentials
		WHERE cluster_id=$1 AND host=$2 AND purpose=$3
		ORDER BY credential_version DESC LIMIT 1 FOR UPDATE`, clusterID, input.Host, input.Purpose).Scan(&priorID, &priorVersion, &priorStatus)
	if errors.Is(err, pgx.ErrNoRows) {
		priorID = ""
		priorVersion = 0
	} else if err != nil {
		clearBytes(input.SSHPassword)
		clearBytes(input.SudoPassword)
		return CredentialMetadata{}, fmt.Errorf("lock current credential: %w", err)
	}
	if input.ExpectedVersion != priorVersion {
		clearBytes(input.SSHPassword)
		clearBytes(input.SudoPassword)
		return CredentialMetadata{}, finishRejectedCredentialTx(ctx, tx, clusterID, subject, CredentialRejectConflict, audit, fmt.Errorf("%w: credential version changed", ErrConflict))
	}
	if priorID != "" && priorStatus == "ACTIVE" {
		if input.ExpectedCredentialID != priorID {
			clearBytes(input.SSHPassword)
			clearBytes(input.SudoPassword)
			return CredentialMetadata{}, finishRejectedCredentialTx(ctx, tx, clusterID, subject, CredentialRejectConflict, audit, fmt.Errorf("%w: credential identity changed", ErrConflict))
		}
	}
	if priorID != "" && priorStatus == "REVOKED" && input.ExpectedCredentialID != priorID {
		clearBytes(input.SSHPassword)
		clearBytes(input.SudoPassword)
		return CredentialMetadata{}, finishRejectedCredentialTx(ctx, tx, clusterID, subject, CredentialRejectConflict, audit, fmt.Errorf("%w: revoked credential requires a fresh version", ErrConflict))
	}
	nextVersion := priorVersion + 1
	version, nonce, ciphertext, err := store.credentialCipher.seal(clusterID, input.Host, input.Purpose, input.Username, credentialID, nextVersion, CredentialSecrets{SSHPassword: input.SSHPassword, SudoPassword: input.SudoPassword})
	clearBytes(input.SSHPassword)
	clearBytes(input.SudoPassword)
	if err != nil {
		return CredentialMetadata{}, err
	}
	if priorID != "" && priorStatus == "ACTIVE" {
		now := audit.OccurredAt.UTC()
		if _, err := tx.Exec(ctx, `UPDATE cluster_credentials SET status='REVOKED', revoked_at=$2, ciphertext=''::bytea, nonce=''::bytea WHERE credential_id=$1 AND status='ACTIVE'`, priorID, now); err != nil {
			clearBytes(nonce)
			clearBytes(ciphertext)
			return CredentialMetadata{}, fmt.Errorf("revoke replaced credential: %w", err)
		}
	}
	createdAt := audit.OccurredAt.UTC()
	if _, err := tx.Exec(ctx, `
		INSERT INTO cluster_credentials (credential_id, cluster_id, host, purpose, username, ciphertext, nonce, key_version, credential_version, status, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'ACTIVE',$10)`, credentialID, clusterID, input.Host, input.Purpose, input.Username, ciphertext, nonce, version, nextVersion, createdAt); err != nil {
		clearBytes(nonce)
		clearBytes(ciphertext)
		return CredentialMetadata{}, classifyMutationError("store credential", err)
	}
	if priorID != "" {
		if _, err := tx.Exec(ctx, `UPDATE cluster_credentials SET replaced_by=$2 WHERE credential_id=$1`, priorID, credentialID); err != nil {
			clearBytes(nonce)
			clearBytes(ciphertext)
			return CredentialMetadata{}, fmt.Errorf("link replaced credential: %w", err)
		}
	}
	audit.EventKind = EventCredentialCreated
	if priorID != "" {
		audit.EventKind = EventCredentialReplaced
	}
	audit.ClusterID = clusterID
	audit.CredentialID = credentialID
	audit.CredentialVersion = nextVersion
	if err := insertCredentialAudit(ctx, tx, audit); err != nil {
		clearBytes(nonce)
		clearBytes(ciphertext)
		return CredentialMetadata{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		clearBytes(nonce)
		clearBytes(ciphertext)
		return CredentialMetadata{}, classifyMutationError("commit credential replacement", err)
	}
	clearBytes(nonce)
	clearBytes(ciphertext)
	return CredentialMetadata{ID: credentialID, ClusterID: clusterID, Host: input.Host, Purpose: input.Purpose, Username: input.Username, KeyVersion: version, Version: nextVersion, Status: "ACTIVE", CreatedAt: createdAt}, nil
}

func (store *PostgresStore) RevokeCredential(ctx context.Context, clusterID, subject, credentialID string, expectedVersion int64, audit MutationAudit) error {
	if !store.credentialsEnabled() {
		return ErrCredentialKeyUnavailable
	}
	if err := validateClusterID(clusterID); err != nil || !validCredentialID(credentialID) || expectedVersion < 1 {
		return fmt.Errorf("%w: credential reference is invalid", ErrInvalid)
	}
	if err := validateMutationAudit(audit, EventCredentialRevoked); err != nil {
		return err
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin credential revocation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT cluster_id FROM clusters WHERE cluster_id=$1 AND removed_at IS NULL FOR UPDATE`, clusterID); err != nil {
		return fmt.Errorf("lock cluster for credential revocation: %w", err)
	}
	allowed, err := credentialAdminAllowedTx(ctx, tx, clusterID, subject)
	if err != nil {
		return err
	}
	if !allowed {
		return finishRejectedCredentialTx(ctx, tx, clusterID, subject, CredentialRejectAccessDenied, audit, ErrCredentialAccessDenied)
	}
	command, err := tx.Exec(ctx, `UPDATE cluster_credentials SET status='REVOKED', credential_version=credential_version+1, revoked_at=$4, ciphertext=''::bytea, nonce=''::bytea WHERE credential_id=$1 AND cluster_id=$2 AND credential_version=$3 AND status='ACTIVE'`, credentialID, clusterID, expectedVersion, audit.OccurredAt.UTC())
	if err != nil {
		return classifyMutationError("revoke credential", err)
	}
	if command.RowsAffected() == 0 {
		return finishRejectedCredentialTx(ctx, tx, clusterID, subject, CredentialRejectConflict, audit, fmt.Errorf("%w: active credential version does not exist", ErrConflict))
	}
	audit.ClusterID = clusterID
	audit.CredentialID = credentialID
	audit.CredentialVersion = expectedVersion + 1
	if err := insertCredentialAudit(ctx, tx, audit); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return classifyMutationError("commit credential revocation", err)
	}
	return nil
}

// ResolveCredential is a trusted backend boundary for a future reviewed
// operation. No HTTP handler calls it and its result cannot be JSON encoded.
func (store *PostgresStore) ResolveCredential(ctx context.Context, reference CredentialReference) (ResolvedCredential, error) {
	if !store.credentialsEnabled() || !validCredentialID(reference.ID) || validateClusterID(reference.ClusterID) != nil {
		return ResolvedCredential{}, ErrCredentialKeyUnavailable
	}
	var host, purpose, username, version string
	var credentialVersion int64
	var nonce, ciphertext []byte
	err := store.pool.QueryRow(ctx, `SELECT cc.host,cc.purpose,cc.username,cc.key_version,cc.credential_version,cc.nonce,cc.ciphertext FROM cluster_credentials cc JOIN clusters c ON c.cluster_id=cc.cluster_id WHERE cc.credential_id=$1 AND cc.cluster_id=$2 AND cc.status='ACTIVE' AND c.removed_at IS NULL`, reference.ID, reference.ClusterID).Scan(&host, &purpose, &username, &version, &credentialVersion, &nonce, &ciphertext)
	if errors.Is(err, pgx.ErrNoRows) {
		return ResolvedCredential{}, ErrNotFound
	}
	if err != nil {
		return ResolvedCredential{}, fmt.Errorf("load credential for trusted operation: %w", err)
	}
	secrets, err := store.credentialCipher.open(reference.ClusterID, host, purpose, username, reference.ID, credentialVersion, version, nonce, ciphertext)
	clearBytes(nonce)
	clearBytes(ciphertext)
	if err != nil {
		return ResolvedCredential{}, err
	}
	return secrets, nil
}

// RotateCredentials decrypts and re-encrypts every active record in one
// transaction. The caller must retain old keys until backups are covered.
func (store *PostgresStore) RotateCredentials(ctx context.Context, next *CredentialKeyring, audit MutationAudit) error {
	if !store.credentialsEnabled() || next == nil {
		return ErrCredentialKeyUnavailable
	}
	if err := validateMutationAudit(audit, EventCredentialKeyRotated); err != nil || !validAccessSubject(audit.ActorSubject) {
		return fmt.Errorf("%w: key rotation audit metadata is invalid", ErrInvalid)
	}
	nextCipher, err := newCredentialCipher(next, rand.Reader)
	if err != nil {
		return err
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin credential key rotation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT cluster_id FROM clusters WHERE removed_at IS NULL ORDER BY cluster_id FOR UPDATE`); err != nil {
		return fmt.Errorf("lock clusters for credential key rotation: %w", err)
	}
	rows, err := tx.Query(ctx, `SELECT credential_id,cluster_id,host,purpose,username,key_version,credential_version,nonce,ciphertext FROM cluster_credentials WHERE status='ACTIVE' ORDER BY credential_id FOR UPDATE`)
	if err != nil {
		return fmt.Errorf("list credentials for key rotation: %w", err)
	}
	type rotated struct {
		id, clusterID, version string
		credentialVersion      int64
		nonce, ciphertext      []byte
	}
	updates := make([]rotated, 0)
	for rows.Next() {
		var id, clusterID, host, purpose, username, oldVersion string
		var credentialVersion int64
		var nonce, ciphertext []byte
		if err := rows.Scan(&id, &clusterID, &host, &purpose, &username, &oldVersion, &credentialVersion, &nonce, &ciphertext); err != nil {
			rows.Close()
			return err
		}
		secrets, err := store.credentialCipher.open(clusterID, host, purpose, username, id, credentialVersion, oldVersion, nonce, ciphertext)
		clearBytes(nonce)
		clearBytes(ciphertext)
		if err != nil {
			rows.Close()
			return fmt.Errorf("decrypt credential during rotation: %w", err)
		}
		version, newNonce, newCiphertext, err := nextCipher.seal(clusterID, host, purpose, username, id, credentialVersion, secrets)
		secrets.Destroy()
		if err != nil {
			rows.Close()
			return err
		}
		updates = append(updates, rotated{id: id, clusterID: clusterID, version: version, credentialVersion: credentialVersion, nonce: newNonce, ciphertext: newCiphertext})
		if len(updates) > credentialRotationMaximumRecords {
			rows.Close()
			return fmt.Errorf("%w: credential rotation exceeds %d records", ErrConflict, credentialRotationMaximumRecords)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, item := range updates {
		if _, err := tx.Exec(ctx, `UPDATE cluster_credentials SET key_version=$2,nonce=$3,ciphertext=$4 WHERE credential_id=$1`, item.id, item.version, item.nonce, item.ciphertext); err != nil {
			return fmt.Errorf("update credential key version: %w", err)
		}
		eventID, err := newCredentialAuditID()
		if err != nil {
			return err
		}
		itemAudit := audit
		itemAudit.EventID = eventID
		itemAudit.ClusterID = item.clusterID
		itemAudit.CredentialID = item.id
		itemAudit.CredentialVersion = item.credentialVersion
		if itemAudit.ReasonCode == "" {
			itemAudit.ReasonCode = "CREDENTIAL_KEY_ROTATED"
		}
		if err := insertCredentialAudit(ctx, tx, itemAudit); err != nil {
			return err
		}
		clearBytes(item.nonce)
		clearBytes(item.ciphertext)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit credential key rotation: %w", err)
	}
	store.credentialCipher.mu.Lock()
	old := store.credentialCipher.ring
	store.credentialCipher.ring = next.clone()
	store.credentialCipher.mu.Unlock()
	old.clear()
	return nil
}

func (store *PostgresStore) credentialsEnabled() bool { return store.credentialCipher != nil }

func validateCredentialInput(clusterID string, input CredentialInput) error {
	passwordMode := input.Purpose == domain.CredentialAccessTestPurpose && validCredentialSecret(input.SudoPassword)
	passwordlessMode := input.Purpose == domain.CredentialAccessPasswordlessPurpose && len(input.SudoPassword) == 0 && len(input.SSHPassword) == 0
	if validateClusterID(clusterID) != nil || strings.TrimSpace(input.Host) == "" || len(input.Host) > 256 || strings.ContainsAny(input.Host, "\x00\r\n") || (!passwordMode && !passwordlessMode) || strings.TrimSpace(input.Username) == "" || len(input.Username) > 256 || strings.ContainsAny(input.Username, "\x00\r\n") || (len(input.SSHPassword) > 0 && !validCredentialSecret(input.SSHPassword)) || input.ExpectedVersion < 0 {
		return fmt.Errorf("%w: credential input is invalid", ErrInvalid)
	}
	return nil
}

func validCredentialSecret(value []byte) bool {
	return len(value) > 0 && len(value) <= credentialMaxPlaintext && utf8.Valid(value) && !strings.ContainsAny(string(value), "\x00\r\n")
}

func validAccessSubject(subject string) bool {
	return len(subject) > 0 && len(subject) <= 256 && !strings.ContainsAny(subject, "\x00\r\n")
}
func validCredentialID(id string) bool {
	return len(id) > 0 && len(id) <= 128 && strings.HasPrefix(id, "cred_") && !strings.ContainsAny(id, "\x00\r\n/\\")
}

func newCredentialID() (string, error) {
	bytes := make([]byte, 18)
	if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
		return "", err
	}
	return "cred_" + base64.RawURLEncoding.EncodeToString(bytes), nil
}

func newCredentialAuditID() (string, error) {
	bytes := make([]byte, 18)
	if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
		return "", err
	}
	return "cred_audit_" + base64.RawURLEncoding.EncodeToString(bytes), nil
}

func validateLimit(limit int) error {
	if limit < 1 || limit > maxListLimit {
		return fmt.Errorf("%w: limit must be between 1 and %d", ErrInvalid, maxListLimit)
	}
	return nil
}

func validateClusterID(id string) error {
	if id == "" || len(id) > 128 {
		return fmt.Errorf("%w: cluster ID must contain 1 to 128 characters", ErrInvalid)
	}
	return nil
}

func normalizeExpectedCollectors(values []string) ([]string, error) {
	if len(values) > 100 {
		return nil, fmt.Errorf("%w: expected collector inventory cannot exceed 100 names", ErrInvalid)
	}
	normalized := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		name := strings.TrimSpace(value)
		if name == "" || len(name) > 256 || strings.ContainsAny(name, "\x00\r\n") {
			return nil, fmt.Errorf("%w: expected collector names must contain 1 to 256 printable characters", ErrInvalid)
		}
		key := strings.ToLower(name)
		if _, duplicate := seen[key]; duplicate {
			return nil, fmt.Errorf("%w: expected collector names must be unique", ErrInvalid)
		}
		seen[key] = struct{}{}
		normalized = append(normalized, name)
	}
	return normalized, nil
}

func validateInvestigationID(id string) error {
	if id == "" || len(id) > 128 {
		return fmt.Errorf("%w: investigation ID must contain 1 to 128 characters", ErrInvalid)
	}
	for _, character := range id {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || strings.ContainsRune("._:-", character) {
			continue
		}
		return fmt.Errorf("%w: investigation ID contains unsupported characters", ErrInvalid)
	}
	return nil
}

func validateMutationAudit(audit MutationAudit, expectedKind string) error {
	if audit.EventID == "" || len(audit.EventID) > 128 || audit.EventKind != expectedKind ||
		audit.ReasonCode == "" || len(audit.ReasonCode) > 128 || len(audit.RequestID) > 128 ||
		len(audit.SessionFingerprint) != 32 || audit.OccurredAt.IsZero() {
		return fmt.Errorf("%w: mutation audit metadata is invalid", ErrInvalid)
	}
	return nil
}

func insertMutationAudit(ctx context.Context, tx pgx.Tx, audit MutationAudit) error {
	fingerprint := append([]byte(nil), audit.SessionFingerprint...)
	_, err := tx.Exec(ctx, `
		INSERT INTO admin_dashboard_audit_events
			(event_id, event_kind, outcome, reason_code, session_fingerprint, request_id, occurred_at)
		VALUES ($1,$2,'SUCCEEDED',$3,$4,$5,$6)`,
		audit.EventID, audit.EventKind, audit.ReasonCode, fingerprint, audit.RequestID, audit.OccurredAt.UTC())
	if err != nil {
		return classifyMutationError("record cluster mutation audit", err)
	}
	return nil
}

func insertCredentialAudit(ctx context.Context, tx pgx.Tx, audit MutationAudit) error {
	rejected := audit.EventKind == EventCredentialAttempt
	if !validAccessSubject(audit.ActorSubject) || validateClusterID(audit.ClusterID) != nil || (!rejected && !validCredentialID(audit.CredentialID)) || (rejected && audit.CredentialID != "cred_rejected") || audit.CredentialVersion < 0 || (!rejected && audit.CredentialVersion == 0) || len(audit.SessionFingerprint) != 32 || len(audit.ReasonCode) == 0 || len(audit.ReasonCode) > 128 || len(audit.RequestID) > 128 || audit.OccurredAt.IsZero() {
		return fmt.Errorf("%w: credential audit metadata is invalid", ErrInvalid)
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO admin_credential_audit_events
			(event_id,event_kind,outcome,reason_code,actor_subject,cluster_id,credential_id,credential_version,session_fingerprint,request_id,occurred_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		audit.EventID, audit.EventKind, map[bool]string{true: "REJECTED", false: "SUCCEEDED"}[rejected], audit.ReasonCode, audit.ActorSubject, audit.ClusterID, audit.CredentialID,
		audit.CredentialVersion, append([]byte(nil), audit.SessionFingerprint...), audit.RequestID, audit.OccurredAt.UTC())
	if err != nil {
		return classifyMutationError("record credential audit", err)
	}
	return nil
}

// finishRejectedCredentialTx records the bounded rejection before committing
// the lock-only transaction. It must share the mutation transaction: opening a
// second transaction here would deadlock behind the cluster FOR UPDATE lock.
func finishRejectedCredentialTx(ctx context.Context, tx pgx.Tx, clusterID, subject, reason string, source MutationAudit, primary error) error {
	eventID, err := newCredentialAuditID()
	if err != nil {
		return fmt.Errorf("%w: rejection audit unavailable", primary)
	}
	audit := MutationAudit{EventID: eventID, EventKind: EventCredentialAttempt, ReasonCode: reason, ActorSubject: subject, ClusterID: clusterID, CredentialID: "cred_rejected", CredentialVersion: 0, SessionFingerprint: append([]byte(nil), source.SessionFingerprint...), RequestID: source.RequestID, OccurredAt: source.OccurredAt}
	if err := insertCredentialAudit(ctx, tx, audit); err != nil {
		return fmt.Errorf("%w: rejection audit unavailable", primary)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("%w: rejection audit unavailable", primary)
	}
	return primary
}

func classifyMissingCluster(ctx context.Context, tx pgx.Tx, id string) error {
	var removed bool
	err := tx.QueryRow(ctx, `SELECT removed_at IS NOT NULL FROM clusters WHERE cluster_id=$1`, id).Scan(&removed)
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("%w: cluster does not exist", ErrNotFound)
	}
	if err != nil {
		return fmt.Errorf("classify cluster update: %w", err)
	}
	if removed {
		return fmt.Errorf("%w: removed cluster cannot be updated", ErrConflict)
	}
	return fmt.Errorf("%w: cluster update was not applied", ErrConflict)
}

func classifyMutationError(operation string, err error) error {
	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) && postgresError.Code == "23505" {
		return fmt.Errorf("%w: %s", ErrConflict, operation)
	}
	return fmt.Errorf("%s: %w", operation, err)
}
