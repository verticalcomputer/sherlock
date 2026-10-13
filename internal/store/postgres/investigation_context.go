package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/investigationcontext"
	"github.com/verticalcomputer/sherlock/internal/investigationtools"
)

const maxXIDContextRecords = 256

type metricContextRecord struct {
	EntityKey  string    `json:"entity_key"`
	Metric     string    `json:"metric"`
	Value      float64   `json:"value"`
	Unit       string    `json:"unit,omitempty"`
	ObservedAt time.Time `json:"observed_at"`
}

type metricAggregate struct {
	count            int
	minimum, maximum float64
	unit             string
}

func (store *InvestigationStore) loadMetricContext(ctx context.Context, clusterID domain.ClusterID, runID domain.RunID, operation domain.EvidenceOperationID, start, end time.Time) (string, string, error) {
	rows, err := store.pool.Query(ctx, `SELECT entity_key,metric,value,unit,observed_at FROM observations WHERE run_id=$1 AND cluster_id=$2 AND observed_at >= $3 AND observed_at <= $4 ORDER BY metric,entity_key,observed_at,observation_id LIMIT $5`, runID, clusterID, start.UTC(), end.UTC(), maxXIDContextRecords+1)
	if err != nil {
		return "", "", fmt.Errorf("query bounded %s evidence: %w", operation, err)
	}
	defer rows.Close()
	records := make([]metricContextRecord, 0, maxXIDContextRecords)
	truncated := false
	for rows.Next() {
		var record metricContextRecord
		if err := rows.Scan(&record.EntityKey, &record.Metric, &record.Value, &record.Unit, &record.ObservedAt); err != nil {
			return "", "", err
		}
		if len(records) == maxXIDContextRecords {
			truncated = true
			continue
		}
		record.ObservedAt = record.ObservedAt.UTC()
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return "", "", err
	}
	aggregates := map[string]metricAggregate{}
	for _, record := range records {
		value, ok := aggregates[record.Metric]
		if !ok {
			value.minimum, value.maximum, value.unit = record.Value, record.Value, record.Unit
		} else {
			if record.Value < value.minimum {
				value.minimum = record.Value
			}
			if record.Value > value.maximum {
				value.maximum = record.Value
			}
		}
		value.count++
		aggregates[record.Metric] = value
	}
	metrics := make([]string, 0, len(aggregates))
	for metric, value := range aggregates {
		metrics = append(metrics, fmt.Sprintf("%s(count=%d,min=%g,max=%g,unit=%s)", metric, value.count, value.minimum, value.maximum, value.unit))
	}
	sort.Strings(metrics)
	qualifier := ""
	if truncated {
		qualifier = "at least "
	}
	summary := fmt.Sprintf("%s normalized evidence contains %s%d bounded observations across %d metrics: %s. Values describe the recorded window only and do not by themselves establish onset or causality.", operation, qualifier, len(records), len(metrics), strings.Join(metrics, "; "))
	excerpt, err := json.Marshal(struct {
		SchemaVersion int                        `json:"schema_version"`
		Operation     domain.EvidenceOperationID `json:"operation"`
		Truncated     bool                       `json:"truncated"`
		Records       []metricContextRecord      `json:"records"`
	}{1, operation, truncated, records})
	if err != nil {
		return "", "", err
	}
	return summary, string(excerpt), nil
}

// LoadInvestigationEvidenceContext resolves only evidence that the durable
// investigation ledger already attached. XID records come from normalized
// observations for the immutable envelope's run; raw artifacts, source URLs,
// credentials, and arbitrary queries are outside this boundary.
func (store *InvestigationStore) LoadInvestigationEvidenceContext(ctx context.Context, snapshot application.InvestigationSnapshot) ([]investigationcontext.EvidenceInput, error) {
	if store == nil {
		return nil, fmt.Errorf("investigation evidence context store is unavailable")
	}
	request := snapshot.Investigation.Request()
	entries := snapshot.Evidence.Entries()
	result := make([]investigationcontext.EvidenceInput, 0, len(entries))
	for _, entry := range entries {
		var status domain.EvidenceStatus
		var sourceID domain.SourceID
		var operation domain.EvidenceOperationID
		var runID domain.RunID
		var observedFrom, observedTo, collectedAt, createdAt time.Time
		var artifactAvailability string
		var superseded bool
		var expectedJSON, coveredJSON []byte
		var sourceKind string
		var diagnosticRunID domain.DiagnosticRunID
		err := store.pool.QueryRow(ctx, `
			SELECT status,source_id,operation,COALESCE(run_id,''),observed_start,observed_end,collected_at,created_at,coverage_expected,coverage_covered,artifact_availability,
			       EXISTS(SELECT 1 FROM evidence_envelopes newer WHERE newer.cluster_id=$2 AND newer.supersedes_evidence_id=evidence_envelopes.evidence_id AND newer.created_at <= $3),
			       COALESCE((SELECT kind FROM sources WHERE sources.source_id=evidence_envelopes.source_id),''),
			       COALESCE(diagnostic_run_id,'')
			FROM evidence_envelopes
			WHERE evidence_id=$1 AND cluster_id=$2`, entry.EvidenceID, request.ClusterID, request.RequestedAt).Scan(
			&status, &sourceID, &operation, &runID, &observedFrom, &observedTo, &collectedAt, &createdAt, &expectedJSON, &coveredJSON, &artifactAvailability, &superseded, &sourceKind, &diagnosticRunID)
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("attached investigation evidence %s is unavailable", entry.EvidenceID)
		}
		if err != nil {
			return nil, fmt.Errorf("load attached investigation evidence %s: %w", entry.EvidenceID, err)
		}
		var diagnosticAdmission *diagnosticContextAdmission
		if createdAt.After(request.RequestedAt) {
			diagnosticAdmission, err = store.authorizePostRequestDiagnosticEvidence(ctx, request, entry, diagnosticRunID, createdAt)
			if err != nil {
				return nil, err
			}
		}
		if diagnosticAdmission == nil {
			observedFrom = latestTime(observedFrom, request.Scope.Start)
			observedTo = earliestTime(observedTo, request.Scope.End)
		}
		if observedTo.Before(observedFrom) {
			return nil, fmt.Errorf("attached investigation evidence is outside its durable scope")
		}
		var coverage domain.EvidenceCoverage
		if err := json.Unmarshal(expectedJSON, &coverage.Expected); err != nil {
			return nil, fmt.Errorf("decode expected context coverage: %w", err)
		}
		if err := json.Unmarshal(coveredJSON, &coverage.Covered); err != nil {
			return nil, fmt.Errorf("decode observed context coverage: %w", err)
		}
		expectedFrom, expectedTo := investigationEvidenceWindow(snapshot, entry.EvidenceID, request.Scope.Start, request.Scope.End)
		if diagnosticAdmission != nil {
			expectedFrom, expectedTo = observedFrom, observedTo
		}
		input := investigationcontext.EvidenceInput{
			EvidenceID: entry.EvidenceID, ClusterID: request.ClusterID, Operation: operation, EvidenceClass: string(operation), Status: status, EntityIDs: slices.Clone(entry.EntityIDs),
			ObservedFrom: observedFrom, ObservedTo: observedTo, CollectedAt: collectedAt,
			Source: string(sourceID) + ":" + string(operation), Priority: 10,
			Coverage: coverage, ExpectedFrom: expectedFrom, ExpectedTo: expectedTo,
			SummaryVersion: "operation-summary-v1", CommittedAt: createdAt, Retained: true,
			ArtifactAvailable: artifactAvailability == "NONE" || artifactAvailability == "AVAILABLE", CitationEligible: true, Superseded: superseded,
			AdmittedPostRequestDiagnostic: diagnosticAdmission != nil,
			// The reviewed binding, not the envelope, says whether this operation
			// reads history: the envelope's own window is what is under question.
			HistoricalWindow: investigationtools.DiagnosticObservationLookback(domain.DiagnosticDefinitionID(operation)) > 0,
		}
		if len(snapshot.PriorActions) > 0 {
			input.Latest = slices.Contains(snapshot.PriorActions[len(snapshot.PriorActions)-1].EvidenceIDs, entry.EvidenceID)
		}
		if operation == domain.EvidenceOperationID(domain.QueryGPUXID) {
			input.SummaryQuality = "MEANINGFUL"
			input.Summary, input.Excerpt, err = store.loadXIDContext(ctx, request.ClusterID, runID, entry.EntityIDs, observedFrom, observedTo)
			if err != nil {
				return nil, err
			}
		} else if diagnosticAdmission != nil || sourceKind == domain.DiagnosticEvidenceSourceKind {
			// A diagnostic writes no observations, so the metric path below finds
			// nothing for its run and the model is told a probe ran without being
			// told what it found. Read the execution's own recorded result.
			input.SummaryQuality = "MEANINGFUL"
			if diagnosticAdmission != nil {
				input.Summary, input.Excerpt, err = store.loadDiagnosticContext(ctx, request.ClusterID, diagnosticRunID, diagnosticAdmission.workID, diagnosticAdmission.attempt)
			} else {
				input.Summary, input.Excerpt, err = store.loadDiagnosticContext(ctx, request.ClusterID, diagnosticRunID, "", 0)
			}
			if err != nil {
				return nil, err
			}
		} else if runID != "" {
			input.SummaryQuality = "MEANINGFUL"
			input.Summary, input.Excerpt, err = store.loadMetricContext(ctx, request.ClusterID, runID, operation, observedFrom, observedTo)
			if err != nil {
				return nil, err
			}
		} else {
			input.SummaryQuality = "PROVENANCE_ONLY"
			input.Summary = fmt.Sprintf("%s evidence has status %s and covers %d of %d declared targets from %s to %s. No safe normalized detail is available, so this descriptor establishes provenance and coverage only, not event values or causality.", operation, status, len(coverage.Covered), len(coverage.Expected), observedFrom.UTC().Format(time.RFC3339), observedTo.UTC().Format(time.RFC3339))
		}
		result = append(result, input)
	}
	return result, nil
}

type diagnosticContextAdmission struct {
	workID  domain.DiagnosticWorkID
	attempt int
}

// authorizePostRequestDiagnosticEvidence is the only exception to the ordinary
// pre-request admission rule. It admits no evidence merely because it looks
// diagnostic: the investigation ledger, successfully recorded diagnostic
// action, unique action-to-run link, coherent terminal result, reviewed tool
// binding, exact targets, and immutable evidence projection must all name the
// same execution. A coherently failed run is admitted only as UNAVAILABLE;
// status-only tampering remains inconsistent with the target results.
func (store *InvestigationStore) authorizePostRequestDiagnosticEvidence(ctx context.Context, request domain.InvestigationRequest, entry domain.InvestigationEvidence, diagnosticRunID domain.DiagnosticRunID, createdAt time.Time) (*diagnosticContextAdmission, error) {
	if diagnosticRunID == "" {
		return nil, fmt.Errorf("attached investigation evidence was not committed before the request")
	}
	var toolID string
	var actionArguments, exactScope, planDigest []byte
	var workID domain.DiagnosticWorkID
	var attempt int
	var runnerID, attemptStatus string
	var startedAt, completedAt, attemptFinalizedAt, actionCompletionRecordedAt time.Time
	var durableStatus domain.EvidenceStatus
	var durableObservedStart, durableObservedEnd, durableRecordedAt time.Time
	var durableRequestedAt, durableWindowStart, durableWindowEnd time.Time
	var durableScope []byte
	err := store.pool.QueryRow(ctx, `
		SELECT a.tool_id,a.arguments,w.work_id,attempt.attempt,attempt.runner_id,attempt.status,
		       attempt.plan_digest,attempt.started_at,attempt.completed_at,attempt.finalized_at,a.completion_recorded_at,
		       ie.status,ie.exact_scope,ie.observed_start,ie.observed_end,ie.recorded_at,
		       i.created_at,i.window_start,i.window_end,i.scope
		FROM investigation_evidence ie
		JOIN investigations i
		  ON i.investigation_id=ie.investigation_id AND i.cluster_id=ie.cluster_id
		JOIN investigation_actions a
		  ON a.investigation_id=ie.investigation_id AND a.cluster_id=ie.cluster_id AND a.action_id=ie.action_id
		JOIN evidence_envelopes e
		  ON e.evidence_id=ie.evidence_id AND e.cluster_id=ie.cluster_id
		JOIN diagnostic_runs r
		  ON r.run_id=a.diagnostic_run_id AND r.run_id=e.diagnostic_run_id AND r.cluster_id=ie.cluster_id
		JOIN diagnostic_work_items w ON w.run_id=r.run_id
		JOIN diagnostic_work_attempts attempt
		  ON attempt.work_id=w.work_id
		 AND attempt.attempt=(
		   SELECT max(candidate.attempt) FROM diagnostic_work_attempts candidate
			WHERE candidate.work_id=w.work_id AND candidate.status IN ('SUCCEEDED','PARTIAL','FAILED')
		 )
		WHERE ie.investigation_id=$1 AND ie.cluster_id=$2 AND ie.evidence_id=$3
		  AND a.operation='DIAGNOSTIC' AND a.status='SUCCEEDED'
		  AND a.execution_receipt IS NOT NULL AND a.execution_receipt<>''
		  AND a.completed_at IS NOT NULL AND a.completion_recorded_at IS NOT NULL
		  AND attempt.finalized_at IS NOT NULL
		  AND a.diagnostic_run_id=$4
		  AND r.status IN ('SUCCEEDED','PARTIAL','FAILED')
		  AND w.status=r.status AND attempt.status=r.status
		  AND r.completed_at=attempt.completed_at`, request.ID, request.ClusterID, entry.EvidenceID, diagnosticRunID).Scan(
		&toolID, &actionArguments, &workID, &attempt, &runnerID, &attemptStatus,
		&planDigest, &startedAt, &completedAt, &attemptFinalizedAt, &actionCompletionRecordedAt,
		&durableStatus, &exactScope, &durableObservedStart, &durableObservedEnd, &durableRecordedAt,
		&durableRequestedAt, &durableWindowStart, &durableWindowEnd, &durableScope)
	if err == pgx.ErrNoRows {
		return nil, fmt.Errorf("post-request diagnostic evidence is not durably attributable to this investigation")
	}
	if err != nil {
		return nil, fmt.Errorf("authorize post-request diagnostic evidence: %w", err)
	}
	if !diagnosticCausalOrder(attemptFinalizedAt, createdAt, actionCompletionRecordedAt) {
		return nil, fmt.Errorf("post-request diagnostic evidence causal order is inconsistent")
	}
	if !durableRequestedAt.Equal(request.RequestedAt) || !durableWindowStart.Equal(request.Scope.Start) || !durableWindowEnd.Equal(request.Scope.End) {
		return nil, fmt.Errorf("post-request diagnostic evidence investigation scope is inconsistent")
	}
	var storedScope struct {
		EntityKind string   `json:"entity_kind"`
		EntityIDs  []string `json:"entity_ids"`
	}
	if err := json.Unmarshal(durableScope, &storedScope); err != nil || storedScope.EntityKind != request.Scope.EntityKind || !sameStringSet(storedScope.EntityIDs, request.Scope.EntityIDs) {
		return nil, fmt.Errorf("post-request diagnostic evidence investigation scope is inconsistent")
	}
	var ledgerScope struct {
		EntityIDs []string `json:"entity_ids"`
	}
	if err := json.Unmarshal(exactScope, &ledgerScope); err != nil || durableStatus != entry.Status || !durableObservedStart.Equal(entry.ObservedStart) || !durableObservedEnd.Equal(entry.ObservedEnd) || !durableRecordedAt.Equal(entry.RecordedAt) || !sameStringSet(ledgerScope.EntityIDs, entry.EntityIDs) {
		return nil, fmt.Errorf("post-request diagnostic evidence ledger attribution is inconsistent")
	}
	var action domain.InvestigationAction
	if err := decodeInvestigationActionArguments(actionArguments, &action); err != nil {
		return nil, fmt.Errorf("decode diagnostic action scope: %w", err)
	}
	if len(action.Arguments) != 0 || action.FanOut != len(action.Targets) || action.Start.IsZero() || action.End.Before(action.Start) ||
		action.Start.Before(request.Scope.Start) || action.End.After(request.Scope.End) ||
		!sameStringSet(action.Targets, ledgerScope.EntityIDs) || !targetsWithinScope(action.Targets, request.Scope.EntityIDs) {
		return nil, fmt.Errorf("post-request diagnostic evidence target is outside investigation scope")
	}
	binding, reviewed := investigationtools.DiagnosticBindingForTool(investigationtools.ToolID(toolID))
	if !reviewed {
		return nil, fmt.Errorf("post-request diagnostic evidence action has no reviewed definition binding")
	}
	run, found, err := loadDiagnosticRun(ctx, store.pool, diagnosticRunID, false)
	if err != nil || !found {
		return nil, fmt.Errorf("load post-request diagnostic run: %w", err)
	}
	runRequest := run.Request()
	if runRequest.ClusterID != request.ClusterID || run.Status() != domain.DiagnosticSucceeded && run.Status() != domain.DiagnosticPartial && run.Status() != domain.DiagnosticFailed ||
		runRequest.Definition.DefinitionID != binding.DefinitionID || runRequest.Definition.DefinitionVersion != binding.DefinitionVersion ||
		runRequest.Privilege != domain.DiagnosticUnprivileged || len(runRequest.Arguments) != 0 ||
		!sameDiagnosticTargets(runRequest.Targets, action.Targets) || runRequest.RequestedAt.Before(request.RequestedAt) ||
		runRequest.Deadline.After(request.Deadline) || startedAt.Before(runRequest.RequestedAt) || completedAt.After(runRequest.Deadline) {
		return nil, fmt.Errorf("post-request diagnostic run does not match the admitted action")
	}
	if len(planDigest) != len(domain.SHA256{}) {
		return nil, fmt.Errorf("post-request diagnostic plan digest is invalid")
	}
	var digest domain.SHA256
	copy(digest[:], planDigest)
	targetResults, err := loadDiagnosticTargetResults(ctx, store.pool, workID, attempt)
	if err != nil {
		return nil, fmt.Errorf("load post-request diagnostic target results: %w", err)
	}
	attemptResult := domain.DiagnosticAttemptResult{WorkID: workID, RunID: diagnosticRunID, Attempt: attempt, RunnerID: runnerID, PlanDigest: digest, StartedAt: startedAt.UTC(), CompletedAt: completedAt.UTC(), Targets: targetResults}
	if err := attemptResult.Validate(runRequest.Targets); err != nil {
		return nil, fmt.Errorf("post-request diagnostic result is incomplete: %w", err)
	}
	resultStatus := domain.DiagnosticFailed
	succeeded := 0
	for _, target := range targetResults {
		if target.Status == domain.DiagnosticTargetSucceeded {
			succeeded++
		}
	}
	if succeeded == len(targetResults) {
		resultStatus = domain.DiagnosticSucceeded
	} else if succeeded > 0 {
		resultStatus = domain.DiagnosticPartial
	}
	if run.Status() != resultStatus || attemptStatus != string(resultStatus) {
		return nil, fmt.Errorf("post-request diagnostic terminal state is inconsistent with its target results")
	}
	projected, err := domain.DiagnosticEvidenceForAttempt(runRequest, attemptResult, binding.ObservationLookback)
	if err != nil {
		return nil, fmt.Errorf("project post-request diagnostic evidence: %w", err)
	}
	stored, availability, found, err := (&EvidenceStore{pool: store.pool}).LoadEvidence(ctx, entry.EvidenceID)
	if err != nil || !found {
		return nil, fmt.Errorf("load post-request diagnostic evidence: %w", err)
	}
	if !stored.Equal(projected) || availability != domain.ArtifactAvailability("NONE") {
		return nil, fmt.Errorf("post-request diagnostic evidence provenance is inconsistent")
	}
	return &diagnosticContextAdmission{workID: workID, attempt: attempt}, nil
}

func diagnosticCausalOrder(attemptFinalizedAt, evidenceCreatedAt, actionCompletionRecordedAt time.Time) bool {
	if attemptFinalizedAt.IsZero() || evidenceCreatedAt.IsZero() || actionCompletionRecordedAt.IsZero() {
		return false
	}
	return !evidenceCreatedAt.Before(attemptFinalizedAt) && !actionCompletionRecordedAt.Before(evidenceCreatedAt)
}

func sameStringSet(left, right []string) bool {
	left, right = slices.Clone(left), slices.Clone(right)
	slices.Sort(left)
	slices.Sort(right)
	return slices.Equal(left, right)
}

func targetsWithinScope(targets, scope []string) bool {
	allowed := make(map[string]struct{}, len(scope))
	for _, target := range scope {
		allowed[target] = struct{}{}
	}
	for _, target := range targets {
		if _, ok := allowed[target]; !ok {
			return false
		}
	}
	return len(targets) > 0
}

func sameDiagnosticTargets(targets []domain.DiagnosticTarget, actionTargets []string) bool {
	values := make([]string, len(targets))
	for index, target := range targets {
		values[index] = string(target)
	}
	return sameStringSet(values, actionTargets)
}

func investigationEvidenceWindow(snapshot application.InvestigationSnapshot, evidenceID domain.EvidenceID, fallbackStart, fallbackEnd time.Time) (time.Time, time.Time) {
	for _, action := range snapshot.PriorActions {
		if slices.Contains(action.EvidenceIDs, evidenceID) && !action.Start.IsZero() && !action.End.Before(action.Start) {
			return latestTime(action.Start, fallbackStart), earliestTime(action.End, fallbackEnd)
		}
	}
	return fallbackStart, fallbackEnd
}

type xidContextRecord struct {
	Hostname     string    `json:"hostname,omitempty"`
	GPUUUID      string    `json:"gpu_uuid,omitempty"`
	Device       string    `json:"device,omitempty"`
	XIDCode      string    `json:"xid_code"`
	ErrorCode    string    `json:"exporter_error_code,omitempty"`
	ErrorMessage string    `json:"exporter_error_message,omitempty"`
	ObservedAt   time.Time `json:"observed_at"`
}

func (store *InvestigationStore) loadXIDContext(ctx context.Context, clusterID domain.ClusterID, runID domain.RunID, targets []string, start, end time.Time) (string, string, error) {
	if runID == "" {
		return "", "", fmt.Errorf("XID evidence has no collection run")
	}
	clusterWide := slices.Contains(targets, string(clusterID))
	rows, err := store.pool.Query(ctx, `
		SELECT labels,value,observed_at
		FROM observations
		WHERE run_id=$1 AND cluster_id=$2 AND metric='DCGM_FI_DEV_XID_ERRORS'
		  AND observed_at >= $3 AND observed_at <= $4
		  AND ($5 OR EXISTS (
		    SELECT 1 FROM jsonb_array_elements(labels) AS label
		    WHERE label->>'Name' IN ('Hostname','hostname','UUID','uuid')
		      AND label->>'Value'=ANY($6::text[])
		  ))
		ORDER BY entity_key,observed_at,observation_id
		LIMIT $7`, runID, clusterID, start.UTC(), end.UTC(), clusterWide, targets, maxXIDContextRecords+1)
	if err != nil {
		return "", "", fmt.Errorf("query bounded XID evidence: %w", err)
	}
	defer rows.Close()
	targetSet := make(map[string]struct{}, len(targets))
	for _, target := range targets {
		targetSet[target] = struct{}{}
	}
	records := make([]xidContextRecord, 0, maxXIDContextRecords)
	truncated := false
	for rows.Next() {
		var encoded []byte
		var value float64
		var observedAt time.Time
		if err := rows.Scan(&encoded, &value, &observedAt); err != nil {
			return "", "", fmt.Errorf("scan bounded XID evidence: %w", err)
		}
		var labels []domain.Label
		if err := json.Unmarshal(encoded, &labels); err != nil {
			return "", "", fmt.Errorf("decode bounded XID labels: %w", err)
		}
		values := labelValues(labels)
		host, uuid := values["Hostname"], values["UUID"]
		if host == "" {
			host = values["hostname"]
		}
		if uuid == "" {
			uuid = values["uuid"]
		}
		if !xidTargetAllowed(targetSet, string(clusterID), host, uuid) {
			continue
		}
		if len(records) == maxXIDContextRecords {
			truncated = true
			continue
		}
		records = append(records, xidContextRecord{
			Hostname: host, GPUUUID: uuid, Device: values["device"], XIDCode: strconv.FormatFloat(value, 'f', -1, 64),
			ErrorCode: boundedText(values["err_code"], 128), ErrorMessage: boundedText(values["err_msg"], 256), ObservedAt: observedAt.UTC(),
		})
	}
	if err := rows.Err(); err != nil {
		return "", "", fmt.Errorf("iterate bounded XID evidence: %w", err)
	}
	nodes := map[string]struct{}{}
	codes := map[string]int{}
	nonzero := 0
	for _, record := range records {
		if record.Hostname != "" {
			nodes[record.Hostname] = struct{}{}
		}
		codes[record.XIDCode]++
		if record.XIDCode != "0" {
			nonzero++
		}
	}
	codeParts := make([]string, 0, len(codes))
	for code, count := range codes {
		codeParts = append(codeParts, code+"="+strconv.Itoa(count))
	}
	sort.Strings(codeParts)
	qualifier := ""
	if truncated {
		qualifier = "at least "
	}
	summary := fmt.Sprintf("Prometheus DCGM XID snapshot contains %s%d normalized samples across %d nodes; %d samples are non-zero; code counts: %s. XID gauges may retain the last reported code, so this snapshot does not by itself prove event onset.", qualifier, len(records), len(nodes), nonzero, strings.Join(codeParts, ","))
	excerpt, err := json.Marshal(struct {
		SchemaVersion int                `json:"schema_version"`
		Metric        string             `json:"metric"`
		Truncated     bool               `json:"truncated"`
		Records       []xidContextRecord `json:"records"`
	}{SchemaVersion: 1, Metric: "DCGM_FI_DEV_XID_ERRORS", Truncated: truncated, Records: records})
	if err != nil {
		return "", "", fmt.Errorf("encode bounded XID evidence: %w", err)
	}
	return summary, string(excerpt), nil
}

func labelValues(labels []domain.Label) map[string]string {
	result := make(map[string]string, len(labels))
	for _, label := range labels {
		result[label.Name] = label.Value
	}
	return result
}

func xidTargetAllowed(targets map[string]struct{}, cluster, host, uuid string) bool {
	for _, candidate := range []string{cluster, host, uuid} {
		if _, allowed := targets[candidate]; allowed {
			return true
		}
	}
	return false
}

func boundedText(value string, maximum int) string {
	value = strings.ReplaceAll(strings.ReplaceAll(value, "\r", " "), "\n", " ")
	if len(value) > maximum {
		return value[:maximum]
	}
	return value
}

func latestTime(left, right time.Time) time.Time {
	if right.After(left) {
		return right
	}
	return left
}

func earliestTime(left, right time.Time) time.Time {
	if right.Before(left) {
		return right
	}
	return left
}

// maxDiagnosticContextTargets bounds how many per-target results one diagnostic
// contributes, so a wide fan-out cannot crowd out every other evidence block.
const maxDiagnosticContextTargets = 16

// loadDiagnosticContext projects one remote execution into a summary and an
// excerpt.
//
// The summary is Sherlock's own account of the execution -- which hosts
// answered, how they exited -- and is trusted because the control plane
// recorded it. The excerpt is what the probe printed, and is not: it is
// untrusted output from a cluster host, so it travels in the excerpt channel
// the context builder renders as untrusted_excerpt and never in the summary.
func (store *InvestigationStore) loadDiagnosticContext(ctx context.Context, clusterID domain.ClusterID, runID domain.DiagnosticRunID, admittedWorkID domain.DiagnosticWorkID, admittedAttempt int) (string, string, error) {
	if runID == "" {
		return "", "", fmt.Errorf("diagnostic evidence has no run")
	}
	rows, err := store.pool.Query(ctx, `
		SELECT t.target, t.status, t.exit_code, t.stdout_bytes, t.stdout_truncated, t.stdout_excerpt, t.error_code, t.stdout_transformation_state
		FROM diagnostic_target_results t
		JOIN diagnostic_work_items w ON w.work_id=t.work_id
		JOIN diagnostic_runs r ON r.run_id=w.run_id
		WHERE r.cluster_id=$1 AND r.run_id=$2
		  AND ($4='' OR t.work_id=$4 AND t.attempt=$5)
		ORDER BY t.attempt DESC, t.target
		LIMIT $3`, clusterID, runID, maxDiagnosticContextTargets+1, admittedWorkID, admittedAttempt)
	if err != nil {
		return "", "", fmt.Errorf("query bounded diagnostic evidence: %w", err)
	}
	defer rows.Close()
	type targetRecord struct {
		target, status, excerpt, errorCode, transformationState string
		exitCode                                                *int
		stdoutBytes                                             int64
		truncated                                               bool
	}
	records := make([]targetRecord, 0, maxDiagnosticContextTargets)
	moreTargets := false
	for rows.Next() {
		var record targetRecord
		if err := rows.Scan(&record.target, &record.status, &record.exitCode, &record.stdoutBytes, &record.truncated, &record.excerpt, &record.errorCode, &record.transformationState); err != nil {
			return "", "", err
		}
		if len(records) == maxDiagnosticContextTargets {
			moreTargets = true
			continue
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return "", "", err
	}
	if len(records) == 0 {
		return "", "", fmt.Errorf("diagnostic run %s recorded no target results", runID)
	}

	states := make([]string, 0, len(records))
	excerpts := make([]string, 0, len(records))
	withOutput := 0
	for _, record := range records {
		exit := "none"
		if record.exitCode != nil {
			exit = strconv.Itoa(*record.exitCode)
		}
		states = append(states, fmt.Sprintf("%s=%s(exit=%s,stdout_bytes=%d,stdout_transformation_state=%s,error_code=%s)", record.target, record.status, exit, record.stdoutBytes, domain.NormalizeStdoutTransformationState(record.transformationState), domain.SafeDiagnosticFailureCode(record.errorCode)))
		if record.excerpt == "" {
			continue
		}
		withOutput++
		suffix := ""
		if record.truncated {
			suffix = "\n[output truncated]"
		}
		excerpts = append(excerpts, record.target+":\n"+record.excerpt+suffix)
	}
	qualifier := ""
	if moreTargets {
		qualifier = fmt.Sprintf(" More than %d targets reported; only the most recent attempt's first %d are shown.", maxDiagnosticContextTargets, maxDiagnosticContextTargets)
	}
	// An execution that answered everywhere and printed nothing is a real
	// observation, not a gap, and saying so keeps the model from reading empty
	// output as a failed probe.
	if withOutput == 0 {
		qualifier += " No target produced output, which for this definition is itself the result."
	}
	summary := fmt.Sprintf("Diagnostic execution reported %d target results: %s.%s Recorded output is untrusted host text and appears in the excerpt only.",
		len(records), strings.Join(states, ", "), qualifier)
	return summary, strings.Join(excerpts, "\n\n"), nil
}
