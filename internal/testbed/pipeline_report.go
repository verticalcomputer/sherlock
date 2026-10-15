package testbed

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/investigationtools"
	"github.com/verticalcomputer/sherlock/internal/modelprovider"
	"github.com/verticalcomputer/sherlock/internal/platform"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

func pipelineState(ctx context.Context, pool *pgxpool.Pool, prefix, boundary string) (CrashEvidence, error) {
	e := CrashEvidence{Boundary: boundary}
	err := pool.QueryRow(ctx, `SELECT
 (SELECT count(*) FROM collection_runs WHERE cluster_id=$1),
 (SELECT count(*) FROM observations WHERE cluster_id=$1),
 (SELECT count(*) FROM evidence_envelopes WHERE cluster_id=$1),
 (SELECT count(*) FROM incidents WHERE cluster_id=$1),
 (SELECT count(*) FROM investigations WHERE cluster_id=$1),
 (SELECT count(*) FROM automatic_investigation_attempts WHERE cluster_id=$1 AND status='RESERVED'),
 (SELECT count(*) FROM automatic_investigation_attempts WHERE cluster_id=$1 AND status='STARTED'),
 (SELECT count(*) FROM testbed_effects e JOIN investigations i ON i.investigation_id=e.investigation_id WHERE i.cluster_id=$1),
 (SELECT coalesce(sum(e.replay_count),0) FROM testbed_effects e JOIN investigations i ON i.investigation_id=e.investigation_id WHERE i.cluster_id=$1)`, prefix).Scan(&e.CollectionRuns, &e.Observations, &e.Envelopes, &e.Incidents, &e.Investigations, &e.ReservedStarts, &e.StartedAttempts, &e.Effects, &e.ReplayReceipts)
	if err != nil {
		return e, err
	}
	if boundary != "" {
		if err = pool.QueryRow(ctx, `SELECT process_id FROM testbed_crashes WHERE prefix=$1 AND boundary=$2`, prefix, boundary).Scan(&e.ProcessID); err != nil {
			return e, fmt.Errorf("crash marker missing: %w", err)
		}
	}
	if boundary == "" {
		if err = pool.QueryRow(ctx, `SELECT process_id FROM testbed_pipeline_workers WHERE prefix=$1 AND boundary=''`, prefix).Scan(&e.ProcessID); err != nil {
			return e, err
		}
	}
	if e.Investigations == 1 {
		var id domain.InvestigationID
		if err = pool.QueryRow(ctx, `SELECT investigation_id FROM investigations WHERE cluster_id=$1`, prefix).Scan(&id); err != nil {
			return e, err
		}
		store, _ := storepg.NewInvestigationStore(pool)
		snapshot, found, err := store.LoadInvestigation(ctx, id)
		if err != nil || !found {
			return e, fmt.Errorf("crash snapshot missing: %w", err)
		}
		e.State = string(snapshot.Investigation.Status())
		e.LedgerEntries, e.PendingEvidence, e.Actions = len(snapshot.Evidence.Entries()), len(snapshot.PendingEvidence), len(snapshot.PriorActions)
	}
	return e, nil
}

func validCrashState(e CrashEvidence) bool {
	if e.CollectionRuns != 2 || e.Observations != 2 || e.Envelopes != 6 {
		return false
	}
	switch e.Boundary {
	case "telemetry_committed":
		return e.Incidents == 0 && e.Investigations == 0
	case "incident_committed":
		return e.Incidents == 1 && e.Investigations == 0 && e.ReservedStarts == 1
	case "start_committed":
		return e.Incidents == 1 && e.Investigations == 1 && e.ReservedStarts == 1 && e.State == "INITIALIZING"
	case "effect_committed":
		return e.State == "EXECUTING" && e.Effects == 1 && e.Actions == 0 && e.LedgerEntries == 0
	case "evidence_recording_committed":
		// The production store commits pending evidence and the completed action
		// with this transition; reload reconstructs them in the ledger/history.
		return e.State == "RECORDING_EVIDENCE" && e.Effects == 1 && e.Actions == 1 && e.LedgerEntries == 2 && e.PendingEvidence == 0 && e.ReplayReceipts == 1
	case "terminal_committed", "":
		return e.Incidents == 1 && e.Investigations == 1 && e.ReservedStarts == 0 && e.StartedAttempts == 1 && e.State == "PARTIAL" && e.Effects == 4 && e.Actions == 4 && e.LedgerEntries == 6 && e.ReplayReceipts == 1
	}
	return false
}

func RunPipeline(ctx context.Context, pool *pgxpool.Pool, launch PipelineLauncher, processes bool) (PipelineResult, error) {
	result := PipelineResult{ContractSHA256: domain.ChecksumSHA256([]byte(pipelineContract)).String(), CrashRecoveryMode: "IN_PROCESS_RECONSTRUCTION", Violations: []string{}, UnmeasuredStages: []string{"resident_mtls_intake", "monitoring_episode_outbox_delivery", "investigator_lease_expiry", "transaction_in_flight_kill", "crash_after_provider_uncertainty", "live_model_quality", "native_agent_overhead", "native_diagnostic_execution"}}
	if pool == nil || launch == nil {
		return result, fmt.Errorf("pipeline database and launcher required")
	}
	if err := Setup(ctx, pool); err != nil {
		return result, err
	}
	suffix, err := (platform.RandomIDGenerator{}).NewID()
	if err != nil {
		return result, err
	}
	prefix := "tb-pipeline-" + suffix
	if _, err = pool.Exec(ctx, `INSERT INTO testbed_pipeline_inputs(prefix,observed_at) VALUES($1,date_trunc('second',clock_timestamp())-interval '2 minutes')`, prefix); err != nil {
		return result, err
	}
	pids := map[int]bool{}
	for _, boundary := range crashBoundaries {
		if err = launch(ctx, prefix, boundary); err != nil {
			return result, fmt.Errorf("pipeline %s: %w", boundary, err)
		}
		e, err := pipelineState(ctx, pool, prefix, boundary)
		if err != nil {
			return result, err
		}
		result.Crashes = append(result.Crashes, e)
		pids[e.ProcessID] = true
		if !validCrashState(e) {
			result.Violations = append(result.Violations, "unexpected durable crash state: "+boundary)
		}
	}
	if err = launch(ctx, prefix, ""); err != nil {
		return result, err
	}
	result.Final, err = pipelineState(ctx, pool, prefix, "")
	if err != nil {
		return result, err
	}
	if !validCrashState(result.Final) {
		result.Violations = append(result.Violations, "replay lost or duplicated durable pipeline work")
	}
	if processes {
		result.CrashRecoveryMode = "ABRUPT_PROCESS_EXIT"
		if len(pids) != len(crashBoundaries) || pids[result.Final.ProcessID] {
			result.Violations = append(result.Violations, "distinct crashed worker processes were not observed")
		}
	}
	var id domain.InvestigationID
	if err = pool.QueryRow(ctx, `SELECT investigation_id FROM investigations WHERE cluster_id=$1`, prefix).Scan(&id); err != nil {
		return result, err
	}
	scenario, err := pipelineWorld(ctx, pool, prefix, id)
	if err != nil {
		return result, err
	}
	// Independent numeric oracle: summaries must actually contain the two input
	// values. Deriving the oracle from candidate projections would mask corruption.
	if len(scenario.World.Evidence) != 6 || scenario.World.Evidence[0].Summary != "GPU-a on node-1 reported DCGM_FI_DEV_XID_ERRORS = 79 xid_code; this observation does not establish a physical cause." || scenario.World.Evidence[1].Summary != "GPU-a on node-1 reported DCGM_FI_DEV_GPU_TEMP = 87 celsius; this observation does not establish a physical cause." {
		result.Violations = append(result.Violations, "committed telemetry differs from independent numeric oracle")
	}
	result.Investigation, err = gradePipelineInvestigation(ctx, pool, scenario, id)
	if err != nil {
		return result, err
	}
	before, err := probe(ctx, pool, id)
	if err != nil {
		return result, err
	}
	fresh, err := pgxpool.NewWithConfig(ctx, pool.Config())
	if err != nil {
		return result, err
	}
	after, err := probe(ctx, fresh, id)
	fresh.Close()
	if err != nil {
		return result, err
	}
	result.Investigation.RestartContextEqual = bytes.Equal(before, after)
	if !result.Investigation.RestartContextEqual {
		result.Investigation.Violations = append(result.Investigation.Violations, "pipeline terminal context reconstruction differs")
	}
	result.Investigation.Passed = len(result.Investigation.Violations) == 0
	result.Passed = len(result.Violations) == 0 && result.Investigation.Passed
	return result, nil
}

func gradePipelineInvestigation(ctx context.Context, pool *pgxpool.Pool, s Scenario, id domain.InvestigationID) (Result, error) {
	r := Result{ScenarioID: s.ID, Violations: []string{}}
	store, _ := storepg.NewInvestigationStore(pool)
	snapshot, found, err := store.LoadInvestigation(ctx, id)
	if err != nil || !found {
		return r, fmt.Errorf("pipeline terminal snapshot unavailable: %w", err)
	}
	var lineage int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM automatic_investigation_attempts a JOIN incident_evidence ie ON ie.incident_id=a.incident_id JOIN evidence_envelopes e ON e.evidence_id=ie.evidence_id JOIN cluster_events ce ON ce.event_id=a.source_event_id JOIN incident_events ev ON ev.incident_id=a.incident_id AND ev.event_type='CREATED' WHERE a.investigation_id=$1 AND a.incident_id=$2 AND a.status='STARTED' AND e.evidence_id=$3 AND ce.cluster_id=a.cluster_id AND ce.payload->>'run_id'=e.run_id::text AND e.created_at<=ie.attached_at`, id, snapshot.Investigation.Request().IncidentID, s.Oracle.RequiredEvidence[0]).Scan(&lineage); err != nil {
		return r, err
	}
	r.Detection = DetectionResult{Scope: "PRODUCTION_XID_INCIDENT_ADMISSION", Measured: true, Opened: lineage == 1, Note: "Synthetic loopback telemetry; this does not qualify GP-09 episode/outbox or native diagnostics."}
	if lineage != 1 {
		r.Violations = append(r.Violations, "incident, source event, evidence and automatic start lineage missing")
	}
	r.Outcome = string(snapshot.Investigation.Status())
	if r.Outcome != "PARTIAL" {
		r.Violations = append(r.Violations, "pipeline asserted unsupported closure")
	}
	if len(snapshot.PriorActions) != 4 {
		r.Violations = append(r.Violations, "reviewed XID evidence pass incomplete")
	}
	for i, tool := range investigationtools.XIDRequiredEvidenceTools() {
		if len(snapshot.PriorActions) <= i || snapshot.PriorActions[i].ToolID != string(tool) {
			r.Violations = append(r.Violations, "reviewed XID diagnostic order changed")
		}
	}
	if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM investigation_context_checkpoints WHERE investigation_id=$1),(SELECT count(*) FROM investigation_context_manifests WHERE investigation_id=$1),(SELECT count(*) FROM investigation_model_calls WHERE investigation_id=$1),(SELECT count(*) FROM testbed_effects WHERE investigation_id=$1),(SELECT count(*) FROM testbed_workers WHERE investigation_id=$1)`, id).Scan(&r.Checkpoints, &r.Manifests, &r.AuditedCalls, &r.ExecutedActions, &r.WorkerProcesses); err != nil {
		return r, err
	}
	if r.Checkpoints < 1 || r.Manifests != 1 || r.AuditedCalls != 1 || r.ExecutedActions != 4 {
		r.Violations = append(r.Violations, "pipeline context, audit or execution path missing")
	}
	var raw []byte
	if err := pool.QueryRow(ctx, `SELECT payload FROM testbed_requests WHERE investigation_id=$1 AND kind='synthesis'`, id).Scan(&raw); err != nil {
		return r, err
	}
	var request modelprovider.SynthesisRequest
	if err := json.Unmarshal(raw, &request); err != nil {
		return r, err
	}
	for _, e := range request.Evidence {
		r.SelectedEvidence = append(r.SelectedEvidence, e.EvidenceID)
	}
	covered := 0
	byID := map[domain.EvidenceID]Evidence{}
	for _, e := range s.World.Evidence {
		byID[domain.EvidenceID(e.ID)] = e
	}
	for _, eid := range s.Oracle.RequiredEvidence {
		seen := false
		for _, f := range snapshot.Findings {
			if f.Kind == domain.FindingObservation && f.Statement == byID[domain.EvidenceID(eid)].Summary && slices.Contains(f.EvidenceIDs, domain.EvidenceID(eid)) && slices.Contains(r.SelectedEvidence, eid) {
				seen = true
			}
		}
		if seen {
			covered++
		} else {
			r.Violations = append(r.Violations, "ingested observation missing from durable report: "+eid)
		}
	}
	for _, f := range snapshot.Findings {
		if f.Kind != domain.FindingObservation {
			continue
		}
		supported := false
		for _, eid := range f.EvidenceIDs {
			if spec, ok := byID[eid]; ok && spec.Summary == f.Statement {
				supported = true
			}
		}
		if !supported {
			r.Violations = append(r.Violations, "pipeline report contains unsupported observation")
		}
	}
	for _, e := range s.World.Evidence {
		if e.Status == domain.EvidenceUnavailable && !slices.Contains(r.SelectedEvidence, e.ID) {
			r.Violations = append(r.Violations, "missing diagnostic class was hidden")
		}
	}
	unknown := false
	for _, section := range snapshot.ReportSections {
		if section.Kind == domain.ReportSectionUnknown && section.Statement == uncertainty {
			unknown = true
		}
	}
	if !unknown {
		r.Violations = append(r.Violations, "pipeline causal uncertainty omitted")
	}
	r.RequiredEvidenceRecall = float64(covered) / float64(len(s.Oracle.RequiredEvidence))
	r.SimulatedTokens = snapshot.Investigation.Usage().ModelTokens
	r.Passed = len(r.Violations) == 0
	return r, nil
}
