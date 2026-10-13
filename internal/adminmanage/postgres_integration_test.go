//go:build integration

package adminmanage_test

import (
	"context"
	"crypto/sha256"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/adminmanage"
	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

func TestPostgresStoreClusterLifecycleAndOperationalListings(t *testing.T) {
	databaseURL := os.Getenv("SHERLOCK_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("SHERLOCK_TEST_DATABASE_URL is not set; use an isolated migrated test database")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	store, err := adminmanage.NewPostgresStore(pool)
	if err != nil {
		t.Fatal(err)
	}

	suffix := time.Now().UTC().Format("20060102150405.000000000")
	clusterID := "admin-managed-cluster-" + suffix
	sourceID := "admin-managed-source-" + suffix
	jobID := "admin-managed-job-" + suffix
	collectorID := "admin-managed-collector-" + suffix
	certificateSerial := "admin-managed-cert-" + suffix
	apiKeyID := "admin-managed-key-" + suffix
	incidentID := "admin-managed-incident-" + suffix
	investigationID := "admin-managed-investigation-" + suffix
	findingID := "admin-managed-finding-" + suffix
	evidenceID := "admin-managed-evidence-" + suffix
	callID := "admin-managed-call-" + suffix
	timelineID := "admin-managed-timeline-" + suffix
	unknownID := "admin-managed-unknown-" + suffix
	actionCardID := "admin-managed-action-card-" + suffix
	now := time.Now().UTC().Truncate(time.Microsecond)

	mustExec(t, pool, `INSERT INTO clusters (cluster_id,display_name,created_at) VALUES ($1,'Before update',$2)`, clusterID, now)
	mustExec(t, pool, `INSERT INTO sources (source_id,cluster_id,kind,display_name,created_at) VALUES ($1,$2,'prometheus','Source',$3)`, sourceID, clusterID, now)
	mustExec(t, pool, `INSERT INTO collection_jobs (job_id,cluster_id,source_id,query_kind,interval_seconds,next_run_at,active) VALUES ($1,$2,$3,'GPU_HEALTH',60,$4,true)`, jobID, clusterID, sourceID, now)
	mustExec(t, pool, `INSERT INTO collectors (collector_id,cluster_id,display_name,status,version,build_commit,protocol_min,protocol_max,operating_system,architecture,created_at) VALUES ($1,$2,'Collector','ACTIVE','1.0.0','test',1,1,'linux','amd64',$3)`, collectorID, clusterID, now)
	certificateDigest := sha256.Sum256([]byte(certificateSerial))
	mustExec(t, pool, `INSERT INTO collector_identities (certificate_serial,collector_id,certificate_sha256,not_before,not_after,created_at) VALUES ($1,$2,$3,$4,$5,$4)`, certificateSerial, collectorID, certificateDigest[:], now, now.Add(time.Hour))
	mustExec(t, pool, `INSERT INTO api_keys (public_key_id,cluster_id,label,secret_hash,expires_at,created_at) VALUES ($1,$2,'Admin test',$3,$4,$5)`, apiKeyID, clusterID, make([]byte, 32), now.Add(time.Hour), now)
	mustExec(t, pool, `INSERT INTO incidents (incident_id,cluster_id,title,summary,severity,status,created_by,created_at,updated_at) VALUES ($1,$2,'Live admin ticket','Useful ticket context','HIGH','OPEN','test',$3,$3)`, incidentID, clusterID, now)
	mustExec(t, pool, `INSERT INTO investigations (investigation_id,cluster_id,incident_id,question,requested_by,scope,window_start,window_end,success_criteria,status,stop_reason,created_at,updated_at,completed_at) VALUES ($1,$2,$3,'What happened?','test','{"entity_kind":"node","entity_ids":["node-1"]}'::jsonb,$4,$4,'["identify cause"]'::jsonb,'PARTIAL','integration fixture',$4,$4,$4)`, investigationID, clusterID, incidentID, now)
	mustExec(t, pool, `INSERT INTO investigation_budgets(investigation_id,cluster_id,deadline,max_decision_iterations,max_tool_calls,max_privileged_calls,max_fan_out,max_model_tokens,max_cost_microunits) VALUES($1,$2,$3,1,1,0,1,1000,1000)`, investigationID, clusterID, now.Add(time.Hour))
	mustExec(t, pool, `INSERT INTO investigation_evidence (ledger_entry_id,cluster_id,investigation_id,sequence,entry_kind,status,exact_scope,observed_start,observed_end,recorded_at) VALUES ($1,$2,$3,1,'SOURCE_FRESHNESS','PARTIAL','{}'::jsonb,$4,$4,$4)`, "ledger-"+evidenceID, clusterID, investigationID, now)
	mustExec(t, pool, `INSERT INTO investigation_action_cards (investigation_id,cluster_id,action_card_id,owner,action,urgency,targets,rationale,blocking_gaps,escalation_condition,created_at,updated_at) VALUES ($1,$2,$3,'CLUSTER_OPERATIONS','Collect a fresh GPU snapshot','NEXT_SHIFT',ARRAY['node-1'],'The retained evidence is partial.',ARRAY['Kernel events are missing.'],'Escalate if the GPU remains degraded.',$4,$4)`, investigationID, clusterID, actionCardID, now)
	mustExec(t, pool, `INSERT INTO investigation_action_card_citations (cluster_id,investigation_id,action_card_id,ledger_entry_id) VALUES ($1,$2,$3,$4)`, clusterID, investigationID, actionCardID, "ledger-"+evidenceID)
	mustExec(t, pool, `INSERT INTO investigation_findings (finding_id,cluster_id,investigation_id,kind,statement,scope,severity,status,validation_status,validation_code,created_at,validated_at) VALUES ($1,$2,$3,'RECOMMENDATION','Inspect the affected node read-only','{"entity_ids":["node-1"]}'::jsonb,'INFO','CURRENT','VALID','',$4,$4)`, findingID, clusterID, investigationID, now)
	mustExec(t, pool, `INSERT INTO investigation_finding_citations (cluster_id,investigation_id,finding_id,ledger_entry_id,relationship) VALUES ($1,$2,$3,$4,'EVIDENCE')`, clusterID, investigationID, findingID, "ledger-"+evidenceID)
	mustExec(t, pool, `INSERT INTO investigation_report_omissions (cluster_id,investigation_id,kind,reason,omitted_count,created_at) VALUES ($1,$2,'OBSERVATION','NO_SUPPORTED_ENTITY',3,$3)`, clusterID, investigationID, now)
	// A context drop is the other half of the account: what the model was never
	// shown, as against what it answered and the domain then refused.
	mustExec(t, pool, `INSERT INTO investigation_report_omissions (cluster_id,investigation_id,kind,reason,omitted_count,created_at) VALUES ($1,$2,'EVIDENCE','CONTEXT_SIZE_LIMIT',7,$3)`, clusterID, investigationID, now)
	mustExec(t, pool, `INSERT INTO investigation_report_sections (section_id,cluster_id,investigation_id,kind,ordinal,statement,observed_at,created_at) VALUES ($1,$2,$3,'TIMELINE',0,'XID 94 first appeared on node-1',$4,$4)`, timelineID, clusterID, investigationID, now)
	mustExec(t, pool, `INSERT INTO investigation_report_section_citations (cluster_id,investigation_id,section_id,ledger_entry_id) VALUES ($1,$2,$3,$4)`, clusterID, investigationID, timelineID, "ledger-"+evidenceID)
	mustExec(t, pool, `INSERT INTO investigation_report_sections (section_id,cluster_id,investigation_id,kind,ordinal,statement,created_at) VALUES ($1,$2,$3,'UNKNOWN',0,'Onset before the window is unknown',$4)`, unknownID, clusterID, investigationID, now)
	mustExec(t, pool, `INSERT INTO investigation_model_calls (call_id,call_key,cluster_id,investigation_id,call_kind,provider,model,model_config_version,prompt_schema_version,tool_schema_version,input_tokens,output_tokens,cost_microunits,latency_milliseconds,outcome,reason_code,occurred_at) VALUES ($1,$1,$2,$3,'PLANNING','test','model','config-v1','prompt-v1','tools-v1',10,20,30,40,'SUCCEEDED','',$4)`, callID, clusterID, investigationID, now)

	updateAudit := mutationAudit("admin-update-audit-"+suffix, adminmanage.EventClusterUpdated, "DISPLAY_NAME_CHANGED", now)
	if err := store.UpdateCluster(ctx, clusterID, "After update", []string{"Collector", "Backup collector"}, updateAudit); err != nil {
		t.Fatal(err)
	}
	clusters, err := store.ListClusters(ctx, false, 10)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, cluster := range clusters {
		if cluster.ID == clusterID {
			found = cluster.DisplayName == "After update" && strings.Join(cluster.ExpectedCollectors, ",") == "Collector,Backup collector" && cluster.RemovedAt == nil
		}
	}
	if !found {
		t.Fatalf("updated cluster missing from active list: %+v", clusters)
	}

	operations, err := store.ListOperations(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if !containsTicket(operations.Tickets, incidentID, "Useful ticket context") || !containsInvestigation(operations.Investigations, investigationID, "node", "node-1", 30, 30) {
		t.Fatalf("operations do not include seeded records: %+v", operations)
	}
	clusterOperations, err := store.ListClusterOperations(ctx, clusterID, 100)
	if err != nil || len(clusterOperations.Tickets) != 1 || clusterOperations.Tickets[0].ClusterID != clusterID || len(clusterOperations.Investigations) != 1 || clusterOperations.Investigations[0].ClusterID != clusterID {
		t.Fatalf("cluster operations are not scoped: %+v, %v", clusterOperations, err)
	}
	report, err := store.GetInvestigationReport(ctx, investigationID)
	if err != nil {
		t.Fatal(err)
	}
	if report.Version < 1 {
		t.Fatalf("report missing controller version: %d", report.Version)
	}
	// The timeline entry must survive with its instant and citation, and the
	// uncited unknown must survive at all: a statement about absent data has no
	// evidence to point at, and dropping it would make the report look more
	// complete than the run was.
	// A report that dropped statements must say so; the count is the whole point.
	omitted := map[string]int{}
	for _, omission := range report.ReportOmissions {
		omitted[omission.Kind+"/"+omission.Reason] = omission.Count
	}
	if len(report.ReportOmissions) != 2 || omitted["OBSERVATION/NO_SUPPORTED_ENTITY"] != 3 || omitted["EVIDENCE/CONTEXT_SIZE_LIMIT"] != 7 {
		t.Fatalf("report omissions did not survive to the report: %+v", report.ReportOmissions)
	}
	if len(report.ReportSections) != 2 {
		t.Fatalf("report sections did not survive: %+v", report.ReportSections)
	}
	timeline, unknown := report.ReportSections[0], report.ReportSections[1]
	if timeline.Kind != "TIMELINE" || timeline.ObservedAt == nil || !timeline.ObservedAt.Equal(now) || len(timeline.EvidenceIDs) != 1 || timeline.EvidenceIDs[0] != evidenceID {
		t.Fatalf("timeline section lost its instant or citation: %+v", timeline)
	}
	if unknown.Kind != "UNKNOWN" || unknown.ObservedAt != nil || len(unknown.EvidenceIDs) != 0 {
		t.Fatalf("unknown section did not round-trip: %+v", unknown)
	}
	if report.PrimaryAction == nil || report.PrimaryAction.ID != actionCardID || report.PrimaryAction.Owner != "CLUSTER_OPERATIONS" || len(report.PrimaryAction.EvidenceIDs) != 1 || report.PrimaryAction.EvidenceIDs[0] != evidenceID {
		t.Fatalf("primary action card did not round-trip: %+v", report.PrimaryAction)
	}
	if report.EntityKind != "node" || len(report.SuccessCriteria) != 1 || len(report.Findings) != 1 || report.Findings[0].ID != findingID || len(report.Findings[0].EvidenceIDs) != 1 || report.Findings[0].EvidenceIDs[0] != evidenceID || len(report.Evidence) != 1 || len(report.ModelCalls) != 1 || report.ModelCalls[0].Input.Availability != adminmanage.PayloadNotRecorded || report.ModelUsage.AuditedTokens != 30 || report.ModelUsage.AuditedCostMicrounits != 30 {
		t.Fatalf("investigation report mismatch: %+v", report)
	}

	removedAt := now.Add(time.Minute)
	collections, err := storepg.NewCollectionStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	seeds := application.LegacyPrometheusSchedules(domain.ClusterID(clusterID), domain.SourceID(sourceID), domain.SchedulingLegacy, time.Minute, 10*time.Second, 100, 1024)
	if err := collections.ImportLegacyPrometheusSchedules(ctx, seeds, now); err != nil {
		t.Fatal(err)
	}
	// Include a durable owner: removal must disable desired intent even when
	// its compatibility job is already inactive.
	desired, err := collections.DesiredSchedule(ctx, seeds[0].ScheduleKey)
	if err != nil {
		t.Fatal(err)
	}
	desired.Mode = domain.SchedulingDurable
	if _, err := collections.UpdateDesiredSchedule(ctx, desired); err != nil {
		t.Fatal(err)
	}
	removeAudit := mutationAudit("admin-remove-audit-"+suffix, adminmanage.EventClusterRemoved, "OPERATOR_REMOVED", removedAt)
	if err := store.RemoveCluster(ctx, clusterID, removedAt, removeAudit); err != nil {
		t.Fatal(err)
	}
	if err := store.RemoveCluster(ctx, clusterID, removedAt, mutationAudit("admin-remove-retry-"+suffix, adminmanage.EventClusterRemoved, "OPERATOR_REMOVED", removedAt)); err == nil {
		t.Fatal("second removal unexpectedly succeeded")
	}

	var removed bool
	var activeJobs, activeCollectors, activeIdentities, activeKeys, historicalIncidents, historicalInvestigations, audits int
	err = pool.QueryRow(ctx, `SELECT
		(SELECT removed_at IS NOT NULL FROM clusters WHERE cluster_id=$1),
		(SELECT count(*) FROM collection_jobs WHERE cluster_id=$1 AND active),
		(SELECT count(*) FROM collectors WHERE cluster_id=$1 AND status <> 'REVOKED'),
		(SELECT count(*) FROM collector_identities i JOIN collectors c USING (collector_id) WHERE c.cluster_id=$1 AND i.revoked_at IS NULL),
		(SELECT count(*) FROM api_keys WHERE cluster_id=$1 AND revoked_at IS NULL),
		(SELECT count(*) FROM incidents WHERE cluster_id=$1),
		(SELECT count(*) FROM investigations WHERE cluster_id=$1),
		(SELECT count(*) FROM admin_dashboard_audit_events WHERE event_id IN ($2,$3))`,
		clusterID, updateAudit.EventID, removeAudit.EventID).Scan(
		&removed, &activeJobs, &activeCollectors, &activeIdentities, &activeKeys,
		&historicalIncidents, &historicalInvestigations, &audits,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !removed || activeJobs != 0 || activeCollectors != 0 || activeIdentities != 0 || activeKeys != 0 {
		t.Fatalf("removal state removed=%t jobs=%d collectors=%d identities=%d keys=%d", removed, activeJobs, activeCollectors, activeIdentities, activeKeys)
	}
	if historicalIncidents != 1 || historicalInvestigations != 1 || audits != 2 {
		t.Fatalf("history/audits incidents=%d investigations=%d audits=%d", historicalIncidents, historicalInvestigations, audits)
	}
	var enabledSchedules, totalSchedules int
	if err := pool.QueryRow(ctx, `SELECT count(*) FILTER(WHERE enabled),count(*) FROM desired_schedules WHERE cluster_id=$1`, clusterID).Scan(&enabledSchedules, &totalSchedules); err != nil {
		t.Fatal(err)
	}
	if enabledSchedules != 0 || totalSchedules != 4 {
		t.Fatalf("removal desired schedules: enabled=%d total=%d", enabledSchedules, totalSchedules)
	}
	if err := collections.ImportLegacyPrometheusSchedules(ctx, seeds, now); err != nil {
		t.Fatal(err)
	}
	if _, found, err := collections.ClaimDueClusterSourceJob(ctx, "removed-worker", time.Minute, domain.ClusterID(clusterID), domain.SourceID(sourceID)); err != nil || found {
		t.Fatalf("restart reclaimed removed cluster: %v %v", found, err)
	}
}

func mutationAudit(id, kind, reason string, occurredAt time.Time) adminmanage.MutationAudit {
	return adminmanage.MutationAudit{
		EventID: id, EventKind: kind, ReasonCode: reason,
		SessionFingerprint: make([]byte, 32), RequestID: "integration-test", OccurredAt: occurredAt,
	}
}

func containsTicket(tickets []adminmanage.Ticket, id, summary string) bool {
	for _, ticket := range tickets {
		if ticket.ID == id {
			return ticket.Summary == summary
		}
	}
	return false
}

func containsInvestigation(investigations []adminmanage.Investigation, id, entityKind, entityID string, tokens, cost int64) bool {
	for _, investigation := range investigations {
		if investigation.ID == id {
			return investigation.EntityKind == entityKind && len(investigation.EntityIDs) == 1 && investigation.EntityIDs[0] == entityID && investigation.AuditedTokens == tokens && investigation.AuditedCostMicrounits == cost
		}
	}
	return false
}

func mustExec(t *testing.T, pool *pgxpool.Pool, sql string, arguments ...any) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), sql, arguments...); err != nil {
		t.Fatal(err)
	}
}
