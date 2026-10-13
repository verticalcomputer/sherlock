//go:build integration

package postgres_test

import (
	"errors"
	"fmt"
	"github.com/verticalcomputer/sherlock/internal/adapters/investigationapi"
	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/platform"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
	"testing"
	"time"
)

func TestRepairProposalFrozenWarningsAndRepeatedInvestigations(t *testing.T) {
	ctx, pool := openContextAdmissionDatabase(t)
	suffix := time.Now().UTC().Format("20060102150405.000000000")
	cluster := domain.ClusterID("repair-" + suffix)
	source := domain.SourceID("source-" + suffix)
	collections, _ := storepg.NewCollectionStore(pool)
	if err := collections.EnsureSource(ctx, cluster, "repair", source, "repair"); err != nil {
		t.Fatal(err)
	}
	evidenceStore, _ := storepg.NewEvidenceStore(pool)
	store, _ := storepg.NewInvestigationStore(pool)
	observed := time.Now().UTC().Truncate(time.Microsecond).Add(-time.Minute)
	insert := func(id, operation string, status domain.EvidenceStatus, kind domain.EvidenceTargetKind, at time.Time) domain.EvidenceID {
		t.Helper()
		expected := []domain.EvidenceTarget{{Kind: domain.EvidenceTargetCluster, ID: domain.EvidenceTargetID(cluster)}, {Kind: kind, ID: "target-1"}}
		var covered []domain.EvidenceTarget
		if status == domain.EvidenceComplete {
			covered = expected
		}
		envelope, err := domain.CreateEvidenceEnvelope(domain.NewEvidenceEnvelope{ID: domain.EvidenceID(id + "-" + suffix), SchemaVersion: 1, ClusterID: cluster, Status: status, Source: domain.EvidenceSourceReference{SourceID: source, Operation: domain.EvidenceOperationID(operation), DefinitionVersion: "v1", Reference: "fixture://repair"}, TimeRange: domain.EvidenceTimeRange{Start: at, End: at}, CollectedAt: at, Coverage: domain.EvidenceCoverage{Expected: expected, Covered: covered}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = evidenceStore.CreateEvidence(ctx, envelope); err != nil {
			t.Fatal(err)
		}
		return envelope.ID()
	}
	// More history than the lookup limit must not hide another current stream.
	for n := 0; n < 260; n++ {
		insert(fmt.Sprintf("history-%d", n), "gpu.ecc_counters", domain.EvidenceUnavailable, domain.EvidenceTargetNode, observed.Add(-time.Duration(n+1)*time.Second))
	}
	ecc := insert("ecc", "gpu.ecc_counters", domain.EvidenceUnavailable, domain.EvidenceTargetNode, observed)
	xid := insert("xid", "dcgm_gpu_xid", domain.EvidencePartial, domain.EvidenceTargetGPU, observed)
	insert("old-fixed", "fixed", domain.EvidenceUnavailable, domain.EvidenceTargetNode, observed.Add(-time.Second))
	insert("fixed", "fixed", domain.EvidenceComplete, domain.EvidenceTargetNode, observed)
	var now time.Time
	if err := pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	// A later update must not rewrite the proposal's admitted warning set.
	future := insert("future-fixed", "dcgm_gpu_xid", domain.EvidenceComplete, domain.EvidenceTargetGPU, observed.Add(time.Second))
	if _, err := pool.Exec(ctx, `UPDATE evidence_envelopes SET created_at=$2 WHERE evidence_id=$1`, future, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	entries, more, err := store.FindCurrentRepairEvidence(ctx, "lookup", cluster, now.Add(-24*time.Hour), now, now, 256)
	if err != nil || more || len(entries) != 2 {
		t.Fatalf("entries=%d more=%t err=%v", len(entries), more, err)
	}
	ids := map[domain.EvidenceID]bool{}
	for _, entry := range entries {
		ids[entry.EvidenceID] = true
	}
	if !ids[ecc] || !ids[xid] {
		t.Fatalf("wrong current warnings: %+v", entries)
	}
	incident := domain.IncidentID("incident-" + suffix)
	if _, err := pool.Exec(ctx, `INSERT INTO incidents(incident_id,cluster_id,title,severity,status,created_by,created_at,updated_at) VALUES($1,$2,'repair','HIGH','OPEN','test',$3,$3)`, incident, cluster, now); err != nil {
		t.Fatal(err)
	}
	// Two different proposals must both be able to cite the same immutable rows.
	for n := 0; n < 2; n++ {
		id := domain.InvestigationID(fmt.Sprintf("repair-inv-%d-%s", n, suffix))
		action := domain.InvestigationAction{ID: domain.InvestigationActionID(fmt.Sprintf("repair-action-%d-%s", n, suffix)), ToolID: investigationapi.EvidenceLookupToolID, Digest: domain.ChecksumSHA256([]byte(id)), FanOut: 1, Targets: []string{string(cluster)}, Start: now.Add(-24 * time.Hour), End: now}
		request := domain.InvestigationRequest{ID: id, IncidentID: incident, ClusterID: cluster, Purpose: domain.InvestigationPurposeRepairPlan, Question: "Combined repair plan with XID", RequestedBy: "test", IdempotencyKey: string(id), Scope: domain.InvestigationScope{EntityKind: "cluster", EntityIDs: []string{string(cluster)}, Start: action.Start, End: action.End}, SuccessCriteria: []string{"cite every warning"}, Budget: domain.InvestigationBudget{MaxDecisions: 4, MaxToolCalls: 2, MaxFanOut: 1}, RequestedAt: now, Deadline: now.Add(time.Hour)}
		executor, _ := investigationapi.NewEvidenceExecutor(store, []domain.ClusterID{cluster})
		planner := &integrationSynthPlanner{ScriptedInvestigationPlanner: application.ScriptedInvestigationPlanner{Decisions: []application.InvestigationDecision{{Action: &action}, {Stop: true, Outcome: domain.InvestigationPartial, Reason: domain.StopNoUsefulAction}}}}
		controller, _ := application.NewInvestigationController(store, planner, executor, &integrationClock{now: now}, platform.RandomIDGenerator{})
		if _, created, err := controller.Start(ctx, application.StartInvestigationInput{Request: request}); err != nil || !created {
			t.Fatalf("created=%t err=%v", created, err)
		}
		for step := 0; step < 15; step++ {
			snapshot, found, err := store.LoadInvestigation(ctx, id)
			if err != nil || !found {
				t.Fatalf("load=%t err=%v", found, err)
			}
			if snapshot.Investigation.Request().Purpose != request.Purpose {
				t.Fatal("purpose lost during reload")
			}
			if len(snapshot.Evidence.Entries()) == 2 {
				break
			}
			if step == 14 {
				t.Fatal("warnings never attached")
			}
			if _, err := controller.Advance(ctx, id); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// The context-exhausted fallback report used fixed section and finding IDs.
// Those tables key on the ID alone, so the second investigation's upsert
// updated the first investigation's row, its citation insert violated the
// section foreign key, and the investigation could never become terminal.
func TestTerminalContextFallbackPersistsForEveryInvestigation(t *testing.T) {
	ctx, pool := openContextAdmissionDatabase(t)
	suffix := time.Now().UTC().Format("20060102150405.000000000")
	cluster := domain.ClusterID("fallback-" + suffix)
	source := domain.SourceID("source-" + suffix)
	collections, _ := storepg.NewCollectionStore(pool)
	if err := collections.EnsureSource(ctx, cluster, "fallback", source, "fallback"); err != nil {
		t.Fatal(err)
	}
	evidenceStore, _ := storepg.NewEvidenceStore(pool)
	store, _ := storepg.NewInvestigationStore(pool)
	observed := time.Now().UTC().Truncate(time.Microsecond).Add(-time.Minute)
	for _, operation := range []string{"gpu.ecc_counters", "dcgm_gpu_xid"} {
		expected := []domain.EvidenceTarget{{Kind: domain.EvidenceTargetCluster, ID: domain.EvidenceTargetID(cluster)}, {Kind: domain.EvidenceTargetGPU, ID: "target-1"}}
		envelope, err := domain.CreateEvidenceEnvelope(domain.NewEvidenceEnvelope{ID: domain.EvidenceID(operation + "-" + suffix), SchemaVersion: 1, ClusterID: cluster, Status: domain.EvidenceUnavailable, Source: domain.EvidenceSourceReference{SourceID: source, Operation: domain.EvidenceOperationID(operation), DefinitionVersion: "v1", Reference: "fixture://fallback"}, TimeRange: domain.EvidenceTimeRange{Start: observed, End: observed}, CollectedAt: observed, Coverage: domain.EvidenceCoverage{Expected: expected}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = evidenceStore.CreateEvidence(ctx, envelope); err != nil {
			t.Fatal(err)
		}
	}
	var now time.Time
	if err := pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	incident := domain.IncidentID("incident-" + suffix)
	if _, err := pool.Exec(ctx, `INSERT INTO incidents(incident_id,cluster_id,title,severity,status,created_by,created_at,updated_at) VALUES($1,$2,'fallback','HIGH','OPEN','test',$3,$3)`, incident, cluster, now); err != nil {
		t.Fatal(err)
	}
	cause := application.ClassifyInvestigationFailure(errors.New("synthesis context"), application.FailureEncodedContext)
	for n := 0; n < 2; n++ {
		id := domain.InvestigationID(fmt.Sprintf("fallback-inv-%d-%s", n, suffix))
		action := domain.InvestigationAction{ID: domain.InvestigationActionID(fmt.Sprintf("fallback-action-%d-%s", n, suffix)), ToolID: investigationapi.EvidenceLookupToolID, Digest: domain.ChecksumSHA256([]byte(id)), FanOut: 1, Targets: []string{string(cluster)}, Start: now.Add(-24 * time.Hour), End: now}
		request := domain.InvestigationRequest{ID: id, IncidentID: incident, ClusterID: cluster, Purpose: domain.InvestigationPurposeRepairPlan, Question: "Combined repair plan", RequestedBy: "test", IdempotencyKey: string(id), Scope: domain.InvestigationScope{EntityKind: "cluster", EntityIDs: []string{string(cluster)}, Start: action.Start, End: action.End}, SuccessCriteria: []string{"cite every warning"}, Budget: domain.InvestigationBudget{MaxDecisions: 4, MaxToolCalls: 2, MaxFanOut: 1}, RequestedAt: now, Deadline: now.Add(time.Hour)}
		executor, _ := investigationapi.NewEvidenceExecutor(store, []domain.ClusterID{cluster})
		planner := &integrationSynthPlanner{ScriptedInvestigationPlanner: application.ScriptedInvestigationPlanner{Decisions: []application.InvestigationDecision{{Action: &action}, {Stop: true, Outcome: domain.InvestigationPartial, Reason: domain.StopNoUsefulAction}}}}
		controller, _ := application.NewInvestigationController(store, planner, executor, &integrationClock{now: now}, platform.RandomIDGenerator{})
		if _, created, err := controller.Start(ctx, application.StartInvestigationInput{Request: request}); err != nil || !created {
			t.Fatalf("created=%t err=%v", created, err)
		}
		for step := 0; ; step++ {
			snapshot, found, err := store.LoadInvestigation(ctx, id)
			if err != nil || !found {
				t.Fatalf("load=%t err=%v", found, err)
			}
			if len(snapshot.Evidence.Entries()) == 2 && !snapshot.Investigation.Status().Terminal() {
				break
			}
			if step == 14 || snapshot.Investigation.Status().Terminal() {
				t.Fatalf("evidence was not attached before a terminal state: status=%s entries=%d", snapshot.Investigation.Status(), len(snapshot.Evidence.Entries()))
			}
			if _, err := controller.Advance(ctx, id); err != nil {
				t.Fatal(err)
			}
		}

		stopped, err := controller.StopAfterFailure(ctx, id, cause)
		if err != nil {
			t.Fatalf("investigation %d fallback was not persisted: %v", n, err)
		}
		if stopped.Investigation.Status() != domain.InvestigationPartial || stopped.Investigation.StopReason() != domain.StopContextExhausted {
			t.Fatalf("investigation %d stopped as %s/%s", n, stopped.Investigation.Status(), stopped.Investigation.StopReason())
		}
		var sections, sectionCitations, findings int
		// Count by owning investigation, not by ID, so the check is independent of
		// the fallback's identifier scheme.
		if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM investigation_report_sections WHERE investigation_id=$1 AND statement LIKE 'Terminal fallback%'), (SELECT count(*) FROM investigation_report_section_citations c JOIN investigation_report_sections s USING (cluster_id,investigation_id,section_id) WHERE c.investigation_id=$1 AND s.statement LIKE 'Terminal fallback%'), (SELECT count(*) FROM investigation_findings WHERE investigation_id=$1 AND kind='RECOMMENDATION')`, id).Scan(&sections, &sectionCitations, &findings); err != nil {
			t.Fatal(err)
		}
		if sections != 1 || sectionCitations != 2 || findings != 1 {
			t.Fatalf("investigation %d fallback rows: sections=%d citations=%d findings=%d", n, sections, sectionCitations, findings)
		}
		reloaded, found, err := store.LoadInvestigation(ctx, id)
		if err != nil || !found || reloaded.PrimaryActionCard == nil || len(reloaded.PrimaryActionCard.EvidenceIDs) != 2 {
			t.Fatalf("reload found=%t err=%v card=%+v", found, err, reloaded.PrimaryActionCard)
		}
	}
}
