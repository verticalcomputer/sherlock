//go:build integration

package testbed

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/verticalcomputer/sherlock/internal/application"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/alertdelivery"
	"github.com/verticalcomputer/sherlock/internal/domain"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

func TestSlurmFailureControlsReplayAndCrashRecovery(t *testing.T) {
	pool := labPool(t)
	r, err := RunSlurm(t.Context(), pool, func(ctx context.Context, prefix, boundary string) error {
		err := SlurmWorker(ctx, pool, prefix, boundary, nil)
		if boundary != "" && errors.Is(err, ErrInjectedCrash) {
			return nil
		}
		return err
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Passed || len(r.Cases) != 5 || len(r.CrashPIDs) != 3 {
		raw, _ := json.MarshalIndent(r, "", "  ")
		t.Fatal(string(raw))
	}
}
func TestSlurmPublicationAtomicRollbackRevocationAndReceiverFailure(t *testing.T) {
	pool := labPool(t)
	ctx := t.Context()
	if err := slurmSetup(ctx, pool); err != nil {
		t.Fatal(err)
	}
	prefix, err := slurmPrepare(ctx, pool, "distinct_attempts")
	if err != nil {
		t.Fatal(err)
	}
	store := storepg.NewSlurmFailureStore(pool)
	// A publication failure must roll back the incident, evidence, outbox and
	// consumed attempt keys, leaving the same observations eligible on retry.
	_, err = pool.Exec(ctx, `CREATE FUNCTION testbed_slurm_reject() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.transition='SLURM_FAILURES' THEN RAISE EXCEPTION 'synthetic private do not log'; END IF; RETURN NEW; END $$; CREATE TRIGGER testbed_slurm_reject BEFORE INSERT ON gp09_alert_outbox FOR EACH ROW EXECUTE FUNCTION testbed_slurm_reject()`)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP TRIGGER IF EXISTS testbed_slurm_reject ON gp09_alert_outbox;DROP FUNCTION IF EXISTS testbed_slurm_reject()`)
	})
	if err = store.Refresh(ctx); err == nil || strings.Contains(err.Error(), "synthetic private") {
		t.Fatalf("unsafe publication failure: %v", err)
	}
	var incidents, consumed int
	if err = pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM incidents WHERE cluster_id=$1),(SELECT count(*) FROM slurm_failure_consumed WHERE policy_id=$2)`, prefix, prefix+"-policy").Scan(&incidents, &consumed); err != nil || incidents != 0 || consumed != 0 {
		t.Fatalf("non-atomic publication: %d %d %v", incidents, consumed, err)
	}
	status, err := store.Status(ctx, domain.ClusterID(prefix), prefix+"-policy")
	if err != nil || status.LastCode != "EVALUATION_FAILED" {
		t.Fatalf("failure invisible: %+v %v", status, err)
	}
	if _, err = pool.Exec(ctx, `DROP TRIGGER testbed_slurm_reject ON gp09_alert_outbox;DROP FUNCTION testbed_slurm_reject()`); err != nil {
		t.Fatal(err)
	}
	if err = store.Evaluate(ctx, domain.ClusterID(prefix), prefix+"-policy"); err != nil {
		t.Fatal(err)
	}
	outbox, _ := storepg.NewAlertOutboxStore(pool)
	claim, found, err := outbox.ClaimForCluster(ctx, prefix)
	if err != nil || !found {
		t.Fatalf("claim: %v %v", found, err)
	}
	result := sendSlurmFixture(ctx, pool, prefix, claim, true)
	if result.Outcome != alertdelivery.RetryableFailure {
		t.Fatal("receiver failure treated as success")
	}
	if _, err = outbox.Finish(ctx, claim, result); err != nil {
		t.Fatal(err)
	}
	status, err = store.Status(ctx, domain.ClusterID(prefix), prefix+"-policy")
	if err != nil || len(status.Notifications) != 1 || status.Notifications[0].Status != "PENDING" || status.Notifications[0].LastCode != "RECEIVER_RETRYABLE" {
		t.Fatalf("receiver failure hidden: %+v %v", status, err)
	}
	// Retrying evaluation cannot duplicate a queued incident/notification.
	if err = store.Evaluate(ctx, domain.ClusterID(prefix), prefix+"-policy"); err != nil {
		t.Fatal(err)
	}
	revoked, err := slurmPrepare(ctx, pool, "distinct_attempts")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `UPDATE collectors SET status='REVOKED',revoked_at=clock_timestamp() WHERE collector_id=$1`, revoked+"-collector"); err != nil {
		t.Fatal(err)
	}
	if err = store.Evaluate(ctx, domain.ClusterID(revoked), revoked+"-policy"); err != nil {
		t.Fatal(err)
	}
	status, err = store.Status(ctx, domain.ClusterID(revoked), revoked+"-policy")
	if err != nil || status.ActiveIncidentID != nil || status.LastCode != "ACCOUNTING_STALE_OR_UNAVAILABLE" {
		t.Fatalf("revoked collector qualified: %+v %v", status, err)
	}
}

func TestSlurmConcurrentEvaluationDisableAndRearm(t *testing.T) {
	pool := labPool(t)
	ctx := t.Context()
	if err := slurmSetup(ctx, pool); err != nil {
		t.Fatal(err)
	}
	prefix, err := slurmPrepare(ctx, pool, "distinct_attempts")
	if err != nil {
		t.Fatal(err)
	}
	store := storepg.NewSlurmFailureStore(pool)
	var group sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		group.Add(1)
		go func() { defer group.Done(); results <- store.Evaluate(ctx, domain.ClusterID(prefix), prefix+"-policy") }()
	}
	group.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}
	status, err := store.Status(ctx, domain.ClusterID(prefix), prefix+"-policy")
	if err != nil || status.Occurrence != 1 || len(status.Notifications) != 1 || len(status.Notifications[0].Snapshot) != 3 {
		t.Fatalf("duplicate concurrent episode: %+v %v", status, err)
	}
	// The real context loader must expose meaningful committed failure evidence.
	investigationStore, _ := storepg.NewInvestigationStore(pool)
	evidenceStore, _ := storepg.NewEvidenceStore(pool)
	envelope, _, found, err := evidenceStore.LoadEvidence(ctx, domain.EvidenceID(status.Notifications[0].EvidenceID))
	if err != nil || !found {
		t.Fatal(err)
	}
	var at time.Time
	if err = pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&at); err != nil {
		t.Fatal(err)
	}
	request := domain.InvestigationRequest{ID: domain.InvestigationID(prefix + "-investigation"), IncidentID: domain.IncidentID(*status.ActiveIncidentID), ClusterID: domain.ClusterID(prefix), Question: "Why are Slurm attempts failing?", RequestedBy: "testbed", IdempotencyKey: prefix + "-investigation", Scope: domain.InvestigationScope{EntityKind: "source", EntityIDs: []string{prefix + "-source"}, Start: envelope.TimeRange().Start, End: envelope.TimeRange().End}, SuccessCriteria: []string{"Retain failure evidence and uncertainty"}, Budget: domain.InvestigationBudget{MaxDecisions: 2, MaxToolCalls: 1, MaxFanOut: 1}, RequestedAt: at, Deadline: at.Add(time.Hour)}
	inv, err := domain.NewInvestigation(request)
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := domain.NewEvidenceLedger([]domain.InvestigationEvidence{{EvidenceID: envelope.ID(), InvestigationID: request.ID, ClusterID: request.ClusterID, EntityIDs: request.Scope.EntityIDs, Status: envelope.Status(), ObservedStart: envelope.TimeRange().Start, ObservedEnd: envelope.TimeRange().End, RecordedAt: envelope.CollectedAt()}}, inv)
	if err != nil {
		t.Fatal(err)
	}
	contexts, err := investigationStore.LoadInvestigationEvidenceContext(ctx, application.InvestigationSnapshot{Investigation: inv, Evidence: ledger})
	if err != nil || len(contexts) != 1 || contexts[0].SummaryQuality != "MEANINGFUL" || !strings.Contains(contexts[0].Excerpt, "42") {
		t.Fatalf("failure evidence lost in context: %+v %v", contexts, err)
	}
	// Disable is revision-checked; reenabling does not discard the consumed keys.
	if err = store.Disable(ctx, domain.ClusterID(prefix), prefix+"-policy", 1, "testbed"); err != nil {
		t.Fatal(err)
	}
	if err = store.Disable(ctx, domain.ClusterID(prefix), prefix+"-policy", 1, "testbed"); err == nil {
		t.Fatal("stale disable revision accepted")
	}
	if _, err = store.Enroll(ctx, slurmPolicy(prefix), 2, "testbed"); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `UPDATE incidents SET status='RESOLVED',resolved_at=clock_timestamp(),updated_at=clock_timestamp() WHERE incident_id=$1`, *status.ActiveIncidentID); err != nil {
		t.Fatal(err)
	}
	if err = store.Evaluate(ctx, domain.ClusterID(prefix), prefix+"-policy"); err != nil {
		t.Fatal(err)
	}
	status, err = store.Status(ctx, domain.ClusterID(prefix), prefix+"-policy")
	if err != nil || status.Occurrence != 1 || status.ActiveIncidentID != nil {
		t.Fatalf("old attempts reopened incident: %+v %v", status, err)
	}
	if err = pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&at); err != nil {
		t.Fatal(err)
	}
	records := []domain.SlurmJobLifecycle{}
	for i := 3; i < 6; i++ {
		l := slurmLifecycle(prefix, "42", i, "FAILED", at)
		l.EndAt = at
		l.RecordIdentity = domain.CanonicalSlurmLifecycleRecordID(l)
		records = append(records, l)
	}
	if err = submitSlurmFixture(ctx, pool, prefix, prefix+"-new", records); err != nil {
		t.Fatal(err)
	}
	if err = store.Evaluate(ctx, domain.ClusterID(prefix), prefix+"-policy"); err != nil {
		t.Fatal(err)
	}
	status, err = store.Status(ctx, domain.ClusterID(prefix), prefix+"-policy")
	if err != nil || status.Occurrence != 2 || len(status.Notifications) != 2 {
		t.Fatalf("new attempts did not rearm: %+v %v", status, err)
	}
}

func TestSlurmMigrationBackfillsExistingFacts(t *testing.T) {
	pool := labPool(t)
	ctx := t.Context()
	prefix, err := slurmPrepare(ctx, pool, "distinct_attempts")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `DELETE FROM slurm_failure_inputs WHERE cluster_id=$1`, prefix); err != nil {
		t.Fatal(err)
	}
	migration, err := os.ReadFile("../../migrations/000081_slurm_failure_monitor.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := string(migration)
	start := strings.Index(sql, "INSERT INTO slurm_failure_inputs")
	end := strings.Index(sql[start:], ";") + start
	if start < 0 || end < start {
		t.Fatal("backfill migration missing")
	}
	if _, err = pool.Exec(ctx, sql[start:end+1]); err != nil {
		t.Fatal(err)
	}
	var records int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM slurm_failure_inputs WHERE cluster_id=$1 AND failed`, prefix).Scan(&records); err != nil || records != 3 {
		t.Fatalf("legacy attempts not backfilled: %d %v", records, err)
	}
	if err = storepg.NewSlurmFailureStore(pool).Evaluate(ctx, domain.ClusterID(prefix), prefix+"-policy"); err != nil {
		t.Fatal(err)
	}
	status, err := storepg.NewSlurmFailureStore(pool).Status(ctx, domain.ClusterID(prefix), prefix+"-policy")
	if err != nil || status.Occurrence != 1 {
		t.Fatalf("backfilled facts not evaluated: %+v %v", status, err)
	}
	// Missing accounting freshness cannot turn an existing fault into recovery.
	if _, err = pool.Exec(ctx, `UPDATE collectors SET status='REVOKED',revoked_at=clock_timestamp() WHERE collector_id=$1`, prefix+"-collector"); err != nil {
		t.Fatal(err)
	}
	if err = storepg.NewSlurmFailureStore(pool).Evaluate(ctx, domain.ClusterID(prefix), prefix+"-policy"); err != nil {
		t.Fatal(err)
	}
	status, err = storepg.NewSlurmFailureStore(pool).Status(ctx, domain.ClusterID(prefix), prefix+"-policy")
	if err != nil || status.ActiveIncidentID == nil || status.LastCode != "ACCOUNTING_STALE_OR_UNAVAILABLE" {
		t.Fatalf("missing data cleared fault: %+v %v", status, err)
	}
}
