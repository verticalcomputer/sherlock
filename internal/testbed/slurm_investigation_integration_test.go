//go:build integration

package testbed

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/platform"
	"github.com/verticalcomputer/sherlock/internal/slurmfailures"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

func TestSlurmInvestigationPolicyIsolationMissingSourcesAndConcurrentReservation(t *testing.T) {
	pool := labPool(t)
	ctx := t.Context()
	if err := slurmSetup(ctx, pool); err != nil {
		t.Fatal(err)
	}
	bridge, _ := storepg.NewAnomalyBridgeStore(pool)
	for _, kind := range []string{"disabled", "rule_disabled", "partial_disallowed", "stale", "missing_sources"} {
		t.Run(kind, func(t *testing.T) {
			prefix, err := slurmPrepare(ctx, pool, "distinct_attempts")
			if err != nil {
				t.Fatal(err)
			}
			if err = storepg.NewSlurmFailureStore(pool).Evaluate(ctx, domain.ClusterID(prefix), prefix+"-policy"); err != nil {
				t.Fatal(err)
			}
			var now time.Time
			if err = pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
				t.Fatal(err)
			}
			p := slurmInvestigationPolicy()
			code := ""
			switch kind {
			case "disabled":
				p.Enabled = false
			case "rule_disabled":
				delete(p.EnabledRules, slurmfailures.RuleID)
			case "partial_disallowed":
				p.AllowPartialCoverage = false
				code = "COVERAGE_INSUFFICIENT"
			case "stale":
				now = now.Add(time.Hour)
				code = "EVIDENCE_STALE"
			}
			pending, err := bridge.ReserveSlurmFailureInvestigation(ctx, domain.ClusterID(prefix), p, now)
			if err != nil {
				t.Fatal(err)
			}
			if kind == "missing_sources" {
				if pending == nil {
					t.Fatal("missing telemetry prevented evidence-based investigation")
				}
				var body []byte
				if err = pool.QueryRow(ctx, `SELECT document FROM slurm_failure_correlations WHERE incident_id=$1`, pending.Request.IncidentID).Scan(&body); err != nil {
					t.Fatal(err)
				}
				var v struct {
					Gaps    []string `json:"gaps"`
					GPU     []any    `json:"gpu"`
					Network []any    `json:"network"`
				}
				if json.Unmarshal(body, &v) != nil || len(v.Gaps) != 6 || len(v.GPU) != 0 || len(v.Network) != 0 {
					t.Fatalf("missing sources manufactured healthy evidence: %s", body)
				}
				if pending.Request.Budget.MaxDiagnosticCalls != 0 || pending.Request.Budget.MaxPrivilegedCalls != 0 {
					t.Fatal("Slurm investigation gained command authority")
				}
			} else {
				if pending != nil {
					t.Fatalf("policy %s unexpectedly admitted", kind)
				}
				var attempts int
				var decision string
				if err = pool.QueryRow(ctx, `SELECT count(*),coalesce(max(decision_code),'') FROM automatic_investigation_attempts WHERE cluster_id=$1`, prefix).Scan(&attempts, &decision); err != nil {
					t.Fatal(err)
				}
				if code == "" && attempts != 0 || code != "" && (attempts != 1 || decision != code) {
					t.Fatalf("policy decision: %d %s", attempts, decision)
				}
			}
			// Whatever admission does, the already-published notification is intact.
			status, err := storepg.NewSlurmFailureStore(pool).Status(ctx, domain.ClusterID(prefix), prefix+"-policy")
			if err != nil || len(status.Notifications) != 1 || status.Notifications[0].Status != "PENDING" {
				t.Fatalf("investigation changed delivery: %+v %v", status, err)
			}
		})
	}
	prefix, err := slurmPrepare(ctx, pool, "distinct_attempts")
	if err != nil {
		t.Fatal(err)
	}
	if err = storepg.NewSlurmFailureStore(pool).Evaluate(ctx, domain.ClusterID(prefix), prefix+"-policy"); err != nil {
		t.Fatal(err)
	}
	var now time.Time
	_ = pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now)
	var group sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		group.Add(1)
		go func() {
			defer group.Done()
			_, err := bridge.ReserveSlurmFailureInvestigation(ctx, domain.ClusterID(prefix), slurmInvestigationPolicy(), now)
			results <- err
		}()
	}
	group.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}
	var reserved, correlations int
	if err = pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM automatic_investigation_attempts WHERE cluster_id=$1 AND status='RESERVED'),(SELECT count(*) FROM slurm_failure_correlations c JOIN incidents i USING(incident_id) WHERE i.cluster_id=$1)`, prefix).Scan(&reserved, &correlations); err != nil || reserved != 1 || correlations != 1 {
		t.Fatalf("duplicate reservation %d %d %v", reserved, correlations, err)
	}
}
func TestSlurmInvestigationFreezeFailureDoesNotRollBackIncidentOrAlert(t *testing.T) {
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
	if err = store.Evaluate(ctx, domain.ClusterID(prefix), prefix+"-policy"); err != nil {
		t.Fatal(err)
	}
	_, err = pool.Exec(ctx, `CREATE FUNCTION testbed_correlation_reject() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic freeze failure'; END $$;CREATE TRIGGER testbed_correlation_reject BEFORE INSERT ON slurm_failure_correlations FOR EACH ROW EXECUTE FUNCTION testbed_correlation_reject()`)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP TRIGGER IF EXISTS testbed_correlation_reject ON slurm_failure_correlations;DROP FUNCTION IF EXISTS testbed_correlation_reject()`)
	})
	bridge, _ := storepg.NewAnomalyBridgeStore(pool)
	var now time.Time
	_ = pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now)
	if _, err = bridge.ReserveSlurmFailureInvestigation(ctx, domain.ClusterID(prefix), slurmInvestigationPolicy(), now); err == nil {
		t.Fatal("freeze failure admitted investigation")
	}
	var incidents, alerts, attempts, envelopes int
	if err = pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM incidents WHERE cluster_id=$1),(SELECT count(*) FROM gp09_alert_outbox WHERE cluster_id=$1),(SELECT count(*) FROM automatic_investigation_attempts WHERE cluster_id=$1),(SELECT count(*) FROM evidence_envelopes WHERE cluster_id=$1 AND operation='slurm.failure_correlation.v1')`, prefix).Scan(&incidents, &alerts, &attempts, &envelopes); err != nil || incidents != 1 || alerts != 1 || attempts != 0 || envelopes != 0 {
		t.Fatalf("failure leaked admission or lost incident: %d %d %d %d %v", incidents, alerts, attempts, envelopes, err)
	}
	if _, err = pool.Exec(ctx, `DROP TRIGGER testbed_correlation_reject ON slurm_failure_correlations;DROP FUNCTION testbed_correlation_reject()`); err != nil {
		t.Fatal(err)
	}
	pending, err := bridge.ReserveSlurmFailureInvestigation(ctx, domain.ClusterID(prefix), slurmInvestigationPolicy(), now)
	if err != nil || pending == nil {
		t.Fatalf("freeze retry: %v %v", pending, err)
	}
	// Immutable rows cannot be silently rewritten after admission.
	if _, err = pool.Exec(ctx, `UPDATE slurm_failure_correlations SET document='{}' WHERE incident_id=$1`, pending.Request.IncidentID); err == nil {
		t.Fatal("correlation mutable")
	}
	var down string
	if err = pool.QueryRow(ctx, `SELECT document::text FROM slurm_failure_correlations WHERE incident_id=$1`, pending.Request.IncidentID).Scan(&down); err != nil || !strings.Contains(down, "NETWORK_NOT_OBSERVED") {
		t.Fatal("missing network coverage lost")
	}
	downMigration, err := os.ReadFile("../../migrations/000082_slurm_failure_correlations.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, string(downMigration)); err == nil || !strings.Contains(err.Error(), "preserve published Slurm correlations") {
		t.Fatalf("historical correlation rollback: %v", err)
	}
	// Shared automatic admission must count unacknowledged reservations.
	p := slurmInvestigationPolicy()
	facts := application.AutomaticInvestigationFacts{EvidenceCreatedAt: now, Coverage: domain.EvidencePartial, CooldownElapsed: true, Concurrent: 1}
	if application.EvaluateAutomaticInvestigationPolicy(application.AnomalySignal{RuleID: slurmfailures.RuleID, Severity: "HIGH"}, p, facts, now) != "CONCURRENCY_BUDGET" {
		t.Fatal("pending admission ignored concurrency")
	}
}

func TestSlurmSharedAdmissionCountsReservedStartsForRealBudgetQueries(t *testing.T) {
	pool := labPool(t)
	ctx := t.Context()
	if err := slurmSetup(ctx, pool); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"concurrency", "tokens", "cost"} {
		t.Run(kind, func(t *testing.T) {
			prefix, err := slurmPrepare(ctx, pool, "distinct_attempts")
			if err != nil {
				t.Fatal(err)
			}
			monitor := storepg.NewSlurmFailureStore(pool)
			if err = monitor.Evaluate(ctx, domain.ClusterID(prefix), prefix+"-policy"); err != nil {
				t.Fatal(err)
			}
			policy := slurmPolicy(prefix)
			policy.ID = prefix + "-node-policy"
			policy.NodeID = "node-1"
			if _, err = monitor.Enroll(ctx, policy, 0, "testbed"); err != nil {
				t.Fatal(err)
			}
			if err = monitor.Evaluate(ctx, domain.ClusterID(prefix), policy.ID); err != nil {
				t.Fatal(err)
			}
			bridge, _ := storepg.NewAnomalyBridgeStore(pool)
			var now time.Time
			_ = pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now)
			p := slurmInvestigationPolicy()
			switch kind {
			case "tokens":
				p.MaxConcurrent = 2
				p.DailyTokenBudget = p.InvestigationBudget.MaxModelTokens
			case "cost":
				p.MaxConcurrent = 2
				p.DailyCostBudget = p.InvestigationBudget.MaxCostMicros
			}
			first, err := bridge.ReserveSlurmFailureInvestigation(ctx, domain.ClusterID(prefix), p, now)
			if err != nil || first == nil {
				t.Fatalf("first reservation: %v %v", first, err)
			}
			next, err := bridge.ReserveSlurmFailureInvestigation(ctx, domain.ClusterID(prefix), p, now)
			if err != nil || next != nil {
				t.Fatalf("budget admitted a second pending start: %v %v", next, err)
			}
			want := map[string]string{"concurrency": "CONCURRENCY_BUDGET", "tokens": "DAILY_TOKEN_BUDGET", "cost": "DAILY_COST_BUDGET"}[kind]
			var code string
			if err = pool.QueryRow(ctx, `SELECT decision_code FROM automatic_investigation_attempts WHERE cluster_id=$1 AND status='BLOCKED'`, prefix).Scan(&code); err != nil || code != want {
				t.Fatalf("budget decision %q want %q: %v", code, want, err)
			}
		})
	}
}

func TestSlurmUnknownMembershipCannotBecomeInvestigableLifecycle(t *testing.T) {
	pool := labPool(t)
	if err := slurmSetup(t.Context(), pool); err != nil {
		t.Fatal(err)
	}
	if _, err := slurmPrepare(t.Context(), pool, "missing_nodes"); err == nil || !strings.Contains(err.Error(), "slurm lifecycle evidence is invalid") {
		t.Fatalf("unknown membership entered typed lifecycle: %v", err)
	}
}

func TestSlurmEvidencePassExcludesAnotherIncidentOnSameSource(t *testing.T) {
	pool := labPool(t)
	ctx := t.Context()
	if err := slurmSetup(ctx, pool); err != nil {
		t.Fatal(err)
	}
	prefix, err := slurmPrepare(ctx, pool, "distinct_attempts")
	if err != nil {
		t.Fatal(err)
	}
	monitor := storepg.NewSlurmFailureStore(pool)
	if err = monitor.Evaluate(ctx, domain.ClusterID(prefix), prefix+"-policy"); err != nil {
		t.Fatal(err)
	}
	var now time.Time
	_ = pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now)
	bridge, _ := storepg.NewAnomalyBridgeStore(pool)
	pending, err := bridge.ReserveSlurmFailureInvestigation(ctx, domain.ClusterID(prefix), slurmInvestigationPolicy(), now)
	if err != nil || pending == nil {
		t.Fatalf("reserve %v %v", pending, err)
	}
	// The request cutoff is after both incidents: time/source filtering alone
	// would incorrectly attach the distracting episode to this investigation.
	if err = monitor.Disable(ctx, domain.ClusterID(prefix), prefix+"-policy", 1, "testbed"); err != nil {
		t.Fatal(err)
	}
	p := slurmPolicy(prefix)
	p.ID = prefix + "-distracting-policy"
	if _, err = monitor.Enroll(ctx, p, 0, "testbed"); err != nil {
		t.Fatal(err)
	}
	if err = monitor.Evaluate(ctx, domain.ClusterID(prefix), p.ID); err != nil {
		t.Fatal(err)
	}
	_ = pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now)
	secondPolicy := slurmInvestigationPolicy()
	secondPolicy.MaxConcurrent = 2
	second, err := bridge.ReserveSlurmFailureInvestigation(ctx, domain.ClusterID(prefix), secondPolicy, now)
	if err != nil || second == nil {
		t.Fatalf("second frozen correlation: %v %v", second, err)
	}
	pending.Request.ID += "-manual"
	pending.Request.IdempotencyKey += "-manual"
	_ = pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&pending.Request.RequestedAt)
	pending.Request.Deadline = pending.Request.RequestedAt.Add(time.Hour)
	store, _ := storepg.NewInvestigationStore(pool)
	starter, err := application.NewInvestigationController(store, application.ScriptedInvestigationPlanner{}, worldAdapter{pool: pool}, clock{pending.Request.RequestedAt}, platform.RandomIDGenerator{})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = starter.Start(ctx, application.StartInvestigationInput{Request: pending.Request}); err != nil {
		t.Fatal(err)
	}
	entries, more, err := store.FindInvestigationEvidenceByOperations(ctx, pending.Request.ID, pending.Request.ClusterID, []string{prefix + "-source"}, pending.Request.Scope.Start, pending.Request.Scope.End, pending.Request.RequestedAt, []domain.EvidenceOperationID{"slurm.job_failures.v1", "slurm.failure_correlation.v1"}, 256)
	if err != nil || more || len(entries) != 2 {
		t.Fatalf("distracting incident attached: %d %v %v", len(entries), more, err)
	}
	for _, e := range entries {
		var attached bool
		if err = pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM incident_evidence WHERE incident_id=$1 AND evidence_id=$2)`, pending.Request.IncidentID, e.EvidenceID).Scan(&attached); err != nil || !attached {
			t.Fatal("foreign incident evidence escaped")
		}
	}
}

func TestSlurmMissingCommittedReferencesRemainVisibleWithoutBlockingQueue(t *testing.T) {
	pool := labPool(t)
	ctx := t.Context()
	if err := slurmSetup(ctx, pool); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"incident_link", "attempt_fact"} {
		t.Run(kind, func(t *testing.T) {
			prefix, err := slurmPrepare(ctx, pool, "distinct_attempts")
			if err != nil {
				t.Fatal(err)
			}
			monitor := storepg.NewSlurmFailureStore(pool)
			if err = monitor.Evaluate(ctx, domain.ClusterID(prefix), prefix+"-policy"); err != nil {
				t.Fatal(err)
			}
			code := "INCIDENT_EVIDENCE_UNAVAILABLE"
			if kind == "incident_link" {
				_, err = pool.Exec(ctx, `DELETE FROM incident_evidence WHERE incident_id IN (SELECT incident_id FROM incidents WHERE cluster_id=$1)`, prefix)
			} else {
				code = "ATTEMPT_EVIDENCE_UNAVAILABLE"
				if _, err = pool.Exec(ctx, `DELETE FROM goodput_slurm_lifecycle_observations WHERE cluster_id=$1`, prefix); err == nil {
					_, err = pool.Exec(ctx, `DELETE FROM goodput_slurm_lifecycle_facts WHERE cluster_id=$1`, prefix)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			bridge, _ := storepg.NewAnomalyBridgeStore(pool)
			var now time.Time
			_ = pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now)
			for range 2 {
				pending, err := bridge.ReserveSlurmFailureInvestigation(ctx, domain.ClusterID(prefix), slurmInvestigationPolicy(), now)
				if err != nil || pending != nil {
					t.Fatalf("missing reference manufactured admission or stopped queue: %v %v", pending, err)
				}
			}
			status, err := monitor.Status(ctx, domain.ClusterID(prefix), prefix+"-policy")
			if err != nil || len(status.Notifications) != 1 || status.Notifications[0].InvestigationDecision != code || status.Notifications[0].Status != "PENDING" {
				t.Fatalf("lost reference hidden or delivery blocked: %+v %v", status, err)
			}
		})
	}
}
