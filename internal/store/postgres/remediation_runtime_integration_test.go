//go:build integration

package postgres_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/remediation"
	"github.com/verticalcomputer/sherlock/internal/remediationruntime"
)

// TestRemediationRuntimeRunsTheSignedSimulationEndToEnd exercises the actual
// supervisor rather than calling application transitions directly.  A success
// requires separate controlled simulation observations after each durable
// attempt; executor receipts alone never satisfy a postcondition.
func TestRemediationRuntimeRunsTheSignedSimulationEndToEnd(t *testing.T) {
	f := newRemediationFixture(t)
	ctx := context.Background()
	rt := runtimeForFixture(t, f)
	expandRuntimePopulation(t, f, 12)
	prepareRuntimeFixture(t, f, f.targets[:3])

	var runID domain.RemediationRunID
	for iteration := 0; iteration < 80; iteration++ {
		if _, err := rt.RunOnce(ctx); err != nil {
			t.Fatalf("iteration %d: %v", iteration, err)
		}
		if runID == "" {
			if err := f.pool.QueryRow(ctx, `SELECT run_id FROM remediation_runs WHERE cluster_id=$1 ORDER BY created_at LIMIT 1`, f.clusterID).Scan(&runID); err != nil {
				t.Fatal(err)
			}
		}
		loaded, found, err := f.store.LoadRemediationRun(ctx, f.clusterID, runID)
		if err != nil || !found {
			t.Fatalf("load: found=%v err=%v", found, err)
		}
		if loaded.Run.State() == domain.RemediationVerifying && loaded.LatestAttemptID != "" {
			insertSimulationEvidence(t, f, runID, loaded.LatestAttemptID, loaded.LatestTargets)
		}
		if loaded.Run.State() == domain.RemediationSucceeded {
			if len(loaded.ExecutedTargets) != 3 {
				t.Fatalf("executed targets=%v", loaded.ExecutedTargets)
			}
			var attempts int
			if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM remediation_attempts WHERE cluster_id=$1 AND run_id=$2`, f.clusterID, runID).Scan(&attempts); err != nil {
				t.Fatal(err)
			}
			if attempts != 3 {
				t.Fatalf("attempts=%d want canary plus two rollout waves", attempts)
			}
			var runs int
			if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM remediation_runs WHERE cluster_id=$1 AND action_card_id=$2`, f.clusterID, f.actionCardID).Scan(&runs); err != nil {
				t.Fatal(err)
			}
			if runs != 1 {
				t.Fatalf("action-card dedup created %d runs", runs)
			}
			return
		}
		time.Sleep(12 * time.Millisecond)
	}
	t.Fatal("runtime did not reach SUCCEEDED")
}

// TestRemediationRuntimeHonoursTheGlobalKillSwitch drives the same supervisor
// path with an otherwise valid signed release and standing policy.  Default-off
// remains a durable admission gate, not a constructor option that can be lost
// after restart.
func TestRemediationRuntimeHonoursTheGlobalKillSwitch(t *testing.T) {
	f := newRemediationFixture(t)
	rt := runtimeForFixture(t, f)
	prepareRuntimeFixture(t, f, f.targets[:1])
	if _, err := f.pool.Exec(context.Background(), `UPDATE remediation_global_state SET remediation_enabled=false WHERE id`); err != nil {
		t.Fatal(err)
	}
	var state domain.RemediationState
	for iteration := 0; iteration < 20; iteration++ {
		if _, err := rt.RunOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
		err := f.pool.QueryRow(context.Background(), `SELECT state FROM remediation_runs WHERE cluster_id=$1 ORDER BY created_at LIMIT 1`, f.clusterID).Scan(&state)
		if err == nil && state == domain.RemediationPolicyBlocked {
			return
		}
		time.Sleep(12 * time.Millisecond)
	}
	t.Fatalf("kill switch state=%s, want POLICY_BLOCKED", state)
}

func TestRemediationRuntimeHonoursClusterPolicyRevocation(t *testing.T) {
	f := newRemediationFixture(t)
	rt := runtimeForFixture(t, f)
	prepareRuntimeFixture(t, f, f.targets[:1])
	if _, err := f.pool.Exec(context.Background(), `UPDATE remediation_policies SET revoked_at=clock_timestamp() WHERE cluster_id=$1`, f.clusterID); err != nil {
		t.Fatal(err)
	}
	assertRuntimePolicyBlocked(t, f, rt)
}

func TestRemediationRuntimeTimeoutRollsBackAndRevisionMismatchFails(t *testing.T) {
	for _, tc := range []struct {
		name     string
		mismatch bool
		want     domain.RemediationState
	}{
		{"restores", false, domain.RemediationRolledBack},
		{"revision-mismatch", true, domain.RemediationRollbackFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newRemediationFixture(t)
			rt := runtimeForFixture(t, f)
			prepareRuntimeFixture(t, f, f.targets[:1])
			runID := advanceRuntimeToVerifying(t, f, rt)
			for poll := 0; poll < 3; poll++ {
				if _, err := rt.RunOnce(context.Background()); err != nil {
					t.Fatal(err)
				}
				loaded, found, err := f.store.LoadRemediationRun(context.Background(), f.clusterID, runID)
				if err != nil || !found || loaded.Run.State() != domain.RemediationVerifying {
					t.Fatalf("pending poll %d state=%v found=%v err=%v", poll, loaded.Run.State(), found, err)
				}
				if loaded.Attempts(domain.RemediationStageCanary) != 1 {
					t.Fatalf("pending verification redispatched canary")
				}
				time.Sleep(12 * time.Millisecond)
			}
			if _, err := f.pool.Exec(context.Background(), `UPDATE remediation_runs SET deadline_at=clock_timestamp()-interval '1 second' WHERE cluster_id=$1 AND run_id=$2`, f.clusterID, runID); err != nil {
				t.Fatal(err)
			}
			if tc.mismatch {
				if _, err := f.pool.Exec(context.Background(), `UPDATE remediation_simulation_state SET revision=revision+1 WHERE cluster_id=$1 AND run_id=$2`, f.clusterID, runID); err != nil {
					t.Fatal(err)
				}
			}
			for i := 0; i < 20; i++ {
				if _, err := rt.RunOnce(context.Background()); err != nil {
					t.Fatal(err)
				}
				loaded, found, err := f.store.LoadRemediationRun(context.Background(), f.clusterID, runID)
				if err != nil || !found {
					t.Fatalf("load=%v found=%v", err, found)
				}
				if loaded.Run.State() == tc.want {
					return
				}
				time.Sleep(12 * time.Millisecond)
			}
			t.Fatalf("state did not reach %s", tc.want)
		})
	}
}

func TestRemediationRuntimeRestartResumesDurableVerification(t *testing.T) {
	f := newRemediationFixture(t)
	rt := runtimeForFixture(t, f)
	prepareRuntimeFixture(t, f, f.targets[:1])
	runID := advanceRuntimeToVerifying(t, f, rt)
	// A new runtime has no inherited process state. It must resume from the
	// attempt and receipt rows, then accept only post-restart evidence.
	restarted := runtimeForFixture(t, f)
	loaded, found, err := f.store.LoadRemediationRun(context.Background(), f.clusterID, runID)
	if err != nil || !found {
		t.Fatalf("load=%v found=%v", err, found)
	}
	insertSimulationEvidence(t, f, runID, loaded.LatestAttemptID, loaded.LatestTargets)
	for i := 0; i < 15; i++ {
		if _, err := restarted.RunOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
		loaded, found, err = f.store.LoadRemediationRun(context.Background(), f.clusterID, runID)
		if err != nil || !found {
			t.Fatalf("load=%v found=%v", err, found)
		}
		if loaded.Run.State() == domain.RemediationSucceeded {
			return
		}
		time.Sleep(12 * time.Millisecond)
	}
	t.Fatal("restarted runtime did not resume verification")
}

func TestRemediationRuntimeContainsAmbiguousDispatchedAttempt(t *testing.T) {
	f := newRemediationFixture(t)
	input, audit := newRemediationDispatchSecurityInput(t, f, f.targets[:1], 1, 0)
	committed, err := f.store.DispatchRemediationAttempt(context.Background(), input, audit)
	if err != nil {
		t.Fatal(err)
	}
	rt := runtimeForFixture(t, f)
	if _, err := rt.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	loaded, found, err := f.store.LoadRemediationRun(context.Background(), f.clusterID, committed.RunID)
	if err != nil || !found {
		t.Fatalf("load=%v found=%v", err, found)
	}
	if loaded.Run.State() != domain.RemediationContained {
		t.Fatalf("state=%s", loaded.Run.State())
	}
	var attempts int
	if err := f.pool.QueryRow(context.Background(), `SELECT count(*) FROM remediation_attempts WHERE cluster_id=$1 AND run_id=$2`, f.clusterID, committed.RunID).Scan(&attempts); err != nil {
		t.Fatal(err)
	}
	if attempts != 1 {
		t.Fatalf("ambiguous dispatch retried: attempts=%d", attempts)
	}
}

func TestRemediationRuntimePartialForwardFailureRollsBackOnlyExecutedTargets(t *testing.T) {
	f := newRemediationFixture(t)
	rt := runtimeForFixture(t, f)
	expandRuntimePopulation(t, f, 8)
	prepareRuntimeFixture(t, f, f.targets[:2])
	runID := advanceRuntimeToVerifying(t, f, rt)
	loaded, _, _ := f.store.LoadRemediationRun(context.Background(), f.clusterID, runID)
	insertSimulationEvidence(t, f, runID, loaded.LatestAttemptID, loaded.LatestTargets)
	// Persist the canary verification, but stop before the next wave dispatch.
	if _, err := rt.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	second := f.targets[1]
	if _, err := f.pool.Exec(context.Background(), `INSERT INTO remediation_schedule_snapshots(cluster_id,run_id,target,prior_active,prior_interval,prior_next,prior_revision)
		SELECT cluster_id,$2,job_id,active,interval_seconds,next_run_at,schedule_revision FROM collection_jobs WHERE cluster_id=$1 AND job_id=$3`, f.clusterID, runID, second); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(context.Background(), `INSERT INTO remediation_simulation_state(cluster_id,run_id,target,active,interval_seconds,next_run_at,revision,forward_revision)
		SELECT cluster_id,run_id,target,prior_active,prior_interval,prior_next,1,1 FROM remediation_schedule_snapshots WHERE cluster_id=$1 AND run_id=$2 AND target=$3`, f.clusterID, runID, second); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		if _, err := rt.RunOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
		loaded, _, _ = f.store.LoadRemediationRun(context.Background(), f.clusterID, runID)
		if loaded.Run.State() == domain.RemediationRollingBack {
			break
		}
		time.Sleep(12 * time.Millisecond)
	}
	for i := 0; i < 20; i++ {
		if _, err := rt.RunOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
		loaded, _, _ = f.store.LoadRemediationRun(context.Background(), f.clusterID, runID)
		if loaded.Run.State() == domain.RemediationRolledBack {
			break
		}
		time.Sleep(12 * time.Millisecond)
	}
	if loaded.Run.State() != domain.RemediationRolledBack {
		t.Fatalf("state=%s", loaded.Run.State())
	}
	if len(loaded.ExecutedTargets) != 1 || loaded.ExecutedTargets[0] != f.targets[0] {
		t.Fatalf("executed=%v", loaded.ExecutedTargets)
	}
	var rollbackTargets []string
	rows, err := f.pool.Query(context.Background(), `SELECT t.target FROM remediation_attempt_targets t JOIN remediation_attempts a ON a.cluster_id=t.cluster_id AND a.attempt_id=t.attempt_id WHERE a.cluster_id=$1 AND a.run_id=$2 AND a.stage='ROLLBACK'`, f.clusterID, runID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var v string
		_ = rows.Scan(&v)
		rollbackTargets = append(rollbackTargets, v)
	}
	if len(rollbackTargets) != 1 || rollbackTargets[0] != string(f.targets[0]) {
		t.Fatalf("rollback targets=%v", rollbackTargets)
	}
}

func advanceRuntimeToVerifying(t *testing.T, f remediationFixture, rt *remediationruntime.Runtime) domain.RemediationRunID {
	t.Helper()
	var runID domain.RemediationRunID
	for i := 0; i < 30; i++ {
		if _, err := rt.RunOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
		if runID == "" {
			_ = f.pool.QueryRow(context.Background(), `SELECT run_id FROM remediation_runs WHERE cluster_id=$1 ORDER BY created_at LIMIT 1`, f.clusterID).Scan(&runID)
		}
		if runID != "" {
			loaded, found, err := f.store.LoadRemediationRun(context.Background(), f.clusterID, runID)
			if err != nil || !found {
				t.Fatalf("load=%v found=%v", err, found)
			}
			if loaded.Run.State() == domain.RemediationVerifying {
				return runID
			}
		}
		time.Sleep(12 * time.Millisecond)
	}
	t.Fatal("runtime did not reach VERIFYING")
	return ""
}

func assertRuntimePolicyBlocked(t *testing.T, f remediationFixture, rt *remediationruntime.Runtime) {
	t.Helper()
	var state domain.RemediationState
	for iteration := 0; iteration < 20; iteration++ {
		if _, err := rt.RunOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
		err := f.pool.QueryRow(context.Background(), `SELECT state FROM remediation_runs WHERE cluster_id=$1 ORDER BY created_at LIMIT 1`, f.clusterID).Scan(&state)
		if err == nil && state == domain.RemediationPolicyBlocked {
			return
		}
		time.Sleep(12 * time.Millisecond)
	}
	t.Fatalf("policy gate state=%s, want POLICY_BLOCKED", state)
}

func expandRuntimePopulation(t *testing.T, f remediationFixture, want int) {
	t.Helper()
	for index := len(f.targets); index < want; index++ {
		if _, err := f.pool.Exec(context.Background(), `INSERT INTO collection_jobs(job_id,cluster_id,source_id,query_kind,interval_seconds,next_run_at)
			SELECT $1,cluster_id,source_id,$2,60,clock_timestamp() FROM collection_jobs WHERE cluster_id=$3 LIMIT 1`,
			"runtime-population-"+f.suffix+"-"+string(rune('a'+index)), fmt.Sprintf("runtime-kind-%d", index), f.clusterID); err != nil {
			t.Fatal(err)
		}
	}
}

func runtimeForFixture(t *testing.T, f remediationFixture) *remediationruntime.Runtime {
	t.Helper()
	trustedNow := f.now.UTC().Truncate(time.Second)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	release, err := remediation.SignRecipeRelease([]remediation.Recipe{f.forward, f.rollback}, "runtime-root", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := remediation.NewRecipeTrustStore([]remediation.RecipeTrustRoot{{
		ID: "runtime-root", Issuer: "sherlock.runtime", PublicKey: publicKey,
		ActivatesAt: trustedNow.Add(-time.Hour), RetiresAt: trustedNow.Add(2 * 365 * 24 * time.Hour),
	}})
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := trust.Verify(release, trustedNow)
	if err != nil {
		t.Fatal(err)
	}
	rt, err := remediationruntime.New(f.pool, catalog, remediationruntime.Config{
		Enabled: true, ClusterID: f.clusterID, Owner: "runtime-owner", PollInterval: 10 * time.Millisecond, Lease: time.Second, Batch: 8,
	}, slog.New(slog.NewTextHandler(testWriter{t}, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return rt
}

type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) { w.t.Log(string(p)); return len(p), nil }

func prepareRuntimeFixture(t *testing.T, f remediationFixture, targets []domain.RemediationTarget) {
	t.Helper()
	ctx := context.Background()
	strings := make([]string, len(targets))
	for i, target := range targets {
		strings[i] = string(target)
	}
	if _, err := f.pool.Exec(ctx, `UPDATE investigation_action_cards SET targets=$3 WHERE cluster_id=$1 AND action_card_id=$2`, f.clusterID, f.actionCardID, strings); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `INSERT INTO investigation_action_card_citations(cluster_id,investigation_id,action_card_id,ledger_entry_id) VALUES($1,$2,$3,$4)`, f.clusterID, f.investigationID, f.actionCardID, f.ledgerEntryID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `INSERT INTO remediation_policies(cluster_id,policy_id,version,recipe_id,recipe_version,enabled,max_tier,incident_kinds,max_targets,max_concurrent_runs,cooldown_seconds,evidence_max_age_seconds,min_evidence_coverage,not_before,not_after)
		VALUES($1,$2,1,$3,$4,true,1,ARRAY[$5],4,1,0,900,100,clock_timestamp()-interval '1 hour',clock_timestamp()+interval '1 hour')`, f.clusterID, "runtime-policy-"+f.suffix, f.forward.ID, f.forward.Version, remediation.IncidentKindEvidenceStreamStale); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `UPDATE remediation_global_state SET remediation_enabled=true WHERE id`); err != nil {
		t.Fatal(err)
	}
}

func insertSimulationEvidence(t *testing.T, f remediationFixture, runID domain.RemediationRunID, attemptID domain.RemediationAttemptID, targets []domain.RemediationTarget) {
	t.Helper()
	for _, target := range targets {
		if _, err := f.pool.Exec(context.Background(), `INSERT INTO remediation_simulation_observations(evidence_id,cluster_id,run_id,attempt_id,target,observed_start,observed_end,complete)
			VALUES($1,$2,$3,$4,$5,clock_timestamp(),clock_timestamp(),true) ON CONFLICT DO NOTHING`, "runtime-evidence-"+string(attemptID)+"-"+string(target), f.clusterID, runID, attemptID, target); err != nil {
			t.Fatal(err)
		}
	}
}
