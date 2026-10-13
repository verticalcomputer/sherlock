//go:build integration

package postgres_test

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/platform"
	"github.com/verticalcomputer/sherlock/internal/remediationlive"
	"github.com/verticalcomputer/sherlock/internal/remediationruntime"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

// TestM15ExpiredLiveRequestCompensatesToRolledBack starts with a real signed
// request but withholds collector delivery, expires the run, and lets a fresh
// production supervisor perform its compensating cancellation.
func TestM15ExpiredLiveRequestCompensatesToRolledBack(t *testing.T) {
	m15RunRecovery(t, m15RecoveryHooks{StopAfterRequest: true, AfterRequest: func(t *testing.T, ctx context.Context, p *pgxpool.Pool, r m15RecoveryResult) {
		if _, err := p.Exec(ctx, `UPDATE remediation_runs SET deadline_at=clock_timestamp()-interval '1 millisecond' WHERE cluster_id=$1 AND run_id=$2`, r.ClusterID, r.RemediationRun); err != nil {
			t.Fatal(err)
		}
		runtime, err := remediationruntime.New(p, r.Catalog, remediationruntime.Config{Enabled: true, Live: true, ClusterID: r.ClusterID, Owner: "m15-expiry-supervisor", PollInterval: 10 * time.Millisecond, Lease: 10 * time.Second, Batch: 1}, slog.New(slog.NewTextHandler(testLogWriter{t}, nil)))
		if err != nil {
			t.Fatal(err)
		}
		if err = m15Eventually(ctx, 6*time.Second, 25*time.Millisecond, func() (bool, error) {
			if _, runErr := runtime.RunOnce(ctx); runErr != nil {
				return false, runErr
			}
			var state domain.RemediationState
			err := p.QueryRow(ctx, `SELECT state FROM remediation_runs WHERE cluster_id=$1 AND run_id=$2`, r.ClusterID, r.RemediationRun).Scan(&state)
			return err == nil && state == domain.RemediationRolledBack, err
		}); err != nil {
			t.Fatalf("expired live request did not reach ROLLED_BACK: %v", err)
		}
		var requestStatus, workStatus string
		if err = p.QueryRow(ctx, `SELECT r.status,w.status FROM collection_repair_requests r JOIN collector_work_items w ON w.work_id=r.work_id WHERE r.request_id=$1`, r.RepairRequestID).Scan(&requestStatus, &workStatus); err != nil {
			t.Fatal(err)
		}
		if requestStatus != "CANCELLED" || workStatus != "CANCELLED" {
			t.Fatalf("expired compensation request=%s work=%s, want CANCELLED/CANCELLED", requestStatus, workStatus)
		}
	}})
}

// TestM15CancellationAfterSourceStartContainsButPreservesEvidence pauses the
// actual loopback source after the collector has STARTED its work. Cancellation
// is reconciled while delivery is pending, then the same response completes;
// durable result ingestion must win over any false cancellation claim.
func TestM15CancellationAfterSourceStartContainsButPreservesEvidence(t *testing.T) {
	m15RunRecovery(t, m15RecoveryHooks{ExpectContained: true, AfterRepairSourceStart: func(t *testing.T, ctx context.Context, p *pgxpool.Pool, r m15RecoveryResult) {
		store, err := storepg.NewRemediationStore(p)
		if err != nil {
			t.Fatal(err)
		}
		executor, err := remediationlive.New(r.Catalog, store)
		if err != nil {
			t.Fatal(err)
		}
		service, err := application.NewLiveRemediationService(store, store, r.Catalog, executor, m15RuntimeAuthorizer{cluster: r.ClusterID}, platform.SystemClock{}, platform.RandomIDGenerator{}, 10*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		cancelled, err := service.CancelRemediation(ctx, r.ClusterID, domain.RemediationRunID(r.RemediationRun), "sherlock-remediator")
		if err != nil {
			t.Fatal(err)
		}
		if cancelled.State() != domain.RemediationContained {
			t.Fatalf("live cancellation state=%s, want CONTAINED", cancelled.State())
		}
		var runState domain.RemediationState
		var status, workStatus string
		if err = p.QueryRow(ctx, `SELECT rr.state,r.status,w.status FROM remediation_runs rr JOIN collection_repair_requests r ON r.cluster_id=rr.cluster_id AND r.run_id=rr.run_id JOIN collector_work_items w ON w.work_id=r.work_id WHERE r.request_id=$1`, r.RepairRequestID).Scan(&runState, &status, &workStatus); err != nil {
			t.Fatal(err)
		}
		if runState != domain.RemediationContained || status != "CANCEL_REQUESTED" || workStatus != "LEASED" {
			t.Fatalf("in-flight cancellation run=%s request=%s work=%s, want CONTAINED/CANCEL_REQUESTED/LEASED", runState, status, workStatus)
		}
	}})
}

// TestM15FailedCompensationContainsCompletedForwardEffect invalidates the
// delivered forward evidence before verification and expires its deadline.
// The production supervisor must attempt rollback, refuse to erase the already
// completed collection, and report the truthful ROLLBACK_FAILED terminal state.
func TestM15FailedCompensationContainsCompletedForwardEffect(t *testing.T) {
	m15RunRecovery(t, m15RecoveryHooks{ExpectedTerminal: domain.RemediationRollbackFailed, BeforeVerification: func(t *testing.T, ctx context.Context, p *pgxpool.Pool, r m15RecoveryResult) {
		if _, err := p.Exec(ctx, `UPDATE evidence_envelopes SET status='PARTIAL' WHERE run_id=$1`, r.RepairRequestID); err != nil {
			t.Fatal(err)
		}
		if _, err := p.Exec(ctx, `UPDATE remediation_runs SET deadline_at=clock_timestamp()-interval '1 millisecond' WHERE cluster_id=$1 AND run_id=$2`, r.ClusterID, r.RemediationRun); err != nil {
			t.Fatal(err)
		}
	}})
}

// Every cancellation case starts from a real autonomously admitted request.
// Hooks inject the operator/policy race; they do not manufacture a success.
func TestM15CancellationBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		claim, start, revoke bool
	}{
		{name: "cancel before collector reservation"},
		{name: "cancel leased before start", claim: true},
		{name: "revoke leased before start", claim: true, revoke: true},
		{name: "cancel started and expire", claim: true, start: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m15RunRecovery(t, m15RecoveryHooks{StopAfterRequest: true, AfterRequest: func(t *testing.T, ctx context.Context, p *pgxpool.Pool, r m15RecoveryResult) {
				s, _ := storepg.NewRemediationStore(p)
				control, _ := storepg.NewCollectorControlStore(p)
				var attempt domain.RemediationAttemptID
				if err := p.QueryRow(ctx, `SELECT attempt_id FROM collection_repair_requests WHERE request_id=$1`, r.RepairRequestID).Scan(&attempt); err != nil {
					t.Fatal(err)
				}
				var lease domain.WorkLease
				if tc.claim {
					var found bool
					var err error
					lease, found, err = control.ClaimWork(ctx, r.CollectorID, "local-cancel-fixture-token", time.Minute)
					if err != nil || !found {
						t.Fatalf("claim found=%v err=%v", found, err)
					}
					if tc.start {
						if err = control.AcknowledgeWorkStart(ctx, r.CollectorID, lease.Work.WorkID, lease.Attempt, lease.LeaseToken); err != nil {
							t.Fatal(err)
						}
					}
				}
				if tc.revoke {
					if _, err := p.Exec(ctx, `UPDATE remediation_policies SET revoked_at=clock_timestamp() WHERE cluster_id=$1`, r.ClusterID); err != nil {
						t.Fatal(err)
					}
				} else {
					if err := s.RequestRemediationCancellation(ctx, r.ClusterID, domain.RemediationRunID(r.RemediationRun), "fixture-operator"); err != nil {
						t.Fatal(err)
					}
				}
				if tc.claim && !tc.start {
					if err := control.AcknowledgeWorkStart(ctx, r.CollectorID, lease.Work.WorkID, lease.Attempt, lease.LeaseToken); err == nil {
						t.Fatal("START accepted revoked/cancelled request")
					}
				}
				if err := s.ReconcileCollectionRequest(ctx, r.ClusterID, domain.RemediationRunID(r.RemediationRun), attempt); err != nil {
					t.Fatal(err)
				}
				if tc.claim {
					var status string
					if err := p.QueryRow(ctx, `SELECT status FROM collection_repair_requests WHERE request_id=$1`, r.RepairRequestID).Scan(&status); err != nil {
						t.Fatal(err)
					}
					if status != "CANCEL_REQUESTED" {
						t.Fatalf("leased cancellation status=%s", status)
					}
					// The authority trigger rejects synthetic expiry of a still-live
					// lease. Model the reconciler's actual terminal expiry instead,
					// retaining started_at when the ambiguity case was started.
					if _, err := p.Exec(ctx, `UPDATE collector_work_attempts SET status='EXPIRED',completed_at=clock_timestamp() WHERE work_id=$1`, lease.Work.WorkID); err != nil {
						t.Fatal(err)
					}
					if err := s.ReconcilePendingCollectionRequests(ctx, r.ClusterID, 32); err != nil {
						t.Fatal(err)
					}
				}
				var requestStatus, workStatus string
				var samples int
				if err := p.QueryRow(ctx, `SELECT r.status,w.status,(SELECT count(*) FROM observations o WHERE o.run_id=r.request_id) FROM collection_repair_requests r JOIN collector_work_items w ON w.work_id=r.work_id WHERE r.request_id=$1`, r.RepairRequestID).Scan(&requestStatus, &workStatus, &samples); err != nil {
					t.Fatal(err)
				}
				expected := "CANCELLED"
				if tc.start {
					expected = "CONTAINED"
				}
				if requestStatus != expected || workStatus != "CANCELLED" || samples != 0 {
					t.Fatalf("terminal request=%s work=%s samples=%d", requestStatus, workStatus, samples)
				}
			}})
		})
	}
}

func TestM15CompletedCollectionCannotBeCancelledOrErased(t *testing.T) {
	m15RunRecovery(t, m15RecoveryHooks{AfterVerification: func(t *testing.T, ctx context.Context, p *pgxpool.Pool, r m15RecoveryResult) {
		s, _ := storepg.NewRemediationStore(p)
		if err := s.RequestRemediationCancellation(ctx, r.ClusterID, domain.RemediationRunID(r.RemediationRun), "fixture-operator"); err == nil {
			t.Fatal("cancelled completed remediation")
		}
		if err := s.ReconcilePendingCollectionRequests(ctx, r.ClusterID, 32); err != nil {
			t.Fatal(err)
		}
		var samples, evidence int
		if err := p.QueryRow(ctx, `SELECT (SELECT count(*) FROM observations WHERE run_id=$1),(SELECT count(*) FROM evidence_envelopes WHERE run_id=$1)`, r.RepairRequestID).Scan(&samples, &evidence); err != nil {
			t.Fatal(err)
		}
		if samples < 1 || evidence < 1 {
			t.Fatal("completed immutable evidence was lost")
		}
	}})
}
