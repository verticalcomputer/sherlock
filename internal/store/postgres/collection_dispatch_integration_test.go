//go:build integration

package postgres_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/domain"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

func dispatchEnqueue(t *testing.T, p *pgxpool.Pool, c *storepg.CollectorControlStore, cluster domain.ClusterID, source domain.SourceID, id string) domain.WorkID {
	t.Helper()
	now := fixtureDatabaseTime(t, context.Background(), p)
	w := domain.CollectorWork{WorkID: domain.WorkID(id), Status: domain.WorkAvailable, Task: domain.CollectionTask{RunID: domain.RunID(id), ClusterID: cluster, SourceID: source, Query: domain.QueryGPUUtilization,
		ScheduledFor: now, Deadline: now.Add(time.Minute), MaxSeries: 100, MaxBytes: 100000, IdempotencyKey: id}, AvailableAt: now, WorkExpiresAt: now.Add(time.Minute)}
	if _, err := c.EnqueueCollectionWork(context.Background(), w); err != nil {
		t.Fatal(err)
	}
	return w.WorkID
}

func TestGP04cQuotaRejectionFacts(t *testing.T) {
	p := durableTestDatabase(t)
	s, _ := storepg.NewCollectionStore(p)
	c, _ := storepg.NewCollectorControlStore(p)
	ctx := context.Background()
	for _, tc := range []struct {
		reason          string
		global, cluster int
	}{{"global", 1, 1}, {"cluster", 3, 1}, {"source", 3, 3}} {
		t.Run(tc.reason, func(t *testing.T) {
			f := durableFixture{p, s, c, domain.DurableAdmissionPolicy{GlobalLimit: tc.global, ClusterLimit: tc.cluster}}
			f.exec(t, `TRUNCATE clusters CASCADE`)
			f.exec(t, `TRUNCATE durable_admission_state`)
			f.seed(t, "a", -time.Minute)
			admitted := f.admit(t)
			var before, after string
			state := `SELECT string_agg(row_to_json(st)::text,',' ORDER BY source_id,operation) FROM durable_schedule_state st`
			if err := p.QueryRow(ctx, state).Scan(&before); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 2; i++ {
				a, found, err := s.AdmitDueSchedule(ctx, f.policy)
				if err != nil || found || a.QuotaRejection != tc.reason || a.ClusterID != "a" || a.SourceID != "a-source" || a.WorkID != "" {
					t.Fatalf("denial: %+v %v %v", a, found, err)
				}
			}
			if err := p.QueryRow(ctx, state).Scan(&after); err != nil {
				t.Fatal(err)
			}
			if before != after {
				t.Fatal("denial changed due/occurrence state")
			}
			f.exec(t, `UPDATE collectors SET last_heartbeat_at=clock_timestamp()-interval '1 hour' WHERE collector_id='a-collector'`)
			a, found, err := s.AdmitDueSchedule(ctx, f.policy)
			if err != nil || found || a.QuotaRejection != "" {
				t.Fatalf("ineligible counted as quota: %+v %v", a, err)
			}
			f.report(t, "a-collector", "a-source")
			f.terminal(t, admitted)
			if a := f.admit(t); a.QuotaRejection != "" {
				t.Fatal("released slot still rejected")
			}
		})
	}
}

func TestGP04cDispatchRestartConcurrencyAndEnrollment(t *testing.T) {
	p := durableTestDatabase(t)
	s, _ := storepg.NewCollectionStore(p)
	c, _ := storepg.NewCollectorControlStore(p)
	ctx := context.Background()
	f := durableFixture{p, s, c, domain.DurableAdmissionPolicy{GlobalLimit: 2, ClusterLimit: 2}}
	f.seed(t, "a", -time.Minute)
	policy := domain.CollectionDispatchPolicy{Floor: 2, Period: 3}
	for _, bad := range []domain.CollectionDispatchPolicy{{}, {Floor: 2, Period: 2}, {Floor: 1, Period: 101}} {
		if err := s.ConfigureCollectionDispatch(ctx, "a", "a-collector", bad); err == nil {
			t.Fatal("accepted invalid floor")
		}
	}
	if err := s.ConfigureCollectionDispatch(ctx, "foreign", "a-collector", policy); err == nil {
		t.Fatal("cross-cluster enrollment")
	}
	if err := s.ConfigureCollectionDispatch(ctx, "a", "a-collector", policy); err != nil {
		t.Fatal(err)
	}
	if err := s.ConfigureCollectionDispatch(ctx, "a", "a-collector", domain.CollectionDispatchPolicy{Floor: 1, Period: 2}); err == nil {
		t.Fatal("policy overwrite")
	}
	// Empty polls and cancellations must not consume a persisted turn.
	if _, found, err := c.ClaimWork(ctx, "a-collector", "empty", time.Minute); err != nil || found {
		t.Fatalf("empty %v %v", found, err)
	}
	a := f.admit(t)
	f.exec(t, `UPDATE desired_schedules SET revision=revision+1 WHERE cluster_id=$1 AND source_id=$2 AND operation=$3`, a.ClusterID, a.SourceID, a.Operation)
	for i := 0; i < 8; i++ {
		dispatchEnqueue(t, p, c, "a", "a-source", fmt.Sprintf("ordinary-%d", i))
	}
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	ids := make(chan domain.WorkID, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			replica, _ := storepg.NewCollectorControlStore(p)
			lease, found, err := replica.ClaimWork(ctx, "a-collector", fmt.Sprintf("lease-%d", i), time.Minute)
			if err == nil && !found {
				err = fmt.Errorf("empty concurrent claim")
			}
			errs <- err
			ids <- lease.Work.WorkID
		}(i)
	}
	wg.Wait()
	close(errs)
	close(ids)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	seen := map[domain.WorkID]bool{}
	for id := range ids {
		if seen[id] {
			t.Fatal("duplicate concurrent grant")
		}
		seen[id] = true
	}
	// All turns were borrowable; exactly 8 committed grants advanced the cursor.
	restarted, _ := storepg.NewCollectionStore(p)
	if err := restarted.ConfigureCollectionDispatch(ctx, "a", "a-collector", policy); err != nil {
		t.Fatal(err)
	}
	var turn int
	if err := p.QueryRow(ctx, `SELECT collection_dispatch_turn FROM collectors WHERE collector_id='a-collector'`).Scan(&turn); err != nil || turn != 2 {
		t.Fatalf("cursor reset/lost: %d %v", turn, err)
	}
	// Real durable grant/revision fence remains enforced on the reserved path.
	if _, found, err := c.ClaimWork(ctx, "a-collector", "stale", time.Minute); err != nil || found {
		t.Fatalf("stale grant claimed: %v %v", found, err)
	}
}

func TestGP04cDispatchWithAuthorizedRepair(t *testing.T) {
	m15RunRecovery(t, m15RecoveryHooks{StopBeforeCollectorDelivery: true, BeforeCollectorDelivery: func(t *testing.T, ctx context.Context, p *pgxpool.Pool, r m15RecoveryResult) {
		s, _ := storepg.NewCollectionStore(p)
		c, _ := storepg.NewCollectorControlStore(p)
		policy := domain.CollectionDispatchPolicy{Floor: 2, Period: 3}
		if err := s.ConfigureCollectionDispatch(ctx, r.ClusterID, r.CollectorID, policy); err != nil {
			t.Fatal(err)
		}
		var repairWork domain.WorkID
		if err := p.QueryRow(ctx, `SELECT work_id FROM collection_repair_requests WHERE request_id=$1`, r.RepairRequestID).Scan(&repairWork); err != nil {
			t.Fatal(err)
		}
		// Exhaust diagnostic and model allowances on the real investigation;
		// its active repair already occupies the policy's only concurrent slot.
		if command, err := p.Exec(ctx, `UPDATE investigation_budgets SET used_diagnostic_calls=max_diagnostic_calls,used_model_tokens=max_model_tokens,used_cost_microunits=max_cost_microunits WHERE investigation_id=(SELECT investigation_id FROM remediation_runs WHERE cluster_id=$1 AND run_id=$2)`, r.ClusterID, r.RemediationRun); err != nil || command.RowsAffected() != 1 {
			t.Fatalf("exhaust fixture budgets: %d %v", command.RowsAffected(), err)
		}
		for i := 0; i < 12; i++ {
			dispatchEnqueue(t, p, c, r.ClusterID, r.SourceID, fmt.Sprintf("floor-%s-%d", r.ClusterID, i))
		}
		for i := 0; i < 9; i++ {
			// Restarting each control object cannot reset the persisted sequence.
			replica, _ := storepg.NewCollectorControlStore(p)
			lease, found, err := replica.ClaimWork(ctx, r.CollectorID, fmt.Sprintf("turn-%d", i), time.Minute)
			if err != nil || !found {
				t.Fatalf("turn %d: %v %v", i, found, err)
			}
			if (lease.Work.WorkID == repairWork) != (i%3 == 2) {
				t.Fatalf("turn %d granted %s; repair=%s", i, lease.Work.WorkID, repairWork)
			}
			if lease.Work.WorkID == repairWork {
				if _, err = p.Exec(ctx, `UPDATE collector_work_attempts SET claimed_at=clock_timestamp()-interval '2 minutes',lease_expires_at=clock_timestamp()-interval '1 minute' WHERE work_id=$1 AND attempt=$2`, repairWork, lease.Attempt); err != nil {
					t.Fatal(err)
				}
			}
		}
		// Concurrent replicas must consume one shared mixed-class cycle.
		var wg sync.WaitGroup
		results := make(chan domain.WorkLease, 3)
		errors := make(chan error, 3)
		for i := 0; i < 3; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				replica, _ := storepg.NewCollectorControlStore(p)
				lease, found, err := replica.ClaimWork(ctx, r.CollectorID, fmt.Sprintf("mixed-%d", i), time.Minute)
				if err == nil && !found {
					err = fmt.Errorf("empty mixed grant")
				}
				errors <- err
				results <- lease
			}(i)
		}
		wg.Wait()
		close(results)
		close(errors)
		for err := range errors {
			if err != nil {
				t.Fatal(err)
			}
		}
		repairs := 0
		for lease := range results {
			if lease.Work.WorkID == repairWork {
				repairs++
			}
		}
		if repairs != 1 {
			t.Fatalf("concurrent cycle repair grants=%d, want 1", repairs)
		}
		if _, err := p.Exec(ctx, `UPDATE collector_work_attempts SET claimed_at=clock_timestamp()-interval '2 minutes',lease_expires_at=clock_timestamp()-interval '1 minute' WHERE work_id=$1 AND status IN ('CLAIMED','STARTED')`, repairWork); err != nil {
			t.Fatal(err)
		}
		// Hold actual repair authority, including on a repair-preferred turn.
		// Ordinary work must still return while that transaction stays open.
		holder, err := p.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer holder.Rollback(ctx)
		if err = storepg.LockRepairAuthority(ctx, holder, r.ClusterID); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 3; i++ {
			bounded, cancel := context.WithTimeout(ctx, 2*time.Second)
			lease, found, err := c.ClaimWork(bounded, r.CollectorID, fmt.Sprintf("busy-%d", i), time.Minute)
			cancel()
			if err != nil || !found || lease.Work.WorkID == repairWork {
				t.Fatalf("busy repair blocked collection: %v %v %+v", found, err, lease)
			}
		}
		if err = holder.Rollback(ctx); err != nil && err != pgx.ErrTxClosed {
			t.Fatal(err)
		}
		// Revoke repair authority: borrowing never bypasses the safety predicate.
		if _, err = p.Exec(ctx, `UPDATE remediation_policies SET enabled=false WHERE cluster_id=$1`, r.ClusterID); err != nil {
			t.Fatal(err)
		}
		lease, found, err := c.ClaimWork(ctx, r.CollectorID, "revoked", time.Minute)
		if err != nil || !found || lease.Work.WorkID == repairWork {
			t.Fatalf("revoked repair selected: %v %v %+v", found, err, lease)
		}
	}})
}

func TestGP04cReservedReclaimCannotOvertakeRenewal(t *testing.T) {
	p := durableTestDatabase(t)
	s, _ := storepg.NewCollectionStore(p)
	c, _ := storepg.NewCollectorControlStore(p)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	f := durableFixture{p, s, c, domain.DurableAdmissionPolicy{GlobalLimit: 1, ClusterLimit: 1}}
	f.seed(t, "a", -time.Minute)
	if err := s.ConfigureCollectionDispatch(ctx, "a", "a-collector", domain.CollectionDispatchPolicy{Floor: 1, Period: 2}); err != nil {
		t.Fatal(err)
	}
	work := dispatchEnqueue(t, p, c, "a", "a-source", "renewal-race")
	lease, found, err := c.ClaimWork(ctx, "a-collector", "original", time.Minute)
	if err != nil || !found {
		t.Fatalf("initial claim %v %v", found, err)
	}
	lock, err := p.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Release()
	if _, err = lock.Exec(ctx, `SELECT pg_advisory_lock(60404)`); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = lock.Exec(context.Background(), `SELECT pg_advisory_unlock(60404)`) }()
	f.exec(t, `UPDATE collector_work_attempts SET lease_expires_at=clock_timestamp()+interval '500 milliseconds' WHERE work_id=$1`, work)
	f.exec(t, `CREATE FUNCTION fixture_pause_renewal() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(60404); RETURN NEW; END $$`)
	f.exec(t, `CREATE TRIGGER fixture_pause_renewal AFTER UPDATE OF lease_expires_at ON collector_work_attempts FOR EACH ROW EXECUTE FUNCTION fixture_pause_renewal()`)
	renewed := make(chan error, 1)
	go func() { renewed <- c.RenewWorkLease(ctx, "a-collector", work, lease.Attempt, "original", time.Minute) }()
	for {
		var paused, expired bool
		if err = p.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND objid=60404 AND NOT granted),EXISTS(SELECT 1 FROM collector_work_attempts WHERE work_id=$1 AND lease_expires_at<clock_timestamp())`, work).Scan(&paused, &expired); err != nil {
			t.Fatal(err)
		}
		if paused && expired {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("renewal did not pause across expiry")
		case <-time.After(5 * time.Millisecond):
		}
	}
	if _, found, err = c.ClaimWork(ctx, "a-collector", "overtake", time.Minute); err != nil || found {
		t.Fatalf("overtook locked renewal: %v %v", found, err)
	}
	if _, err = lock.Exec(ctx, `SELECT pg_advisory_unlock(60404)`); err != nil {
		t.Fatal(err)
	}
	if err = <-renewed; err != nil {
		t.Fatal(err)
	}
	if _, found, err = c.ClaimWork(ctx, "a-collector", "still-live", time.Minute); err != nil || found {
		t.Fatalf("reclaimed renewed lease: %v %v", found, err)
	}
	f.exec(t, `DROP TRIGGER fixture_pause_renewal ON collector_work_attempts`)
	f.exec(t, `UPDATE collector_work_attempts SET lease_expires_at=claimed_at+interval '1 microsecond' WHERE work_id=$1`, work)
	lease, found, err = c.ClaimWork(ctx, "a-collector", "reclaim", time.Minute)
	if err != nil || !found || lease.Attempt != 2 {
		t.Fatalf("expired lease not reclaimed: %+v %v %v", lease, found, err)
	}
	var turn int
	if err = p.QueryRow(ctx, `SELECT collection_dispatch_turn FROM collectors WHERE collector_id='a-collector'`).Scan(&turn); err != nil || turn != 0 {
		t.Fatalf("renew/empty polls consumed turns: %d %v", turn, err)
	}
}

func TestGP04cReservedNonOwnerAndRollback(t *testing.T) {
	p := durableTestDatabase(t)
	s, _ := storepg.NewCollectionStore(p)
	c, _ := storepg.NewCollectorControlStore(p)
	ctx := context.Background()
	f := durableFixture{p, s, c, domain.DurableAdmissionPolicy{GlobalLimit: 1, ClusterLimit: 1}}
	f.seed(t, "a", -time.Minute)
	if err := s.ConfigureCollectionDispatch(ctx, "a", "a-collector", domain.CollectionDispatchPolicy{Floor: 1, Period: 2}); err != nil {
		t.Fatal(err)
	}
	a := f.admit(t)
	name := fmt.Sprintf("gp04c_control_%d", time.Now().UnixNano())
	role := pgx.Identifier{name}.Sanitize()
	f.exec(t, `CREATE ROLE `+role+` NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS`)
	t.Cleanup(func() { f.exec(t, `DROP OWNED BY `+role); f.exec(t, `DROP ROLE `+role) })
	f.exec(t, `GRANT USAGE ON SCHEMA public TO `+role)
	f.exec(t, `GRANT SELECT ON ALL TABLES IN SCHEMA public TO `+role)
	f.exec(t, `GRANT INSERT,UPDATE ON collector_work_items,collector_work_attempts,collection_repair_requests TO `+role)
	f.exec(t, `GRANT UPDATE(collection_dispatch_turn) ON collectors TO `+role)
	f.exec(t, `GRANT EXECUTE ON FUNCTION public.durable_work_claimable(text,text) TO `+role)
	cfg := p.Config().Copy()
	cfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		_, err := conn.Exec(ctx, `SET ROLE `+role)
		return err
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	control, _ := storepg.NewCollectorControlStore(pool)
	// A deferred failure after attempt insertion must roll back both grant and
	// turn. The trigger is test-only in this private database.
	f.exec(t, `CREATE FUNCTION fixture_reject_dispatch() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture rollback'; END $$`)
	f.exec(t, `CREATE CONSTRAINT TRIGGER fixture_reject_dispatch AFTER INSERT ON collector_work_attempts DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION fixture_reject_dispatch()`)
	if _, found, err := control.ClaimWork(ctx, "a-collector", "rollback", time.Minute); err == nil || found {
		t.Fatalf("injected commit failure: %v %v", found, err)
	}
	var turn, attempts int
	var status string
	if err = p.QueryRow(ctx, `SELECT c.collection_dispatch_turn,w.status,(SELECT count(*) FROM collector_work_attempts WHERE work_id=w.work_id) FROM collectors c,collector_work_items w WHERE c.collector_id='a-collector' AND w.work_id=$1`, a.WorkID).Scan(&turn, &status, &attempts); err != nil || turn != 0 || status != "AVAILABLE" || attempts != 0 {
		t.Fatalf("rollback state: %d %s %d %v", turn, status, attempts, err)
	}
	f.exec(t, `DROP TRIGGER fixture_reject_dispatch ON collector_work_attempts`)
	lease, found, err := control.ClaimWork(ctx, "a-collector", "success", time.Minute)
	if err != nil || !found || lease.Work.WorkID != a.WorkID {
		t.Fatalf("non-owner reserved claim: %v %v", found, err)
	}
}
