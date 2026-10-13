//go:build integration

package postgres_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	promadapter "github.com/verticalcomputer/sherlock/internal/adapters/prometheus"
	slurmadapter "github.com/verticalcomputer/sherlock/internal/adapters/slurm"
	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/collectorcontrol"
	promexecution "github.com/verticalcomputer/sherlock/internal/collectorexecution/prometheus"
	slurmexecution "github.com/verticalcomputer/sherlock/internal/collectorexecution/slurm"
	"github.com/verticalcomputer/sherlock/internal/collectorruntime"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/platform"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

// Quota tests need a genuinely empty authority, isolated from other packages'
// concurrent integration fixtures. This database is created and dropped here.
func durableTestDatabase(t *testing.T) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()
	dsn := os.Getenv("SHERLOCK_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("SHERLOCK_TEST_DATABASE_URL is not set")
	}
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("gp04b_%d", time.Now().UnixNano())
	if _, err = admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		_ = admin.Close(ctx)
		t.Fatal(err)
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.Database = name
	p, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		p.Close()
		_, err := admin.Exec(ctx, "DROP DATABASE "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)")
		if err != nil {
			t.Error(err)
		}
		_ = admin.Close(ctx)
	})
	files, err := filepath.Glob("../../../migrations/*.up.sql")
	if err != nil || len(files) == 0 {
		t.Fatalf("migrations: %v", err)
	}
	for _, file := range files {
		body, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = p.Exec(ctx, string(body)); err != nil {
			t.Fatalf("%s: %v", file, err)
		}
	}
	return p
}

type durableFixture struct {
	p      *pgxpool.Pool
	s      *storepg.CollectionStore
	c      *storepg.CollectorControlStore
	policy domain.DurableAdmissionPolicy
}

func (f durableFixture) exec(t *testing.T, query string, args ...any) {
	t.Helper()
	if _, err := f.p.Exec(context.Background(), query, args...); err != nil {
		t.Fatal(err)
	}
}
func (f durableFixture) seed(t *testing.T, cluster string, offset time.Duration) []domain.DesiredSchedule {
	t.Helper()
	ctx := context.Background()
	id := domain.ClusterID(cluster)
	source := domain.SourceID(cluster + "-source")
	collector := domain.CollectorID(cluster + "-collector")
	if err := f.s.EnsureSource(ctx, id, cluster, source, cluster); err != nil {
		t.Fatal(err)
	}
	if err := f.c.RegisterCollector(ctx, storepg.CollectorRegistration{CollectorID: collector, ClusterID: id, DisplayName: cluster, Version: "fixture", ProtocolMin: 1, ProtocolMax: 2, OperatingSystem: "linux", Architecture: "amd64"}); err != nil {
		t.Fatal(err)
	}
	seeds := application.LegacyPrometheusSchedules(id, source, domain.SchedulingDurable, 30*time.Second, 10*time.Second, 100, 100000)
	if err := f.s.ImportLegacyPrometheusSchedules(ctx, seeds, time.Now().UTC().Add(offset)); err != nil {
		t.Fatal(err)
	}
	caps := map[string]string{}
	for i, seed := range seeds {
		d, err := f.s.DesiredSchedule(ctx, seed.ScheduleKey)
		if err != nil {
			t.Fatal(err)
		}
		seeds[i] = d
		op, _ := domain.ReviewedCollectionOperation(d.Operation)
		caps[string(op.Query)] = "1"
		if err = f.s.ConfigureDurableExecution(ctx, domain.DurableExecution{ScheduleKey: d.ScheduleKey, Revision: d.Revision, CollectorID: collector}); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.c.ReplaceCapabilities(ctx, collector, caps); err != nil {
		t.Fatal(err)
	}
	f.report(t, collector, source)
	return seeds
}
func (f durableFixture) report(t *testing.T, collector domain.CollectorID, sources ...domain.SourceID) {
	t.Helper()
	report := collectorcontrol.Heartbeat{CollectorID: collector, Version: "fixture", ProtocolMin: 1, ProtocolMax: 2, ReportedAt: time.Now().UTC()}
	for _, q := range []domain.QueryKind{domain.QuerySourceHealth, domain.QueryGPUIdentity, domain.QueryGPUUtilization, domain.QueryGPUXID} {
		report.Capabilities = append(report.Capabilities, collectorcontrol.CapabilityReport{Name: string(q), Version: "1"})
	}
	for _, source := range sources {
		report.SourceHealth = append(report.SourceHealth, collectorcontrol.SourceHealthReport{SourceID: source, Availability: collectorcontrol.SourceUnknown, CheckedAt: time.Now().UTC()})
	}
	if err := f.c.RecordHeartbeat(context.Background(), report); err != nil {
		t.Fatal(err)
	}
}
func (f durableFixture) admit(t *testing.T) domain.ScheduleAdmission {
	t.Helper()
	a, found, err := application.AdmitDurableSchedule(context.Background(), f.s, f.policy)
	if err != nil || !found {
		t.Fatalf("admit found=%v err=%v", found, err)
	}
	return a
}
func (f durableFixture) none(t *testing.T) {
	t.Helper()
	a, found, err := application.AdmitDurableSchedule(context.Background(), f.s, f.policy)
	if err != nil || found {
		t.Fatalf("unexpected admission %+v %v %v", a, found, err)
	}
}
func (f durableFixture) terminal(t *testing.T, a domain.ScheduleAdmission) {
	f.exec(t, `UPDATE collector_work_items SET status='FAILED',completed_at=clock_timestamp() WHERE work_id=$1`, a.WorkID)
}

func TestGP04bDurableAdmission(t *testing.T) {
	p := durableTestDatabase(t)
	s, _ := storepg.NewCollectionStore(p)
	c, _ := storepg.NewCollectorControlStore(p)
	ctx := context.Background()
	fixture := func(t *testing.T, global, cluster int) durableFixture {
		f := durableFixture{p, s, c, domain.DurableAdmissionPolicy{GlobalLimit: global, ClusterLimit: cluster}}
		f.exec(t, `TRUNCATE clusters CASCADE`)
		f.exec(t, `TRUNCATE durable_admission_state`)
		return f
	}
	t.Run("TwoWorkersRestartAndCoalescing", func(t *testing.T) {
		f := fixture(t, 2, 1)
		seeds := f.seed(t, "a", -48*time.Hour)
		// One enabled operation makes occurrence uniqueness independent of quota.
		for _, d := range seeds[1:] {
			d.Enabled = false
			if _, err := s.UpdateDesiredSchedule(ctx, d); err != nil {
				t.Fatal(err)
			}
		}
		var wg sync.WaitGroup
		out := make(chan domain.ScheduleAdmission, 2)
		errs := make(chan error, 2)
		for i := 0; i < 2; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				a, found, err := application.AdmitDurableSchedule(ctx, s, f.policy)
				errs <- err
				if found {
					out <- a
				}
			}()
		}
		wg.Wait()
		close(out)
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatal(err)
			}
		}
		if len(out) != 1 {
			t.Fatalf("admitted %d copies", len(out))
		}
		a := <-out
		if a.Occurrence != 1 || a.CoalescedIntervals < 5759 || !a.NextDueAt.After(time.Now()) {
			t.Fatalf("unbounded backlog: %+v", a)
		}
		restarted, _ := storepg.NewCollectionStore(p)
		if _, found, err := restarted.AdmitDueSchedule(ctx, f.policy); err != nil || found {
			t.Fatalf("restart replay: %v %v", found, err)
		}
		f.terminal(t, a)
		f.none(t)
	})
	t.Run("FairRoundsOldestDueFailureAndBusyCluster", func(t *testing.T) {
		f := fixture(t, 1, 1)
		aSeeds := f.seed(t, "a", -time.Hour)
		f.seed(t, "b", -time.Minute)
		f.exec(t, `UPDATE durable_schedule_state SET next_due_at=clock_timestamp()-interval '2 hours' WHERE cluster_id='a' AND operation=$1`, aSeeds[2].Operation)
		a := f.admit(t)
		if a.ClusterID != "a" || a.Operation != aSeeds[2].Operation {
			t.Fatalf("oldest: %+v", a)
		}
		f.none(t)
		f.terminal(t, a)
		b := f.admit(t)
		if b.ClusterID != "b" {
			t.Fatalf("backlog starved second cluster: %+v", b)
		}
		f.terminal(t, b)
		lock, err := p.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = lock.Rollback(ctx) }()
		if _, err = lock.Exec(ctx, `SELECT * FROM desired_schedules WHERE cluster_id='a' FOR UPDATE`); err != nil {
			t.Fatal(err)
		}
		busy := f.admit(t)
		if busy.ClusterID != "b" {
			t.Fatalf("busy cluster blocked fairness: %+v", busy)
		}
	})
	t.Run("QuotasSourceSlotTerminalExpiryAndLiveAttempt", func(t *testing.T) {
		f := fixture(t, 2, 1)
		f.seed(t, "a", -time.Minute)
		f.seed(t, "b", -time.Minute)
		f.seed(t, "c", -time.Minute)
		a := f.admit(t)
		b := f.admit(t)
		f.none(t)
		lease, found, err := c.ClaimWork(ctx, domain.CollectorID(string(a.ClusterID)+"-collector"), strings.Repeat("a", 32), time.Minute)
		if err != nil || !found {
			t.Fatalf("claim: %v %v", found, err)
		}
		f.exec(t, `UPDATE collector_work_items SET deadline=scheduled_for+interval '1 microsecond',work_expires_at=available_at+interval '1 microsecond' WHERE work_id=$1`, a.WorkID)
		f.none(t) // deadline alone cannot free a still-live attempt's quota.
		f.terminal(t, b)
		next := f.admit(t)
		if next.ClusterID != "c" {
			t.Fatalf("release fairness: %+v", next)
		}
		f.exec(t, `UPDATE collector_work_attempts SET lease_expires_at=claimed_at+interval '1 microsecond' WHERE work_id=$1 AND attempt=$2`, lease.Work.WorkID, lease.Attempt)
		f.admit(t)
	})
	t.Run("RevisionDisableModeGrantAndCrossClusterFences", func(t *testing.T) {
		for _, change := range []string{"revision", "disable", "mode"} {
			t.Run(change, func(t *testing.T) {
				f := fixture(t, 2, 1)
				seeds := f.seed(t, "a", -time.Minute)
				f.seed(t, "b", -time.Minute)
				a := f.admit(t)
				d, err := s.DesiredSchedule(ctx, a.ScheduleKey)
				if err != nil {
					t.Fatal(err)
				}
				switch change {
				case "revision":
					d.MaxTargets--
				case "disable":
					d.Enabled = false
				case "mode":
					d.Mode = domain.SchedulingLegacy
				}
				if _, err = s.UpdateDesiredSchedule(ctx, d); err != nil {
					t.Fatal(err)
				}
				if _, found, err := c.ClaimWork(ctx, "a-collector", strings.Repeat("a", 32), time.Minute); err != nil || found {
					t.Fatalf("stale claimed: %v %v", found, err)
				}
				if err = s.ConfigureDurableExecution(ctx, domain.DurableExecution{ScheduleKey: d.ScheduleKey, Revision: d.Revision, CollectorID: "a-collector"}); err == nil {
					t.Fatal("stale startup restored grant")
				}
				if err = s.ConfigureDurableExecution(ctx, domain.DurableExecution{ScheduleKey: seeds[0].ScheduleKey, Revision: seeds[0].Revision, CollectorID: "b-collector"}); err == nil {
					t.Fatal("cross cluster grant")
				}
				b := f.admit(t)
				if b.ClusterID != "b" {
					t.Fatalf("stale capacity not released: %+v", b)
				}
			})
		}
	})
	t.Run("ClaimRacesConfiguration", func(t *testing.T) {
		f := fixture(t, 2, 1)
		f.seed(t, "a", -time.Minute)
		a := f.admit(t)
		lock, err := p.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = lock.Rollback(ctx) }()
		if _, err = lock.Exec(ctx, `UPDATE desired_schedules SET enabled=false WHERE cluster_id=$1 AND source_id=$2 AND operation=$3`, a.ClusterID, a.SourceID, a.Operation); err != nil {
			t.Fatal(err)
		}
		bounded, cancel := context.WithTimeout(ctx, time.Second)
		defer cancel()
		if _, found, err := c.ClaimWork(bounded, "a-collector", strings.Repeat("a", 32), time.Minute); err == nil || found {
			t.Fatalf("concurrent configuration bypass: %v %v", found, err)
		}
		if err = lock.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		var attempts int
		if err = p.QueryRow(ctx, `SELECT count(*) FROM collector_work_attempts WHERE work_id=$1`, a.WorkID).Scan(&attempts); err != nil || attempts != 0 {
			t.Fatalf("partial claim: %d %v", attempts, err)
		}
	})
	t.Run("CapabilityUnknownInactiveAndEventsDoNotAdvance", func(t *testing.T) {
		f := fixture(t, 2, 1)
		f.seed(t, "a", -time.Minute)
		f.seed(t, "b", -time.Minute)
		f.exec(t, `UPDATE collector_capabilities SET version='99' WHERE collector_id='a-collector'`)
		b := f.admit(t)
		if b.ClusterID != "b" {
			t.Fatal("unknown version was admitted")
		}
		f.terminal(t, b)
		f.exec(t, `UPDATE collectors SET last_heartbeat_at=clock_timestamp()-interval '3 minutes' WHERE collector_id='a-collector'`)
		if a := f.admit(t); a.ClusterID != "b" {
			t.Fatal("unavailable executor was admitted")
		}
		f.exec(t, `INSERT INTO sources(source_id,cluster_id,kind,display_name) VALUES('events','a','slurm','events')`)
		event, err := s.CreateDesiredSchedule(ctx, domain.DesiredSchedule{ScheduleKey: domain.ScheduleKey{ClusterID: "a", SourceID: "events", Operation: domain.OperationSlurmEvents}, Enabled: true, Mode: domain.SchedulingDurable, Interval: 30 * time.Second, Timeout: time.Second, MaxTargets: 1, MaxBytes: 10000})
		if err != nil {
			t.Fatal(err)
		}
		if err = s.ConfigureDurableExecution(ctx, domain.DurableExecution{ScheduleKey: event.ScheduleKey, Revision: event.Revision, CollectorID: "a-collector", Nodes: []domain.StableNodeID{"node-1"}}); err == nil {
			t.Fatal("unsupported event executor accepted")
		}
		f.exec(t, `UPDATE durable_schedule_state SET next_due_at='2020-01-01' WHERE source_id='events'`)
		f.none(t)
		var n, coalesced int64
		var due time.Time
		if err = p.QueryRow(ctx, `SELECT occurrence,coalesced_intervals,next_due_at FROM durable_schedule_state WHERE source_id='events'`).Scan(&n, &coalesced, &due); err != nil || n != 0 || coalesced != 0 || due.Year() != 2020 {
			t.Fatalf("event gap lost: %d %d %v %v", n, coalesced, due, err)
		}
	})
	t.Run("V1AdmissionResultPublicationAndReplay", func(t *testing.T) {
		f := fixture(t, 1, 1)
		f.seed(t, "a", -time.Minute)
		f.exec(t, `UPDATE durable_schedule_state SET next_due_at=clock_timestamp()-interval '2 minutes' WHERE operation=$1`, domain.OperationPrometheusSourceHealth)
		a := f.admit(t)
		lease, found, err := c.ClaimWork(ctx, "a-collector", strings.Repeat("a", 32), time.Minute)
		if err != nil || !found {
			t.Fatalf("claim: %v %v", found, err)
		}
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = fmt.Fprintf(w, `{"status":"success","data":{"resultType":"vector","result":[{"metric":{"__name__":"up","instance":"node-a:9400"},"value":[%d,"1"]}]}}`, time.Now().Unix())
		}))
		defer server.Close()
		client, err := promadapter.NewClient(promadapter.Config{BaseURL: server.URL, Timeout: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		executor, err := promexecution.New(client, platform.SystemClock{}, platform.RandomIDGenerator{})
		if err != nil {
			t.Fatal(err)
		}
		result := executor.Execute(ctx, lease.Work.Task)
		if result.Status != domain.ResultSucceeded || len(result.Observations) != 1 {
			t.Fatalf("supported executor: %+v", result)
		}
		document := domain.CollectorResultDocument{SchemaVersion: 1, WorkID: a.WorkID, Attempt: lease.Attempt, Result: result}
		body, err := json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		hash := sha256.Sum256(body)
		checksum := hex.EncodeToString(hash[:])
		ref := collectorcontrol.LeaseRef{WorkID: a.WorkID, Attempt: lease.Attempt, LeaseToken: lease.LeaseToken}
		if _, err = c.UploadResultChunk(ctx, "a-collector", collectorcontrol.ResultChunk{LeaseRef: ref, Index: 0, Payload: body, SHA256: checksum}); err != nil {
			t.Fatal(err)
		}
		fin := collectorcontrol.ResultFinalization{LeaseRef: ref, RunID: result.Task.RunID, Status: result.Status, ChunkCount: 1, Bytes: int64(len(body)), SHA256: checksum}
		if _, err = c.FinalizeResult(ctx, "a-collector", fin); err != nil {
			t.Fatal(err)
		}
		if replay, err := c.FinalizeResult(ctx, "a-collector", fin); err != nil || !replay.PreviouslyFinalized {
			t.Fatalf("replay: %+v %v", replay, err)
		}
		var runs int
		if err = p.QueryRow(ctx, `SELECT count(*) FROM collection_runs WHERE run_id=$1`, result.Task.RunID).Scan(&runs); err != nil || runs != 1 {
			t.Fatalf("publication: %d %v", runs, err)
		}
		for _, table := range []string{"observations", "current_projections"} {
			var count int
			if err = p.QueryRow(ctx, `SELECT count(*) FROM `+table+` WHERE cluster_id='a'`).Scan(&count); err != nil || count != 1 {
				t.Fatalf("%s publication: %d %v", table, count, err)
			}
		}
		f.admit(t)
	})
	t.Run("ClusterQuotaAcrossIndependentSources", func(t *testing.T) {
		f := fixture(t, 3, 1)
		f.seed(t, "a", -time.Minute)
		f.seed(t, "b", -time.Minute)
		if err := s.EnsureSource(ctx, "a", "a", "a-second", "second"); err != nil {
			t.Fatal(err)
		}
		seeds := application.LegacyPrometheusSchedules("a", "a-second", domain.SchedulingDurable, 30*time.Second, 10*time.Second, 100, 100000)
		if err := s.ImportLegacyPrometheusSchedules(ctx, seeds, time.Now().Add(-time.Minute)); err != nil {
			t.Fatal(err)
		}
		for _, d := range seeds {
			if err := c.RegisterCollector(ctx, storepg.CollectorRegistration{CollectorID: "a-second-collector", ClusterID: "a", DisplayName: "second", Version: "fixture", ProtocolMin: 1, ProtocolMax: 2, OperatingSystem: "linux", Architecture: "amd64"}); err != nil {
				t.Fatal(err)
			}
			if err := s.ConfigureDurableExecution(ctx, domain.DurableExecution{ScheduleKey: d.ScheduleKey, Revision: 1, CollectorID: "a-second-collector"}); err != nil {
				t.Fatal(err)
			}
		}
		f.report(t, "a-second-collector", "a-second")
		a := f.admit(t)
		b := f.admit(t)
		if a.ClusterID != "a" || b.ClusterID != "b" {
			t.Fatalf("round: %+v %+v", a, b)
		}
		f.none(t) // Global room remains; a-second is blocked by the cluster cap.
		f.terminal(t, a)
		next := f.admit(t)
		if next.ClusterID != "a" {
			t.Fatalf("cluster quota failed to release: %+v", next)
		}
	})
	t.Run("ClusterRemovalLockAndTemporaryShadowFence", func(t *testing.T) {
		f := fixture(t, 2, 1)
		f.seed(t, "a", -time.Minute)
		a := f.admit(t)
		lock, err := p.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = lock.Rollback(ctx) }()
		if _, err = lock.Exec(ctx, `SELECT cluster_id FROM clusters WHERE cluster_id='a' FOR UPDATE`); err != nil {
			t.Fatal(err)
		}
		bounded, cancel := context.WithTimeout(ctx, time.Second)
		defer cancel()
		if _, found, err := c.ClaimWork(bounded, "a-collector", strings.Repeat("a", 32), time.Minute); err == nil || found {
			t.Fatalf("cluster removal lock bypass: %v %v", found, err)
		}
		if _, err = lock.Exec(ctx, `UPDATE clusters SET removed_at=clock_timestamp() WHERE cluster_id='a'`); err != nil {
			t.Fatal(err)
		}
		if err = lock.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		shadow, err := p.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = shadow.Rollback(ctx) }()
		if _, err = shadow.Exec(ctx, `CREATE TEMP TABLE durable_schedule_occurrences(work_id text)`); err != nil {
			t.Fatal(err)
		}
		var allowed bool
		if err = shadow.QueryRow(ctx, `SELECT public.durable_work_claimable($1,'a-collector')`, a.WorkID).Scan(&allowed); err != nil || allowed {
			t.Fatalf("temp shadow bypass: %v %v", allowed, err)
		}
		if _, err = shadow.Exec(ctx, `SET LOCAL ROLE sherlock_m15_remediator_v1`); err != nil {
			t.Fatal(err)
		}
		if err = shadow.QueryRow(ctx, `SELECT public.durable_work_claimable($1,'a-collector')`, a.WorkID).Scan(&allowed); err == nil {
			t.Fatal("restricted role received definer authority")
		}
	})
	t.Run("TypedInventorySupportedExecutorAndBoundResult", func(t *testing.T) {
		f := fixture(t, 1, 1)
		f.seed(t, "a", -time.Minute)
		f.exec(t, `UPDATE desired_schedules SET enabled=false WHERE cluster_id='a'`)
		f.exec(t, `INSERT INTO sources(source_id,cluster_id,kind,display_name) VALUES('slurm','a','slurm','Slurm')`)
		d, err := s.CreateDesiredSchedule(ctx, domain.DesiredSchedule{ScheduleKey: domain.ScheduleKey{ClusterID: "a", SourceID: "slurm", Operation: domain.OperationSlurmInventory}, Enabled: true, Mode: domain.SchedulingDurable, Interval: 30 * time.Second, Timeout: 10 * time.Second, MaxTargets: 1, MaxBytes: 100000})
		if err != nil {
			t.Fatal(err)
		}
		g := domain.DurableExecution{ScheduleKey: d.ScheduleKey, Revision: d.Revision, CollectorID: "a-collector", Nodes: []domain.StableNodeID{"node-1"}}
		if err = s.ConfigureDurableExecution(ctx, g); err != nil {
			t.Fatal(err)
		}
		if err = c.ReplaceCapabilities(ctx, "a-collector", map[string]string{string(domain.OperationSlurmInventory): "1"}); err != nil {
			t.Fatal(err)
		}
		f.exec(t, `INSERT INTO collector_source_health(collector_id,source_id,availability,checked_at) VALUES('a-collector','slurm','AVAILABLE',clock_timestamp())`)
		a := f.admit(t)
		if a.Operation != domain.OperationSlurmInventory {
			t.Fatal(a)
		}
		if _, found, err := c.ClaimTypedWork(ctx, "foreign", "a-collector", strings.Repeat("a", 32), time.Minute, []domain.SourceID{"slurm"}); err == nil || found {
			t.Fatal("cross-cluster claim accepted")
		}
		lease, found, err := c.ClaimTypedWork(ctx, "a", "a-collector", strings.Repeat("a", 32), time.Minute, []domain.SourceID{"slurm"})
		if err != nil || !found {
			t.Fatalf("typed claim: %v %v", found, err)
		}
		// Already bound work can finish after a desired revision is disabled.
		d.Enabled = false
		if _, err = s.UpdateDesiredSchedule(ctx, d); err != nil {
			t.Fatal(err)
		}
		executor, err := slurmexecution.New(durableNodes{}, platform.SystemClock{}, map[domain.StableNodeID]string{"node-1": "comp001"})
		if err != nil {
			t.Fatal(err)
		}
		registry, err := application.NewTypedCollectionRegistry(2, []application.TypedCollectionSource{{ClusterID: "a", SourceID: "slurm", Kind: domain.CollectionSourceSlurm, Operations: []domain.CollectionOperationID{domain.OperationSlurmInventory}, Executor: executor}}, platform.SystemClock{})
		if err != nil {
			t.Fatal(err)
		}
		result := registry.ExecuteTyped(ctx, lease)
		if result.Status != domain.ResultSucceeded {
			t.Fatalf("typed executor: %+v", result)
		}
		ref := collectorcontrol.LeaseRef{WorkID: a.WorkID, Attempt: lease.Lease.Attempt, LeaseToken: lease.Lease.LeaseToken}
		if _, err = c.SubmitTypedResult(ctx, "a", "a-collector", ref, result, typedChecksum(result)); err != nil {
			t.Fatal(err)
		}
		if out, err := c.SubmitTypedResult(ctx, "a", "a-collector", ref, result, typedChecksum(result)); err != nil || !out.PreviouslyFinalized {
			t.Fatalf("typed replay: %+v %v", out, err)
		}
		var count int
		if err = p.QueryRow(ctx, `SELECT count(*) FROM goodput_source_coverage WHERE run_id=$1`, result.Plan.RunID).Scan(&count); err != nil || count != 1 {
			t.Fatalf("typed publication: %d %v", count, err)
		}
	})
	t.Run("TypedSlurmSnapshotMaterializesOnlyAfterExplicitEnrollment", func(t *testing.T) {
		f := fixture(t, 1, 1)
		f.seed(t, "a", -time.Minute)
		f.exec(t, `UPDATE desired_schedules SET enabled=false WHERE cluster_id='a'`)
		f.exec(t, `INSERT INTO sources(source_id,cluster_id,kind,display_name) VALUES('snapshot','a','slurm','Slurm snapshot')`)
		d, err := s.CreateDesiredSchedule(ctx, domain.DesiredSchedule{ScheduleKey: domain.ScheduleKey{ClusterID: "a", SourceID: "snapshot", Operation: domain.OperationSlurmSnapshot}, Enabled: true, Mode: domain.SchedulingDurable, Interval: time.Minute, Timeout: 10 * time.Second, MaxTargets: 20, MaxBytes: 1000000})
		if err != nil {
			t.Fatal(err)
		}
		if _, found, err := s.AdmitDueSchedule(ctx, f.policy); err != nil || found {
			t.Fatalf("unenrolled snapshot admitted: %v %v", found, err)
		}
		if err = s.ConfigureDurableExecution(ctx, domain.DurableExecution{ScheduleKey: d.ScheduleKey, Revision: d.Revision, CollectorID: "a-collector", Nodes: []domain.StableNodeID{"node-1", "node-2"}}); err != nil {
			t.Fatal(err)
		}
		f.report(t, "a-collector", "snapshot")
		if err = c.ReplaceCapabilities(ctx, "a-collector", map[string]string{string(domain.OperationSlurmSnapshot): "1"}); err != nil {
			t.Fatal(err)
		}
		f.exec(t, `UPDATE collector_source_health SET availability='AVAILABLE',checked_at=clock_timestamp() WHERE collector_id='a-collector' AND source_id='snapshot'`)
		a := f.admit(t)
		lease, found, err := c.ClaimTypedWork(ctx, "a", "a-collector", strings.Repeat("s", 32), time.Minute, []domain.SourceID{"snapshot"})
		if err != nil || !found || lease.Plan.Operation != domain.OperationSlurmSnapshot || lease.Plan.PayloadSchema != domain.CollectionSlurmSnapshotSchema || len(lease.Plan.Scope.Nodes) != 2 || a.WorkID != lease.Lease.Work.WorkID {
			t.Fatalf("snapshot lease=%+v admission=%+v found=%v err=%v", lease, a, found, err)
		}
	})
	t.Run("NonOwnerCollectorControlRole", func(t *testing.T) {
		f := fixture(t, 1, 1)
		f.seed(t, "a", -time.Minute)
		a := f.admit(t)
		name := fmt.Sprintf("gp04b_control_%d", time.Now().UnixNano())
		role := pgx.Identifier{name}.Sanitize()
		f.exec(t, `CREATE ROLE `+role+` NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS`)
		t.Cleanup(func() { f.exec(t, `DROP OWNED BY `+role); f.exec(t, `DROP ROLE `+role) })
		f.exec(t, `GRANT USAGE ON SCHEMA public TO `+role)
		f.exec(t, `GRANT SELECT ON ALL TABLES IN SCHEMA public TO `+role)
		f.exec(t, `GRANT INSERT,UPDATE ON collector_work_items,collector_work_attempts,collection_repair_requests TO `+role)
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
		control, err := storepg.NewCollectorControlStore(pool)
		if err != nil {
			t.Fatal(err)
		}
		lease, found, err := control.ClaimWork(ctx, "a-collector", strings.Repeat("a", 32), time.Minute)
		if err != nil || !found || lease.Work.WorkID != a.WorkID {
			t.Fatalf("non-owner control claim: %v %v", found, err)
		}
	})
	t.Run("RuntimeColdStartOutageRecoveryAndTypedOnly", func(t *testing.T) {
		for _, typed := range []bool{false, true} {
			t.Run(fmt.Sprint(typed), func(t *testing.T) {
				f := fixture(t, 1, 1)
				seeds := f.seed(t, "a", -time.Minute)
				f.exec(t, `DELETE FROM collector_capabilities WHERE collector_id='a-collector'`)
				f.exec(t, `UPDATE collectors SET last_heartbeat_at=NULL WHERE collector_id='a-collector'`)
				f.exec(t, `DELETE FROM collector_source_health WHERE collector_id='a-collector'`)
				for _, d := range seeds {
					if typed || d.Operation != domain.OperationPrometheusSourceHealth {
						d.Enabled = false
						if _, err := s.UpdateDesiredSchedule(ctx, d); err != nil {
							t.Fatal(err)
						}
					}
				}
				clock := platform.SystemClock{}
				var executor application.CollectionExecutor
				var registry *application.TypedCollectionRegistry
				var caps []string
				var healthy atomic.Bool
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					if !healthy.Load() {
						w.WriteHeader(503)
						return
					}
					_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[]}}`))
				}))
				defer server.Close()
				if typed {
					f.exec(t, `INSERT INTO sources(source_id,cluster_id,kind,display_name) VALUES('slurm','a','slurm','Slurm')`)
					d, err := s.CreateDesiredSchedule(ctx, domain.DesiredSchedule{ScheduleKey: domain.ScheduleKey{ClusterID: "a", SourceID: "slurm", Operation: domain.OperationSlurmInventory}, Enabled: true, Mode: domain.SchedulingDurable, Interval: 30 * time.Second, Timeout: time.Second, MaxTargets: 1, MaxBytes: 100000})
					if err != nil {
						t.Fatal(err)
					}
					if err = s.ConfigureDurableExecution(ctx, domain.DurableExecution{ScheduleKey: d.ScheduleKey, Revision: d.Revision, CollectorID: "a-collector", Nodes: []domain.StableNodeID{"node-1"}}); err != nil {
						t.Fatal(err)
					}
					e, err := slurmexecution.New(durableNodes{}, clock, map[domain.StableNodeID]string{"node-1": "comp001"})
					if err != nil {
						t.Fatal(err)
					}
					registry, err = application.NewTypedCollectionRegistry(2, []application.TypedCollectionSource{{ClusterID: "a", SourceID: "slurm", Kind: domain.CollectionSourceSlurm, Operations: []domain.CollectionOperationID{domain.OperationSlurmInventory}, Executor: e}}, clock)
					if err != nil {
						t.Fatal(err)
					}
				} else {
					client, err := promadapter.NewClient(promadapter.Config{BaseURL: server.URL, Timeout: time.Second})
					if err != nil {
						t.Fatal(err)
					}
					executor, err = promexecution.New(client, clock, platform.RandomIDGenerator{})
					if err != nil {
						t.Fatal(err)
					}
					caps = []string{string(domain.QuerySourceHealth)}
				}
				f.none(t) // No heartbeat capability means no executable work.
				bridge := &durableRuntimeControl{fixture: f, completed: make(chan domain.ResultStatus, 4), healthy: &healthy, recover: !typed}
				journal, err := collectorruntime.OpenJournal(filepath.Join(t.TempDir(), "journal.json"), clock)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = journal.Close() }()
				runtime, err := collectorruntime.NewRuntimeWithTyped(collectorruntime.RuntimeConfig{CollectorID: "a-collector", SourceID: "a-source", Version: "fixture", Capabilities: caps, HeartbeatInterval: 20 * time.Millisecond, ClaimWait: 10 * time.Millisecond, RenewInterval: time.Second, BackoffMinimum: time.Millisecond, BackoffMaximum: 10 * time.Millisecond}, bridge, executor, registry, journal, clock)
				if err != nil {
					t.Fatal(err)
				}
				runctx, cancel := context.WithTimeout(ctx, 5*time.Second)
				defer cancel()
				done := make(chan error, 1)
				go func() { done <- runtime.Run(runctx) }()
				want := []domain.ResultStatus{domain.ResultFailed, domain.ResultNoData}
				if typed {
					want = []domain.ResultStatus{domain.ResultSucceeded}
				}
				for _, expected := range want {
					select {
					case status := <-bridge.completed:
						if status != expected {
							cancel()
							<-done
							t.Fatalf("runtime result %s want %s", status, expected)
						}
					case <-runctx.Done():
						cancel()
						<-done
						t.Fatalf("runtime stalled: %v", runctx.Err())
					}
				}
				cancel()
				<-done
				if typed {
					var count int
					if err = p.QueryRow(ctx, `SELECT count(*) FROM collector_source_health WHERE collector_id='a-collector'`).Scan(&count); err != nil || count != 0 {
						t.Fatalf("typed cold start required source health: %d %v", count, err)
					}
				} else {
					if len(bridge.availability) < 2 || bridge.availability[0] != collectorcontrol.SourceUnknown || bridge.availability[1] != collectorcontrol.SourceUnavailable {
						t.Fatalf("runtime health transitions: %v", bridge.availability)
					}
				}
			})
		}
	})
	t.Run("CurrentReportedV1SourceAdmissionAndClaim", func(t *testing.T) {
		f := fixture(t, 2, 1)
		f.seed(t, "a", -time.Minute)
		if err := s.EnsureSource(ctx, "a", "a", "source-b", "B"); err != nil {
			t.Fatal(err)
		}
		f.report(t, "a-collector", "source-b")
		f.none(t) // A grant and operation capability cannot authorize source B as A.
		f.report(t, "a-collector", "a-source")
		a := f.admit(t)
		f.report(t, "a-collector", "source-b")
		var oldFresh bool
		if err := p.QueryRow(ctx, `SELECT reported_at>clock_timestamp()-interval '2 minutes' FROM collector_source_health WHERE collector_id='a-collector' AND source_id='a-source'`).Scan(&oldFresh); err != nil || !oldFresh {
			t.Fatalf("old source history missing: %v %v", oldFresh, err)
		}
		if _, found, err := c.ClaimWork(ctx, "a-collector", strings.Repeat("a", 32), time.Minute); err != nil || found {
			t.Fatalf("old fresh source accepted: %v %v", found, err)
		}
		var attempts int
		if err := p.QueryRow(ctx, `SELECT count(*) FROM collector_work_attempts WHERE work_id=$1`, a.WorkID).Scan(&attempts); err != nil || attempts != 0 {
			t.Fatalf("mismatched source bound: %d %v", attempts, err)
		}
	})
	t.Run("UncommittedClaimOrRenewalAcrossExpiryRetainsCapacity", func(t *testing.T) {
		for _, typed := range []bool{false, true} {
			for _, renewal := range []bool{false, true} {
				t.Run(fmt.Sprintf("typed=%v/renewal=%v", typed, renewal), func(t *testing.T) {
					f := fixture(t, 1, 1)
					f.seed(t, "a", -time.Minute)
					f.seed(t, "b", -time.Minute)
					if typed {
						f.exec(t, `UPDATE desired_schedules SET enabled=false WHERE cluster_id='a'`)
						f.exec(t, `INSERT INTO sources(source_id,cluster_id,kind,display_name) VALUES('slurm','a','slurm','Slurm')`)
						d, err := s.CreateDesiredSchedule(ctx, domain.DesiredSchedule{ScheduleKey: domain.ScheduleKey{ClusterID: "a", SourceID: "slurm", Operation: domain.OperationSlurmInventory}, Enabled: true, Mode: domain.SchedulingDurable, Interval: 30 * time.Second, Timeout: time.Second, MaxTargets: 1, MaxBytes: 100000})
						if err != nil {
							t.Fatal(err)
						}
						if err = s.ConfigureDurableExecution(ctx, domain.DurableExecution{ScheduleKey: d.ScheduleKey, Revision: d.Revision, CollectorID: "a-collector", Nodes: []domain.StableNodeID{"node-1"}}); err != nil {
							t.Fatal(err)
						}
						if err = c.ReplaceCapabilities(ctx, "a-collector", map[string]string{string(domain.OperationSlurmInventory): "1"}); err != nil {
							t.Fatal(err)
						}
					}
					a := f.admit(t)
					if a.ClusterID != "a" {
						t.Fatal(a)
					}
					if renewal {
						var found bool
						var err error
						if typed {
							_, found, err = c.ClaimTypedWork(ctx, "a", "a-collector", strings.Repeat("a", 32), time.Minute, []domain.SourceID{"slurm"})
						} else {
							_, found, err = c.ClaimWork(ctx, "a-collector", strings.Repeat("a", 32), time.Minute)
						}
						if err != nil || !found {
							t.Fatalf("initial lease: %v %v", found, err)
						}
					}
					// The AFTER trigger pauses the real claim after attempt insertion but
					// before commit, leaving its old AVAILABLE row visible to admission.
					f.exec(t, `CREATE FUNCTION gp04b_pause_claim() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.work_id=TG_ARGV[0] THEN PERFORM pg_advisory_xact_lock(4717); END IF; RETURN NEW; END $$`)
					event := "INSERT"
					if renewal {
						event = "UPDATE OF lease_expires_at"
					}
					f.exec(t, `CREATE TRIGGER gp04b_pause_claim AFTER `+event+` ON collector_work_attempts FOR EACH ROW EXECUTE FUNCTION gp04b_pause_claim('`+string(a.WorkID)+`')`)
					t.Cleanup(func() {
						f.exec(t, `DROP TRIGGER gp04b_pause_claim ON collector_work_attempts`)
						f.exec(t, `DROP FUNCTION gp04b_pause_claim()`)
					})
					lock, err := p.Acquire(ctx)
					if err != nil {
						t.Fatal(err)
					}
					defer lock.Release()
					if _, err = lock.Exec(ctx, `SELECT pg_advisory_lock(4717)`); err != nil {
						t.Fatal(err)
					}
					defer func() { _, _ = lock.Exec(ctx, `SELECT pg_advisory_unlock(4717)`) }()
					f.exec(t, `UPDATE collector_work_items SET deadline=clock_timestamp()+interval '300 milliseconds',work_expires_at=clock_timestamp()+interval '300 milliseconds' WHERE work_id=$1`, a.WorkID)
					if renewal {
						// Disable only the test pause while setting the old lease deadline.
						f.exec(t, `ALTER TABLE collector_work_attempts DISABLE TRIGGER gp04b_pause_claim`)
						f.exec(t, `UPDATE collector_work_attempts SET lease_expires_at=clock_timestamp()+interval '300 milliseconds' WHERE work_id=$1`, a.WorkID)
						f.exec(t, `ALTER TABLE collector_work_attempts ENABLE TRIGGER gp04b_pause_claim`)
					}
					claimed := make(chan error, 1)
					go func() {
						var found bool
						var err error
						if renewal {
							err = c.RenewWorkLease(ctx, "a-collector", a.WorkID, 1, strings.Repeat("a", 32), time.Minute)
							found = err == nil
						} else if typed {
							_, found, err = c.ClaimTypedWork(ctx, "a", "a-collector", strings.Repeat("a", 32), time.Minute, []domain.SourceID{"slurm"})
						} else {
							_, found, err = c.ClaimWork(ctx, "a-collector", strings.Repeat("a", 32), time.Minute)
						}
						if err == nil && !found {
							err = fmt.Errorf("claim not found")
						}
						claimed <- err
					}()
					until := time.Now().Add(3 * time.Second)
					for {
						var paused, expired bool
						if err = p.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND objid=4717 AND NOT granted),(SELECT deadline<clock_timestamp() FROM collector_work_items WHERE work_id=$1)
 AND (NOT $2 OR EXISTS(SELECT 1 FROM collector_work_attempts WHERE work_id=$1 AND lease_expires_at<clock_timestamp()))`, a.WorkID, renewal).Scan(&paused, &expired); err != nil {
							t.Fatal(err)
						}
						if paused && expired {
							break
						}
						if time.Now().After(until) {
							t.Fatal("claim did not pause across deadline")
						}
						time.Sleep(5 * time.Millisecond)
					}
					f.none(t)
					if _, err = lock.Exec(ctx, `SELECT pg_advisory_unlock(4717)`); err != nil {
						t.Fatal(err)
					}
					if err = <-claimed; err != nil {
						t.Fatal(err)
					}
					f.exec(t, `DROP TRIGGER gp04b_pause_claim ON collector_work_attempts`)
					f.exec(t, `CREATE TRIGGER gp04b_pause_claim AFTER INSERT ON collector_work_attempts FOR EACH ROW EXECUTE FUNCTION gp04b_pause_claim('unused')`)
					f.none(t) // The committed live attempt still owns capacity.
					f.exec(t, `UPDATE collector_work_attempts SET lease_expires_at=claimed_at+interval '1 microsecond' WHERE work_id=$1`, a.WorkID)
					if next := f.admit(t); next.ClusterID != "b" {
						t.Fatalf("expired capacity did not release: %+v", next)
					}
				})
			}
		}
	})
}

// The bridge exercises the real collector runtime/journal/executors with the
// production store ports, keeping transport and live credentials out of fixtures.
type durableRuntimeControl struct {
	fixture      durableFixture
	completed    chan domain.ResultStatus
	healthy      *atomic.Bool
	recover      bool
	availability []collectorcontrol.SourceAvailability
}

func (b *durableRuntimeControl) Heartbeat(ctx context.Context, h collectorruntime.Heartbeat) error {
	report := collectorcontrol.Heartbeat{CollectorID: h.CollectorID, ProtocolMin: h.ProtocolMin, ProtocolMax: h.ProtocolMax, Version: h.Version, ReportedAt: time.Now().UTC()}
	for _, cap := range h.Capabilities {
		report.Capabilities = append(report.Capabilities, collectorcontrol.CapabilityReport{Name: cap.Name, Version: cap.Version})
	}
	for _, health := range h.SourceHealth {
		availability := collectorcontrol.SourceAvailability(health.Availability)
		b.availability = append(b.availability, availability)
		report.SourceHealth = append(report.SourceHealth, collectorcontrol.SourceHealthReport{SourceID: health.SourceID, Availability: availability, CheckedAt: health.CheckedAt})
	}
	if err := b.fixture.c.RecordHeartbeat(ctx, report); err != nil {
		return err
	}
	_, _, err := application.AdmitDurableSchedule(ctx, b.fixture.s, b.fixture.policy)
	return err
}
func (b *durableRuntimeControl) Claim(ctx context.Context, _ collectorruntime.ClaimRequest) (*domain.WorkLease, error) {
	lease, found, err := b.fixture.c.ClaimWork(ctx, "a-collector", strings.Repeat("a", 32), time.Minute)
	if !found {
		return nil, err
	}
	return &lease, err
}
func (b *durableRuntimeControl) ClaimTyped(ctx context.Context, r collectorruntime.ClaimRequest) (*domain.TypedWorkLease, error) {
	lease, found, err := b.fixture.c.ClaimTypedWork(ctx, "a", "a-collector", strings.Repeat("a", 32), time.Minute, r.SourceIDs)
	if !found {
		return nil, err
	}
	return &lease, err
}
func (b *durableRuntimeControl) Start(ctx context.Context, r collectorruntime.LeaseRef) error {
	return b.fixture.c.AcknowledgeWorkStart(ctx, "a-collector", r.WorkID, r.Attempt, r.LeaseToken)
}
func (b *durableRuntimeControl) StartTyped(ctx context.Context, r collectorruntime.LeaseRef) error {
	return b.Start(ctx, r)
}
func (b *durableRuntimeControl) Renew(ctx context.Context, r collectorruntime.LeaseRef) (time.Time, error) {
	err := b.fixture.c.RenewWorkLease(ctx, "a-collector", r.WorkID, r.Attempt, r.LeaseToken, time.Minute)
	return time.Now().Add(time.Minute), err
}
func (b *durableRuntimeControl) RenewTyped(ctx context.Context, r collectorruntime.LeaseRef) (time.Time, error) {
	return b.Renew(ctx, r)
}
func (b *durableRuntimeControl) UploadChunk(ctx context.Context, r collectorruntime.ResultChunk) error {
	_, err := b.fixture.c.UploadResultChunk(ctx, "a-collector", collectorcontrol.ResultChunk{LeaseRef: collectorcontrol.LeaseRef{WorkID: r.WorkID, Attempt: r.Attempt, LeaseToken: r.LeaseToken}, Index: r.Index, Payload: r.Payload, SHA256: r.SHA256})
	return err
}
func (b *durableRuntimeControl) Finalize(ctx context.Context, r collectorruntime.Finalization) error {
	_, err := b.fixture.c.FinalizeResult(ctx, "a-collector", collectorcontrol.ResultFinalization{LeaseRef: collectorcontrol.LeaseRef{WorkID: r.WorkID, Attempt: r.Attempt, LeaseToken: r.LeaseToken}, RunID: r.RunID, Status: r.Status, ChunkCount: r.ChunkCount, Bytes: r.Bytes, SHA256: r.SHA256})
	if err != nil {
		return err
	}
	if b.recover {
		b.recover = false
		b.healthy.Store(true)
		if _, err = b.fixture.p.Exec(ctx, `UPDATE durable_schedule_state SET next_due_at=clock_timestamp()-interval '1 second' WHERE cluster_id='a'`); err != nil {
			return err
		}
	}
	b.completed <- r.Status
	return nil
}
func (b *durableRuntimeControl) SubmitTyped(ctx context.Context, r collectorruntime.LeaseRef, result domain.TypedCollectorResult) error {
	_, err := b.fixture.c.SubmitTypedResult(ctx, "a", "a-collector", collectorcontrol.LeaseRef{WorkID: r.WorkID, Attempt: r.Attempt, LeaseToken: r.LeaseToken}, result, typedChecksum(result))
	if err == nil {
		b.completed <- result.Status
	}
	return err
}

type durableNodes struct{}

func (durableNodes) Nodes(_ context.Context, names []string) (slurmadapter.Result, error) {
	if len(names) != 1 || names[0] != "comp001" {
		return slurmadapter.Result{}, fmt.Errorf("unexpected scope")
	}
	return slurmadapter.Result{Records: []slurmadapter.Record{{Kind: "node", ID: "comp001", ObservedAt: time.Now().UTC()}}, BytesRead: 64}, nil
}
