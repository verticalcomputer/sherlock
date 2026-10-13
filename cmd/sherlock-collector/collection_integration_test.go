//go:build integration

package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/collectorcontrol"
	"github.com/verticalcomputer/sherlock/internal/collectorruntime"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/platform"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

// Only the certificate verification edge is injected. Authentication, cluster
// binding, work/attempt authority and result ingestion use real PostgreSQL.
type collectionFixtureAuth struct{ certificate *x509.Certificate }

func (a collectionFixtureAuth) Certificate(*http.Request) (*x509.Certificate, error) {
	return a.certificate, nil
}
func (collectionFixtureAuth) AllowEnrollment(*http.Request) bool { return false }

type collectionFixtureIdentity struct{}

func (collectionFixtureIdentity) Enroll(context.Context, collectorcontrol.EnrollmentRequest) (collectorcontrol.Enrollment, error) {
	return collectorcontrol.Enrollment{}, errors.New("fixture enrollment disabled")
}
func (collectionFixtureIdentity) Renew(context.Context, domain.CollectorID, []byte) (collectorcontrol.IssuedIdentity, error) {
	return collectorcontrol.IssuedIdentity{}, errors.New("fixture renewal disabled")
}

type replayCollectionClient struct {
	*collectorruntime.HTTPClient
	submitted int
	cancel    context.CancelFunc
	loseFirst bool
}

func (c *replayCollectionClient) SubmitTyped(ctx context.Context, ref collectorruntime.LeaseRef, result domain.TypedCollectorResult) error {
	if err := c.HTTPClient.SubmitTyped(ctx, ref, result); err != nil {
		return err
	}
	c.submitted++
	if c.loseFirst && c.submitted == 1 {
		c.cancel()
		return errors.New("fixture lost successful response")
	}
	c.cancel()
	return nil
}

func TestCollectorTypedSlurmFixtureEndToEnd(t *testing.T) {
	dsn := os.Getenv("SHERLOCK_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires isolated migrated PostgreSQL")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	store, err := storepg.NewCollectorControlStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	suffix := fmt.Sprint(time.Now().UnixNano())
	cluster, source, collector := domain.ClusterID("e2e-c-"+suffix), domain.SourceID("e2e-s-"+suffix), domain.CollectorID("e2e-collector-"+suffix)
	collections, _ := storepg.NewCollectionStore(pool)
	if err := collections.EnsureSource(ctx, cluster, "Local fixture", source, "Slurm fixture"); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE sources SET kind='slurm' WHERE source_id=$1`, source); err != nil {
		t.Fatal(err)
	}
	if err := store.RegisterCollector(ctx, storepg.CollectorRegistration{CollectorID: collector, ClusterID: cluster, DisplayName: "fixture", Version: "old-v1", ProtocolMin: 1, ProtocolMax: 1, OperatingSystem: "linux", Architecture: "amd64"}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	certificate := &x509.Certificate{Raw: []byte(suffix), SerialNumber: big.NewInt(now.UnixNano())}
	// RegisterCollector is a queue fixture helper, not enrollment; seed its
	// absent current identity before exercising the renewal persistence port.
	if _, err := pool.Exec(ctx, `UPDATE collectors SET identity_serial='' WHERE collector_id=$1`, collector); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordRenewedIdentity(ctx, collector, collectorcontrol.IssuedIdentity{Serial: hex.EncodeToString(certificate.SerialNumber.Bytes()), Fingerprint: sha256.Sum256(certificate.Raw), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	transport, err := collectorcontrol.NewTransportWithRequestAuthenticator(collectionFixtureIdentity{}, store, store, store, store, platform.SystemClock{}, rand.Reader, collectionFixtureAuth{certificate})
	if err != nil {
		t.Fatal(err)
	}
	if err := transport.ConfigureTypedCollection(store); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(transport)
	defer server.Close()
	client, err := collectorruntime.NewHTTPClient(server.URL, server.Client(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Heartbeat(ctx, collectorruntime.Heartbeat{CollectorID: collector, Version: "old-v1", Capabilities: []collectorruntime.Capability{{Name: string(domain.QueryGPUUtilization), Version: "1"}}}); err != nil {
		t.Fatal(err)
	}
	if lease, err := client.Claim(ctx, collectorruntime.ClaimRequest{CollectorID: collector}); err != nil || lease != nil {
		t.Fatalf("old collector claimed typed work: %v %v", lease, err)
	}
	// An old client still receives its existing v1 Prometheus task on new control.
	promSource := domain.SourceID("e2e-prom-" + suffix)
	if err := collections.EnsureSource(ctx, cluster, "Local fixture", promSource, "Prometheus fixture"); err != nil {
		t.Fatal(err)
	}
	legacyDeadline := now.Add(time.Minute)
	legacy := domain.CollectorWork{WorkID: domain.WorkID("e2e-v1-work-" + suffix), Status: domain.WorkAvailable, AvailableAt: now, WorkExpiresAt: legacyDeadline,
		Task: domain.CollectionTask{RunID: domain.RunID("e2e-v1-run-" + suffix), ClusterID: cluster, SourceID: promSource, Query: domain.QueryGPUUtilization, ScheduledFor: now, Deadline: legacyDeadline, MaxSeries: 10, MaxBytes: 100000, IdempotencyKey: "e2e-v1-key-" + suffix}}
	if _, err := store.EnqueueCollectionWork(ctx, legacy); err != nil {
		t.Fatal(err)
	}
	if lease, err := client.Claim(ctx, collectorruntime.ClaimRequest{CollectorID: collector}); err != nil || lease == nil || lease.Work.WorkID != legacy.WorkID {
		t.Fatalf("v1 compatibility claim: %v %v", lease, err)
	}
	desired, err := collections.CreateDesiredSchedule(ctx, domain.DesiredSchedule{ScheduleKey: domain.ScheduleKey{ClusterID: cluster, SourceID: source, Operation: domain.OperationSlurmSnapshot}, Enabled: true, Mode: domain.SchedulingDurable, Interval: time.Hour, Timeout: time.Minute, MaxTargets: 100, MaxBytes: 1000000})
	if err != nil {
		t.Fatal(err)
	}
	if err = collections.ConfigureDurableExecution(ctx, domain.DurableExecution{ScheduleKey: desired.ScheduleKey, Revision: desired.Revision, CollectorID: collector, Nodes: []domain.StableNodeID{"node-1", "node-2"}}); err != nil {
		t.Fatal(err)
	}
	if err = store.RecordHeartbeat(ctx, collectorcontrol.Heartbeat{CollectorID: collector, ProtocolMin: 1, ProtocolMax: 2, Version: "new-v2", ReportedAt: time.Now().UTC(), Capabilities: []collectorcontrol.CapabilityReport{{Name: string(domain.OperationSlurmSnapshot), Version: "1"}}, SourceHealth: []collectorcontrol.SourceHealthReport{{SourceID: source, Availability: collectorcontrol.SourceAvailable, CheckedAt: time.Now().UTC()}}}); err != nil {
		t.Fatal(err)
	}
	admission, found, err := collections.AdmitDueSchedule(ctx, domain.DurableAdmissionPolicy{GlobalLimit: 10, ClusterLimit: 10})
	if err != nil || !found || admission.Operation != domain.OperationSlurmSnapshot {
		t.Fatalf("snapshot admission=%+v found=%v err=%v", admission, found, err)
	}
	workID := admission.WorkID
	if lease, err := client.Claim(ctx, collectorruntime.ClaimRequest{CollectorID: collector}); err != nil || lease != nil {
		t.Fatalf("v1 collector claimed admitted typed snapshot: %v %v", lease, err)
	}
	for _, path := range []string{"/collector/v1/diagnostic-work/claim", "/collector/v2/diagnostic-work/claim", "/collector/v2/repair-work/claim"} {
		request, _ := http.NewRequest(http.MethodGet, server.URL+path, nil)
		request.Header.Set("X-Sherlock-Protocol-Version", "2")
		request.Header.Set("X-Correlation-ID", "collection-fixture")
		response, err := server.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != 404 {
			t.Fatalf("collection credentials exposed execution route %s: %d", path, response.StatusCode)
		}
	}
	cfg := slurmFixtureConfig()
	cfg.Operations = []domain.CollectionOperationID{domain.OperationSlurmSnapshot}
	cfg.SlurmClusterID = string(cluster)
	cfg.SlurmSourceID = string(source)
	cfg.SlurmNodes = map[domain.StableNodeID]string{"node-1": "comp007", "node-2": "comp008"}
	cfg.SlurmSchedulerNamespace = "slurm/cluster-a"
	cfg.SlurmSchedulerCluster = "cluster-a"
	cfg.SlurmCurrentJobsComplete = true
	cfg.SlurmAccountingComplete = true
	cfg.SlurmAccountingOverlap = 5 * time.Minute
	fixture := func(name string) string {
		body, err := os.ReadFile(filepath.Join("..", "..", "internal", "adapters", "slurm", "testdata", "upstream-data-parser-v0.0.40-hand-authored", name+".json"))
		if err != nil {
			t.Fatal(err)
		}
		return string(body)
	}
	runner := &slurmFixtureRunner{bodies: map[string]string{
		"scontrol show nodes --json comp007,comp008": fixture("nodes"),
		"scontrol show partitions --json":            fixture("partitions"),
		"squeue":                                     fixture("jobs"), "sacct": fixture("accounting"),
	}}
	legacyExecutor, registry, err := buildCollectionExecutors(cfg, runner)
	if err != nil {
		t.Fatal(err)
	}
	journalPath := filepath.Join(t.TempDir(), "journal.json")
	journal, err := collectorruntime.OpenJournal(journalPath, platform.SystemClock{})
	if err != nil {
		t.Fatal(err)
	}
	runContext, cancel := context.WithTimeout(ctx, 10*time.Second)
	replay := &replayCollectionClient{HTTPClient: client, cancel: cancel, loseFirst: true}
	runtime, err := collectorruntime.NewRuntimeWithTyped(collectorruntime.RuntimeConfig{CollectorID: collector, SourceID: source, Version: "new-v2", HeartbeatInterval: time.Second, ClaimWait: time.Millisecond, RenewInterval: time.Second, BackoffMinimum: time.Millisecond, BackoffMaximum: time.Millisecond}, replay, legacyExecutor, registry, journal, platform.SystemClock{})
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.Run(runContext); !errors.Is(err, context.Canceled) {
		t.Fatalf("runtime: %v", err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	if runner.calls != 4 || replay.submitted != 1 {
		t.Fatalf("execution=%d submission=%d", runner.calls, replay.submitted)
	}
	journal, err = collectorruntime.OpenJournal(journalPath, platform.SystemClock{})
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	restartContext, restartCancel := context.WithTimeout(ctx, 10*time.Second)
	replay = &replayCollectionClient{HTTPClient: client, cancel: restartCancel}
	runtime, err = collectorruntime.NewRuntimeWithTyped(collectorruntime.RuntimeConfig{CollectorID: collector, SourceID: source, Version: "new-v2", HeartbeatInterval: time.Second, ClaimWait: time.Millisecond, RenewInterval: time.Second, BackoffMinimum: time.Millisecond, BackoffMaximum: time.Millisecond}, replay, legacyExecutor, registry, journal, platform.SystemClock{})
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.Run(restartContext); !errors.Is(err, context.Canceled) {
		t.Fatalf("restart runtime: %v", err)
	}
	if runner.calls != 4 || replay.submitted != 1 {
		t.Fatalf("restart reexecuted source: calls=%d submissions=%d", runner.calls, replay.submitted)
	}
	result, found, err := store.LoadFinalizedTypedResult(ctx, cluster, workID)
	if err != nil || !found || result.Status != domain.ResultPartial || result.Payload.SlurmSnapshot.Inventory == nil || len(result.Payload.SlurmSnapshot.UnresolvedAccounting) != 1 {
		t.Fatalf("persisted typed result=%+v found=%t err=%v", result, found, err)
	}
	goodput, err := storepg.NewGoodputStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	projection, found, err := goodput.GetCurrentInventoryRevision(ctx, cluster, source, application.InventoryObserved)
	if err != nil || !found || projection.Revision.ID != result.Payload.SlurmSnapshot.Inventory.ID || len(projection.Revision.Entities) != 2 {
		t.Fatalf("persisted inventory projection=%+v found=%t err=%v", projection, found, err)
	}
	public, err := storepg.NewPublicQueryStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	runs, _, err := public.ListCollectionRuns(ctx, cluster, application.CollectionRunFilters{SourceID: source}, 10, 0)
	if err != nil || len(runs) != 1 || runs[0].Status != domain.ResultPartial || runs[0].Coverage.Complete || len(runs[0].Failures) == 0 {
		t.Fatalf("public gap projection=%+v err=%v", runs, err)
	}
	for _, table := range []string{"collection_runs", "collector_typed_result_ingestions", "goodput_source_coverage"} {
		var count int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM `+table+` WHERE run_id=$1`, result.Plan.RunID).Scan(&count); err != nil || count != 1 {
			t.Fatalf("%s count=%d err=%v", table, count, err)
		}
	}
	var maxProtocol, attempts int
	if err := pool.QueryRow(ctx, `SELECT protocol_max FROM collectors WHERE collector_id=$1`, collector).Scan(&maxProtocol); err != nil || maxProtocol != 2 {
		t.Fatalf("upgraded protocol=%d err=%v", maxProtocol, err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM collector_work_attempts WHERE work_id=$1 AND status='SUCCEEDED'`, workID).Scan(&attempts); err != nil || attempts != 1 {
		t.Fatalf("durable successful attempts=%d err=%v", attempts, err)
	}
	encoded, _ := domain.EncodeTypedCollectorResult(result)
	if strings.Contains(string(encoded), "comp007") || strings.Contains(string(encoded), "scontrol") {
		t.Fatal("typed result exposed CLI output or command")
	}
}
