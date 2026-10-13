package investigationapi

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/collectorcontrol"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

type recordingQueue struct {
	claims          int
	records         int
	lease           domain.DiagnosticWorkLease
	found           bool
	claimCluster    domain.ClusterID
	claimCollector  domain.CollectorID
	recordCluster   domain.ClusterID
	recordCollector domain.CollectorID
	recordWork      domain.DiagnosticWorkID
	recordAttempt   int
	recordToken     string
	recordResult    domain.DiagnosticAttemptResult
	claimedToken    string
}

func (queue *recordingQueue) Claim(_ context.Context, clusterID domain.ClusterID, collectorID domain.CollectorID, token string, _ time.Duration) (domain.DiagnosticWorkLease, bool, error) {
	queue.claims++
	queue.claimCluster, queue.claimCollector = clusterID, collectorID
	queue.claimedToken = token
	lease := queue.lease
	lease.LeaseToken = token
	return lease, queue.found, nil
}

func (queue *recordingQueue) Record(_ context.Context, clusterID domain.ClusterID, collectorID domain.CollectorID, workID domain.DiagnosticWorkID, attempt int, token string, result domain.DiagnosticAttemptResult) (domain.DiagnosticRun, bool, error) {
	if queue.lease.Work.Run.Request().ClusterID != clusterID || queue.lease.RunnerID != string(collectorID) || token != queue.claimedToken || workID != queue.lease.Work.WorkID || attempt != queue.lease.Attempt {
		return domain.DiagnosticRun{}, false, application.ErrDiagnosticLeaseInvalid
	}
	queue.records++
	queue.recordCluster, queue.recordCollector = clusterID, collectorID
	queue.recordWork, queue.recordAttempt, queue.recordToken, queue.recordResult = workID, attempt, token, result
	return queue.lease.Work.Run, false, nil
}

func scopedLease(t *testing.T, clusterID domain.ClusterID, collectorID domain.CollectorID) domain.DiagnosticWorkLease {
	t.Helper()
	now := time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC)
	request := domain.DiagnosticRequest{
		RunID: "run-1", ClusterID: clusterID,
		Definition: domain.DiagnosticDefinitionRef{PackID: "standard.readonly", PackVersion: "1.1.0", DefinitionID: "gpu.ecc_counters", DefinitionVersion: "1.0.0", DefinitionDigest: domain.ChecksumSHA256([]byte("definition"))},
		Privilege:  domain.DiagnosticUnprivileged, Targets: []domain.DiagnosticTarget{"comp001"},
		RequestedBy: "investigator", IdempotencyKey: "key-1", RequestedAt: now, Deadline: now.Add(time.Minute), MaxAttempts: 1,
	}
	run, err := domain.NewDiagnosticRun(request, false)
	if err != nil {
		t.Fatal(err)
	}
	return domain.DiagnosticWorkLease{Work: domain.DiagnosticWork{WorkID: "work-1", Run: run, Deadline: request.Deadline, MaxAttempts: 1}, Attempt: 1, RunnerID: string(collectorID), LeaseExpires: now.Add(time.Minute)}
}

// Authorization to poll metrics is not authorization to run commands, so the
// permission check must happen before the queue is touched at all.
func TestDiagnosticWorkTransportRefusesACollectorOutsideTheAllowList(t *testing.T) {
	authority, err := NewAllowedCollectors([]string{"collector-head"})
	if err != nil {
		t.Fatal(err)
	}
	queue := &recordingQueue{}
	transport, err := NewDiagnosticWorkTransport(queue, authority)
	if err != nil {
		t.Fatal(err)
	}

	if _, _, err := transport.ClaimDiagnosticWork(context.Background(), "cluster-a", "collector-metrics", "token", time.Minute); !errors.Is(err, collectorcontrol.ErrDiagnosticExecutionNotPermitted) {
		t.Fatalf("an unlisted collector claimed work: %v", err)
	}
	if _, _, err := transport.RecordDiagnosticAttempt(context.Background(), "cluster-a", "collector-metrics", "work-1", 1, "token", domain.DiagnosticAttemptResult{}); !errors.Is(err, collectorcontrol.ErrDiagnosticExecutionNotPermitted) {
		t.Fatalf("an unlisted collector recorded an attempt: %v", err)
	}
	if queue.claims != 0 || queue.records != 0 {
		t.Fatalf("the queue was reached by an unpermitted collector: %+v", queue)
	}

	if _, _, err := transport.ClaimDiagnosticWork(context.Background(), "cluster-a", "collector-head", "token", time.Minute); err != nil {
		t.Fatalf("a permitted collector was refused: %v", err)
	}
	if queue.claims != 1 {
		t.Fatalf("claims = %d, want the permitted collector to reach the queue", queue.claims)
	}
	if queue.claimCluster != "cluster-a" || queue.claimCollector != "collector-head" {
		t.Fatalf("queue scope = %q/%q", queue.claimCluster, queue.claimCollector)
	}
}

// An empty allow-list is a configuration mistake, not a control plane that
// permits everyone or one that authenticates and then refuses everyone.
func TestNewAllowedCollectorsRequiresExplicitEntries(t *testing.T) {
	if _, err := NewAllowedCollectors(nil); err == nil {
		t.Fatal("an empty allow-list was accepted")
	}
	if _, err := NewAllowedCollectors([]string{"collector-head", ""}); err == nil {
		t.Fatal("an empty collector identity was accepted")
	}
	var absent *AllowedCollectors
	if permitted, err := absent.MayExecuteDiagnostics(context.Background(), "cluster-a", "collector-head"); permitted || err != nil {
		t.Fatalf("an absent authority permitted execution: %t %v", permitted, err)
	}
}

func TestDiagnosticWorkTransportBindsLeasesAndResultsToClusterAndCollector(t *testing.T) {
	authority, err := NewAllowedCollectors([]string{"collector-head"})
	if err != nil {
		t.Fatal(err)
	}
	queue := &recordingQueue{lease: scopedLease(t, "cluster-a", "collector-head"), found: true}
	transport, err := NewDiagnosticWorkTransport(queue, authority)
	if err != nil {
		t.Fatal(err)
	}
	lease, found, err := transport.ClaimDiagnosticWork(context.Background(), "cluster-a", "collector-head", "lease-token", time.Minute)
	if err != nil || !found {
		t.Fatalf("claim found=%t err=%v", found, err)
	}
	result := domain.DiagnosticAttemptResult{WorkID: "work-1", RunID: "run-1", Attempt: 1, RunnerID: "collector-head"}
	if _, _, err := transport.RecordDiagnosticAttempt(context.Background(), "cluster-b", "collector-head", "work-1", 1, lease.LeaseToken, result); !errors.Is(err, application.ErrDiagnosticLeaseInvalid) {
		t.Fatalf("cross-cluster result was not denied: %v", err)
	}
	if _, _, err := transport.RecordDiagnosticAttempt(context.Background(), "cluster-a", "collector-other", "work-1", 1, lease.LeaseToken, result); !errors.Is(err, collectorcontrol.ErrDiagnosticExecutionNotPermitted) {
		t.Fatalf("foreign collector result was not denied: %v", err)
	}
	if queue.records != 0 {
		t.Fatalf("denied results reached the queue: %d", queue.records)
	}
}

func TestDiagnosticWorkTransportRecordsAfterControlProcessRestart(t *testing.T) {
	authority, err := NewAllowedCollectors([]string{"collector-head"})
	if err != nil {
		t.Fatal(err)
	}
	queue := &recordingQueue{lease: scopedLease(t, "cluster-a", "collector-head"), found: true}
	beforeRestart, err := NewDiagnosticWorkTransport(queue, authority)
	if err != nil {
		t.Fatal(err)
	}
	lease, found, err := beforeRestart.ClaimDiagnosticWork(context.Background(), "cluster-a", "collector-head", "lease-token", time.Minute)
	if err != nil || !found {
		t.Fatalf("claim found=%t err=%v", found, err)
	}

	// A new transport has no process-local knowledge of the claim. The durable
	// queue receives the full result identity and reconstructs the lease.
	afterRestart, err := NewDiagnosticWorkTransport(queue, authority)
	if err != nil {
		t.Fatal(err)
	}
	result := domain.DiagnosticAttemptResult{WorkID: "work-1", RunID: "run-1", Attempt: 1, RunnerID: "collector-head"}
	if _, _, err := afterRestart.RecordDiagnosticAttempt(context.Background(), "cluster-a", "collector-head", "work-1", 1, lease.LeaseToken, result); err != nil {
		t.Fatalf("result after restart was refused: %v", err)
	}
	if queue.records != 1 || queue.recordWork != "work-1" || queue.recordAttempt != 1 || queue.recordToken != "lease-token" {
		t.Fatalf("durable record identity = %+v", queue)
	}
}

func TestDiagnosticWorkTransportRejectsAQueueLeaseFromAnotherCluster(t *testing.T) {
	authority, _ := NewAllowedCollectors([]string{"collector-head"})
	queue := &recordingQueue{lease: scopedLease(t, "cluster-b", "collector-head"), found: true}
	transport, _ := NewDiagnosticWorkTransport(queue, authority)
	if _, _, err := transport.ClaimDiagnosticWork(context.Background(), "cluster-a", "collector-head", "lease-token", time.Minute); !errors.Is(err, application.ErrDiagnosticLeaseInvalid) {
		t.Fatalf("cross-cluster queue lease was accepted: %v", err)
	}
}
