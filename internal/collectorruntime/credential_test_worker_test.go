package collectorruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/collectorcontrol"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

const workerCanary = "synthetic-worker-canary-5c1e"

type fakeCredentialControl struct {
	mu          sync.Mutex
	plan        domain.CredentialAccessTestPlan
	token       string
	claimed     bool
	started     bool
	deliveries  int
	refuse      int
	results     []domain.CredentialAccessTestResult
	requests    []string
	renewals    int
	stalled     chan struct{}
	stallClaims bool
}

func (f *fakeCredentialControl) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.requests = append(f.requests, r.Method+" "+r.URL.Path)
		if r.Header.Get(protocolHeader) != "2" {
			t.Errorf("credential test request without protocol v2: %s", r.URL.Path)
		}
		body, _ := readAll(r)
		if strings.Contains(string(body)+r.URL.RawQuery, workerCanary) {
			t.Errorf("secret sent back to control on %s", r.URL.Path)
		}
		switch {
		case r.URL.Path == "/collector/v2/credential-tests/claim":
			if f.claimed || f.stallClaims {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			f.claimed = true
			f.token = strings.Repeat("t", 40)
			_ = json.NewEncoder(w).Encode(collectorcontrol.CredentialAccessTestLease{TestID: f.plan.TestID, Attempt: 1, LeaseToken: f.token, LeaseExpires: time.Now().Add(time.Minute), Plan: f.plan})
		case strings.HasSuffix(r.URL.Path, "/start"):
			var lease credentialLeaseWire
			_ = json.Unmarshal(body, &lease)
			if lease.LeaseToken != f.token {
				w.WriteHeader(http.StatusConflict)
				return
			}
			f.started = true
			_ = json.NewEncoder(w).Encode(credentialLeaseResponseWire{LeaseExpires: time.Now().Add(time.Minute)})
		case strings.HasSuffix(r.URL.Path, "/renew"):
			f.renewals++
			_ = json.NewEncoder(w).Encode(credentialLeaseResponseWire{LeaseExpires: time.Now().Add(time.Minute)})
		case strings.HasSuffix(r.URL.Path, "/credential"):
			var request credentialDeliveryWire
			_ = json.Unmarshal(body, &request)
			digest, _ := domain.CredentialAccessTestPlanDigest(f.plan)
			if request.LeaseToken != f.token || request.PlanDigest != digest.String() {
				w.WriteHeader(http.StatusConflict)
				return
			}
			if f.refuse > 0 {
				f.refuse--
				w.WriteHeader(http.StatusConflict)
				return
			}
			f.deliveries++
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("X-Sherlock-Credential-Username", f.plan.Username)
			w.Header().Set("X-Sherlock-Credential-Host", f.plan.Host)
			w.Header().Set("X-Sherlock-Credential-Version", "3")
			_, _ = w.Write([]byte(workerCanary))
		case strings.HasSuffix(r.URL.Path, "/result"):
			var request credentialResultWire
			_ = json.Unmarshal(body, &request)
			if request.LeaseToken != f.token {
				w.WriteHeader(http.StatusConflict)
				return
			}
			var result domain.CredentialAccessTestResult
			if err := json.Unmarshal(request.Document, &result); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			f.results = append(f.results, result)
			if f.stalled != nil {
				close(f.stalled)
				f.stalled = nil
			}
			_ = json.NewEncoder(w).Encode(credentialResultResponseWire{Status: "SUCCEEDED", Outcome: string(result.Outcome)})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
}

func readAll(r *http.Request) ([]byte, error) {
	var buffer bytes.Buffer
	_, err := buffer.ReadFrom(r.Body)
	return buffer.Bytes(), err
}

type recordingExecutor struct {
	mu        sync.Mutex
	received  []byte
	plan      domain.CredentialAccessTestPlan
	outcome   domain.CredentialAccessOutcome
	block     chan struct{}
	callCount int
}

// Check mimics the real bcmaccess.Checker's contract: it calls fetch only
// after recording that it was invoked (standing in for the executor's own
// unprivileged pre-checks), and turns a fetch failure into
// CREDENTIAL_UNAVAILABLE without ever observing a password.
func (e *recordingExecutor) Check(ctx context.Context, plan domain.CredentialAccessTestPlan, attempt int, fetch func(context.Context) ([]byte, error)) domain.CredentialAccessTestResult {
	e.mu.Lock()
	e.plan = plan
	e.callCount++
	block := e.block
	e.mu.Unlock()
	digest, _ := domain.CredentialAccessTestPlanDigest(plan)
	now := time.Now().UTC()
	password, err := fetch(ctx)
	if err != nil {
		return domain.CredentialAccessTestResult{SchemaVersion: 1, TestID: plan.TestID, Attempt: attempt, PlanDigest: digest.String(), Outcome: domain.CredentialAccessCredentialUnavailable, Summary: "fixture fetch failed", StartedAt: now, CompletedAt: now, Checks: []domain.CredentialAccessCheck{}}
	}
	e.mu.Lock()
	e.received = append([]byte(nil), password...)
	e.mu.Unlock()
	clear(password)
	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
		}
	}
	outcome := e.outcome
	if ctx.Err() != nil {
		outcome = domain.CredentialAccessCancelled
	}
	completed := time.Now().UTC()
	result := domain.CredentialAccessTestResult{SchemaVersion: 1, TestID: plan.TestID, Attempt: attempt, PlanDigest: digest.String(), Outcome: outcome, Summary: "fixture outcome " + string(outcome), StartedAt: now, CompletedAt: completed, Checks: []domain.CredentialAccessCheck{}}
	if outcome.Success() {
		result.DevicesListed = 4
		result.BCMVersion = "10.24"
	}
	return result
}

func workerPlan() domain.CredentialAccessTestPlan {
	now := time.Now().UTC()
	return domain.CredentialAccessTestPlan{SchemaVersion: 1, TestID: "ctest_worker", ClusterID: "cluster-1", Operation: domain.CredentialAccessTestOperation, Host: "head-1", Purpose: domain.CredentialAccessTestPurpose, Username: "fixture_user_1", CredentialID: "cred_worker", CredentialVersion: 3, RequestedAt: now, Deadline: now.Add(5 * time.Minute), Limits: domain.CredentialAccessTestLimits{TimeoutSeconds: 10, MaxOutputBytes: 4096}}
}

func newWorkerFixture(t *testing.T, control *fakeCredentialControl, executor *recordingExecutor) (*CredentialTestWorker, *bytes.Buffer) {
	t.Helper()
	server := httptest.NewServer(control.handler(t))
	t.Cleanup(server.Close)
	client, err := NewHTTPClient(server.URL, server.Client(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	logs := &bytes.Buffer{}
	worker, err := NewCredentialTestWorker(CredentialTestWorkerConfig{CollectorID: "collector-1", ClaimWait: time.Second, RenewInterval: 20 * time.Millisecond, BackoffMinimum: 10 * time.Millisecond, BackoffMaximum: 50 * time.Millisecond, Logger: slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))}, client, executor, fakeRuntimeClock{})
	if err != nil {
		t.Fatal(err)
	}
	return worker, logs
}

type fakeRuntimeClock struct{}

func (fakeRuntimeClock) Now() time.Time { return time.Now().UTC() }

func TestCredentialTestWorkerRunsClaimDeliverCheckSubmitWithoutLeakingSecret(t *testing.T) {
	control := &fakeCredentialControl{plan: workerPlan(), stalled: make(chan struct{})}
	stalled := control.stalled
	executor := &recordingExecutor{outcome: domain.CredentialAccessVerified}
	worker, logs := newWorkerFixture(t, control, executor)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- worker.Run(ctx) }()
	select {
	case <-stalled:
	case <-time.After(10 * time.Second):
		t.Fatal("worker did not submit a result")
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("worker stop error: %v", err)
	}
	control.mu.Lock()
	defer control.mu.Unlock()
	if !control.started || control.deliveries != 1 || len(control.results) != 1 || control.results[0].Outcome != domain.CredentialAccessVerified {
		t.Fatalf("unexpected control state started=%v deliveries=%d results=%+v", control.started, control.deliveries, control.results)
	}
	executor.mu.Lock()
	defer executor.mu.Unlock()
	if string(executor.received) != workerCanary || executor.plan.TestID != "ctest_worker" {
		t.Fatalf("executor received wrong secret/plan: %q %+v", executor.received, executor.plan)
	}
	if strings.Contains(logs.String(), workerCanary) {
		t.Fatalf("logs leaked the secret: %s", logs.String())
	}
	if !strings.Contains(logs.String(), `"outcome":"BCM_ACCESS_VERIFIED"`) {
		t.Fatalf("completion was not logged: %s", logs.String())
	}
	encoded, _ := json.Marshal(control.results[0])
	if strings.Contains(string(encoded), workerCanary) {
		t.Fatal("result document leaked the secret")
	}
	order := strings.Join(control.requests, "\n")
	if !strings.Contains(order, "/start") || strings.Index(order, "/start") > strings.Index(order, "attempts/1/credential") || strings.Index(order, "attempts/1/credential") > strings.Index(order, "/result") {
		t.Fatalf("unexpected request order:\n%s", order)
	}
}

func TestCredentialTestWorkerStopsWhenDeliveryIsRefusedAndReportsTransientFailure(t *testing.T) {
	refused := &fakeCredentialControl{plan: workerPlan(), refuse: 5}
	executor := &recordingExecutor{outcome: domain.CredentialAccessVerified}
	worker, logs := newWorkerFixture(t, refused, executor)
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	_ = worker.Run(ctx)
	refused.mu.Lock()
	if len(refused.results) != 0 || refused.deliveries != 0 {
		t.Fatalf("refused delivery must not produce a result: %+v", refused.results)
	}
	refused.mu.Unlock()
	executor.mu.Lock()
	if executor.callCount == 0 {
		t.Fatal("with the new order the executor must still be invoked; only its fetch fails")
	}
	if len(executor.received) != 0 {
		t.Fatalf("no password may ever be observed when delivery is refused: %q", executor.received)
	}
	executor.mu.Unlock()
	if !strings.Contains(logs.String(), "delivery_refused") {
		t.Fatalf("refusal was not logged: %s", logs.String())
	}
}

func TestCredentialTestWorkerCancelsExecutionOnShutdownAndKeepsRenewingWhileRunning(t *testing.T) {
	control := &fakeCredentialControl{plan: workerPlan()}
	executor := &recordingExecutor{outcome: domain.CredentialAccessVerified, block: make(chan struct{})}
	worker, _ := newWorkerFixture(t, control, executor)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- worker.Run(ctx) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		control.mu.Lock()
		renewals := control.renewals
		control.mu.Unlock()
		if renewals >= 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("lease was not renewed during execution")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("worker stop error: %v", err)
	}
	control.mu.Lock()
	defer control.mu.Unlock()
	for _, result := range control.results {
		if result.Outcome != domain.CredentialAccessCancelled {
			t.Fatalf("a result submitted after shutdown must be CANCELLED, got %s", result.Outcome)
		}
	}
}
