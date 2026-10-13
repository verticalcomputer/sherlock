package collectorruntime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/diagnosticrunner"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

// The client is the collector half of the head-node loop, so it must satisfy
// the port that loop consumes. Proving it here keeps the two halves from
// drifting apart in a way only the wiring in cmd/ would reveal.
var _ diagnosticrunner.DiagnosticWorkSource = (*DiagnosticWorkClient)(nil)

const diagnosticLeaseToken = "0123456789abcdef0123456789abcdef"

func diagnosticClaimBody(deadline time.Time) string {
	return fmt.Sprintf(`{
		"work_id": "work-1",
		"attempt": 1,
		"lease_token": %q,
		"lease_expires_at": %q,
		"invocation": {
			"run_id": "run-1",
			"cluster_id": "pilot-cluster",
			"definition": {
				"pack_id": "standard.readonly",
				"pack_version": "1.1.0",
				"definition_id": "gpu.ecc_counters",
				"definition_version": "1.0.0",
				"definition_sha256": %q
			},
			"privilege": "UNPRIVILEGED",
			"targets": ["comp001", "comp002"],
			"arguments": [],
			"deadline": %q,
			"max_attempts": 1
		}
	}`, diagnosticLeaseToken, deadline.Add(-30*time.Minute).Format(time.RFC3339), strings.Repeat("a", 64), deadline.Format(time.RFC3339))
}

func diagnosticTestClient(t *testing.T, handler http.HandlerFunc) *DiagnosticWorkClient {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	control, err := NewHTTPClient(server.URL, server.Client(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewDiagnosticWorkClient(control, "head-1", 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func recordedAttempt(lease domain.DiagnosticWorkLease) domain.DiagnosticAttemptResult {
	started := lease.LeaseExpires.Add(-time.Minute)
	exitCode := 0
	return domain.DiagnosticAttemptResult{
		WorkID: lease.Work.WorkID, RunID: lease.Work.Run.Request().RunID, Attempt: lease.Attempt, RunnerID: "head-1",
		PlanDigest: domain.ChecksumSHA256([]byte("plan")), StartedAt: started, CompletedAt: started.Add(time.Second),
		Targets: []domain.DiagnosticTargetResult{
			{Target: "comp001", Status: domain.DiagnosticTargetSucceeded, ExitCode: &exitCode, StdoutBytes: 24, StdoutSHA256: domain.ChecksumSHA256([]byte("out")), StdoutExcerpt: "remapped_rows.pending: 0\n", StdoutTransformationState: domain.StdoutTransformationUnmodified},
			{Target: "comp002", Status: domain.DiagnosticTargetRejected, ErrorCode: "NO_RESULT_REPORTED"},
		},
	}
}

// The claim carries a definition by reference. Everything the head node needs
// to execute must survive the mapping, and the reconstructed request must be
// valid on its own terms, because the domain validates it as a whole.
func TestClaimDiagnosticWorkMapsTheInvocationOntoAValidLease(t *testing.T) {
	deadline := time.Date(2026, 8, 22, 11, 0, 0, 0, time.UTC)
	client := diagnosticTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/collector/v1/diagnostic-work/claim" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		if r.URL.Query().Get("wait_seconds") != "5" {
			t.Errorf("wait_seconds = %q", r.URL.Query().Get("wait_seconds"))
		}
		if r.Header.Get(protocolHeader) != "1" || r.Header.Get(correlationHeader) == "" {
			t.Error("protocol or correlation header missing")
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, diagnosticClaimBody(deadline))
	})

	lease, found, err := client.ClaimDiagnosticWork(context.Background(), 5*time.Second)
	if err != nil || !found {
		t.Fatalf("found=%t err=%v", found, err)
	}
	if lease.Work.WorkID != "work-1" || lease.Attempt != 1 || lease.LeaseToken != diagnosticLeaseToken || lease.RunnerID != "head-1" {
		t.Fatalf("lease identity = %+v", lease)
	}
	request := lease.Work.Run.Request()
	if err := request.Validate(); err != nil {
		t.Fatalf("the reconstructed request is not valid: %v", err)
	}
	if request.RunID != "run-1" || request.ClusterID != "pilot-cluster" || request.Privilege != domain.DiagnosticUnprivileged {
		t.Fatalf("request identity = %+v", request)
	}
	if request.Definition.DefinitionID != "gpu.ecc_counters" || request.Definition.DefinitionDigest.String() != strings.Repeat("a", 64) {
		t.Fatalf("definition reference = %+v", request.Definition)
	}
	if len(request.Targets) != 2 || request.Targets[0] != "comp001" || request.Targets[1] != "comp002" {
		t.Fatalf("targets = %v", request.Targets)
	}
	if !request.Deadline.Equal(deadline) {
		t.Fatalf("deadline = %s, want %s", request.Deadline, deadline)
	}
}

// An empty queue is a successful exchange, and must leave the client free to
// claim again rather than looking like an outstanding lease.
func TestClaimDiagnosticWorkReportsAnEmptyQueueWithoutHoldingALease(t *testing.T) {
	calls := 0
	client := diagnosticTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusNoContent)
	})
	for range 2 {
		lease, found, err := client.ClaimDiagnosticWork(context.Background(), 5*time.Second)
		if err != nil || found {
			t.Fatalf("found=%t err=%v lease=%+v", found, err, lease)
		}
	}
	if calls != 2 {
		t.Fatalf("calls = %d, want the client free to poll again", calls)
	}
	if _, outstanding := client.Outstanding(); outstanding {
		t.Fatal("an empty claim left a lease outstanding")
	}
}

// A collector authorized to poll metrics is not thereby authorized to execute.
// The refusal must stay distinguishable from an empty queue, or a head node
// that is not permitted to run anything looks exactly like an idle one.
func TestClaimDiagnosticWorkClassifiesAForbiddenCollector(t *testing.T) {
	client := diagnosticTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})
	_, found, err := client.ClaimDiagnosticWork(context.Background(), 5*time.Second)
	if found || !errors.Is(err, ErrDiagnosticExecutionForbidden) {
		t.Fatalf("found=%t err=%v, want a forbidden-execution refusal", found, err)
	}
	if _, outstanding := client.Outstanding(); outstanding {
		t.Fatal("a refused claim left a lease outstanding")
	}
}

func TestRecordDiagnosticAttemptSendsTheAttemptContractAndReleasesTheLease(t *testing.T) {
	deadline := time.Date(2026, 8, 22, 11, 0, 0, 0, time.UTC)
	var body map[string]any
	client := diagnosticTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			fmt.Fprint(w, diagnosticClaimBody(deadline))
			return
		}
		if r.URL.Path != "/collector/v1/diagnostic-work/work-1/attempts/1/results" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		fmt.Fprint(w, `{"run_id":"run-1","status":"PARTIAL","recorded":true}`)
	})

	lease, found, err := client.ClaimDiagnosticWork(context.Background(), 5*time.Second)
	if err != nil || !found {
		t.Fatalf("found=%t err=%v", found, err)
	}
	if err := client.RecordDiagnosticAttempt(context.Background(), lease, recordedAttempt(lease)); err != nil {
		t.Fatalf("recording failed: %v", err)
	}
	if body["lease_token"] != diagnosticLeaseToken || body["run_id"] != "run-1" || body["runner_id"] != "head-1" {
		t.Fatalf("attempt attribution = %+v", body)
	}
	if digest, _ := body["plan_sha256"].(string); len(digest) != 64 {
		t.Fatalf("plan digest = %v", body["plan_sha256"])
	}
	targets, _ := body["targets"].([]any)
	if len(targets) != 2 {
		t.Fatalf("targets = %v", body["targets"])
	}
	first, _ := targets[0].(map[string]any)
	if first["target"] != "comp001" || first["status"] != "SUCCEEDED" || first["exit_code"] != float64(0) {
		t.Fatalf("first target = %+v", first)
	}
	// The excerpt is what makes a diagnostic reach the model as a result rather
	// than as proof that a check ran.
	if first["stdout_excerpt"] != "remapped_rows.pending: 0\n" {
		t.Fatalf("the probe output did not cross the boundary: %+v", first)
	}
	if first["stdout_transformation_state"] != "UNMODIFIED" {
		t.Fatalf("producer proof did not cross collector transport: %+v", first)
	}
	second, _ := targets[1].(map[string]any)
	if second["error_code"] != "NO_RESULT_REPORTED" || second["stderr_sha256"] != strings.Repeat("0", 64) {
		t.Fatalf("second target = %+v", second)
	}
	if second["stdout_transformation_state"] != "UNKNOWN" {
		t.Fatalf("unreported target gained proof: %+v", second)
	}
	if _, outstanding := client.Outstanding(); outstanding {
		t.Fatal("a recorded attempt left its lease outstanding")
	}
}

func TestRestartedDiagnosticClientSubmitsJournaledResultWithoutLocalLease(t *testing.T) {
	deadline := time.Date(2026, 8, 22, 11, 0, 0, 0, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			fmt.Fprint(w, diagnosticClaimBody(deadline))
			return
		}
		fmt.Fprint(w, `{"run_id":"run-1","status":"PARTIAL","recorded":false}`)
	}))
	defer server.Close()
	control, err := NewHTTPClient(server.URL, server.Client(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	claiming, err := NewDiagnosticWorkClient(control, "head-1", 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	lease, found, err := claiming.ClaimDiagnosticWork(context.Background(), 5*time.Second)
	if err != nil || !found {
		t.Fatalf("claim found=%t err=%v", found, err)
	}
	restarted, err := NewDiagnosticWorkClient(control, "head-1", 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, outstanding := restarted.Outstanding(); outstanding {
		t.Fatal("new client unexpectedly inherited process-local lease state")
	}
	if err := restarted.RecordDiagnosticAttempt(context.Background(), lease, recordedAttempt(lease)); err != nil {
		t.Fatalf("restarted client refused journaled result: %v", err)
	}
}

// One head node executes one diagnostic at a time. A second claim would strand
// the first lease until it expired, with the investigation that dispatched it
// parked for that whole window.
func TestClaimDiagnosticWorkRefusesASecondConcurrentLease(t *testing.T) {
	deadline := time.Date(2026, 8, 22, 11, 0, 0, 0, time.UTC)
	client := diagnosticTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, diagnosticClaimBody(deadline))
	})
	lease, found, err := client.ClaimDiagnosticWork(context.Background(), 5*time.Second)
	if err != nil || !found {
		t.Fatalf("found=%t err=%v", found, err)
	}
	if _, _, err := client.ClaimDiagnosticWork(context.Background(), 5*time.Second); !errors.Is(err, ErrDiagnosticWorkOutstanding) {
		t.Fatalf("a second claim returned %v, want a refusal while a lease is outstanding", err)
	}
	if held, outstanding := client.Outstanding(); !outstanding || held.LeaseToken != lease.LeaseToken {
		t.Fatalf("the outstanding lease was disturbed: %+v", held)
	}
}

func TestRecordDiagnosticAttemptDefersLeaseAuthorizationToControlPlane(t *testing.T) {
	calls := 0
	client := diagnosticTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method == http.MethodGet {
			fmt.Fprint(w, diagnosticClaimBody(time.Date(2026, 8, 22, 11, 0, 0, 0, time.UTC)))
			return
		}
		w.WriteHeader(http.StatusConflict)
	})
	lease, _, err := client.ClaimDiagnosticWork(context.Background(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	claimCalls := calls

	foreign := lease
	foreign.LeaseToken = strings.Repeat("f", 32)
	if err := client.RecordDiagnosticAttempt(context.Background(), foreign, recordedAttempt(lease)); !errors.Is(err, diagnosticrunner.ErrDiagnosticLeaseLost) {
		t.Fatalf("recording under a foreign token returned %v", err)
	}
	if calls != claimCalls+1 {
		t.Fatal("process-local state prevented durable lease authorization")
	}
	if _, outstanding := client.Outstanding(); !outstanding {
		t.Fatal("a refused attempt released the lease it did not match")
	}
}

// Recording can fail after the command has already run. Holding the lease then
// would stop the head node claiming anything ever again, which is worse than
// releasing a lease the control plane will expire on its own.
func TestRecordDiagnosticAttemptReleasesTheLeaseEvenWhenRecordingFails(t *testing.T) {
	client := diagnosticTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			fmt.Fprint(w, diagnosticClaimBody(time.Date(2026, 8, 22, 11, 0, 0, 0, time.UTC)))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	})
	lease, _, err := client.ClaimDiagnosticWork(context.Background(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.RecordDiagnosticAttempt(context.Background(), lease, recordedAttempt(lease)); err == nil {
		t.Fatal("a failed recording was reported as success")
	}
	if _, outstanding := client.Outstanding(); outstanding {
		t.Fatal("a failed recording stranded the lease")
	}
}

// An incoherent claim is refused rather than executed. A definition digest the
// head node cannot read is exactly the case where it must not guess.
func TestClaimDiagnosticWorkRefusesAnIncoherentInvocation(t *testing.T) {
	client := diagnosticTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		body := diagnosticClaimBody(time.Date(2026, 8, 22, 11, 0, 0, 0, time.UTC))
		fmt.Fprint(w, strings.Replace(body, strings.Repeat("a", 64), "not-a-digest", 1))
	})
	if _, found, err := client.ClaimDiagnosticWork(context.Background(), 5*time.Second); found || err == nil {
		t.Fatalf("found=%t err=%v, want the claim refused", found, err)
	}
	if _, outstanding := client.Outstanding(); outstanding {
		t.Fatal("a refused claim left a lease outstanding")
	}
}
