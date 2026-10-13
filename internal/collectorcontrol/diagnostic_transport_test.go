package collectorcontrol

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

type fakeDiagnosticOperations struct {
	lease      domain.DiagnosticWorkLease
	available  bool
	permitted  bool
	claims     int
	recorded   []domain.DiagnosticAttemptResult
	status     domain.DiagnosticRunStatus
	wasNew     bool
	tokens     []string
	clusters   []domain.ClusterID
	collectors []domain.CollectorID
}

func (fake *fakeDiagnosticOperations) ClaimDiagnosticWork(_ context.Context, clusterID domain.ClusterID, collectorID domain.CollectorID, token string, _ time.Duration) (domain.DiagnosticWorkLease, bool, error) {
	fake.claims++
	fake.tokens = append(fake.tokens, token)
	fake.clusters = append(fake.clusters, clusterID)
	fake.collectors = append(fake.collectors, collectorID)
	if !fake.permitted {
		return domain.DiagnosticWorkLease{}, false, ErrDiagnosticExecutionNotPermitted
	}
	if !fake.available {
		return domain.DiagnosticWorkLease{}, false, nil
	}
	lease := fake.lease
	lease.LeaseToken = token
	return lease, true, nil
}

func (fake *fakeDiagnosticOperations) RecordDiagnosticAttempt(_ context.Context, clusterID domain.ClusterID, collectorID domain.CollectorID, _ domain.DiagnosticWorkID, _ int, _ string, result domain.DiagnosticAttemptResult) (domain.DiagnosticRunStatus, bool, error) {
	if !fake.permitted {
		return "", false, ErrDiagnosticExecutionNotPermitted
	}
	fake.recorded = append(fake.recorded, result)
	fake.clusters = append(fake.clusters, clusterID)
	fake.collectors = append(fake.collectors, collectorID)
	return fake.status, fake.wasNew, nil
}

func diagnosticLease(t *testing.T) domain.DiagnosticWorkLease {
	t.Helper()
	now := time.Date(2026, 8, 22, 10, 0, 0, 0, time.UTC)
	request := domain.DiagnosticRequest{
		RunID: "run-1", ClusterID: "cluster-1",
		Definition:  domain.DiagnosticDefinitionRef{PackID: "standard.readonly", PackVersion: "1.1.0", DefinitionID: "gpu.ecc_counters", DefinitionVersion: "1.0.0", DefinitionDigest: domain.ChecksumSHA256([]byte("definition"))},
		Privilege:   domain.DiagnosticUnprivileged,
		Targets:     []domain.DiagnosticTarget{"comp001"},
		RequestedBy: "investigator", IdempotencyKey: "key-1", RequestedAt: now, Deadline: now.Add(10 * time.Minute), MaxAttempts: 1,
	}
	run, err := domain.NewDiagnosticRun(request, false)
	if err != nil {
		t.Fatal(err)
	}
	return domain.DiagnosticWorkLease{Work: domain.DiagnosticWork{WorkID: "work-1", Run: run, Deadline: request.Deadline, MaxAttempts: 1}, Attempt: 1, RunnerID: "head-1", LeaseExpires: now.Add(time.Minute)}
}

func newDiagnosticTransport(t *testing.T, operations *fakeDiagnosticOperations) *Transport {
	t.Helper()
	transport, _, _, _, _ := newTestTransport(t)
	if err := transport.ConfigureDiagnosticWork(operations); err != nil {
		t.Fatal(err)
	}
	return transport
}

// The claim response must carry the invocation by reference only. The argv is
// resolved by the runner from the pack it verifies itself, so a control plane
// that transmitted a command would be a command-injection surface.
func TestDiagnosticClaimTransmitsAReferenceAndNeverACommand(t *testing.T) {
	operations := &fakeDiagnosticOperations{lease: diagnosticLease(t), available: true, permitted: true}
	transport := newDiagnosticTransport(t, operations)
	response := httptest.NewRecorder()
	transport.ServeHTTP(response, collectorRequest(http.MethodGet, "/collector/v1/diagnostic-work/claim?wait_seconds=0", "", true))
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, forbidden := range []string{"nvidia-smi", "argv", "--query-gpu", "executable", "sudo"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("the claim response carries %q: %s", forbidden, body)
		}
	}
	var claim diagnosticClaimResponseDTO
	if err := json.Unmarshal(response.Body.Bytes(), &claim); err != nil {
		t.Fatal(err)
	}
	if claim.WorkID != "work-1" || claim.Attempt != 1 || claim.LeaseToken == "" {
		t.Fatalf("claim = %+v", claim)
	}
	if claim.Invocation.Definition.DefinitionID != "gpu.ecc_counters" || claim.Invocation.Definition.DefinitionSHA256 == "" {
		t.Fatalf("invocation = %+v", claim.Invocation)
	}
	if claim.Invocation.Privilege != "UNPRIVILEGED" || len(claim.Invocation.Targets) != 1 {
		t.Fatalf("invocation = %+v", claim.Invocation)
	}
	// The lease token is server-generated, never supplied by the collector.
	if operations.tokens[0] != claim.LeaseToken {
		t.Fatal("the transport did not issue the lease token it returned")
	}
	if operations.clusters[0] != "cluster-1" || operations.collectors[0] != "collector-1" {
		t.Fatalf("authenticated scope was dropped: clusters=%v collectors=%v", operations.clusters, operations.collectors)
	}
}

func TestDiagnosticClaimRefusesAnOperationReturningAnotherCluster(t *testing.T) {
	lease := diagnosticLease(t)
	request := lease.Work.Run.Request()
	request.ClusterID = "cluster-b"
	run, err := domain.ReconstituteDiagnosticRun(request, domain.DiagnosticRunning, lease.Work.Run.Version())
	if err != nil {
		t.Fatal(err)
	}
	lease.Work.Run = run
	operations := &fakeDiagnosticOperations{lease: lease, available: true, permitted: true}
	transport := newDiagnosticTransport(t, operations)
	response := httptest.NewRecorder()
	transport.ServeHTTP(response, collectorRequest(http.MethodGet, "/collector/v1/diagnostic-work/claim?wait_seconds=0", "", true))
	if response.Code != http.StatusForbidden {
		t.Fatalf("cross-cluster lease status=%d body=%s", response.Code, response.Body.String())
	}
}

// A collector authorized to poll metrics is not thereby authorized to execute
// commands, and the refusal must be explicit rather than an empty claim.
func TestDiagnosticClaimIsRefusedForACollectorWithoutExecutionAuthority(t *testing.T) {
	operations := &fakeDiagnosticOperations{lease: diagnosticLease(t), available: true, permitted: false}
	transport := newDiagnosticTransport(t, operations)
	response := httptest.NewRecorder()
	transport.ServeHTTP(response, collectorRequest(http.MethodGet, "/collector/v1/diagnostic-work/claim?wait_seconds=0", "", true))
	if response.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

// A control plane that never configures diagnostic work must expose no
// execution surface at all.
func TestUnconfiguredDiagnosticEndpointsAreAbsent(t *testing.T) {
	transport, _, _, _, _ := newTestTransport(t)
	response := httptest.NewRecorder()
	transport.ServeHTTP(response, collectorRequest(http.MethodGet, "/collector/v1/diagnostic-work/claim?wait_seconds=0", "", true))
	if response.Code != http.StatusNotFound {
		t.Fatalf("an unconfigured control plane exposed an execution surface: status=%d", response.Code)
	}
}

// Recording carries per-target exit codes and output digests, which is the
// structure a collection result cannot express and evidence projection needs.
func TestDiagnosticAttemptRecordsPerTargetResults(t *testing.T) {
	operations := &fakeDiagnosticOperations{lease: diagnosticLease(t), available: true, permitted: true, status: domain.DiagnosticSucceeded, wasNew: true}
	transport := newDiagnosticTransport(t, operations)
	body := `{"lease_token":"` + strings.Repeat("t", 32) + `","run_id":"run-1","runner_id":"head-1","plan_sha256":"` + strings.Repeat("a", 64) + `","started_at":"2026-08-22T10:00:00Z","completed_at":"2026-08-22T10:00:02Z","targets":[{"target":"comp001","status":"SUCCEEDED","retryable":false,"exit_code":0,"timed_out":false,"stdout_truncated":false,"stderr_truncated":false,"stdout_bytes":256,"stderr_bytes":0,"stdout_sha256":"` + strings.Repeat("b", 64) + `","stderr_sha256":"` + strings.Repeat("0", 64) + `"}]}`
	response := httptest.NewRecorder()
	transport.ServeHTTP(response, collectorRequest(http.MethodPost, "/collector/v1/diagnostic-work/work-1/attempts/1/results", body, true))
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if len(operations.recorded) != 1 {
		t.Fatalf("recorded = %d", len(operations.recorded))
	}
	if operations.clusters[0] != "cluster-1" || operations.collectors[0] != "collector-1" {
		t.Fatalf("authenticated result scope was dropped: clusters=%v collectors=%v", operations.clusters, operations.collectors)
	}
	attempt := operations.recorded[0]
	if attempt.WorkID != "work-1" || attempt.Attempt != 1 || attempt.RunID != "run-1" || attempt.RunnerID != "head-1" {
		t.Fatalf("attempt = %+v", attempt)
	}
	if len(attempt.Targets) != 1 || attempt.Targets[0].Status != domain.DiagnosticTargetSucceeded {
		t.Fatalf("targets = %+v", attempt.Targets)
	}
	if attempt.Targets[0].ExitCode == nil || *attempt.Targets[0].ExitCode != 0 || attempt.Targets[0].StdoutBytes != 256 {
		t.Fatalf("per-target detail lost: %+v", attempt.Targets[0])
	}
	if attempt.Targets[0].StdoutTransformationState != domain.StdoutTransformationUnknown {
		t.Fatalf("legacy collector result gained proof: %s", attempt.Targets[0].StdoutTransformationState)
	}
	var decoded diagnosticAttemptResponseDTO
	if err := json.Unmarshal(response.Body.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.RunID != "run-1" || decoded.Status != "SUCCEEDED" || !decoded.Recorded {
		t.Fatalf("response = %+v", decoded)
	}
}

func TestDiagnosticAttemptRejectsMalformedInput(t *testing.T) {
	operations := &fakeDiagnosticOperations{lease: diagnosticLease(t), available: true, permitted: true}
	transport := newDiagnosticTransport(t, operations)
	valid := `{"lease_token":"` + strings.Repeat("t", 32) + `","run_id":"run-1","runner_id":"head-1","plan_sha256":"` + strings.Repeat("a", 64) + `","started_at":"2026-08-22T10:00:00Z","completed_at":"2026-08-22T10:00:02Z","targets":[{"target":"comp001","status":"SUCCEEDED","retryable":false,"exit_code":0,"timed_out":false,"stdout_truncated":false,"stderr_truncated":false,"stdout_bytes":256,"stderr_bytes":0,"stdout_sha256":"` + strings.Repeat("b", 64) + `","stderr_sha256":"` + strings.Repeat("0", 64) + `"}]}`
	tests := map[string]string{
		"unknown field":       strings.Replace(valid, `"run_id"`, `"argv","run_id"`, 1),
		"bad plan digest":     strings.Replace(valid, strings.Repeat("a", 64), "not-a-digest", 1),
		"missing runner":      strings.Replace(valid, `"runner_id":"head-1"`, `"runner_id":""`, 1),
		"duplicate target":    strings.Replace(valid, `"targets":[`, `"targets":[{"target":"comp001","status":"FAILED","retryable":false,"timed_out":false,"stdout_truncated":false,"stderr_truncated":false,"stdout_bytes":0,"stderr_bytes":0,"stdout_sha256":"`+strings.Repeat("0", 64)+`","stderr_sha256":"`+strings.Repeat("0", 64)+`"},`, 1),
		"no targets reported": strings.Replace(valid, `"targets":[`, `"targets":[],"ignored":[`, 1),
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			response := httptest.NewRecorder()
			transport.ServeHTTP(response, collectorRequest(http.MethodPost, "/collector/v1/diagnostic-work/work-1/attempts/1/results", body, true))
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
	if len(operations.recorded) != 0 {
		t.Fatal("a malformed attempt was recorded")
	}
	for _, fixture := range []struct {
		name, state string
		want        domain.StdoutTransformationState
	}{
		{"legacy", "", domain.StdoutTransformationUnknown},
		{"malformed", "unmodified", domain.StdoutTransformationUnknown},
		{"producer proof", "UNMODIFIED", domain.StdoutTransformationUnmodified},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			var request diagnosticAttemptRequestDTO
			if err := json.Unmarshal([]byte(valid), &request); err != nil {
				t.Fatal(err)
			}
			request.Targets[0].StdoutTransformationState = fixture.state
			result, err := request.toDomain("work-1", 1)
			if err != nil {
				t.Fatal(err)
			}
			if result.Targets[0].StdoutTransformationState != fixture.want {
				t.Fatalf("state = %s, want %s", result.Targets[0].StdoutTransformationState, fixture.want)
			}
		})
	}
}
