package domain

import (
	"testing"
	"time"
)

func TestDiagnosticApprovalIsActionSpecificAndExpiring(t *testing.T) {
	now := time.Date(2026, 8, 20, 1, 0, 0, 0, time.UTC)
	request := validDiagnosticRequest(now)
	run, err := NewDiagnosticRun(request, true)
	if err != nil {
		t.Fatal(err)
	}
	approval := DiagnosticApproval{
		ApprovalID: "approval-1", RunID: request.RunID, DefinitionDigest: request.Definition.DefinitionDigest,
		TargetDigest: DiagnosticTargetsDigest(request.Targets), ApprovedBy: "operator-1",
		ApprovedAt: now, ExpiresAt: now.Add(5 * time.Minute), RunVersion: run.Version(),
	}
	approved, err := run.Approve(approval, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if approved.Status() != DiagnosticQueued {
		t.Fatalf("status = %s", approved.Status())
	}
	approval.TargetDigest = ChecksumSHA256([]byte("different"))
	if _, err := run.Approve(approval, now); err == nil {
		t.Fatal("expected mismatched target rejection")
	}
	approval.TargetDigest = DiagnosticTargetsDigest(request.Targets)
	if _, err := run.Approve(approval, now.Add(6*time.Minute)); err == nil {
		t.Fatal("expected expired approval rejection")
	}
}

func TestDiagnosticCompletionRequiresExactTargetCoverage(t *testing.T) {
	now := time.Date(2026, 8, 20, 1, 0, 0, 0, time.UTC)
	run, err := NewDiagnosticRun(validDiagnosticRequest(now), false)
	if err != nil {
		t.Fatal(err)
	}
	run, err = run.Start()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := run.Complete([]DiagnosticTargetResult{{Target: "node-1", Status: DiagnosticTargetSucceeded}}); err == nil {
		t.Fatal("expected missing target rejection")
	}
	completed, err := run.Complete([]DiagnosticTargetResult{
		{Target: "node-1", Status: DiagnosticTargetSucceeded},
		{Target: "node-2", Status: DiagnosticTargetFailed, ErrorCode: "EXIT_NONZERO"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if completed.Status() != DiagnosticPartial {
		t.Fatalf("status = %s", completed.Status())
	}
}

func TestDiagnosticRequestRejectsDuplicateAndCredentialShapedArgumentNames(t *testing.T) {
	request := validDiagnosticRequest(time.Now().UTC())
	request.Targets = append(request.Targets, request.Targets[0])
	if err := request.Validate(); err == nil {
		t.Fatal("expected duplicate target rejection")
	}
	request = validDiagnosticRequest(time.Now().UTC())
	request.Arguments = []DiagnosticArgument{{Name: "password", Value: "do-not-store"}}
	if err := request.Validate(); err == nil {
		t.Fatal("expected credential argument rejection")
	}
}

func TestDiagnosticRetryFailsClosedAfterAnyTargetSucceeded(t *testing.T) {
	result := DiagnosticAttemptResult{Attempt: 1, Targets: []DiagnosticTargetResult{
		{Target: "node-1", Status: DiagnosticTargetSucceeded},
		{Target: "node-2", Status: DiagnosticTargetTimedOut, Retryable: true, TimedOut: true},
	}}
	if result.CanRetry(2) {
		t.Fatal("whole-work retry would repeat the successful target")
	}
	result.Targets[0] = DiagnosticTargetResult{Target: "node-1", Status: DiagnosticTargetFailed, Retryable: true}
	if !result.CanRetry(2) {
		t.Fatal("all-target retryable failure should permit a bounded retry")
	}
}

func validDiagnosticRequest(now time.Time) DiagnosticRequest {
	return DiagnosticRequest{
		RunID: "diagnostic-run-1", ClusterID: "cluster-1", RequestedBy: "actor-1", IdempotencyKey: "request-1",
		Definition: DiagnosticDefinitionRef{PackID: "base", PackVersion: "1.0.0", DefinitionID: "gpu-query", DefinitionVersion: "1.0.0", DefinitionDigest: ChecksumSHA256([]byte("definition"))},
		Privilege:  DiagnosticPrivileged, Targets: []DiagnosticTarget{"node-1", "node-2"},
		Arguments: []DiagnosticArgument{{Name: "query", Value: "temperature"}}, RequestedAt: now, Deadline: now.Add(10 * time.Minute), MaxAttempts: 2,
	}
}
