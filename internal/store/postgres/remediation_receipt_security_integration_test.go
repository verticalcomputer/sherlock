//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

// TestRemediationReceiptCannotWidenRollbackAuthority proves the receipt store
// derives its target authority from the committed attempt, not from either of
// the caller's two result representations.
func TestRemediationReceiptCannotWidenRollbackAuthority(t *testing.T) {
	fixture := newRemediationFixture(t)
	ctx := context.Background()
	dispatch, dispatchAudit := newRemediationDispatchSecurityInput(t, fixture, fixture.targets[:1], 1, 0)
	committed, err := fixture.store.DispatchRemediationAttempt(ctx, dispatch, dispatchAudit)
	if err != nil {
		t.Fatal(err)
	}
	validReport := domain.RemediationExecutionReport{
		Outcome: domain.ExecutionExecuted, ExecutedTargets: committed.WaveTargets,
		PerTarget: []domain.RemediationTargetOutcome{{Target: committed.WaveTargets[0], Outcome: domain.ExecutionExecuted}},
	}
	verifying, err := dispatch.Run.RecordCanaryOutcome(validReport, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}

	malicious := domain.RemediationReceipt{
		ID:    domain.RemediationReceiptID("remediation-malicious-receipt-" + fixture.suffix),
		RunID: dispatch.Run.Plan().RunID, AttemptID: committed.ID, ClusterID: fixture.clusterID,
		IdempotencyKey: committed.IdempotencyKey, Stage: committed.Stage,
		Targets:   committed.WaveTargets,
		PerTarget: []domain.RemediationTargetOutcome{{Target: fixture.targets[1], Outcome: domain.ExecutionExecuted}},
		Outcome:   domain.ExecutionExecuted, ObservedAt: time.Now().UTC(),
	}
	malicious.Digest = malicious.ComputeDigest()
	receiptInput := application.RemediationReceiptInput{
		ClusterID: fixture.clusterID, AttemptID: committed.ID, LeaseToken: dispatch.LeaseToken,
		Receipt: malicious, Run: verifying, ExpectedVersion: dispatch.Run.Version(),
	}
	audit := fixture.audit(application.RemediationAuditReceipt, dispatch.Run.Plan(), "malicious-receipt")
	audit.AttemptID = committed.ID
	var rejection domain.RemediationReceiptRejection
	if _, err := fixture.store.RecordRemediationReceipt(ctx, receiptInput, audit); !errors.As(err, &rejection) || rejection.Code != domain.ReceiptTargetNotDispatched {
		t.Fatalf("receipt target substitution must be rejected, got %v", err)
	}
	assertNoReceiptOrRollbackAuthority(t, fixture, committed.ID)

	// Even with the exact wave, the supplied aggregate transition cannot describe
	// EXECUTED while the persisted receipt describes FAILED.
	splitBrain := malicious
	splitBrain.ID = domain.RemediationReceiptID("remediation-split-receipt-" + fixture.suffix)
	splitBrain.PerTarget = []domain.RemediationTargetOutcome{{Target: committed.WaveTargets[0], Outcome: domain.ExecutionFailed}}
	splitBrain.Outcome = domain.ExecutionFailed
	splitBrain.Digest = splitBrain.ComputeDigest()
	receiptInput.Receipt = splitBrain
	splitAudit := fixture.audit(application.RemediationAuditReceipt, dispatch.Run.Plan(), "split-receipt")
	splitAudit.AttemptID = committed.ID
	if _, err := fixture.store.RecordRemediationReceipt(ctx, receiptInput, splitAudit); !errors.Is(err, application.ErrRemediationConflict) {
		t.Fatalf("receipt/run split brain must conflict, got %v", err)
	}
	assertNoReceiptOrRollbackAuthority(t, fixture, committed.ID)

	valid := malicious
	valid.ID = domain.RemediationReceiptID("remediation-valid-receipt-" + fixture.suffix)
	valid.PerTarget = validReport.PerTarget
	valid.Digest = valid.ComputeDigest()
	receiptInput.Receipt = valid
	audit = fixture.audit(application.RemediationAuditReceipt, dispatch.Run.Plan(), "valid-receipt")
	audit.AttemptID = committed.ID
	accepted, err := fixture.store.RecordRemediationReceipt(ctx, receiptInput, audit)
	if err != nil {
		t.Fatal(err)
	}

	// Acknowledgement-loss replay remains safe after lease expiry when its result
	// body is identical; a different body using the same attempt/key is rejected.
	if _, err := fixture.pool.Exec(ctx, `UPDATE remediation_attempts SET
		created_at=clock_timestamp()-interval '10 minutes',
		lease_expires_at=clock_timestamp()-interval '2 minutes',
		lease_deadline_at=clock_timestamp()-interval '1 minute'
		WHERE cluster_id=$1 AND attempt_id=$2`, fixture.clusterID, committed.ID); err != nil {
		t.Fatal(err)
	}
	same := receiptInput
	same.Receipt.ID = domain.RemediationReceiptID("remediation-same-replay-" + fixture.suffix)
	sameAudit := fixture.audit(application.RemediationAuditReceipt, dispatch.Run.Plan(), "same-replay")
	sameAudit.AttemptID = committed.ID
	replayed, err := fixture.store.RecordRemediationReceipt(ctx, same, sameAudit)
	if err != nil || !replayed.PreviouslyRecorded || replayed.Receipt.ID != accepted.Receipt.ID {
		t.Fatalf("identical replay after lease expiry must return the recorded receipt: %+v err=%v", replayed, err)
	}

	different := same
	different.Receipt.ID = domain.RemediationReceiptID("remediation-different-replay-" + fixture.suffix)
	different.Receipt.Outcome = domain.ExecutionFailed
	different.Receipt.PerTarget = []domain.RemediationTargetOutcome{{Target: committed.WaveTargets[0], Outcome: domain.ExecutionFailed}}
	differentAudit := fixture.audit(application.RemediationAuditReceipt, dispatch.Run.Plan(), "different-replay")
	differentAudit.AttemptID = committed.ID
	if _, err := fixture.store.RecordRemediationReceipt(ctx, different, differentAudit); !errors.As(err, &rejection) || rejection.Code != domain.ReceiptReplay {
		t.Fatalf("different body reusing an attempt/key must be rejected, got %v", err)
	}
}

func assertNoReceiptOrRollbackAuthority(t *testing.T, fixture remediationFixture, attemptID domain.RemediationAttemptID) {
	t.Helper()
	var receipts, executed int
	if err := fixture.pool.QueryRow(context.Background(), `SELECT count(*) FROM remediation_receipts
		WHERE cluster_id=$1 AND attempt_id=$2`, fixture.clusterID, attemptID).Scan(&receipts); err != nil {
		t.Fatal(err)
	}
	if err := fixture.pool.QueryRow(context.Background(), `SELECT count(*) FROM remediation_receipt_targets t
		JOIN remediation_receipts r USING(cluster_id,receipt_id)
		WHERE r.cluster_id=$1 AND r.attempt_id=$2 AND t.outcome='EXECUTED'`, fixture.clusterID, attemptID).Scan(&executed); err != nil {
		t.Fatal(err)
	}
	if receipts != 0 || executed != 0 {
		t.Fatalf("rejected receipt persisted receipts=%d executed-target-authority=%d", receipts, executed)
	}
}
