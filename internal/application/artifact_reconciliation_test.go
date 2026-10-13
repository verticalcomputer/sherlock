package application

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

func TestArtifactReconcilerNilReceiverFailsClosed(t *testing.T) {
	var reconciler *ArtifactReconciler
	if _, err := reconciler.Run(context.Background(), time.Now()); err == nil {
		t.Fatal("nil artifact reconciler succeeded")
	}
}

func TestArtifactReconcilerRecordsBoundedConditionsAndRecovery(t *testing.T) {
	payload := []byte("fixture")
	reference, err := domain.NewArtifactReference(domain.ChecksumSHA256(payload), int64(len(payload)), "text/plain", domain.ArtifactUncompressed, "parser-v1", domain.RedactionSummary{PolicyVersion: "redaction-v1"}, domain.ArtifactRetentionStandard)
	if err != nil {
		t.Fatal(err)
	}
	store := &reconciliationStoreFake{candidates: []ArtifactReconciliationCandidate{
		{EvidenceID: "ev-missing", Reference: reference, Condition: domain.ArtifactPending},
		{EvidenceID: "ev-recovered", Reference: reference, Condition: domain.ArtifactUnavailable},
		{EvidenceID: "ev-corrupt", Reference: reference, Condition: domain.ArtifactCorrupt},
	}}
	checker := &reconciliationCheckerFake{conditions: []domain.ArtifactAvailability{domain.ArtifactUnavailable, domain.ArtifactAvailable, domain.ArtifactCorrupt}}
	reconciler, err := NewArtifactReconciler(store, checker, 5*time.Minute, 25)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 20, 1, 2, 3, 0, time.UTC)
	result, err := reconciler.Run(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	if result.Checked != 3 || result.Changed != 2 || result.Available != 1 || result.Unavailable != 1 || result.Corrupt != 1 {
		t.Fatalf("unexpected result: %+v", result)
	}
	if !store.before.Equal(now.Add(-5*time.Minute)) || store.limit != 25 {
		t.Fatalf("query bounds before=%s limit=%d", store.before, store.limit)
	}
	if len(store.updates) != 3 || store.updates[0] != domain.ArtifactUnavailable || store.updates[1] != domain.ArtifactAvailable || store.updates[2] != domain.ArtifactCorrupt {
		t.Fatalf("updates=%v", store.updates)
	}
}

func TestArtifactReconcilerRejectsInvalidCheckerStateAndPropagatesContext(t *testing.T) {
	reference, _ := domain.NewArtifactReference(domain.ChecksumSHA256(nil), 0, "text/plain", domain.ArtifactUncompressed, "parser-v1", domain.RedactionSummary{PolicyVersion: "redaction-v1"}, domain.ArtifactRetentionShort)
	store := &reconciliationStoreFake{candidates: []ArtifactReconciliationCandidate{{EvidenceID: "ev-1", Reference: reference, Condition: domain.ArtifactPending}}}
	reconciler, _ := NewArtifactReconciler(store, &reconciliationCheckerFake{conditions: []domain.ArtifactAvailability{domain.ArtifactPending}}, 0, 1)
	result, err := reconciler.Run(context.Background(), time.Now())
	if err == nil {
		t.Fatal("pending checker result was accepted")
	}
	if result.Failures != 1 {
		t.Fatalf("failures=%d, want 1", result.Failures)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	store.err = ctx.Err()
	if _, err := reconciler.Run(ctx, time.Now()); !errors.Is(err, context.Canceled) {
		t.Fatalf("context error=%v", err)
	}
}

func TestArtifactReconcilerContinuesAfterTransientCandidateFailure(t *testing.T) {
	reference, _ := domain.NewArtifactReference(domain.ChecksumSHA256(nil), 0, "text/plain", domain.ArtifactUncompressed, "parser-v1", domain.RedactionSummary{PolicyVersion: "redaction-v1"}, domain.ArtifactRetentionShort)
	store := &reconciliationStoreFake{candidates: []ArtifactReconciliationCandidate{
		{EvidenceID: "ev-failed", Reference: reference, Condition: domain.ArtifactPending},
		{EvidenceID: "ev-healthy", Reference: reference, Condition: domain.ArtifactPending},
	}}
	checker := &reconciliationCheckerFake{
		conditions: []domain.ArtifactAvailability{"", domain.ArtifactAvailable},
		errors:     []error{errors.New("temporary storage error"), nil},
	}
	reconciler, _ := NewArtifactReconciler(store, checker, 0, 2)

	result, err := reconciler.Run(context.Background(), time.Now())
	if err == nil {
		t.Fatal("candidate failure was not reported")
	}
	if result.Failures != 1 || result.Checked != 1 || result.Available != 1 || len(store.updates) != 1 {
		t.Fatalf("unexpected partial result: %+v updates=%v", result, store.updates)
	}
}

type reconciliationStoreFake struct {
	candidates []ArtifactReconciliationCandidate
	err        error
	before     time.Time
	limit      int
	updates    []domain.ArtifactAvailability
}

func (store *reconciliationStoreFake) ListArtifactReconciliationCandidates(_ context.Context, before time.Time, limit int) ([]ArtifactReconciliationCandidate, error) {
	store.before, store.limit = before, limit
	return store.candidates, store.err
}
func (store *reconciliationStoreFake) SetArtifactAvailability(_ context.Context, _ domain.EvidenceID, _ domain.ArtifactID, condition domain.ArtifactAvailability) error {
	store.updates = append(store.updates, condition)
	return nil
}

type reconciliationCheckerFake struct {
	conditions []domain.ArtifactAvailability
	errors     []error
	next       int
}

func (checker *reconciliationCheckerFake) Check(context.Context, domain.ArtifactReference) (domain.ArtifactAvailability, error) {
	condition := checker.conditions[checker.next]
	var err error
	if len(checker.errors) > checker.next {
		err = checker.errors[checker.next]
	}
	checker.next++
	return condition, err
}
