package remediationlive

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/remediation"
)

type storeStub struct{ calls int }

func (s *storeStub) RequestCollection(_ context.Context, r Request) (domain.ExecutionResult, error) {
	s.calls++
	return domain.ExecutionResult{Outcome: domain.ExecutionExecuted, ObservedAt: r.Now}, nil
}
func (s *storeStub) CancelCollection(_ context.Context, r Request) (domain.ExecutionResult, error) {
	s.calls++
	return domain.ExecutionResult{Outcome: domain.ExecutionExecuted, ObservedAt: r.Now}, nil
}

func verifiedCatalog(t *testing.T, now time.Time) *remediation.Catalog {
	return verifiedRecipeCatalog(t, now, remediation.CollectionRequestRecipes(now.Add(time.Hour)))
}

func verifiedRecipeCatalog(t *testing.T, now time.Time, recipes []remediation.Recipe) *remediation.Catalog {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	release, err := remediation.SignRecipeRelease(recipes, "root", private)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := remediation.NewRecipeTrustStore([]remediation.RecipeTrustRoot{{ID: "root", Issuer: "test", PublicKey: public, ActivatesAt: now.Add(-time.Hour), RetiresAt: now.Add(2 * time.Hour)}})
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := trust.Verify(release, now)
	if err != nil {
		t.Fatal(err)
	}
	return catalog
}

func validUnit(t *testing.T, catalog *remediation.Catalog, now time.Time) domain.ExecutionUnit {
	t.Helper()
	recipe, found := catalog.Lookup(remediation.RecipeEvidenceCollectionRequeue, remediation.CollectionRequestRecipeVersion)
	if !found {
		t.Fatal("missing requeue recipe")
	}
	return domain.ExecutionUnit{
		RunID: "run-1", AttemptID: "attempt-1", ClusterID: "cluster-1",
		Recipe:    recipe.Ref(),
		Operation: domain.OperationEvidenceCollectionRequeue, Stage: domain.RemediationStageCanary,
		Arguments:      domain.TypedArguments{{Name: "priority", Type: domain.ParameterEnum, Enum: "NORMAL"}, {Name: "requeue_reason", Type: domain.ParameterEnum, Enum: "STALE_STREAM"}},
		IdempotencyKey: "idempotency-1", Deadline: now.Add(time.Minute),
		Targets: []domain.ResolvedTarget{{Target: "job-1", Role: domain.RoleManagedCollectionStream, ClusterID: "cluster-1", ResolvedAt: now, Source: domain.SourceCollectionJobs}},
	}
}

func TestLiveExecutorRejectsSignedHistoricalRecipe(t *testing.T) {
	now := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	legacy := verifiedRecipeCatalog(t, now, remediation.BuiltinRecipes(now.Add(time.Hour)))
	store := &storeStub{}
	executor, err := New(legacy, store)
	if err != nil {
		t.Fatal(err)
	}
	u := validUnit(t, verifiedCatalog(t, now), now)
	recipe, _ := legacy.Lookup(remediation.RecipeEvidenceCollectionRequeue, remediation.BuiltinRecipeVersion)
	u.Recipe = recipe.Ref()
	if _, err := executor.Execute(context.Background(), u, now); err == nil || store.calls != 0 {
		t.Fatalf("historical release reached live store: err=%v calls=%d", err, store.calls)
	}
}

func TestExecutorKeepsLiveScopeClosed(t *testing.T) {
	now := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	store := &storeStub{}
	catalog := verifiedCatalog(t, now)
	executor, err := New(catalog, store)
	if err != nil {
		t.Fatal(err)
	}
	unit := validUnit(t, catalog, now)
	if _, err := executor.Execute(context.Background(), unit, now); err != nil {
		t.Fatal(err)
	}
	if store.calls != 1 || executor.Assurance() != domain.AssuranceLive {
		t.Fatalf("calls=%d assurance=%s", store.calls, executor.Assurance())
	}
	unit.Operation = domain.OperationEvidenceCollectionRestore
	if _, err := executor.Execute(context.Background(), unit, now); err == nil {
		t.Fatal("forward restore was accepted")
	}
}

func TestExecutorRejectsExpiredRequest(t *testing.T) {
	if _, err := New(nil, &storeStub{}); err == nil {
		t.Fatal("unverified catalog was accepted")
	}
	now := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	catalog := verifiedCatalog(t, now)
	executor, err := New(catalog, &storeStub{})
	if err != nil {
		t.Fatal(err)
	}
	unit := validUnit(t, catalog, now)
	if _, err := executor.Execute(context.Background(), unit, unit.Deadline.Add(time.Second)); err == nil {
		t.Fatal("expired request was accepted")
	}
}
