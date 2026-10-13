package remediationrunner

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/remediation"
)

func verifiedCatalog(t *testing.T) *remediation.Catalog {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	release, err := remediation.SignRecipeRelease(remediation.BuiltinRecipes(testInstant().Add(time.Hour)), "recipe-root-1", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	store, err := remediation.NewRecipeTrustStore([]remediation.RecipeTrustRoot{{
		ID: "recipe-root-1", Issuer: "sherlock.release", PublicKey: publicKey,
		ActivatesAt: testInstant().Add(-time.Hour), RetiresAt: testInstant().Add(time.Hour),
	}})
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := store.Verify(release, testInstant())
	if err != nil {
		t.Fatal(err)
	}
	return catalog
}

func boundExecutor(t *testing.T) *SimulatedExecutor {
	t.Helper()
	executor, err := NewVerifiedSimulatedExecutor(verifiedCatalog(t), []ScriptedOutcome{{
		Operation: remediation.OperationEvidenceCollectionRequeue, Target: "stream-1", Outcome: domain.ExecutionExecuted,
	}})
	if err != nil {
		t.Fatal(err)
	}
	return executor
}

func boundUnit(t *testing.T) ExecutionUnit {
	t.Helper()
	catalog := verifiedCatalog(t)
	recipe, found := catalog.Lookup(remediation.RecipeEvidenceCollectionRequeue, remediation.BuiltinRecipeVersion)
	if !found {
		t.Fatal("signed recipe missing")
	}
	unit := testExecutionUnit("stream-1")
	unit.Recipe = recipe.Ref()
	return unit
}

func TestVerifiedExecutorRequiresSignedCatalog(t *testing.T) {
	plain, err := remediation.NewCatalog(remediation.BuiltinRecipes(testInstant().Add(time.Hour)), testInstant())
	if err != nil {
		t.Fatal(err)
	}
	for _, catalog := range []*remediation.Catalog{plain, nil} {
		_, err := NewVerifiedSimulatedExecutor(catalog, nil)
		var binding BindingError
		if !errors.As(err, &binding) || binding.Code != BindUnverifiedCatalog {
			t.Fatalf("err=%v", err)
		}
	}
}

func TestVerifiedExecutorIndependentlyBindsUnitToSignedRecipe(t *testing.T) {
	executor := boundExecutor(t)
	unit := boundUnit(t)
	if err := ValidateExecutionUnit(verifiedCatalog(t), unit, testInstant()); err != nil {
		t.Fatalf("standalone validation: %v", err)
	}
	result, err := executor.Execute(context.Background(), unit, testInstant())
	if err != nil || result.Outcome != domain.ExecutionExecuted {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestValidateExecutionUnitRejectsCatalogAfterTrustRootRetirement(t *testing.T) {
	unit := boundUnit(t)
	err := ValidateExecutionUnit(verifiedCatalog(t), unit, testInstant().Add(2*time.Hour))
	var binding BindingError
	if !errors.As(err, &binding) || binding.Code != BindCatalogExpired {
		t.Fatalf("err=%v", err)
	}
}

func TestVerifiedExecutorRefusesEveryMismatchBeforeRecording(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(ExecutionUnit) ExecutionUnit
		want   BindingCode
	}{
		{name: "missing recipe", mutate: func(u ExecutionUnit) ExecutionUnit { u.Recipe = domain.RemediationRecipeRef{}; return u }, want: BindMissingRecipe},
		{name: "digest mismatch", mutate: func(u ExecutionUnit) ExecutionUnit { u.Recipe.Digest[0] ^= 0xff; return u }, want: BindDigestMismatch},
		{name: "operation mismatch", mutate: func(u ExecutionUnit) ExecutionUnit {
			u.Operation = remediation.OperationEvidenceCollectionRestore
			return u
		}, want: BindOperation},
		{name: "argument mismatch", mutate: func(u ExecutionUnit) ExecutionUnit { u.Arguments[1].Enum = "ELEVATED"; return u }, want: BindArguments},
		{name: "target count exceeds recipe", mutate: func(u ExecutionUnit) ExecutionUnit {
			for index := 2; index <= 5; index++ {
				target := u.Targets[0]
				target.Target = domain.RemediationTarget("stream-" + string(rune('0'+index)))
				u.Targets = append(u.Targets, target)
			}
			return u
		}, want: BindTargets},
		{name: "forward recipe in rollback stage", mutate: func(u ExecutionUnit) ExecutionUnit { u.Stage = domain.RemediationStageRollback; return u }, want: BindStage},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			executor := boundExecutor(t)
			unit := testCase.mutate(boundUnit(t))
			_, err := executor.Execute(context.Background(), unit, testInstant())
			var binding BindingError
			if !errors.As(err, &binding) || binding.Code != testCase.want {
				t.Fatalf("err=%v", err)
			}
			if _, recorded := executor.Recorded(unit.IdempotencyKey); recorded {
				t.Fatal("unbound call was recorded")
			}
		})
	}
}
