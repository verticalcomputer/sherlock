package remediation

import (
	"errors"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

// repointRollback rewires a forward recipe at the rollback it should pin and
// recomputes both digests, which is what a real catalog edit looks like.
func repointRollback(forward, rollback Recipe) []Recipe {
	rollback = rollback.WithComputedDigest()
	forward.RollbackRecipe = rollback.Ref()
	return []Recipe{forward.WithComputedDigest(), rollback}
}

func TestNewBuiltinCatalogLoads(t *testing.T) {
	catalog, err := NewBuiltinCatalog(testInstant(), testExpiry())
	if err != nil {
		t.Fatal(err)
	}
	if catalog.Len() != 2 {
		t.Fatalf("catalog size = %d, want 2", catalog.Len())
	}
	forward, found := catalog.Lookup(RecipeEvidenceCollectionRequeue, BuiltinRecipeVersion)
	if !found {
		t.Fatal("forward recipe missing")
	}
	rollback, err := catalog.ResolveRollback(forward)
	if err != nil || rollback.ID != RecipeEvidenceCollectionRestore {
		t.Fatalf("rollback recipe did not resolve: %v", err)
	}
	if _, err := catalog.ResolveRollback(rollback); err == nil {
		t.Fatal("a rollback has no rollback of its own")
	}
	if _, found := catalog.Lookup(RecipeEvidenceCollectionRequeue, "9.9.9"); found {
		t.Fatal("lookup must require an exact version")
	}
	if len(catalog.Recipes()) != 2 {
		t.Fatal("recipe listing is incomplete")
	}
}

// TestCatalogRejectsTheWholeReleaseOnAnySingleFailure follows the command-pack
// rule: a partly trustworthy catalog is not a catalog.
func TestCatalogRejectsTheWholeReleaseOnAnySingleFailure(t *testing.T) {
	cases := []struct {
		name       string
		recipes    func() []Recipe
		wantReason string
	}{
		{
			name: "one recipe has an altered digest",
			recipes: func() []Recipe {
				recipes := BuiltinRecipes(testExpiry())
				recipes[1].MaxTargets = 3
				return recipes
			},
			wantReason: CatalogReasonDigestMismatch,
		},
		{
			name: "one recipe is structurally invalid",
			recipes: func() []Recipe {
				recipes := BuiltinRecipes(testExpiry())
				recipes[1].AuditRequired = false
				return repointRollback(recipes[0], recipes[1])
			},
			wantReason: CatalogReasonInvalidRecipe,
		},
		{
			name: "one recipe escapes the implemented tier",
			recipes: func() []Recipe {
				recipes := BuiltinRecipes(testExpiry())
				recipes[0].Tier = domain.TierWorkloadContainment
				recipes[0] = recipes[0].WithComputedDigest()
				return recipes
			},
			wantReason: CatalogReasonInvalidRecipe,
		},
		{
			name: "one recipe escapes the implemented privilege",
			recipes: func() []Recipe {
				recipes := BuiltinRecipes(testExpiry())
				recipes[0].Privilege = domain.PrivilegeClusterMutate
				recipes[0] = recipes[0].WithComputedDigest()
				return recipes
			},
			wantReason: CatalogReasonInvalidRecipe,
		},
		{
			name: "the same coordinate appears twice",
			recipes: func() []Recipe {
				recipes := BuiltinRecipes(testExpiry())
				return []Recipe{recipes[0], recipes[1], recipes[1]}
			},
			wantReason: CatalogReasonDuplicateRecipe,
		},
		{
			name: "a declared rollback is not in the catalog",
			recipes: func() []Recipe {
				return BuiltinRecipes(testExpiry())[:1]
			},
			wantReason: CatalogReasonRollbackUnresolved,
		},
		{
			name: "the rollback outranks the forward recipe",
			recipes: func() []Recipe {
				recipes := BuiltinRecipes(testExpiry())
				recipes[1].Privilege = domain.PrivilegeClusterRead
				return repointRollback(recipes[0], recipes[1])
			},
			wantReason: CatalogReasonRollbackTier,
		},
		{
			name: "the rollback may reach more targets than the forward recipe",
			recipes: func() []Recipe {
				recipes := BuiltinRecipes(testExpiry())
				recipes[1].MaxTargets = 8
				recipes[1].MaxConcurrency = 1
				return repointRollback(recipes[0], recipes[1])
			},
			wantReason: CatalogReasonRollbackRoles,
		},
		{
			name: "the rollback may touch a role the forward recipe may not",
			recipes: func() []Recipe {
				recipes := BuiltinRecipes(testExpiry())
				recipes[1].PermittedTargetRoles = []domain.TargetRole{domain.RoleManagedCollectionStream, "SHERLOCK_OTHER_ROLE"}
				return repointRollback(recipes[0], recipes[1])
			},
			wantReason: CatalogReasonRollbackRoles,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			catalog, err := NewCatalog(testCase.recipes(), testInstant())
			if catalog != nil {
				t.Fatal("a rejected catalog must not be returned")
			}
			var rejection CatalogRejection
			if !errors.As(err, &rejection) {
				t.Fatalf("err = %v, want a catalog rejection", err)
			}
			if rejection.Reason != testCase.wantReason {
				t.Fatalf("reason = %s, want %s", rejection.Reason, testCase.wantReason)
			}
		})
	}
}

// TestCatalogRollbackResolutionIsVersionPinned covers what the digest-pinned
// reference bought: a catalog carrying two versions of the rollback is no
// longer ambiguous, and a reference to the version that is absent is refused.
func TestCatalogRollbackResolutionIsVersionPinned(t *testing.T) {
	recipes := BuiltinRecipes(testExpiry())
	second := recipes[1]
	second.Version = "1.0.1"
	second = second.WithComputedDigest()
	catalog, err := NewCatalog(append(recipes, second), testInstant())
	if err != nil {
		t.Fatalf("two rollback versions are not ambiguous when the reference is pinned: %v", err)
	}
	forward, _ := catalog.Lookup(RecipeEvidenceCollectionRequeue, BuiltinRecipeVersion)
	rollback, err := catalog.ResolveRollback(forward)
	if err != nil {
		t.Fatal(err)
	}
	if rollback.Version != BuiltinRecipeVersion {
		t.Fatalf("resolved rollback version = %s, want %s", rollback.Version, BuiltinRecipeVersion)
	}

	// A reference naming a version the catalog does not hold is unresolved.
	stale := recipes[0]
	stale.RollbackRecipe.Version = "9.9.9"
	stale = stale.WithComputedDigest()
	_, err = NewCatalog([]Recipe{stale, recipes[1]}, testInstant())
	var rejection CatalogRejection
	if !errors.As(err, &rejection) || rejection.Reason != CatalogReasonRollbackUnresolved {
		t.Fatalf("err = %v, want an unresolved-rollback rejection", err)
	}
}

func TestCatalogRejectsAnExpiredRelease(t *testing.T) {
	_, err := NewBuiltinCatalog(testExpiry().Add(time.Hour), testExpiry())
	var rejection CatalogRejection
	if !errors.As(err, &rejection) || rejection.Reason != CatalogReasonInvalidRecipe {
		t.Fatalf("err = %v, want an expired-recipe rejection", err)
	}
}

func TestCatalogRejectsAnEmptyRelease(t *testing.T) {
	if _, err := NewCatalog(nil, testInstant()); err == nil {
		t.Fatal("an empty catalog must be refused")
	}
}

// TestCatalogResolveRequiresADigestMatch is the check that turns a tampered
// catalog into a refusal rather than the execution of something a run was never
// authorized for.
func TestCatalogResolveRequiresADigestMatch(t *testing.T) {
	catalog, err := NewBuiltinCatalog(testInstant(), testExpiry())
	if err != nil {
		t.Fatal(err)
	}
	forward := forwardRecipe()
	if _, err := catalog.Resolve(forward.Ref()); err != nil {
		t.Fatalf("matching reference: %v", err)
	}

	altered := forward.Ref()
	altered.Digest = domain.ChecksumSHA256([]byte("tampered"))
	var mismatch DigestMismatchError
	if _, err := catalog.Resolve(altered); !errors.As(err, &mismatch) {
		t.Fatalf("err = %v, want a digest mismatch", err)
	}

	fabricated := domain.RemediationRecipeRef{ID: "sherlock.reboot-everything", Version: "1.0.0", Digest: forward.Digest}
	var rejection RejectionError
	if _, err := catalog.Resolve(fabricated); !errors.As(err, &rejection) || rejection.Code != RejectUnknownRecipe {
		t.Fatalf("err = %v, want an unknown-recipe rejection", err)
	}
}

func TestCatalogReturnsDefensiveCopies(t *testing.T) {
	catalog, err := NewBuiltinCatalog(testInstant(), testExpiry())
	if err != nil {
		t.Fatal(err)
	}
	first, _ := catalog.Lookup(RecipeEvidenceCollectionRequeue, BuiltinRecipeVersion)
	first.Parameters[0].AllowedValues[0] = "HIJACKED"
	first.Reviews[0].Reviewer = "attacker"
	second, _ := catalog.Lookup(RecipeEvidenceCollectionRequeue, BuiltinRecipeVersion)
	if second.Parameters[0].AllowedValues[0] == "HIJACKED" || second.Reviews[0].Reviewer == "attacker" {
		t.Fatal("mutating a looked-up recipe must not reach the catalog")
	}
}

func TestNilCatalogIsInert(t *testing.T) {
	var catalog *Catalog
	if catalog.Len() != 0 || catalog.Recipes() != nil {
		t.Fatal("a nil catalog must be empty")
	}
	if _, found := catalog.Lookup("x", "1.0.0"); found {
		t.Fatal("a nil catalog must find nothing")
	}
	if _, err := catalog.Resolve(forwardRecipe().Ref()); err == nil {
		t.Fatal("a nil catalog must resolve nothing")
	}
	if _, err := catalog.ResolveRollback(forwardRecipe()); err == nil {
		t.Fatal("a nil catalog must resolve no rollback")
	}
}
