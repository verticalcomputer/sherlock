package remediation

import (
	"errors"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

func testInstant() time.Time { return time.Date(2026, 9, 10, 3, 0, 0, 0, time.UTC) }

func testExpiry() time.Time { return testInstant().Add(90 * 24 * time.Hour) }

// forwardRecipe is the shipped Tier 1 recipe, digest included.
func forwardRecipe() Recipe { return BuiltinRecipes(testExpiry())[0] }

func rollbackRecipe() Recipe { return BuiltinRecipes(testExpiry())[1] }

// validateForward resolves the rollback the way the catalog does, so a test
// exercises the same path production loading takes.
func validateForward(recipe Recipe) error {
	rollback := rollbackRecipe()
	return recipe.Validate(testInstant(), &rollback)
}

func TestBuiltinRecipesValidate(t *testing.T) {
	rollback := rollbackRecipe()
	for _, recipe := range BuiltinRecipes(testExpiry()) {
		var resolved *Recipe
		if recipe.HasRollback() {
			resolved = &rollback
		}
		if err := recipe.Validate(testInstant(), resolved); err != nil {
			t.Fatalf("%s@%s: %v", recipe.ID, recipe.Version, err)
		}
		if recipe.Digest != recipe.ComputeDigest() {
			t.Fatalf("%s digest is not computed from its own bytes", recipe.ID)
		}
		if recipe.Tier != domain.TierSherlockOwnedRepair || recipe.Assurance != domain.AssuranceSimulated ||
			recipe.Privilege != domain.PrivilegeSherlockInternal {
			t.Fatalf("%s escapes the milestone scope boundary", recipe.ID)
		}
		if len(recipe.Reviews) < 1 {
			t.Fatalf("%s ships without a recorded review", recipe.ID)
		}
	}
	forward := forwardRecipe()
	// The rollback is pinned by identity, version and digest, not by name alone.
	if !forward.RollbackRecipe.Matches(rollback.Ref()) {
		t.Fatalf("rollback reference = %+v", forward.RollbackRecipe)
	}
	if forward.RollbackRecipe.Digest == (domain.SHA256{}) || forward.RollbackRecipe.Version == "" {
		t.Fatal("a rollback reference without a version and a digest is not pinned")
	}
	if rollback.HasRollback() {
		t.Fatal("a rollback must not itself declare a rollback")
	}
	if forward.MaxTargets != 4 || forward.CanaryTargets != 1 || forward.MaxConcurrency != 1 ||
		forward.BlastRadiusPercent != 25 || forward.MaxAttempts != 2 ||
		forward.Cooldown != 30*time.Minute || forward.ObservationWindow != 15*time.Minute {
		t.Fatal("built-in recipe bounds do not match the contract")
	}
}

func TestRecipeValidationRejections(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(Recipe) Recipe
	}{
		{name: "wrong schema", mutate: func(r Recipe) Recipe { r.Schema = "sherlock.remediation-recipe.v2"; return r }},
		{name: "identifier outside the token charset", mutate: func(r Recipe) Recipe { r.ID = "sherlock requeue"; return r }},
		{name: "identifier containing a path", mutate: func(r Recipe) Recipe { r.ID = "/usr/bin/requeue"; return r }},
		{name: "owner outside the token charset", mutate: func(r Recipe) Recipe { r.Owner = "platform team"; return r }},
		{name: "tier above the implemented maximum", mutate: func(r Recipe) Recipe { r.Tier = domain.TierSingleTargetMonitor; return r }},
		{name: "destructive tier", mutate: func(r Recipe) Recipe { r.Tier = domain.TierDestructive; return r }},
		// The unset tier is the case a "<= MaxImplementedTier" ceiling admitted.
		{name: "unset read-only tier", mutate: func(r Recipe) Recipe { r.Tier = domain.TierReadOnly; return r }},
		{name: "unknown tier", mutate: func(r Recipe) Recipe { r.Tier = domain.AutonomyTier(11); return r }},
		{name: "live assurance", mutate: func(r Recipe) Recipe { r.Assurance = domain.AssuranceLive; return r }},
		{name: "recorded assurance", mutate: func(r Recipe) Recipe { r.Assurance = domain.AssuranceRecorded; return r }},
		{name: "unset assurance", mutate: func(r Recipe) Recipe { r.Assurance = ""; return r }},
		{name: "unknown assurance", mutate: func(r Recipe) Recipe { r.Assurance = "TRUST_ME"; return r }},
		{name: "cluster-read privilege", mutate: func(r Recipe) Recipe { r.Privilege = domain.PrivilegeClusterRead; return r }},
		{name: "cluster-mutate privilege", mutate: func(r Recipe) Recipe { r.Privilege = domain.PrivilegeClusterMutate; return r }},
		{name: "unset privilege", mutate: func(r Recipe) Recipe { r.Privilege = ""; return r }},
		{name: "absent expiry", mutate: func(r Recipe) Recipe { r.ExpiresAt = time.Time{}; return r }},
		{name: "already expired", mutate: func(r Recipe) Recipe { r.ExpiresAt = testInstant().Add(-time.Second); return r }},
		{name: "audit not required", mutate: func(r Recipe) Recipe { r.AuditRequired = false; return r }},
		{name: "no recorded review", mutate: func(r Recipe) Recipe { r.Reviews = nil; return r }},
		{name: "repeated reviewer", mutate: func(r Recipe) Recipe {
			r.Reviews = []RecipeReview{{Reviewer: "a", ReviewedAt: testInstant()}, {Reviewer: "a", ReviewedAt: testInstant()}}
			return r
		}},
		{name: "review without an instant", mutate: func(r Recipe) Recipe {
			r.Reviews = []RecipeReview{{Reviewer: "a"}}
			return r
		}},
		{name: "unknown operation", mutate: func(r Recipe) Recipe { r.Operation = "SH_DASH_C"; return r }},
		{name: "credential-like parameter name", mutate: func(r Recipe) Recipe {
			r.Parameters = append(r.Parameters, Parameter{Name: "api_key", Type: domain.ParameterEnum, AllowedValues: []string{"NORMAL"}})
			return r
		}},
		{name: "credential-like parameter name with punctuation", mutate: func(r Recipe) Recipe {
			r.Parameters = append(r.Parameters, Parameter{Name: "SSH.Key", Type: domain.ParameterBoolean})
			return r
		}},
		{name: "enum without allowed values", mutate: func(r Recipe) Recipe {
			r.Parameters = []Parameter{{Name: "priority", Type: domain.ParameterEnum, Required: true}}
			return r
		}},
		{name: "allowed value outside the token charset", mutate: func(r Recipe) Recipe {
			r.Parameters = []Parameter{{Name: "priority", Type: domain.ParameterEnum, Required: true, AllowedValues: []string{"NORMAL; rm -rf /"}}}
			return r
		}},
		{name: "duplicate allowed value", mutate: func(r Recipe) Recipe {
			r.Parameters = []Parameter{{Name: "priority", Type: domain.ParameterEnum, Required: true, AllowedValues: []string{"NORMAL", "NORMAL"}}}
			return r
		}},
		{name: "duplicate parameter name", mutate: func(r Recipe) Recipe {
			r.Parameters = append(r.Parameters, r.Parameters[0])
			return r
		}},
		{name: "inverted numeric bound", mutate: func(r Recipe) Recipe {
			r.Parameters = []Parameter{{Name: "delay", Type: domain.ParameterInteger, Minimum: 10, Maximum: 1}}
			return r
		}},
		{name: "numeric parameter with allowed values", mutate: func(r Recipe) Recipe {
			r.Parameters = []Parameter{{Name: "delay", Type: domain.ParameterInteger, AllowedValues: []string{"1"}}}
			return r
		}},
		{name: "boolean parameter with bounds", mutate: func(r Recipe) Recipe {
			r.Parameters = []Parameter{{Name: "drain", Type: domain.ParameterBoolean, Maximum: 5}}
			return r
		}},
		{name: "unknown parameter type", mutate: func(r Recipe) Recipe {
			r.Parameters = []Parameter{{Name: "script", Type: "STRING"}}
			return r
		}},
		{name: "zero canary targets", mutate: func(r Recipe) Recipe { r.CanaryTargets = 0; return r }},
		{name: "canary above maximum targets", mutate: func(r Recipe) Recipe { r.CanaryTargets = r.MaxTargets + 1; return r }},
		{name: "blast radius zero", mutate: func(r Recipe) Recipe { r.BlastRadiusPercent = 0; return r }},
		{name: "blast radius above one hundred", mutate: func(r Recipe) Recipe { r.BlastRadiusPercent = 101; return r }},
		{name: "zero attempts", mutate: func(r Recipe) Recipe { r.MaxAttempts = 0; return r }},
		{name: "four attempts", mutate: func(r Recipe) Recipe { r.MaxAttempts = 4; return r }},
		{name: "rollback reference to itself", mutate: func(r Recipe) Recipe {
			r.RollbackRecipe = r.Ref()
			return r
		}},
		{name: "rollback declared without verification", mutate: func(r Recipe) Recipe { r.RollbackVerification = nil; return r }},
		{name: "rollback verification without a rollback", mutate: func(r Recipe) Recipe {
			r.RollbackRecipe = domain.RemediationRecipeRef{}
			return r
		}},
		{name: "rollback reference without a digest", mutate: func(r Recipe) Recipe {
			r.RollbackRecipe.Digest = domain.SHA256{}
			return r
		}},
		{name: "rollback reference to another version", mutate: func(r Recipe) Recipe {
			r.RollbackRecipe.Version = "9.9.9"
			return r
		}},
		{name: "unknown target role", mutate: func(r Recipe) Recipe {
			r.PermittedTargetRoles = []domain.TargetRole{"ANY_HOST"}
			return r
		}},
		{name: "no target roles", mutate: func(r Recipe) Recipe { r.PermittedTargetRoles = nil; return r }},
		{name: "no evidence requirement", mutate: func(r Recipe) Recipe { r.RequiredEvidence = nil; return r }},
		{name: "evidence class outside the token charset", mutate: func(r Recipe) Recipe {
			r.RequiredEvidence = []EvidenceRequirement{{Class: "collection freshness", MaxAge: time.Minute, MinCoverage: 100}}
			return r
		}},
		{name: "evidence coverage above one hundred", mutate: func(r Recipe) Recipe {
			r.RequiredEvidence = []EvidenceRequirement{{Class: "COLLECTION_FRESHNESS", MaxAge: time.Minute, MinCoverage: 101}}
			return r
		}},
		{name: "no postcondition", mutate: func(r Recipe) Recipe { r.Postconditions = nil; return r }},
		{name: "no precondition", mutate: func(r Recipe) Recipe { r.Preconditions = nil; return r }},
		{name: "condition identifier outside the token charset", mutate: func(r Recipe) Recipe {
			r.Preconditions = []ConditionSpec{{ID: "stream stale", Kind: ConditionStreamStale, Target: domain.RoleManagedCollectionStream, Window: time.Minute}}
			return r
		}},
		{name: "unknown condition kind", mutate: func(r Recipe) Recipe {
			r.Postconditions = []ConditionSpec{{ID: "x", Kind: "TRUST_EXECUTOR", Target: domain.RoleManagedCollectionStream, Window: time.Minute}}
			return r
		}},
		{name: "zero observation window", mutate: func(r Recipe) Recipe { r.ObservationWindow = 0; return r }},
		{name: "no incident kinds", mutate: func(r Recipe) Recipe { r.AppliesToIncidentKinds = nil; return r }},
		{name: "incident kind outside the token charset", mutate: func(r Recipe) Recipe {
			r.AppliesToIncidentKinds = []string{"evidence stream stale"}
			return r
		}},
		{name: "required capability outside the token charset", mutate: func(r Recipe) Recipe {
			r.RequiredCapabilities = []string{"remediation tier1"}
			return r
		}},
		{name: "invalid redaction class", mutate: func(r Recipe) Recipe { r.RedactionClass = ""; return r }},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			mutated := testCase.mutate(forwardRecipe())
			// Recompute so the mutation itself, and not an incidental digest
			// mismatch, is what the assertion observes.
			mutated = mutated.WithComputedDigest()
			if err := validateForward(mutated); err == nil {
				t.Fatal("expected the recipe to be refused")
			}
		})
	}
}

// TestRecipeRefusesAnOverBroadRollback covers the escalation a bare rollback
// identifier allowed: a Tier 1 forward action whose rollback carries more tier,
// privilege, assurance, reach or roles than the action it undoes.
func TestRecipeRefusesAnOverBroadRollback(t *testing.T) {
	cases := []struct {
		name     string
		mutate   func(Recipe) Recipe
		wantCode string
	}{
		{
			name:     "rollback tier above the forward tier",
			mutate:   func(r Recipe) Recipe { r.Tier = domain.TierWorkloadContainment; return r },
			wantCode: RollbackViolationTier,
		},
		{
			name:     "rollback privilege above the forward privilege",
			mutate:   func(r Recipe) Recipe { r.Privilege = domain.PrivilegeClusterMutate; return r },
			wantCode: RollbackViolationTier,
		},
		{
			name:     "rollback assurance differs from the forward assurance",
			mutate:   func(r Recipe) Recipe { r.Assurance = domain.AssuranceLive; return r },
			wantCode: RollbackViolationTier,
		},
		{
			name:     "rollback reaches more targets than the forward action",
			mutate:   func(r Recipe) Recipe { r.MaxTargets = 8; return r },
			wantCode: RollbackViolationRole,
		},
		{
			name: "rollback permitted a role the forward action is not",
			mutate: func(r Recipe) Recipe {
				r.PermittedTargetRoles = []domain.TargetRole{domain.RoleManagedCollectionStream, "SHERLOCK_OTHER_ROLE"}
				return r
			},
			wantCode: RollbackViolationRole,
		},
		{
			name: "rollback declares a rollback of its own",
			mutate: func(r Recipe) Recipe {
				r.RollbackRecipe = domain.RemediationRecipeRef{ID: "sherlock.third", Version: "1.0.0", Digest: domain.ChecksumSHA256([]byte("third"))}
				r.RollbackVerification = []ConditionSpec{{ID: "schedule-restored", Kind: ConditionScheduleRestored, Target: domain.RoleManagedCollectionStream, Window: time.Minute}}
				return r
			},
			wantCode: RollbackViolationNested,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			rollback := testCase.mutate(rollbackRecipe()).WithComputedDigest()
			forward := forwardRecipe()
			forward.RollbackRecipe = rollback.Ref()
			forward = forward.WithComputedDigest()
			err := forward.Validate(testInstant(), &rollback)
			var violation RollbackViolationError
			if !errors.As(err, &violation) {
				t.Fatalf("err = %v, want a rollback violation", err)
			}
			if violation.Code != testCase.wantCode {
				t.Fatalf("code = %s, want %s", violation.Code, testCase.wantCode)
			}
		})
	}

	// A rollback that is simply not supplied is unresolved, not permitted.
	if err := forwardRecipe().Validate(testInstant(), nil); err == nil {
		t.Fatal("a declared rollback that cannot be resolved must be refused")
	}
	// A supplied rollback whose digest does not match the pinned reference is
	// exactly the substitution the reference exists to prevent.
	substituted := rollbackRecipe()
	substituted.MaxAttempts = 3
	substituted = substituted.WithComputedDigest()
	if err := forwardRecipe().Validate(testInstant(), &substituted); err == nil {
		t.Fatal("a rollback whose digest does not match the pinned reference must be refused")
	}
}

// TestRecipeDigestTamperDetection proves an altered definition is refused with
// a distinct error rather than merely failing some structural rule.
func TestRecipeDigestTamperDetection(t *testing.T) {
	tampered := forwardRecipe()
	tampered.MaxTargets = 64
	err := validateForward(tampered)
	var mismatch DigestMismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("err = %v, want a digest mismatch", err)
	}
	if mismatch.RecipeID != tampered.ID {
		t.Fatalf("mismatch recipe = %s", mismatch.RecipeID)
	}
	if validateForward(tampered.WithComputedDigest()) != nil {
		t.Fatal("recomputing the digest should make the altered recipe structurally valid again")
	}
}

// TestRecipeCanonicalEncodingIsUnambiguous shifts a field boundary without
// changing the concatenated characters. A delimiter-based encoding would
// collide here; the length prefixes keep the two apart.
func TestRecipeCanonicalEncodingIsUnambiguous(t *testing.T) {
	left := forwardRecipe()
	left.ID = "a"
	left.Version = "bc"
	right := forwardRecipe()
	right.ID = "ab"
	right.Version = "c"
	if left.ComputeDigest() == right.ComputeDigest() {
		t.Fatal("a shifted identifier boundary must not produce the same digest")
	}

	oneKind := forwardRecipe()
	oneKind.AppliesToIncidentKinds = []string{"ab"}
	twoKinds := forwardRecipe()
	twoKinds.AppliesToIncidentKinds = []string{"a", "b"}
	if oneKind.ComputeDigest() == twoKinds.ComputeDigest() {
		t.Fatal("a shifted list boundary must not produce the same digest")
	}

	splitOwner := forwardRecipe()
	splitOwner.Owner = "sherlock"
	splitOwner.RedactionClass = "platformoperational"
	joinedOwner := forwardRecipe()
	joinedOwner.Owner = "sherlockplatform"
	joinedOwner.RedactionClass = "operational"
	if splitOwner.ComputeDigest() == joinedOwner.ComputeDigest() {
		t.Fatal("a shifted boundary between distant fields must not produce the same digest")
	}

	// The rollback reference is part of the forward recipe's covered bytes, so
	// swapping which definition it points at cannot leave the digest unchanged.
	repointed := forwardRecipe()
	repointed.RollbackRecipe.Digest = domain.ChecksumSHA256([]byte("substituted"))
	if repointed.ComputeDigest() == forwardRecipe().ComputeDigest() {
		t.Fatal("the pinned rollback reference must be covered by the forward digest")
	}
}

func TestRecipeCanonicalEncodingIsStableAndSetOrderInsensitive(t *testing.T) {
	recipe := forwardRecipe()
	first, second := recipe.ComputeDigest(), recipe.ComputeDigest()
	if first != second {
		t.Fatal("canonical encoding must be deterministic")
	}
	reordered := forwardRecipe()
	reordered.RequiredCapabilities = []string{CapabilityRemediationTier1}
	if reordered.ComputeDigest() != recipe.ComputeDigest() {
		t.Fatal("an unordered set must digest the same whichever way it is written")
	}
	swappedReviews := forwardRecipe()
	swappedReviews.Reviews = []RecipeReview{recipe.Reviews[1], recipe.Reviews[0]}
	if swappedReviews.ComputeDigest() != recipe.ComputeDigest() {
		t.Fatal("review order carries no meaning and must not change the digest")
	}
	// Parameter order is significant: it is part of the reviewed definition.
	swapped := forwardRecipe()
	swapped.Parameters = []Parameter{swapped.Parameters[1], swapped.Parameters[0]}
	if swapped.ComputeDigest() == recipe.ComputeDigest() {
		t.Fatal("parameter order is significant and must change the digest")
	}
}

func TestRecipeRefPinsTheExactCoordinate(t *testing.T) {
	recipe := forwardRecipe()
	ref := recipe.Ref()
	if ref.ID != recipe.ID || ref.Version != recipe.Version || ref.Digest != recipe.Digest {
		t.Fatal("reference must pin identity, version and digest")
	}
	if err := ref.Validate(); err != nil {
		t.Fatalf("reference: %v", err)
	}
}

func TestRecipeEnumsRejectUnknownValues(t *testing.T) {
	if err := RecipeOperation("SHERLOCK_RUN_SHELL").Validate(); err == nil {
		t.Fatal("expected an unknown operation to be refused")
	}
	if err := ConditionKind("EXECUTOR_SAID_SO").Validate(); err == nil {
		t.Fatal("expected an unknown condition kind to be refused")
	}
}
