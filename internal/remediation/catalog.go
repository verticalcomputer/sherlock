package remediation

import (
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

// CatalogRejection names why a whole catalog was refused. Loading follows the
// command-pack rule: an unsafe release is rejected entirely rather than
// partially guessing which definitions were meant to be trustworthy.
type CatalogRejection struct {
	RecipeID domain.RecipeID
	Version  string
	Reason   string
	Err      error
}

func (e CatalogRejection) Error() string {
	return fmt.Sprintf("remediation catalog rejected at recipe %s@%s: %s", e.RecipeID, e.Version, e.Reason)
}

func (e CatalogRejection) Unwrap() error { return e.Err }

const (
	CatalogReasonInvalidRecipe      = "RECIPE_INVALID"
	CatalogReasonDigestMismatch     = "RECIPE_DIGEST_MISMATCH"
	CatalogReasonDuplicateRecipe    = "RECIPE_DUPLICATE"
	CatalogReasonRollbackUnresolved = "ROLLBACK_UNRESOLVED"
	CatalogReasonRollbackTier       = "ROLLBACK_TIER_EXCEEDED"
	CatalogReasonRollbackRoles      = "ROLLBACK_ROLE_EXCEEDED"
)

// Catalog is an immutable in-memory set of digest-verified recipes. It is the
// only authority on what a recipe says. A persisted recipe-reference row is
// written for audit and is never read to authorize anything, so the compiled
// catalog and the database cannot become two sources of truth that disagree.
type Catalog struct {
	recipes map[string]Recipe
	order   []string
	// verified is set only by RecipeTrustStore.Verify.  NewCatalog remains
	// useful for pure policy tests and compiled fixtures, but it is not an
	// execution authority.
	verified    bool
	validBefore time.Time
}

func catalogKey(id domain.RecipeID, version string) string { return string(id) + "@" + version }

// NewCatalog verifies every recipe and every rollback relation before returning
// a catalog. Any single failure rejects the whole set: a catalog that is
// three-quarters trustworthy is not a catalog.
//
// Rollbacks are resolved by the full digest-pinned reference, not by identifier.
// Resolving by identifier meant a catalog carrying two versions of a rollback
// had to be rejected as ambiguous; with a version and digest in the reference
// there is exactly one definition it can name, and a mismatch is unresolved
// rather than ambiguous.
func NewCatalog(recipes []Recipe, now time.Time) (*Catalog, error) {
	return newCatalog(recipes, now, false, time.Time{})
}

// newCatalog is deliberately private so the only way to obtain an execution
// authority is the signature-verification path in signing.go.  All structural,
// digest, expiry and rollback checks happen here after that path has verified
// the release signature.
func newCatalog(recipes []Recipe, now time.Time, verified bool, validBefore time.Time) (*Catalog, error) {
	if len(recipes) == 0 {
		return nil, fmt.Errorf("remediation catalog must contain at least one recipe")
	}
	indexed := make(map[string]Recipe, len(recipes))
	order := make([]string, 0, len(recipes))
	for _, recipe := range recipes {
		key := catalogKey(recipe.ID, recipe.Version)
		if _, exists := indexed[key]; exists {
			return nil, CatalogRejection{RecipeID: recipe.ID, Version: recipe.Version, Reason: CatalogReasonDuplicateRecipe}
		}
		indexed[key] = cloneRecipe(recipe)
		order = append(order, key)
	}
	for _, key := range order {
		recipe := indexed[key]
		var rollback *Recipe
		if recipe.HasRollback() {
			if candidate, found := indexed[catalogKey(recipe.RollbackRecipe.ID, recipe.RollbackRecipe.Version)]; found {
				rollback = &candidate
			}
		}
		if err := recipe.Validate(now, rollback); err != nil {
			return nil, CatalogRejection{
				RecipeID: recipe.ID, Version: recipe.Version, Reason: catalogReason(err), Err: err,
			}
		}
	}
	slices.Sort(order)
	return &Catalog{recipes: indexed, order: order, verified: verified, validBefore: validBefore.UTC()}, nil
}

// Verified reports whether this catalog was constructed from a release whose
// Ed25519 signature and trust-root validity were verified.  It is intentionally
// a property of the catalog rather than a caller assertion.
func (c *Catalog) Verified() bool { return c != nil && c.verified }

// ExecutableAt reports whether the trust root that admitted this catalog is
// still active. A catalog loaded before root retirement is never a perpetual
// authority; callers at the execution edge must check this against their
// server-causal instant.
func (c *Catalog) ExecutableAt(now time.Time) bool {
	return c != nil && c.verified && !now.IsZero() && !c.validBefore.IsZero() && now.Before(c.validBefore)
}

func catalogReason(err error) string {
	var mismatch DigestMismatchError
	if errors.As(err, &mismatch) {
		return CatalogReasonDigestMismatch
	}
	var violation RollbackViolationError
	if errors.As(err, &violation) {
		switch violation.Code {
		case RollbackViolationRole:
			return CatalogReasonRollbackRoles
		case RollbackViolationTier:
			return CatalogReasonRollbackTier
		default:
			return CatalogReasonRollbackUnresolved
		}
	}
	return CatalogReasonInvalidRecipe
}

func (c *Catalog) Len() int {
	if c == nil {
		return 0
	}
	return len(c.recipes)
}

// Lookup returns a defensive copy of the recipe at an exact coordinate.
func (c *Catalog) Lookup(id domain.RecipeID, version string) (Recipe, bool) {
	if c == nil {
		return Recipe{}, false
	}
	recipe, exists := c.recipes[catalogKey(id, version)]
	if !exists {
		return Recipe{}, false
	}
	return cloneRecipe(recipe), true
}

// Resolve re-resolves a persisted reference and requires the digest to match.
// This is the check that turns a tampered catalog into a refusal rather than an
// execution of something the run was never authorized for.
func (c *Catalog) Resolve(ref domain.RemediationRecipeRef) (Recipe, error) {
	recipe, exists := c.Lookup(ref.ID, ref.Version)
	if !exists {
		return Recipe{}, RejectionError{Code: RejectUnknownRecipe}
	}
	if recipe.Digest != ref.Digest {
		return Recipe{}, DigestMismatchError{RecipeID: ref.ID, Version: ref.Version}
	}
	return recipe, nil
}

// ResolveRollback returns the rollback recipe of a forward recipe, resolved by
// the same digest-pinned path as the forward recipe itself.
func (c *Catalog) ResolveRollback(forward Recipe) (Recipe, error) {
	if !forward.HasRollback() {
		return Recipe{}, RollbackViolationError{RecipeID: forward.ID, Code: RollbackViolationUnresolved}
	}
	return c.Resolve(forward.RollbackRecipe)
}

// Recipes returns every recipe in canonical order.
func (c *Catalog) Recipes() []Recipe {
	if c == nil {
		return nil
	}
	result := make([]Recipe, 0, len(c.order))
	for _, key := range c.order {
		result = append(result, cloneRecipe(c.recipes[key]))
	}
	return result
}

const (
	// RecipeEvidenceCollectionRequeue repairs Sherlock's own collection stream
	// after a dispatch gap: the M13 finding was that a stalled retired-page
	// collection silently blocked hardware escalation.
	RecipeEvidenceCollectionRequeue domain.RecipeID = "sherlock.evidence-collection-requeue"
	// RecipeEvidenceCollectionRestore reverses the requeue by restoring the
	// recorded prior schedule state.
	RecipeEvidenceCollectionRestore domain.RecipeID = "sherlock.evidence-collection-restore"

	// BuiltinRecipeVersion pins both built-in recipes.
	BuiltinRecipeVersion = "1.0.0"

	// IncidentKindEvidenceStreamStale is the only incident kind any Tier 1
	// recipe applies to in this milestone.
	IncidentKindEvidenceStreamStale = "EVIDENCE_STREAM_STALE"

	// EvidenceClassCollectionFreshness is the evidence class both recipes need.
	EvidenceClassCollectionFreshness = "COLLECTION_FRESHNESS"

	// CapabilityRemediationTier1 is the capability an actor must hold. It is
	// checked by an authorizer at the application layer, where a real principal
	// exists, not inside the pure policy core.
	CapabilityRemediationTier1 = "remediation:tier1"
)

// BuiltinRecipes returns the Tier 1 recipes with their digests computed from
// their own canonical bytes. No digest is hardcoded: a hex literal in source
// can drift away from the definition it claims to cover without anyone noticing.
// The rollback is digested first, because the forward recipe's canonical bytes
// include the rollback's pinned reference.
func BuiltinRecipes(expiresAt time.Time) []Recipe {
	reviewedAt := expiresAt.Add(-90 * 24 * time.Hour)
	reviews := []RecipeReview{
		{Reviewer: "sherlock.platform-review", ReviewedAt: reviewedAt},
		{Reviewer: "sherlock.security-review", ReviewedAt: reviewedAt},
	}
	restore := Recipe{
		Schema:                 RecipeSchemaVersion,
		ID:                     RecipeEvidenceCollectionRestore,
		Version:                BuiltinRecipeVersion,
		Owner:                  "sherlock.platform",
		ExpiresAt:              expiresAt,
		Reviews:                reviews,
		Assurance:              domain.AssuranceSimulated,
		Tier:                   domain.TierSherlockOwnedRepair,
		Privilege:              domain.PrivilegeSherlockInternal,
		AppliesToIncidentKinds: []string{IncidentKindEvidenceStreamStale},
		RequiredEvidence: []EvidenceRequirement{
			{Class: EvidenceClassCollectionFreshness, MaxAge: 15 * time.Minute, MinCoverage: 100},
		},
		Operation: OperationEvidenceCollectionRestore,
		Parameters: []Parameter{
			{Name: "requeue_reason", Type: domain.ParameterEnum, Required: true, AllowedValues: []string{"STALE_STREAM", "DISPATCH_GAP"}},
		},
		PermittedTargetRoles: []domain.TargetRole{domain.RoleManagedCollectionStream},
		MaxTargets:           4,
		MaxConcurrency:       1,
		BlastRadiusPercent:   25,
		CanaryTargets:        1,
		Preconditions: []ConditionSpec{
			{ID: "stream-fresh", Kind: ConditionStreamFresh, Target: domain.RoleManagedCollectionStream, Window: 15 * time.Minute},
		},
		Postconditions: []ConditionSpec{
			{ID: "schedule-restored", Kind: ConditionScheduleRestored, Target: domain.RoleManagedCollectionStream, Window: 15 * time.Minute},
		},
		ObservationWindow:    15 * time.Minute,
		MaxAttempts:          2,
		Cooldown:             30 * time.Minute,
		RequiredCapabilities: []string{CapabilityRemediationTier1},
		RedactionClass:       "operational",
		AuditRequired:        true,
	}
	restore = restore.WithComputedDigest()

	requeue := Recipe{
		Schema:                 RecipeSchemaVersion,
		ID:                     RecipeEvidenceCollectionRequeue,
		Version:                BuiltinRecipeVersion,
		Owner:                  "sherlock.platform",
		ExpiresAt:              expiresAt,
		Reviews:                reviews,
		Assurance:              domain.AssuranceSimulated,
		Tier:                   domain.TierSherlockOwnedRepair,
		Privilege:              domain.PrivilegeSherlockInternal,
		AppliesToIncidentKinds: []string{IncidentKindEvidenceStreamStale},
		RequiredEvidence: []EvidenceRequirement{
			{Class: EvidenceClassCollectionFreshness, MaxAge: 15 * time.Minute, MinCoverage: 100},
		},
		Operation: OperationEvidenceCollectionRequeue,
		Parameters: []Parameter{
			{Name: "requeue_reason", Type: domain.ParameterEnum, Required: true, AllowedValues: []string{"STALE_STREAM", "DISPATCH_GAP"}},
			{Name: "priority", Type: domain.ParameterEnum, Required: true, AllowedValues: []string{"NORMAL", "ELEVATED"}},
		},
		PermittedTargetRoles: []domain.TargetRole{domain.RoleManagedCollectionStream},
		MaxTargets:           4,
		MaxConcurrency:       1,
		BlastRadiusPercent:   25,
		CanaryTargets:        1,
		Preconditions: []ConditionSpec{
			{ID: "stream-stale", Kind: ConditionStreamStale, Target: domain.RoleManagedCollectionStream, Window: 15 * time.Minute},
		},
		// Verification is an independent observation that a new collection run
		// happened, never the executor's own claim that it requeued one.
		Postconditions: []ConditionSpec{
			{ID: "stream-fresh", Kind: ConditionStreamFresh, Target: domain.RoleManagedCollectionStream, Window: 15 * time.Minute},
		},
		ObservationWindow:    15 * time.Minute,
		MaxAttempts:          2,
		Cooldown:             30 * time.Minute,
		RollbackRecipe:       restore.Ref(),
		RollbackVerification: []ConditionSpec{{ID: "schedule-restored", Kind: ConditionScheduleRestored, Target: domain.RoleManagedCollectionStream, Window: 15 * time.Minute}},
		RequiredCapabilities: []string{CapabilityRemediationTier1},
		RedactionClass:       "operational",
		AuditRequired:        true,
	}
	return []Recipe{requeue.WithComputedDigest(), restore}
}

// NewBuiltinCatalog builds the shipped catalog.
func NewBuiltinCatalog(now, expiresAt time.Time) (*Catalog, error) {
	return NewCatalog(BuiltinRecipes(expiresAt), now)
}

func cloneRecipe(recipe Recipe) Recipe {
	recipe.Reviews = slices.Clone(recipe.Reviews)
	recipe.AppliesToIncidentKinds = slices.Clone(recipe.AppliesToIncidentKinds)
	recipe.RequiredEvidence = slices.Clone(recipe.RequiredEvidence)
	recipe.Parameters = slices.Clone(recipe.Parameters)
	for index := range recipe.Parameters {
		recipe.Parameters[index].AllowedValues = slices.Clone(recipe.Parameters[index].AllowedValues)
	}
	recipe.PermittedTargetRoles = slices.Clone(recipe.PermittedTargetRoles)
	recipe.Preconditions = slices.Clone(recipe.Preconditions)
	recipe.Postconditions = slices.Clone(recipe.Postconditions)
	recipe.RollbackVerification = slices.Clone(recipe.RollbackVerification)
	recipe.RequiredCapabilities = slices.Clone(recipe.RequiredCapabilities)
	recipe.ExpiresAt = recipe.ExpiresAt.UTC()
	return recipe
}
