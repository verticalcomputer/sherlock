package remediation

import (
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

const CollectionRequestRecipeVersion = "2.0.0"

// CollectionRequestRecipes has different ownership from the historical M14
// simulation: forward creates one request and rollback cancels that request.
// It never owns active, cadence, or next_run_at on the permanent schedule.
func CollectionRequestRecipes(expires time.Time) []Recipe {
	recipes := BuiltinRecipes(expires)
	for i := range recipes {
		r := &recipes[i]
		r.Version = CollectionRequestRecipeVersion
		r.Assurance = domain.AssuranceLive
		r.MaxTargets = 1
		r.MaxConcurrency = 1
		r.CanaryTargets = 1
		r.BlastRadiusPercent = 100
		for j := range r.Parameters {
			switch r.Parameters[j].Name {
			case "requeue_reason":
				r.Parameters[j].AllowedValues = []string{"STALE_STREAM"}
			case "priority":
				r.Parameters[j].AllowedValues = []string{"NORMAL"}
			}
		}
	}
	recipes[1] = recipes[1].WithComputedDigest()
	recipes[0].RollbackRecipe = recipes[1].Ref()
	recipes[0] = recipes[0].WithComputedDigest()
	return recipes
}

// This is catalog/schema recognition, not executor enablement. The generic
// RemediationService and M14 executor still accept simulation only.
func isCollectionRequestRecipe(r Recipe) bool {
	return r.Assurance == domain.AssuranceLive && r.Version == CollectionRequestRecipeVersion &&
		(r.ID == RecipeEvidenceCollectionRequeue && r.Operation == OperationEvidenceCollectionRequeue ||
			r.ID == RecipeEvidenceCollectionRestore && r.Operation == OperationEvidenceCollectionRestore) &&
		r.MaxTargets == 1 && r.MaxConcurrency == 1 && r.CanaryTargets == 1
}
