package remediationrunner

import (
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/remediation"
)

// BindingCode is deliberately closed: an executor refusal must not echo a
// caller-provided target or argument value into an audit or operator surface.
type BindingCode string

const (
	BindUnverifiedCatalog BindingCode = "UNVERIFIED_RECIPE_CATALOG"
	BindCatalogExpired    BindingCode = "RECIPE_CATALOG_EXPIRED"
	BindMissingRecipe     BindingCode = "RECIPE_NOT_IN_CATALOG"
	BindDigestMismatch    BindingCode = "RECIPE_DIGEST_MISMATCH"
	BindOperation         BindingCode = "RECIPE_OPERATION_MISMATCH"
	BindArguments         BindingCode = "RECIPE_ARGUMENT_MISMATCH"
	BindTargets           BindingCode = "RECIPE_TARGET_MISMATCH"
	BindStage             BindingCode = "RECIPE_STAGE_MISMATCH"
	BindRecipeExpired     BindingCode = "RECIPE_EXPIRED"
)

type BindingError struct{ Code BindingCode }

func (e BindingError) Error() string {
	return fmt.Sprintf("remediation execution unit refused: %s", e.Code)
}

// bindExecutionUnit repeats the authorization check at the execution edge.
// The application does policy admission and durable orchestration; this adapter
// independently re-resolves the pinned recipe from a signed catalog and proves
// the operation, typed arguments, targets and stage are still what that recipe
// permits.  It has no fallback to the caller's claimed values.
func bindExecutionUnit(catalog *remediation.Catalog, unit ExecutionUnit, now time.Time) error {
	if catalog == nil || !catalog.Verified() {
		return BindingError{Code: BindUnverifiedCatalog}
	}
	if !catalog.ExecutableAt(now) {
		return BindingError{Code: BindCatalogExpired}
	}
	if unit.Recipe.IsZero() {
		return BindingError{Code: BindMissingRecipe}
	}
	recipe, err := catalog.Resolve(unit.Recipe)
	if err != nil {
		var mismatch remediation.DigestMismatchError
		if asDigestMismatch(err, &mismatch) {
			return BindingError{Code: BindDigestMismatch}
		}
		return BindingError{Code: BindMissingRecipe}
	}
	if recipe.Operation != unit.Operation {
		return BindingError{Code: BindOperation}
	}
	if now.IsZero() || !recipe.ExpiresAt.After(now) {
		return BindingError{Code: BindRecipeExpired}
	}
	if !stageMatchesRecipe(recipe, unit.Stage) {
		return BindingError{Code: BindStage}
	}
	if !argumentsMatchRecipe(recipe, unit.Arguments) {
		return BindingError{Code: BindArguments}
	}
	if !targetsMatchRecipe(recipe, unit.Targets) {
		return BindingError{Code: BindTargets}
	}
	return nil
}

// ValidateExecutionUnit is the executor-side admission check for an execution
// unit. Stateful simulation adapters call it before recording their simulated
// effect; it intentionally duplicates the runner's check so a different
// executor implementation cannot bypass signed recipe binding.
func ValidateExecutionUnit(catalog *remediation.Catalog, unit domain.ExecutionUnit, now time.Time) error {
	if err := unit.Validate(); err != nil {
		return err
	}
	if now.IsZero() {
		return fmt.Errorf("execution requires a server-supplied instant")
	}
	return bindExecutionUnit(catalog, unit, now)
}

// asDigestMismatch stays separate to make the catalog error type an internal
// detail of this package's boundary vocabulary.
func asDigestMismatch(err error, target *remediation.DigestMismatchError) bool {
	if err == nil {
		return false
	}
	return errors.As(err, target)
}

func stageMatchesRecipe(recipe remediation.Recipe, stage domain.RemediationStage) bool {
	switch stage {
	case domain.RemediationStageCanary, domain.RemediationStageRollout:
		return recipe.HasRollback()
	case domain.RemediationStageRollback:
		// In the bounded M14 vocabulary the rollback recipe is terminal: it
		// cannot itself name another rollback.  This prevents a rollback stage
		// from executing a forward definition merely because it shares roles.
		return !recipe.HasRollback()
	default:
		return false
	}
}

func argumentsMatchRecipe(recipe remediation.Recipe, arguments domain.TypedArguments) bool {
	if len(arguments) > len(recipe.Parameters) {
		return false
	}
	for _, parameter := range recipe.Parameters {
		argument, found := arguments.Lookup(parameter.Name)
		if !found {
			if parameter.Required {
				return false
			}
			continue
		}
		if argument.Type != parameter.Type {
			return false
		}
		switch parameter.Type {
		case domain.ParameterEnum:
			if !slices.Contains(parameter.AllowedValues, argument.Enum) {
				return false
			}
		case domain.ParameterInteger:
			if argument.Integer < parameter.Minimum || argument.Integer > parameter.Maximum {
				return false
			}
		case domain.ParameterDuration:
			if argument.Duration < 0 || argument.Duration < time.Duration(parameter.Minimum) || argument.Duration > time.Duration(parameter.Maximum) {
				return false
			}
		case domain.ParameterBoolean:
			// The typed value has no additional value-domain restriction.
		default:
			return false
		}
	}
	return true
}

func targetsMatchRecipe(recipe remediation.Recipe, targets []domain.ResolvedTarget) bool {
	if len(targets) == 0 || len(targets) > recipe.MaxTargets {
		return false
	}
	seen := make(map[domain.RemediationTarget]struct{}, len(targets))
	for _, target := range targets {
		if !slices.Contains(recipe.PermittedTargetRoles, target.Role) {
			return false
		}
		if _, exists := seen[target.Target]; exists {
			return false
		}
		seen[target.Target] = struct{}{}
	}
	return true
}
