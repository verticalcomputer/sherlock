// Package remediationrunner is the adapter side of the remediation executor
// boundary, mirroring internal/diagnosticrunner. It holds the simulated
// executor and, for now, the port it satisfies; the port moves to
// internal/application/remediation.go with the use cases that consume it.
//
// Nothing in this package performs I/O of any kind: no process, no host, no
// network, no filesystem, no clock of its own. That is not an implementation
// detail of the simulated executor — it is the whole assurance claim of this
// milestone, and the imports of this file are the evidence for it.
package remediationrunner

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/remediation"
)

// ExecutionUnit and ExecutionResult are declared in the domain so that the
// application layer can declare its executor port without importing this
// adapter package. They are aliased here because this is where they are
// implemented against.
type ExecutionUnit = domain.ExecutionUnit

type ExecutionResult = domain.ExecutionResult

// Executor is the entire mutation surface of the system.
//
// Assurance is part of the port, not a property of a particular adapter: the
// use case refuses to construct unless its executor reports SIMULATED, so
// wave-2 wiring cannot bind a different implementation to the injectable port
// and silently obtain a live path.
type Executor interface {
	Execute(ctx context.Context, unit ExecutionUnit, now time.Time) (ExecutionResult, error)
	Assurance() domain.AssuranceClass
}

// UnsupportedOperationError is returned when a scripted outcome is missing.
// The simulated executor refuses rather than defaulting to success, because a
// default success is indistinguishable from a repair that never happened.
type UnsupportedOperationError struct {
	Operation remediation.RecipeOperation
	Target    domain.RemediationTarget
}

func (e UnsupportedOperationError) Error() string {
	return fmt.Sprintf("simulated executor has no scripted outcome for operation %s", e.Operation)
}

type scriptKey struct {
	operation remediation.RecipeOperation
	target    domain.RemediationTarget
}

// SimulatedExecutor is a recorded executor. It answers from a scripted table
// keyed by (Operation, Target) and records every idempotency key it has seen.
type SimulatedExecutor struct {
	mutex    sync.Mutex
	script   map[scriptKey]domain.ExecutionOutcome
	recorded map[string]ExecutionResult
	catalog  *remediation.Catalog
}

// ScriptedOutcome is one entry of the simulated executor's table.
type ScriptedOutcome struct {
	Operation remediation.RecipeOperation
	Target    domain.RemediationTarget
	Outcome   domain.ExecutionOutcome
}

func NewSimulatedExecutor(outcomes []ScriptedOutcome) (*SimulatedExecutor, error) {
	return newSimulatedExecutor(nil, outcomes)
}

// NewVerifiedSimulatedExecutor constructs the execution-facing adapter.  It
// accepts only a catalog that was admitted by RecipeTrustStore.Verify, so an
// in-memory catalog built by a caller cannot become runtime authority merely
// by being handed to the executor.
func NewVerifiedSimulatedExecutor(catalog *remediation.Catalog, outcomes []ScriptedOutcome) (*SimulatedExecutor, error) {
	if catalog == nil || !catalog.Verified() {
		return nil, BindingError{Code: BindUnverifiedCatalog}
	}
	return newSimulatedExecutor(catalog, outcomes)
}

func newSimulatedExecutor(catalog *remediation.Catalog, outcomes []ScriptedOutcome) (*SimulatedExecutor, error) {
	executor := &SimulatedExecutor{
		script:   make(map[scriptKey]domain.ExecutionOutcome, len(outcomes)),
		recorded: make(map[string]ExecutionResult),
		catalog:  catalog,
	}
	for _, outcome := range outcomes {
		if err := outcome.Operation.Validate(); err != nil {
			return nil, err
		}
		if err := outcome.Outcome.Validate(); err != nil {
			return nil, err
		}
		if !domain.ValidRemediationTarget(string(outcome.Target)) {
			return nil, fmt.Errorf("scripted outcome target is invalid")
		}
		key := scriptKey{operation: outcome.Operation, target: outcome.Target}
		if _, exists := executor.script[key]; exists {
			return nil, fmt.Errorf("scripted outcomes must be unique per operation and target")
		}
		executor.script[key] = outcome.Outcome
	}
	return executor, nil
}

// Assurance reports what this executor actually touches.
func (e *SimulatedExecutor) Assurance() domain.AssuranceClass { return domain.AssuranceSimulated }

// Execute answers from the script. A repeated idempotency key returns the
// previously recorded result rather than acting again, which is what makes a
// duplicate delivery after an acknowledgement loss harmless.
//
// The observation instant is the server-causal now the caller passes in. An
// executor that derived it from the unit's deadline would be inventing a
// timestamp it does not have, and the receipt would then claim an observation
// at an instant when nothing was observed.
func (e *SimulatedExecutor) Execute(ctx context.Context, unit ExecutionUnit, now time.Time) (ExecutionResult, error) {
	if err := ctx.Err(); err != nil {
		return ExecutionResult{}, err
	}
	if now.IsZero() {
		return ExecutionResult{}, fmt.Errorf("execution requires a server-supplied instant")
	}
	if e.catalog != nil {
		if err := ValidateExecutionUnit(e.catalog, unit, now); err != nil {
			return ExecutionResult{}, err
		}
	} else if err := unit.Validate(); err != nil {
		return ExecutionResult{}, err
	}
	e.mutex.Lock()
	defer e.mutex.Unlock()
	if recorded, replayed := e.recorded[unit.IdempotencyKey]; replayed {
		recorded.PerTarget = slices.Clone(recorded.PerTarget)
		return recorded, nil
	}

	perTarget := make([]domain.RemediationTargetOutcome, 0, len(unit.Targets))
	aggregate := domain.ExecutionExecuted
	for _, target := range unit.Targets {
		outcome, scripted := e.script[scriptKey{operation: unit.Operation, target: target.Target}]
		if !scripted {
			return ExecutionResult{}, UnsupportedOperationError{Operation: unit.Operation, Target: target.Target}
		}
		perTarget = append(perTarget, domain.RemediationTargetOutcome{Target: target.Target, Outcome: outcome})
		aggregate = worseOutcome(aggregate, outcome)
	}
	result := ExecutionResult{Outcome: aggregate, PerTarget: perTarget, ObservedAt: now.UTC()}
	e.recorded[unit.IdempotencyKey] = result
	return ExecutionResult{
		Outcome: result.Outcome, PerTarget: slices.Clone(result.PerTarget), ObservedAt: result.ObservedAt,
	}, nil
}

// Recorded reports whether a key has already been executed.
func (e *SimulatedExecutor) Recorded(key string) (ExecutionResult, bool) {
	e.mutex.Lock()
	defer e.mutex.Unlock()
	result, exists := e.recorded[key]
	result.PerTarget = slices.Clone(result.PerTarget)
	return result, exists
}

// worseOutcome collapses per-target outcomes into one. UNKNOWN dominates
// everything: if any target's fate is unknown the attempt's fate is unknown,
// and the run is contained rather than retried. The collapse is deliberately
// not softened to preserve a partial success — containment means a human must
// look, which is the right response to an ambiguous mutation. The per-target
// outcomes travel alongside it precisely so that human can see which targets
// did succeed.
func worseOutcome(left, right domain.ExecutionOutcome) domain.ExecutionOutcome {
	if outcomeSeverity(right) > outcomeSeverity(left) {
		return right
	}
	return left
}

func outcomeSeverity(outcome domain.ExecutionOutcome) int {
	switch outcome {
	case domain.ExecutionExecuted:
		return 0
	case domain.ExecutionRefused:
		return 1
	case domain.ExecutionFailed:
		return 2
	case domain.ExecutionTimedOut:
		return 3
	default:
		return 4
	}
}
