package investigationapi

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/commandpack"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/investigationtools"
)

// Model-visible diagnostic tool identifiers. Each maps to exactly one reviewed
// command-pack definition; the mapping is server-owned and a model never names
// a pack definition directly.
const (
	ECCCountersToolID  = investigationtools.DiagnosticECCCountersToolID
	RowRemapToolID     = investigationtools.DiagnosticRowRemapToolID
	RetiredPagesToolID = investigationtools.DiagnosticRetiredPagesToolID
)

// DiagnosticDispatcher performs one bounded reviewed remote execution and
// returns its immutable result. It applies idempotencyKey at the external
// boundary: an exact replay must return the in-flight or completed run rather
// than executing a second time, which is what closes the crash-after-dispatch
// window.
type DiagnosticDispatcher interface {
	DispatchDiagnostic(ctx context.Context, idempotencyKey string, request domain.DiagnosticRequest, plan commandpack.ExecutionPlan) (domain.DiagnosticAttemptResult, error)
}

// DiagnosticEvidenceSink commits a projected envelope. Diagnostic results enter
// durable storage through the same path as collection results; nothing about
// this envelope is special once it is written.
type DiagnosticEvidenceSink interface {
	RecordDiagnosticEvidence(context.Context, domain.InvestigationID, domain.EvidenceEnvelope) (domain.InvestigationEvidence, error)
}

type diagnosticAuthorityStore interface {
	LoadInvestigation(context.Context, domain.InvestigationID) (application.InvestigationSnapshot, bool, error)
}

// DiagnosticExecutor turns an admitted diagnostic action into a reviewed pack
// invocation and its results into evidence envelopes. It owns no argv, no host
// selection beyond the durable action's targets, and no privilege: everything
// it can reach is what the signed pack and the investigation's own scope
// already permit.
type DiagnosticExecutor struct {
	store      diagnosticAuthorityStore
	catalog    *commandpack.Catalog
	dispatcher DiagnosticDispatcher
	evidence   DiagnosticEvidenceSink
	clock      application.Clock
	clusters   map[domain.ClusterID]struct{}
	bindings   map[string]investigationtools.DiagnosticBinding
}

func NewDiagnosticExecutor(store diagnosticAuthorityStore, catalog *commandpack.Catalog, dispatcher DiagnosticDispatcher, evidence DiagnosticEvidenceSink, clock application.Clock, clusters []domain.ClusterID) (*DiagnosticExecutor, error) {
	if store == nil || catalog == nil || dispatcher == nil || evidence == nil || clock == nil || len(clusters) == 0 {
		return nil, fmt.Errorf("diagnostic executor dependencies and cluster allow-list are required")
	}
	allowed := make(map[domain.ClusterID]struct{}, len(clusters))
	for _, cluster := range clusters {
		if cluster == "" {
			return nil, fmt.Errorf("diagnostic executor cluster allow-list is invalid")
		}
		allowed[cluster] = struct{}{}
	}
	bindings := make(map[string]investigationtools.DiagnosticBinding, 4)
	for _, toolID := range []investigationtools.ToolID{investigationtools.DiagnosticECCCountersToolID, investigationtools.DiagnosticRowRemapToolID, investigationtools.DiagnosticRetiredPagesToolID, investigationtools.DiagnosticKernelXIDToolID} {
		binding, ok := investigationtools.DiagnosticBindingForTool(toolID)
		if !ok {
			return nil, fmt.Errorf("diagnostic tool %q has no reviewed definition binding", toolID)
		}
		bindings[string(toolID)] = binding
	}
	// Fail at construction, not at the first live investigation: a bound tool
	// whose definition is absent from the verified pack must not be reachable.
	for toolID, binding := range bindings {
		if _, err := catalog.Plan(commandpack.Invocation{DefinitionID: string(binding.DefinitionID), DefinitionVersion: binding.DefinitionVersion, Targets: []commandpack.Target{{Name: "probe", Role: commandpack.TargetCompute}}}); err != nil && strings.Contains(err.Error(), "not present in the verified catalog") {
			return nil, fmt.Errorf("diagnostic tool %q is bound to a definition the verified pack does not contain", toolID)
		}
	}
	return &DiagnosticExecutor{store: store, catalog: catalog, dispatcher: dispatcher, evidence: evidence, clock: clock, clusters: allowed, bindings: bindings}, nil
}

// SupportsToolID reports whether this executor owns a model-visible tool, so a
// router can send evidence lookups and diagnostics to the right place without
// either one guessing.
func (executor *DiagnosticExecutor) SupportsToolID(toolID string) bool {
	if executor == nil {
		return false
	}
	_, bound := executor.bindings[toolID]
	return bound
}

func (executor *DiagnosticExecutor) ExecuteInvestigationAction(ctx context.Context, idempotencyKey string, action domain.InvestigationAction) (application.InvestigationExecutionResult, error) {
	investigationID, err := executor.authorize(idempotencyKey, action)
	if err != nil {
		return application.InvestigationExecutionResult{}, err
	}
	snapshot, found, err := executor.store.LoadInvestigation(ctx, investigationID)
	if err != nil {
		return application.InvestigationExecutionResult{}, fmt.Errorf("load diagnostic authority: %w", err)
	}
	if !found {
		return application.InvestigationExecutionResult{}, application.ErrInvestigationNotFound
	}
	request := snapshot.Investigation.Request()
	if err := executor.matchesDurableAction(snapshot, action, request); err != nil {
		return application.InvestigationExecutionResult{}, err
	}
	binding := executor.bindings[action.ToolID]

	// The pack, not this adapter, produces the argv. Planning here proves the
	// targets and roles satisfy the signed definition before anything is
	// dispatched, so a target the definition does not admit never leaves the
	// controller.
	targets := make([]commandpack.Target, 0, len(action.Targets))
	for _, target := range action.Targets {
		targets = append(targets, commandpack.Target{Name: target, Role: commandpack.TargetCompute})
	}
	plan, err := executor.catalog.Plan(commandpack.Invocation{DefinitionID: string(binding.DefinitionID), DefinitionVersion: binding.DefinitionVersion, Targets: targets})
	if err != nil {
		return application.InvestigationExecutionResult{}, fmt.Errorf("plan reviewed diagnostic invocation: %w", err)
	}
	if plan.RequiresPrivilege() {
		// M12 ships no privilege adapter. A definition that grew a privilege
		// requirement must stop the run rather than be executed unprivileged.
		return application.InvestigationExecutionResult{}, fmt.Errorf("diagnostic %q requires privilege, which this executor cannot grant", binding.DefinitionID)
	}
	definitionID, definitionVersion, definitionDigest := plan.DefinitionIdentity()
	digest, err := domain.ParseSHA256(definitionDigest)
	if err != nil {
		return application.InvestigationExecutionResult{}, fmt.Errorf("verified definition digest is unreadable: %w", err)
	}
	packID, packVersion := executor.catalog.Metadata().PackID, executor.catalog.Metadata().PackVersion

	now := executor.clock.Now().UTC()
	timeout := plan.Limits().TimeoutSeconds
	diagnosticRequest := domain.DiagnosticRequest{
		// The run identity is the action digest, so re-dispatching after a crash
		// addresses the same run instead of starting a second one.
		RunID:     domain.DiagnosticRunID("investigation-" + action.Digest.String()[:32]),
		ClusterID: request.ClusterID,
		Definition: domain.DiagnosticDefinitionRef{
			PackID: packID, PackVersion: packVersion,
			DefinitionID: domain.DiagnosticDefinitionID(definitionID), DefinitionVersion: definitionVersion, DefinitionDigest: digest,
		},
		Privilege: domain.DiagnosticUnprivileged, Targets: diagnosticTargets(action.Targets),
		RequestedBy: "sherlock-investigator", IdempotencyKey: strings.ReplaceAll(idempotencyKey, "/", "-"),
		RequestedAt: now, Deadline: now.Add(time.Duration(timeout)*time.Second + time.Minute), MaxAttempts: 1,
	}
	if err := diagnosticRequest.Validate(); err != nil {
		return application.InvestigationExecutionResult{}, fmt.Errorf("translated diagnostic request is invalid: %w", err)
	}
	attempt, err := executor.dispatcher.DispatchDiagnostic(ctx, idempotencyKey, diagnosticRequest, plan)
	if err != nil {
		return application.InvestigationExecutionResult{}, err
	}
	envelope, err := domain.DiagnosticEvidenceForAttempt(diagnosticRequest, attempt, binding.ObservationLookback)
	if err != nil {
		return application.InvestigationExecutionResult{}, err
	}
	entry, err := executor.evidence.RecordDiagnosticEvidence(ctx, investigationID, envelope)
	if err != nil {
		return application.InvestigationExecutionResult{}, fmt.Errorf("commit diagnostic evidence: %w", err)
	}
	if err := entry.ValidateFor(snapshot.Investigation); err != nil {
		return application.InvestigationExecutionResult{}, fmt.Errorf("diagnostic evidence is outside investigation scope: %w", err)
	}
	receipt := domain.ChecksumSHA256([]byte(idempotencyKey + "\x00" + string(envelope.ID())))
	return application.InvestigationExecutionResult{Receipt: "diagnostic:" + receipt.String(), Evidence: []domain.InvestigationEvidence{entry}, DiagnosticRunID: diagnosticRequest.RunID}, nil
}

// authorize checks everything decidable without loading durable state, so a
// malformed or unbound invocation is refused before it can reach a host.
func (executor *DiagnosticExecutor) authorize(idempotencyKey string, action domain.InvestigationAction) (domain.InvestigationID, error) {
	const prefix = "investigation/"
	const separator = "/action/"
	if executor == nil || !executor.SupportsToolID(action.ToolID) {
		return "", fmt.Errorf("diagnostic invocation names no reviewed diagnostic tool")
	}
	if !action.Diagnostic || action.Privileged || len(action.Arguments) != 0 || action.Validate() != nil {
		return "", fmt.Errorf("diagnostic invocation is invalid")
	}
	if !strings.HasPrefix(idempotencyKey, prefix) {
		return "", fmt.Errorf("diagnostic idempotency key is invalid")
	}
	parts := strings.Split(strings.TrimPrefix(idempotencyKey, prefix), separator)
	if len(parts) != 2 || parts[0] == "" || parts[1] != string(action.ID) {
		return "", fmt.Errorf("diagnostic idempotency key is invalid")
	}
	return domain.InvestigationID(parts[0]), nil
}

// matchesDurableAction refuses to execute anything the controller did not
// durably admit. The in-memory action is untrusted relative to the row.
func (executor *DiagnosticExecutor) matchesDurableAction(snapshot application.InvestigationSnapshot, action domain.InvestigationAction, request domain.InvestigationRequest) error {
	durable := snapshot.ProposedAction
	if durable == nil || durable.ID != action.ID || durable.ToolID != action.ToolID || durable.Digest != action.Digest ||
		durable.Diagnostic != action.Diagnostic || durable.Privileged != action.Privileged || len(durable.Arguments) != 0 ||
		!slices.Equal(durable.Targets, action.Targets) {
		return fmt.Errorf("diagnostic does not match the durable proposed action")
	}
	if _, allowed := executor.clusters[request.ClusterID]; !allowed {
		return fmt.Errorf("diagnostic is outside the executor cluster allow-list")
	}
	if !targetsWithin(action.Targets, request.Scope.EntityIDs) {
		return fmt.Errorf("diagnostic target is outside durable investigation scope")
	}
	if request.Budget.MaxDiagnosticCalls < 1 {
		return fmt.Errorf("investigation was granted no diagnostic budget")
	}
	return nil
}

func diagnosticTargets(values []string) []domain.DiagnosticTarget {
	targets := make([]domain.DiagnosticTarget, 0, len(values))
	for _, value := range values {
		targets = append(targets, domain.DiagnosticTarget(value))
	}
	return targets
}

var _ application.InvestigationExecutor = (*DiagnosticExecutor)(nil)

// RoutingExecutor sends each admitted action to the executor that owns its
// tool. The controller stays unaware that two kinds of work exist: it calls
// one executor and receives evidence, exactly as before M12.
type RoutingExecutor struct {
	diagnostics *DiagnosticExecutor
	lookups     application.InvestigationExecutor
}

func NewRoutingExecutor(lookups application.InvestigationExecutor, diagnostics *DiagnosticExecutor) (*RoutingExecutor, error) {
	if lookups == nil || diagnostics == nil {
		return nil, fmt.Errorf("routing executor requires both an evidence lookup and a diagnostic executor")
	}
	return &RoutingExecutor{diagnostics: diagnostics, lookups: lookups}, nil
}

func (executor *RoutingExecutor) ExecuteInvestigationAction(ctx context.Context, idempotencyKey string, action domain.InvestigationAction) (application.InvestigationExecutionResult, error) {
	if executor == nil {
		return application.InvestigationExecutionResult{}, fmt.Errorf("routing executor is unavailable")
	}
	// The durable action's own operation class decides the route. A tool bound
	// to a diagnostic must never be served from committed evidence, and an
	// action not marked diagnostic must never reach a host, so disagreement
	// between the two is refused rather than resolved in either direction.
	bound := executor.diagnostics.SupportsToolID(action.ToolID)
	if bound != action.Diagnostic {
		return application.InvestigationExecutionResult{}, fmt.Errorf("action operation class does not match its tool binding")
	}
	if bound {
		return executor.diagnostics.ExecuteInvestigationAction(ctx, idempotencyKey, action)
	}
	return executor.lookups.ExecuteInvestigationAction(ctx, idempotencyKey, action)
}

var _ application.InvestigationExecutor = (*RoutingExecutor)(nil)
