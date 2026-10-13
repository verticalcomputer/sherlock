package investigationapi

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/commandpack"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/investigationtools"
)

type diagnosticStore struct {
	snapshot application.InvestigationSnapshot
}

func (store *diagnosticStore) LoadInvestigation(context.Context, domain.InvestigationID) (application.InvestigationSnapshot, bool, error) {
	return store.snapshot, true, nil
}

type recordedDispatch struct {
	idempotencyKey string
	request        domain.DiagnosticRequest
	argv           []string
	targets        []commandpack.Target
}

type diagnosticDispatcherFake struct {
	dispatches []recordedDispatch
	statuses   map[string]domain.DiagnosticTargetStatus
	err        error
}

func (fake *diagnosticDispatcherFake) DispatchDiagnostic(_ context.Context, idempotencyKey string, request domain.DiagnosticRequest, plan commandpack.ExecutionPlan) (domain.DiagnosticAttemptResult, error) {
	fake.dispatches = append(fake.dispatches, recordedDispatch{idempotencyKey: idempotencyKey, request: request, argv: plan.Argv(), targets: plan.Targets()})
	if fake.err != nil {
		return domain.DiagnosticAttemptResult{}, fake.err
	}
	started := request.RequestedAt.Add(time.Second)
	results := make([]domain.DiagnosticTargetResult, 0, len(request.Targets))
	code := 0
	for _, target := range request.Targets {
		status := domain.DiagnosticTargetSucceeded
		if fake.statuses != nil {
			if override, ok := fake.statuses[string(target)]; ok {
				status = override
			}
		}
		result := domain.DiagnosticTargetResult{Target: target, Status: status}
		if status == domain.DiagnosticTargetSucceeded {
			result.ExitCode, result.StdoutBytes, result.StdoutSHA256 = &code, 256, domain.ChecksumSHA256([]byte(target))
		} else {
			result.ErrorCode = "EXIT_NONZERO"
		}
		results = append(results, result)
	}
	return domain.DiagnosticAttemptResult{WorkID: "work-1", RunID: request.RunID, Attempt: 1, RunnerID: "head-1", PlanDigest: domain.ChecksumSHA256([]byte("plan")), StartedAt: started, CompletedAt: started.Add(2 * time.Second), Targets: results}, nil
}

type diagnosticEvidenceSinkFake struct{ committed []domain.EvidenceEnvelope }

func (fake *diagnosticEvidenceSinkFake) RecordDiagnosticEvidence(_ context.Context, investigationID domain.InvestigationID, envelope domain.EvidenceEnvelope) (domain.InvestigationEvidence, error) {
	fake.committed = append(fake.committed, envelope)
	entities := make([]string, 0, len(envelope.Coverage().Expected))
	for _, target := range envelope.Coverage().Expected {
		if target.Kind == domain.EvidenceTargetNode {
			entities = append(entities, string(target.ID))
		}
	}
	return domain.InvestigationEvidence{EvidenceID: envelope.ID(), InvestigationID: investigationID, ClusterID: envelope.ClusterID(), EntityIDs: entities, Status: envelope.Status(), ObservedStart: envelope.TimeRange().Start, ObservedEnd: envelope.TimeRange().End, RecordedAt: envelope.CollectedAt()}, nil
}

type diagnosticClock struct{ now time.Time }

func (clock diagnosticClock) Now() time.Time { return clock.now }

func diagnosticCatalog(t *testing.T) *commandpack.Catalog {
	t.Helper()
	definitions, err := commandpack.PilotDefinitions(commandpack.PilotIdentities{
		NvidiaSMI:  commandpack.ExecutableIdentity{Path: "/usr/bin/nvidia-smi", SHA256: strings.Repeat("a", 64)},
		Journalctl: commandpack.ExecutableIdentity{Path: "/usr/bin/journalctl", SHA256: strings.Repeat("b", 64)},
		Scontrol:   commandpack.ExecutableIdentity{Path: "/usr/bin/scontrol", SHA256: strings.Repeat("c", 64)},
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 22, 9, 0, 0, 0, time.UTC)
	pack := commandpack.Pack{SchemaVersion: commandpack.SchemaVersion, ID: "standard.readonly", Version: "1.1.0", Issuer: "sherlock.security", IssuedAt: now, ExpiresAt: now.Add(24 * time.Hour), MinimumRunner: "1.2.0", MaximumRunner: "1.9.0",
		Reviews:     []commandpack.Review{{ReviewerID: "alice", ReviewedAt: now.Add(-2 * time.Minute), Approved: true}, {ReviewerID: "bob", ReviewedAt: now.Add(-time.Minute), Approved: true}},
		Definitions: definitions}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	release, err := commandpack.Sign(pack, "root.current", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	store, err := commandpack.NewTrustStore([]commandpack.TrustRoot{{ID: "root.current", Issuer: pack.Issuer, PublicKey: publicKey, ActivatesAt: pack.IssuedAt.Add(-time.Hour), RetiresAt: pack.ExpiresAt.Add(time.Hour)}})
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := store.Verify(release, "1.4.0", pack.IssuedAt.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	return catalog
}

func diagnosticSnapshot(t *testing.T, now time.Time, grant int, targets ...string) application.InvestigationSnapshot {
	t.Helper()
	request := domain.InvestigationRequest{ID: "inv-1", IncidentID: "incident-1", ClusterID: "cluster-a", Question: "Is the ECC fault degrading?", RequestedBy: "actor-1", IdempotencyKey: "request-1",
		Scope:           domain.InvestigationScope{EntityKind: "node", EntityIDs: targets, Start: now.Add(-time.Hour), End: now},
		SuccessCriteria: []string{"Separate a contained fault from a degrading device"},
		Budget:          domain.InvestigationBudget{MaxDecisions: 3, MaxToolCalls: 2, MaxDiagnosticCalls: grant, MaxFanOut: 4}, RequestedAt: now.Add(-time.Minute), Deadline: now.Add(time.Hour)}
	value, err := domain.NewInvestigation(request)
	if err != nil {
		t.Fatal(err)
	}
	return application.InvestigationSnapshot{Investigation: value}
}

func diagnosticAction(targets ...string) domain.InvestigationAction {
	now := time.Date(2026, 8, 22, 10, 0, 0, 0, time.UTC)
	return domain.InvestigationAction{ID: "action-1", ToolID: ECCCountersToolID, Digest: domain.ChecksumSHA256([]byte("action")), Diagnostic: true, FanOut: len(targets), Targets: targets, Start: now.Add(-time.Hour), End: now}
}

func newDiagnosticExecutor(t *testing.T, store *diagnosticStore, dispatcher DiagnosticDispatcher, sink DiagnosticEvidenceSink, now time.Time) *DiagnosticExecutor {
	t.Helper()
	executor, err := NewDiagnosticExecutor(store, diagnosticCatalog(t), dispatcher, sink, diagnosticClock{now}, []domain.ClusterID{"cluster-a"})
	if err != nil {
		t.Fatal(err)
	}
	return executor
}

// The adapter owns no argv. What reaches a host must be exactly what the signed
// pack produced for the durable action's own targets.
func TestDiagnosticExecutorPlansTheSignedArgvAndCommitsOrdinaryEvidence(t *testing.T) {
	now := time.Date(2026, 8, 22, 10, 0, 0, 0, time.UTC)
	action := diagnosticAction("comp001", "comp002")
	store := &diagnosticStore{snapshot: diagnosticSnapshot(t, now, 2, "comp001", "comp002")}
	store.snapshot.ProposedAction = &action
	dispatcher := &diagnosticDispatcherFake{}
	sink := &diagnosticEvidenceSinkFake{}
	executor := newDiagnosticExecutor(t, store, dispatcher, sink, now)

	result, err := executor.ExecuteInvestigationAction(context.Background(), "investigation/inv-1/action/action-1", action)
	if err != nil {
		t.Fatal(err)
	}
	if len(dispatcher.dispatches) != 1 {
		t.Fatalf("dispatches = %d, want 1", len(dispatcher.dispatches))
	}
	dispatch := dispatcher.dispatches[0]
	wantArgv := []string{"/usr/bin/nvidia-smi", "--query-gpu=index,uuid,ecc.errors.corrected.volatile.total,ecc.errors.uncorrected.volatile.total,ecc.errors.corrected.aggregate.total,ecc.errors.uncorrected.aggregate.total", "--format=csv,noheader,nounits"}
	if len(dispatch.argv) != len(wantArgv) {
		t.Fatalf("argv = %v, want %v", dispatch.argv, wantArgv)
	}
	for index, want := range wantArgv {
		if dispatch.argv[index] != want {
			t.Fatalf("argv[%d] = %q, want %q", index, dispatch.argv[index], want)
		}
	}
	if dispatch.request.Privilege != domain.DiagnosticUnprivileged {
		t.Fatalf("privilege = %s", dispatch.request.Privilege)
	}
	if len(dispatch.targets) != 2 || dispatch.targets[0].Role != commandpack.TargetCompute {
		t.Fatalf("targets = %+v", dispatch.targets)
	}
	if string(dispatch.request.Definition.DefinitionID) != "gpu.ecc_counters" || dispatch.request.Definition.PackID != "standard.readonly" {
		t.Fatalf("definition reference = %+v", dispatch.request.Definition)
	}

	// The result must be an ordinary evidence envelope committed through the
	// same path, and the controller must receive an ordinary evidence reference.
	if len(sink.committed) != 1 {
		t.Fatalf("committed envelopes = %d", len(sink.committed))
	}
	envelope := sink.committed[0]
	if envelope.Status() != domain.EvidenceComplete || !envelope.Coverage().Complete() {
		t.Fatalf("envelope = %s complete=%t", envelope.Status(), envelope.Coverage().Complete())
	}
	if len(result.Evidence) != 1 || result.Evidence[0].EvidenceID != envelope.ID() {
		t.Fatalf("result evidence = %+v", result.Evidence)
	}
	if err := result.Evidence[0].ValidateFor(store.snapshot.Investigation); err != nil {
		t.Fatalf("the committed reference must satisfy investigation scope validation: %v", err)
	}
	if result.Receipt == "" || !strings.HasPrefix(result.Receipt, "diagnostic:") {
		t.Fatalf("receipt = %q", result.Receipt)
	}
	if result.DiagnosticRunID != dispatch.request.RunID {
		t.Fatalf("result run = %q, want %q", result.DiagnosticRunID, dispatch.request.RunID)
	}

	// Re-dispatch after a crash must address the same run, which is what makes
	// the external boundary's idempotency meaningful.
	if _, err := executor.ExecuteInvestigationAction(context.Background(), "investigation/inv-1/action/action-1", action); err != nil {
		t.Fatal(err)
	}
	if dispatcher.dispatches[1].request.RunID != dispatch.request.RunID {
		t.Fatalf("re-dispatch used a different run: %s then %s", dispatch.request.RunID, dispatcher.dispatches[1].request.RunID)
	}
	if dispatcher.dispatches[1].idempotencyKey != dispatch.idempotencyKey {
		t.Fatal("re-dispatch used a different idempotency key")
	}
}

// A host that failed must not discard the hosts that answered.
func TestDiagnosticExecutorCommitsPartialResults(t *testing.T) {
	now := time.Date(2026, 8, 22, 10, 0, 0, 0, time.UTC)
	action := diagnosticAction("comp001", "comp002")
	store := &diagnosticStore{snapshot: diagnosticSnapshot(t, now, 2, "comp001", "comp002")}
	store.snapshot.ProposedAction = &action
	sink := &diagnosticEvidenceSinkFake{}
	dispatcher := &diagnosticDispatcherFake{statuses: map[string]domain.DiagnosticTargetStatus{"comp002": domain.DiagnosticTargetFailed}}
	result, err := newDiagnosticExecutor(t, store, dispatcher, sink, now).ExecuteInvestigationAction(context.Background(), "investigation/inv-1/action/action-1", action)
	if err != nil {
		t.Fatalf("a partly failed diagnostic must still commit what was observed: %v", err)
	}
	if len(result.Evidence) != 1 || result.Evidence[0].Status != domain.EvidencePartial {
		t.Fatalf("result = %+v", result.Evidence)
	}
}

func TestDiagnosticExecutorRefusesEverythingOutsideDurableAuthority(t *testing.T) {
	now := time.Date(2026, 8, 22, 10, 0, 0, 0, time.UTC)
	base := diagnosticAction("comp001")
	tests := []struct {
		name    string
		key     string
		action  func(domain.InvestigationAction) domain.InvestigationAction
		grant   int
		durable func(domain.InvestigationAction) *domain.InvestigationAction
	}{
		{name: "unbound tool", action: func(a domain.InvestigationAction) domain.InvestigationAction { a.ToolID = "gpu.reset.v1"; return a }},
		{name: "not marked diagnostic", action: func(a domain.InvestigationAction) domain.InvestigationAction { a.Diagnostic = false; return a }},
		{name: "privileged", action: func(a domain.InvestigationAction) domain.InvestigationAction { a.Privileged = true; return a }},
		{name: "supplied argument", action: func(a domain.InvestigationAction) domain.InvestigationAction {
			a.Arguments = []domain.InvestigationArgument{{Name: "extra", Kind: "STRING", String: "--gpu-reset"}}
			return a
		}},
		{name: "target outside scope", action: func(a domain.InvestigationAction) domain.InvestigationAction {
			a.Targets, a.FanOut = []string{"comp999"}, 1
			return a
		}},
		{name: "no durable action", durable: func(domain.InvestigationAction) *domain.InvestigationAction { return nil }},
		{name: "durable digest differs", durable: func(a domain.InvestigationAction) *domain.InvestigationAction {
			a.Digest = domain.ChecksumSHA256([]byte("other"))
			return &a
		}},
		{name: "no diagnostic grant", grant: -1},
		{name: "foreign idempotency key", key: "investigation/inv-1/action/action-9"},
		{name: "malformed idempotency key", key: "action-1"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			action := base
			if test.action != nil {
				action = test.action(action)
			}
			grant := 2
			if test.grant == -1 {
				grant = 0
			}
			store := &diagnosticStore{snapshot: diagnosticSnapshot(t, now, grant, "comp001")}
			durable := action
			store.snapshot.ProposedAction = &durable
			if test.durable != nil {
				store.snapshot.ProposedAction = test.durable(action)
			}
			key := "investigation/inv-1/action/action-1"
			if test.key != "" {
				key = test.key
			}
			dispatcher := &diagnosticDispatcherFake{}
			_, err := newDiagnosticExecutor(t, store, dispatcher, &diagnosticEvidenceSinkFake{}, now).ExecuteInvestigationAction(context.Background(), key, action)
			if err == nil {
				t.Fatal("an invocation outside durable authority was executed")
			}
			if len(dispatcher.dispatches) != 0 {
				t.Fatal("a refused invocation still reached a host")
			}
		})
	}
}

// A dispatch failure must surface, not be quietly recorded as an observation.
func TestDiagnosticExecutorPropagatesDispatchFailure(t *testing.T) {
	now := time.Date(2026, 8, 22, 10, 0, 0, 0, time.UTC)
	action := diagnosticAction("comp001")
	store := &diagnosticStore{snapshot: diagnosticSnapshot(t, now, 1, "comp001")}
	store.snapshot.ProposedAction = &action
	sink := &diagnosticEvidenceSinkFake{}
	failure := errors.New("head node unreachable")
	_, err := newDiagnosticExecutor(t, store, &diagnosticDispatcherFake{err: failure}, sink, now).ExecuteInvestigationAction(context.Background(), "investigation/inv-1/action/action-1", action)
	if !errors.Is(err, failure) {
		t.Fatalf("err = %v, want the dispatch failure", err)
	}
	if len(sink.committed) != 0 {
		t.Fatal("a failed dispatch committed evidence")
	}
}

// The controller calls one executor. Routing must follow the durable operation
// class, and a disagreement between the class and the tool binding must fail
// rather than be resolved in either direction.
func TestRoutingExecutorSendsEachActionToItsOwner(t *testing.T) {
	now := time.Date(2026, 8, 22, 10, 0, 0, 0, time.UTC)
	action := diagnosticAction("comp001")
	store := &diagnosticStore{snapshot: diagnosticSnapshot(t, now, 1, "comp001")}
	store.snapshot.ProposedAction = &action
	dispatcher := &diagnosticDispatcherFake{}
	diagnostics := newDiagnosticExecutor(t, store, dispatcher, &diagnosticEvidenceSinkFake{}, now)
	lookups := &countingLookupExecutor{}
	router, err := NewRoutingExecutor(lookups, diagnostics)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := router.ExecuteInvestigationAction(context.Background(), "investigation/inv-1/action/action-1", action); err != nil {
		t.Fatal(err)
	}
	if len(dispatcher.dispatches) != 1 || lookups.calls != 0 {
		t.Fatalf("diagnostic dispatches=%d lookup calls=%d", len(dispatcher.dispatches), lookups.calls)
	}

	lookup := domain.InvestigationAction{ID: "action-2", ToolID: XIDEvidenceToolID, Digest: domain.ChecksumSHA256([]byte("lookup")), FanOut: 1, Targets: []string{"comp001"}, Start: now.Add(-time.Hour), End: now}
	if _, err := router.ExecuteInvestigationAction(context.Background(), "investigation/inv-1/action/action-2", lookup); err != nil {
		t.Fatal(err)
	}
	if lookups.calls != 1 || len(dispatcher.dispatches) != 1 {
		t.Fatalf("an evidence lookup was routed to execution: lookup calls=%d dispatches=%d", lookups.calls, len(dispatcher.dispatches))
	}

	mismatched := lookup
	mismatched.Diagnostic = true
	if _, err := router.ExecuteInvestigationAction(context.Background(), "investigation/inv-1/action/action-2", mismatched); err == nil {
		t.Fatal("a lookup tool marked diagnostic was routed instead of refused")
	}
	unmarked := action
	unmarked.Diagnostic = false
	if _, err := router.ExecuteInvestigationAction(context.Background(), "investigation/inv-1/action/action-1", unmarked); err == nil {
		t.Fatal("a diagnostic tool not marked diagnostic was routed instead of refused")
	}
	if len(dispatcher.dispatches) != 1 {
		t.Fatal("a refused route still reached a host")
	}
}

type countingLookupExecutor struct{ calls int }

func (executor *countingLookupExecutor) ExecuteInvestigationAction(context.Context, string, domain.InvestigationAction) (application.InvestigationExecutionResult, error) {
	executor.calls++
	return application.InvestigationExecutionResult{Receipt: "lookup"}, nil
}

// The declared lookback and the signed argv must agree. They live in different
// packages -- policy beside the binding, the window inside the reviewed command
// -- so nothing but this test stops one from moving without the other, and a
// binding claiming more history than journalctl reads would have evidence
// assert coverage of a window the command never looked at.
func TestDiagnosticLookbacksMatchTheSignedArgv(t *testing.T) {
	definitions, err := commandpack.PilotDefinitions(commandpack.PilotIdentities{
		NvidiaSMI:  commandpack.ExecutableIdentity{Path: "/usr/bin/nvidia-smi", SHA256: strings.Repeat("a", 64)},
		Journalctl: commandpack.ExecutableIdentity{Path: "/usr/bin/journalctl", SHA256: strings.Repeat("b", 64)},
		Scontrol:   commandpack.ExecutableIdentity{Path: "/usr/bin/scontrol", SHA256: strings.Repeat("c", 64)},
	})
	if err != nil {
		t.Fatal(err)
	}
	byKey := map[string]commandpack.Definition{}
	for _, definition := range definitions {
		byKey[definition.ID+"@"+definition.Version] = definition
	}
	for _, toolID := range investigationtools.DiagnosticToolIDs() {
		binding, reviewed := investigationtools.DiagnosticBindingForTool(toolID)
		if !reviewed {
			t.Fatalf("%s has no reviewed binding", toolID)
		}
		definition, present := byKey[string(binding.DefinitionID)+"@"+binding.DefinitionVersion]
		if !present {
			t.Fatalf("%s is bound to %s@%s, which the reviewed set does not contain", toolID, binding.DefinitionID, binding.DefinitionVersion)
		}
		want := time.Duration(0)
		for _, token := range definition.Arguments {
			if after, found := strings.CutPrefix(token.Literal, "--since="); found {
				want = parseJournalSince(t, after)
			}
		}
		if binding.ObservationLookback != want {
			t.Fatalf("%s declares a %s lookback but %s reads %s of journal", toolID, binding.ObservationLookback, binding.DefinitionID, want)
		}
	}
}

// parseJournalSince reads journalctl's relative form, "-N unit", which is the
// only form a reviewed definition may use: an absolute timestamp would freeze
// the window at signing time.
func parseJournalSince(t *testing.T, value string) time.Duration {
	t.Helper()
	fields := strings.Fields(strings.TrimPrefix(value, "-"))
	if len(fields) != 2 {
		t.Fatalf("unsupported --since form %q", value)
	}
	count, err := strconv.Atoi(fields[0])
	if err != nil || count < 0 {
		t.Fatalf("unsupported --since count %q", fields[0])
	}
	switch strings.TrimSuffix(fields[1], "s") {
	case "day":
		return time.Duration(count) * 24 * time.Hour
	case "hour":
		return time.Duration(count) * time.Hour
	case "minute":
		return time.Duration(count) * time.Minute
	}
	t.Fatalf("unsupported --since unit %q", fields[1])
	return 0
}
