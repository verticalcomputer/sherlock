package remediationrunner

import (
	"context"
	"errors"
	"go/parser"
	"go/token"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/remediation"
)

func testInstant() time.Time { return time.Date(2026, 9, 10, 3, 0, 0, 0, time.UTC) }

func testExecutionUnit(targets ...domain.RemediationTarget) ExecutionUnit {
	resolved := make([]domain.ResolvedTarget, 0, len(targets))
	for _, target := range targets {
		resolved = append(resolved, domain.ResolvedTarget{
			Target: target, Role: domain.RoleManagedCollectionStream, ClusterID: "cluster-1",
			ResolvedAt: testInstant(), Source: domain.SourceCollectionJobs,
		})
	}
	return ExecutionUnit{
		RunID: "run-1", AttemptID: "attempt-1", ClusterID: "cluster-1",
		Operation: remediation.OperationEvidenceCollectionRequeue,
		Arguments: domain.TypedArguments{
			{Name: "priority", Type: domain.ParameterEnum, Enum: "NORMAL"},
			{Name: "requeue_reason", Type: domain.ParameterEnum, Enum: "STALE_STREAM"},
		},
		Targets: resolved, Stage: domain.RemediationStageCanary,
		IdempotencyKey: "key-1", Deadline: testInstant().Add(time.Minute),
	}
}

func scripted(t *testing.T, outcomes ...ScriptedOutcome) *SimulatedExecutor {
	t.Helper()
	executor, err := NewSimulatedExecutor(outcomes)
	if err != nil {
		t.Fatal(err)
	}
	return executor
}

func TestSimulatedExecutorAnswersFromItsScript(t *testing.T) {
	executor := scripted(t,
		ScriptedOutcome{Operation: remediation.OperationEvidenceCollectionRequeue, Target: "stream-1", Outcome: domain.ExecutionExecuted},
	)
	result, err := executor.Execute(context.Background(), testExecutionUnit("stream-1"), testInstant())
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome != domain.ExecutionExecuted {
		t.Fatalf("outcome = %s", result.Outcome)
	}
	if len(result.PerTarget) != 1 || result.PerTarget[0].Target != "stream-1" {
		t.Fatalf("per-target = %+v", result.PerTarget)
	}
	if !result.ObservedAt.Equal(testInstant()) {
		t.Fatalf("observedAt = %s, want the caller's server instant", result.ObservedAt)
	}
	if executor.Assurance() != domain.AssuranceSimulated {
		t.Fatalf("assurance = %s, want SIMULATED", executor.Assurance())
	}
}

// TestSimulatedExecutorNeverInventsAnObservationInstant covers the correction
// that the executor takes the server-causal now from its caller. Deriving it
// from the unit's deadline would have a receipt claim an observation at an
// instant when nothing was observed.
func TestSimulatedExecutorNeverInventsAnObservationInstant(t *testing.T) {
	executor := scripted(t,
		ScriptedOutcome{Operation: remediation.OperationEvidenceCollectionRequeue, Target: "stream-1", Outcome: domain.ExecutionExecuted},
	)
	unit := testExecutionUnit("stream-1")
	result, err := executor.Execute(context.Background(), unit, testInstant())
	if err != nil {
		t.Fatal(err)
	}
	if result.ObservedAt.Equal(unit.Deadline) {
		t.Fatal("the observation instant must not be the unit's deadline")
	}
	if _, err := executor.Execute(context.Background(), testExecutionUnit("stream-1"), time.Time{}); err == nil {
		t.Fatal("execution without a server-supplied instant must be refused")
	}
}

func TestSimulatedExecutorRefusesAnUnscriptedOperation(t *testing.T) {
	executor := scripted(t,
		ScriptedOutcome{Operation: remediation.OperationEvidenceCollectionRequeue, Target: "stream-1", Outcome: domain.ExecutionExecuted},
	)
	// A different target under the same operation is unscripted, and a default
	// success would be indistinguishable from a repair that never happened.
	_, err := executor.Execute(context.Background(), testExecutionUnit("stream-2"), testInstant())
	var unsupported UnsupportedOperationError
	if !errors.As(err, &unsupported) {
		t.Fatalf("err = %v, want an unsupported-operation refusal", err)
	}
	unit := testExecutionUnit("stream-1")
	unit.Operation = remediation.OperationEvidenceCollectionRestore
	if _, err := executor.Execute(context.Background(), unit, testInstant()); !errors.As(err, &unsupported) {
		t.Fatalf("err = %v, want an unsupported-operation refusal", err)
	}
	if _, recorded := executor.Recorded(unit.IdempotencyKey); recorded {
		t.Fatal("a refused call must not record a result")
	}
}

func TestSimulatedExecutorIsIdempotent(t *testing.T) {
	executor := scripted(t,
		ScriptedOutcome{Operation: remediation.OperationEvidenceCollectionRequeue, Target: "stream-1", Outcome: domain.ExecutionExecuted},
		ScriptedOutcome{Operation: remediation.OperationEvidenceCollectionRequeue, Target: "stream-2", Outcome: domain.ExecutionFailed},
	)
	first, err := executor.Execute(context.Background(), testExecutionUnit("stream-1"), testInstant())
	if err != nil {
		t.Fatal(err)
	}
	// A duplicate delivery after an acknowledgement loss carries the same key
	// and different targets; the recorded result is returned rather than a
	// second mutation being performed.
	duplicate := testExecutionUnit("stream-2")
	duplicate.IdempotencyKey = "key-1"
	second, err := executor.Execute(context.Background(), duplicate, testInstant().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if second.Outcome != first.Outcome || !second.ObservedAt.Equal(first.ObservedAt) {
		t.Fatal("a repeated key must return the recorded result, not act again")
	}
	if len(second.PerTarget) != 1 || second.PerTarget[0].Target != "stream-1" {
		t.Fatal("a replayed result must describe the original call")
	}
	recorded, found := executor.Recorded("key-1")
	if !found || recorded.Outcome != domain.ExecutionExecuted {
		t.Fatalf("recorded = %+v found = %v", recorded, found)
	}
	recorded.PerTarget[0].Outcome = domain.ExecutionFailed
	again, _ := executor.Recorded("key-1")
	if again.PerTarget[0].Outcome != domain.ExecutionExecuted {
		t.Fatal("mutating a recorded result must not reach the executor")
	}
}

// TestSimulatedExecutorCollapsesTargetOutcomesToTheWorst pins the deliberately
// pessimistic collapse. UNKNOWN dominates everything, and the per-target detail
// survives so a human containing the run can see which targets succeeded.
func TestSimulatedExecutorCollapsesTargetOutcomesToTheWorst(t *testing.T) {
	cases := []struct {
		name    string
		outcome domain.ExecutionOutcome
		want    domain.ExecutionOutcome
	}{
		{name: "refusal outranks execution", outcome: domain.ExecutionRefused, want: domain.ExecutionRefused},
		{name: "failure outranks refusal", outcome: domain.ExecutionFailed, want: domain.ExecutionFailed},
		{name: "timeout outranks failure", outcome: domain.ExecutionTimedOut, want: domain.ExecutionTimedOut},
		{name: "unknown dominates everything", outcome: domain.ExecutionUnknown, want: domain.ExecutionUnknown},
	}
	for index, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			executor := scripted(t,
				ScriptedOutcome{Operation: remediation.OperationEvidenceCollectionRequeue, Target: "stream-1", Outcome: domain.ExecutionExecuted},
				ScriptedOutcome{Operation: remediation.OperationEvidenceCollectionRequeue, Target: "stream-2", Outcome: testCase.outcome},
			)
			unit := testExecutionUnit("stream-1", "stream-2")
			unit.IdempotencyKey = "key-" + strconv.Itoa(index)
			result, err := executor.Execute(context.Background(), unit, testInstant())
			if err != nil {
				t.Fatal(err)
			}
			if result.Outcome != testCase.want {
				t.Fatalf("outcome = %s, want %s", result.Outcome, testCase.want)
			}
			if len(result.PerTarget) != 2 || result.PerTarget[0].Outcome != domain.ExecutionExecuted {
				t.Fatalf("per-target detail lost: %+v", result.PerTarget)
			}
		})
	}
}

func TestNewSimulatedExecutorRejectsAnInvalidScript(t *testing.T) {
	cases := []struct {
		name     string
		outcomes []ScriptedOutcome
	}{
		{name: "unknown operation", outcomes: []ScriptedOutcome{{Operation: "SH_DASH_C", Target: "stream-1", Outcome: domain.ExecutionExecuted}}},
		{name: "unknown outcome", outcomes: []ScriptedOutcome{{Operation: remediation.OperationEvidenceCollectionRequeue, Target: "stream-1", Outcome: "OK"}}},
		{name: "target outside the token charset", outcomes: []ScriptedOutcome{{Operation: remediation.OperationEvidenceCollectionRequeue, Target: "stream 1", Outcome: domain.ExecutionExecuted}}},
		{name: "duplicate entry", outcomes: []ScriptedOutcome{
			{Operation: remediation.OperationEvidenceCollectionRequeue, Target: "stream-1", Outcome: domain.ExecutionExecuted},
			{Operation: remediation.OperationEvidenceCollectionRequeue, Target: "stream-1", Outcome: domain.ExecutionFailed},
		}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := NewSimulatedExecutor(testCase.outcomes); err == nil {
				t.Fatal("expected the script to be refused")
			}
		})
	}
}

func TestExecutionUnitValidation(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(ExecutionUnit) ExecutionUnit
	}{
		{name: "run identifier outside the token charset", mutate: func(u ExecutionUnit) ExecutionUnit { u.RunID = "run 1"; return u }},
		{name: "missing cluster", mutate: func(u ExecutionUnit) ExecutionUnit { u.ClusterID = ""; return u }},
		{name: "unknown operation", mutate: func(u ExecutionUnit) ExecutionUnit { u.Operation = "SH_DASH_C"; return u }},
		{name: "unknown stage", mutate: func(u ExecutionUnit) ExecutionUnit { u.Stage = "SHELL"; return u }},
		{name: "idempotency key outside the token charset", mutate: func(u ExecutionUnit) ExecutionUnit { u.IdempotencyKey = "key 1"; return u }},
		{name: "no targets", mutate: func(u ExecutionUnit) ExecutionUnit { u.Targets = nil; return u }},
		{name: "target from another cluster", mutate: func(u ExecutionUnit) ExecutionUnit {
			u.Targets[0].ClusterID = "cluster-2"
			return u
		}},
		{name: "target with an unreviewed source relation", mutate: func(u ExecutionUnit) ExecutionUnit {
			u.Targets[0].Source = "SSH_HOSTS"
			return u
		}},
		{name: "target with an unknown role", mutate: func(u ExecutionUnit) ExecutionUnit {
			u.Targets[0].Role = "COMPUTE_NODE"
			return u
		}},
		{name: "argument carrying a shell fragment", mutate: func(u ExecutionUnit) ExecutionUnit {
			u.Arguments[0].Enum = "NORMAL; rm -rf /"
			return u
		}},
		{name: "unordered arguments", mutate: func(u ExecutionUnit) ExecutionUnit {
			u.Arguments[0], u.Arguments[1] = u.Arguments[1], u.Arguments[0]
			return u
		}},
		{name: "missing deadline", mutate: func(u ExecutionUnit) ExecutionUnit { u.Deadline = time.Time{}; return u }},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if err := testCase.mutate(testExecutionUnit("stream-1")).Validate(); err == nil {
				t.Fatal("expected the execution unit to be refused")
			}
		})
	}
	if err := testExecutionUnit("stream-1").Validate(); err != nil {
		t.Fatalf("baseline unit: %v", err)
	}
}

func TestSimulatedExecutorHonoursCancellation(t *testing.T) {
	executor := scripted(t,
		ScriptedOutcome{Operation: remediation.OperationEvidenceCollectionRequeue, Target: "stream-1", Outcome: domain.ExecutionExecuted},
	)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := executor.Execute(ctx, testExecutionUnit("stream-1"), testInstant()); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want cancellation", err)
	}
	if _, recorded := executor.Recorded("key-1"); recorded {
		t.Fatal("a cancelled call must not record a result")
	}
}

// TestExecutionBoundaryCarriesNoCommandSurface is a structural assertion, not a
// behavioural one: neither the unit an executor receives nor the result it
// returns has any field that could carry a command, a path, an environment, a
// credential, or free text an operator screen would later render.
func TestExecutionBoundaryCarriesNoCommandSurface(t *testing.T) {
	forbidden := []string{
		"command", "cmd", "script", "shell", "args", "argv", "path", "executable",
		"binary", "env", "environment", "host", "address", "url", "endpoint",
		"credential", "token", "secret", "password", "key", "user", "sudo",
		"message", "output", "stdout", "stderr", "detail", "note", "reason", "log",
	}
	for _, structure := range []reflect.Type{reflect.TypeOf(ExecutionUnit{}), reflect.TypeOf(ExecutionResult{})} {
		for index := 0; index < structure.NumField(); index++ {
			field := structure.Field(index)
			lowered := strings.ToLower(field.Name)
			for _, banned := range forbidden {
				if lowered == banned {
					t.Fatalf("%s.%s reintroduces a command or free-text surface", structure.Name(), field.Name)
				}
			}
			// The only []byte-shaped field would be raw output, which is exactly
			// the untrusted-content-into-logs path this boundary exists to close.
			if field.Type.Kind() == reflect.Slice && field.Type.Elem().Kind() == reflect.Uint8 {
				t.Fatalf("%s.%s carries raw bytes", structure.Name(), field.Name)
			}
		}
	}
	// The result's own string-typed fields must all be closed enums, never free
	// text: every one of them has a Validate method that rejects unknown values.
	result := reflect.TypeOf(ExecutionResult{})
	for index := 0; index < result.NumField(); index++ {
		field := result.Field(index)
		if field.Type.Kind() == reflect.String {
			if _, hasValidate := field.Type.MethodByName("Validate"); !hasValidate {
				t.Fatalf("ExecutionResult.%s is an open string", field.Name)
			}
		}
	}
}

// TestExecutorPackageImportsNothingThatTouchesTheWorld is the assurance claim of
// this milestone made checkable: a simulated executor that imported os/exec,
// net or os would no longer be simulated, and the failure would be silent.
func TestExecutorPackageImportsNothingThatTouchesTheWorld(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "executor.go", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	banned := []string{
		"os", "os/exec", "net", "net/http", "io", "io/ioutil", "bufio", "path/filepath",
		"syscall", "crypto/tls", "database/sql", "net/url", "os/user", "plugin",
	}
	for _, imported := range file.Imports {
		path, err := strconv.Unquote(imported.Path.Value)
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range banned {
			if path == forbidden {
				t.Fatalf("the simulated executor imports %q and therefore touches the world", path)
			}
		}
	}
}
