package remediationrunner

import (
	"context"
	"errors"
	"go/ast"
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

// liveExecutor exists only so the assurance property can be tested as a
// property of the port rather than of one adapter. It touches nothing: the
// point is that a consumer holding an Executor can tell what it would touch
// before calling it, which is what lets a use case refuse to construct.
type liveExecutor struct{ class domain.AssuranceClass }

func (e liveExecutor) Execute(context.Context, ExecutionUnit, time.Time) (ExecutionResult, error) {
	return ExecutionResult{}, errors.New("this executor must never be reachable")
}

func (e liveExecutor) Assurance() domain.AssuranceClass { return e.class }

// TestExecutorPortDeclaresItsAssurance covers the rule that assurance belongs
// to the port and not to a particular adapter. Without it, wave-2 wiring could
// bind a different implementation to the injectable port and silently obtain a
// live path; with it, every consumer can refuse anything but SIMULATED before
// calling Execute.
func TestExecutorPortDeclaresItsAssurance(t *testing.T) {
	var simulated Executor = scripted(t)
	if simulated.Assurance() != domain.AssuranceSimulated {
		t.Fatalf("assurance = %s, want SIMULATED", simulated.Assurance())
	}
	if !simulated.Assurance().Implemented() {
		t.Fatal("the shipped executor must report an implemented assurance class")
	}
	for _, class := range []domain.AssuranceClass{domain.AssuranceRecorded, domain.AssuranceLive, "", "PRODUCTION"} {
		var executor Executor = liveExecutor{class: class}
		if executor.Assurance() == domain.AssuranceSimulated {
			t.Fatalf("class %q must not report itself as simulated", class)
		}
		if executor.Assurance().Implemented() {
			t.Fatalf("class %q must not be an implemented assurance class in this build", class)
		}
	}
	// The method is part of the interface, not an optional extra a consumer
	// might forget to look for.
	port := reflect.TypeOf((*Executor)(nil)).Elem()
	if _, declared := port.MethodByName("Assurance"); !declared {
		t.Fatal("the Executor port must declare Assurance")
	}
	if port.NumMethod() != 2 {
		t.Fatalf("the Executor port declares %d methods; the mutation surface must stay exactly Execute plus Assurance", port.NumMethod())
	}
}

// TestExecutionUnitRefusesEveryHostileStringField sweeps every string-shaped
// field of the unit with a payload that would matter only if something on the
// far side interpreted it. Nothing does, and nothing may: each field is either
// a closed enum or an identifier held to the token charset.
func TestExecutionUnitRefusesEveryHostileStringField(t *testing.T) {
	payloads := []string{
		"; rm -rf /", "$(id)", "`id`", "/bin/sh", "../../etc/shadow",
		"https://evil.example", "a b", "a\nb", "a\x00b", strings.Repeat("a", 129),
		"NORM\u202eAL", "НORMAL",
	}
	mutators := map[string]func(ExecutionUnit, string) ExecutionUnit{
		"RunID":             func(u ExecutionUnit, v string) ExecutionUnit { u.RunID = domain.RemediationRunID(v); return u },
		"AttemptID":         func(u ExecutionUnit, v string) ExecutionUnit { u.AttemptID = domain.RemediationAttemptID(v); return u },
		"Operation":         func(u ExecutionUnit, v string) ExecutionUnit { u.Operation = remediation.RecipeOperation(v); return u },
		"Stage":             func(u ExecutionUnit, v string) ExecutionUnit { u.Stage = domain.RemediationStage(v); return u },
		"IdempotencyKey":    func(u ExecutionUnit, v string) ExecutionUnit { u.IdempotencyKey = v; return u },
		"Arguments[0].Name": func(u ExecutionUnit, v string) ExecutionUnit { u.Arguments[0].Name = v; return u },
		"Arguments[0].Enum": func(u ExecutionUnit, v string) ExecutionUnit { u.Arguments[0].Enum = v; return u },
		"Arguments[0].Type": func(u ExecutionUnit, v string) ExecutionUnit { u.Arguments[0].Type = domain.ParameterType(v); return u },
		"Targets[0].Target": func(u ExecutionUnit, v string) ExecutionUnit {
			u.Targets[0].Target = domain.RemediationTarget(v)
			return u
		},
		"Targets[0].Role": func(u ExecutionUnit, v string) ExecutionUnit { u.Targets[0].Role = domain.TargetRole(v); return u },
		"Targets[0].Source": func(u ExecutionUnit, v string) ExecutionUnit {
			u.Targets[0].Source = domain.TargetSourceRelation(v)
			return u
		},
		"Targets[0].Cluster": func(u ExecutionUnit, v string) ExecutionUnit { u.Targets[0].ClusterID = domain.ClusterID(v); return u },
	}
	for field, mutate := range mutators {
		for _, payload := range payloads {
			t.Run(field+" carrying "+strconv.Quote(payload), func(t *testing.T) {
				unit := mutate(testExecutionUnit("stream-1"), payload)
				if err := unit.Validate(); err == nil {
					t.Fatal("expected the execution unit to be refused")
				}
			})
		}
	}
	// The cluster field is checked separately because the payload has to differ
	// from the unit's own cluster to be rejected rather than merely renamed.
	unit := testExecutionUnit("stream-1")
	unit.ClusterID = "cluster-2"
	if err := unit.Validate(); err == nil {
		t.Fatal("a unit whose cluster does not match its targets must be refused")
	}
}

// TestExecutionUnitHasNoFieldAnExecutorCouldInterpret recurses the whole
// transitive shape of what an executor is handed. The shallow version of this
// check would miss a free-text field introduced inside a nested type, which is
// exactly where it would be easiest to add one without anyone noticing.
func TestExecutionUnitHasNoFieldAnExecutorCouldInterpret(t *testing.T) {
	forbidden := []string{
		"command", "cmd", "script", "shell", "args", "argv", "path", "executable",
		"binary", "env", "environment", "host", "address", "url", "endpoint",
		"credential", "token", "secret", "password", "user", "sudo", "message",
		"output", "stdout", "stderr", "detail", "note", "reason", "log", "rationale",
		"body", "payload", "template", "expression", "query",
	}
	seen := map[reflect.Type]bool{}
	var walk func(structure reflect.Type, path string)
	walk = func(structure reflect.Type, path string) {
		if seen[structure] {
			return
		}
		seen[structure] = true
		for index := 0; index < structure.NumField(); index++ {
			field := structure.Field(index)
			name := path + "." + field.Name
			for _, banned := range forbidden {
				if strings.ToLower(field.Name) == banned {
					t.Fatalf("%s reintroduces a command or free-text surface", name)
				}
			}
			fieldType := field.Type
			if fieldType.Kind() == reflect.Slice {
				if fieldType.Elem().Kind() == reflect.Uint8 {
					t.Fatalf("%s carries raw bytes", name)
				}
				fieldType = fieldType.Elem()
			}
			if fieldType.Kind() == reflect.Ptr {
				fieldType = fieldType.Elem()
			}
			if fieldType.Kind() == reflect.Map || fieldType.Kind() == reflect.Interface ||
				fieldType.Kind() == reflect.Func || fieldType.Kind() == reflect.Chan ||
				fieldType.Kind() == reflect.UnsafePointer {
				t.Fatalf("%s is an open-ended %s and could carry anything", name, fieldType.Kind())
			}
			if fieldType.Kind() == reflect.Struct && fieldType != reflect.TypeOf(time.Time{}) {
				walk(fieldType, name)
			}
		}
	}
	walk(reflect.TypeOf(ExecutionUnit{}), "ExecutionUnit")
	walk(reflect.TypeOf(ExecutionResult{}), "ExecutionResult")
}

// TestExecutionResultCannotClaimTheRepairWorked pins the asymmetry the whole
// verification story rests on. An executor reports what it observed about its
// own call; whether the repair worked is decided elsewhere, from independent
// observations, and the result type gives it no vocabulary to say otherwise.
func TestExecutionResultCannotClaimTheRepairWorked(t *testing.T) {
	structure := reflect.TypeOf(ExecutionResult{})
	for index := 0; index < structure.NumField(); index++ {
		field := structure.Field(index)
		switch strings.ToLower(field.Name) {
		case "succeeded", "success", "verified", "postconditions", "conditions", "healthy", "repaired":
			t.Fatalf("ExecutionResult.%s lets an executor assert the repair worked", field.Name)
		}
		if field.Type.Kind() == reflect.Bool {
			t.Fatalf("ExecutionResult.%s is a bare boolean verdict", field.Name)
		}
		if field.Type.Kind() == reflect.String {
			if _, hasValidate := field.Type.MethodByName("Validate"); !hasValidate {
				t.Fatalf("ExecutionResult.%s is an open string", field.Name)
			}
		}
	}
	// The strongest outcome an executor may report is EXECUTED, which is a claim
	// about a call and not about a repair, and the zero outcome is invalid
	// rather than being read as success.
	if (domain.ExecutionOutcome("")).Validate() == nil {
		t.Fatal("the zero execution outcome must be invalid")
	}
	if domain.ExecutionExecuted.Validate() != nil {
		t.Fatal("EXECUTED must remain a valid outcome")
	}
}

// TestSimulatedExecutorNeverDefaultsToSuccess collects every way a call could
// fall off the end of the script. A default success is indistinguishable from a
// repair that never happened, so each of these must be an error rather than an
// EXECUTED result.
func TestSimulatedExecutorNeverDefaultsToSuccess(t *testing.T) {
	cases := []struct {
		name    string
		script  []ScriptedOutcome
		targets []domain.RemediationTarget
	}{
		{
			name:    "no script at all",
			script:  nil,
			targets: []domain.RemediationTarget{"stream-1"},
		},
		{
			name: "one unscripted target among scripted ones",
			script: []ScriptedOutcome{
				{Operation: remediation.OperationEvidenceCollectionRequeue, Target: "stream-1", Outcome: domain.ExecutionExecuted},
			},
			targets: []domain.RemediationTarget{"stream-1", "stream-2"},
		},
		{
			name: "the target is scripted only for another operation",
			script: []ScriptedOutcome{
				{Operation: remediation.OperationEvidenceCollectionRestore, Target: "stream-1", Outcome: domain.ExecutionExecuted},
			},
			targets: []domain.RemediationTarget{"stream-1"},
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			executor := scripted(t, testCase.script...)
			result, err := executor.Execute(context.Background(), testExecutionUnit(testCase.targets...), testInstant())
			var unsupported UnsupportedOperationError
			if !errors.As(err, &unsupported) {
				t.Fatalf("err = %v result = %+v, want a refusal", err, result)
			}
			if result.Outcome == domain.ExecutionExecuted {
				t.Fatal("a refusal must not also report an execution")
			}
			if _, recorded := executor.Recorded("key-1"); recorded {
				t.Fatal("a refused call must not record a result a retry could replay")
			}
		})
	}
	// The refusal names the operation, which is a compiled enum member, and
	// nothing else: no target detail, no free text.
	refusal := UnsupportedOperationError{
		Operation: remediation.OperationEvidenceCollectionRequeue, Target: "stream-1; reboot",
	}
	if strings.Contains(refusal.Error(), "reboot") {
		t.Fatal("the refusal must not echo an untrusted target name")
	}
}

// TestSimulatedExecutorRefusesAnInvalidUnitBeforeRecordingAnything covers the
// ordering that makes a refusal safe to retry: a unit that fails validation
// must leave no recorded result behind, or a later well-formed call carrying
// the same key would be answered from a call that never happened.
func TestSimulatedExecutorRefusesAnInvalidUnitBeforeRecordingAnything(t *testing.T) {
	executor := scripted(t,
		ScriptedOutcome{Operation: remediation.OperationEvidenceCollectionRequeue, Target: "stream-1", Outcome: domain.ExecutionExecuted},
	)
	invalid := testExecutionUnit("stream-1")
	invalid.Arguments[0].Enum = "NORMAL; rm -rf /"
	if _, err := executor.Execute(context.Background(), invalid, testInstant()); err == nil {
		t.Fatal("an invalid unit must be refused")
	}
	if _, recorded := executor.Recorded(invalid.IdempotencyKey); recorded {
		t.Fatal("a refused unit must not record a result")
	}
	if _, err := executor.Execute(context.Background(), testExecutionUnit("stream-1"), testInstant()); err != nil {
		t.Fatalf("the same key must still be usable by a well-formed call: %v", err)
	}
	// A missing server instant is refused for the same reason: an executor that
	// invented one would put an instant on a receipt at which nothing happened.
	if _, err := executor.Execute(context.Background(), testExecutionUnit("stream-1"), time.Time{}); err == nil {
		t.Fatal("a call without a server-supplied instant must be refused")
	}
}

// TestSimulatedExecutorTouchesNothingUnderConcurrentDuplicateDelivery drives
// the duplicate-delivery path from several goroutines at once, which is what an
// acknowledgement loss followed by a redelivery actually looks like. Exactly
// one recorded result must exist and every caller must see it.
func TestSimulatedExecutorTouchesNothingUnderConcurrentDuplicateDelivery(t *testing.T) {
	executor := scripted(t,
		ScriptedOutcome{Operation: remediation.OperationEvidenceCollectionRequeue, Target: "stream-1", Outcome: domain.ExecutionExecuted},
	)
	const callers = 16
	results := make(chan ExecutionResult, callers)
	failures := make(chan error, callers)
	for index := 0; index < callers; index++ {
		go func(offset int) {
			result, err := executor.Execute(context.Background(), testExecutionUnit("stream-1"),
				testInstant().Add(time.Duration(offset)*time.Second))
			if err != nil {
				failures <- err
				return
			}
			results <- result
		}(index)
	}
	first := ExecutionResult{}
	for index := 0; index < callers; index++ {
		select {
		case err := <-failures:
			t.Fatal(err)
		case result := <-results:
			if index == 0 {
				first = result
				continue
			}
			if result.Outcome != first.Outcome {
				t.Fatalf("outcome = %s, want every duplicate delivery to see one recorded result", result.Outcome)
			}
		}
	}
	recorded, found := executor.Recorded("key-1")
	if !found || !recorded.ObservedAt.Equal(first.ObservedAt) {
		t.Fatal("exactly one observation instant must survive a duplicate delivery")
	}
}

// TestSimulatedExecutorReturnsCopiesOfEveryRecordedResult proves a caller
// cannot reach back into the recorded table. A shared slice would let one
// consumer rewrite the outcome another consumer is about to read, which is a
// receipt forged without touching a database at all.
func TestSimulatedExecutorReturnsCopiesOfEveryRecordedResult(t *testing.T) {
	executor := scripted(t,
		ScriptedOutcome{Operation: remediation.OperationEvidenceCollectionRequeue, Target: "stream-1", Outcome: domain.ExecutionExecuted},
	)
	first, err := executor.Execute(context.Background(), testExecutionUnit("stream-1"), testInstant())
	if err != nil {
		t.Fatal(err)
	}
	first.PerTarget[0].Outcome = domain.ExecutionUnknown
	first.Outcome = domain.ExecutionUnknown

	replayed, err := executor.Execute(context.Background(), testExecutionUnit("stream-1"), testInstant())
	if err != nil {
		t.Fatal(err)
	}
	if replayed.Outcome != domain.ExecutionExecuted || replayed.PerTarget[0].Outcome != domain.ExecutionExecuted {
		t.Fatal("mutating a returned result must not reach the recorded table")
	}
	replayed.PerTarget[0].Outcome = domain.ExecutionFailed
	recorded, _ := executor.Recorded("key-1")
	if recorded.PerTarget[0].Outcome != domain.ExecutionExecuted {
		t.Fatal("mutating a replayed result must not reach the recorded table")
	}
	// The unit's own target slice must not be aliased into the result either.
	unit := testExecutionUnit("stream-1")
	unit.IdempotencyKey = "key-2"
	result, err := executor.Execute(context.Background(), unit, testInstant())
	if err != nil {
		t.Fatal(err)
	}
	unit.Targets[0].Target = "stream-9"
	if result.PerTarget[0].Target != "stream-1" {
		t.Fatal("the result must not alias the caller's target list")
	}
}

// TestExecutorPackageDeclaresNoMutationVocabulary reads this package's own
// syntax tree and asserts it contains no string literal that looks like a
// command, a path or a host. The assurance claim of the milestone is that the
// executor interface is incapable of expressing a command; a literal appearing
// here would be the first sign that something started to build one.
func TestExecutorPackageDeclaresNoMutationVocabulary(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "executor.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	forbidden := []string{
		"/bin/", "/usr/", "/etc/", "sh -c", "bash", "sudo", "ssh", "scontrol",
		"systemctl", "nvidia-smi", "ipmitool", "http://", "https://", "exec.Command",
	}
	ast.Inspect(file, func(node ast.Node) bool {
		literal, isLiteral := node.(*ast.BasicLit)
		if !isLiteral || literal.Kind != token.STRING {
			return true
		}
		value, err := strconv.Unquote(literal.Value)
		if err != nil {
			return true
		}
		lowered := strings.ToLower(value)
		for _, fragment := range forbidden {
			if strings.Contains(lowered, strings.ToLower(fragment)) {
				t.Fatalf("executor.go contains the literal %q, which names something outside the simulated boundary", value)
			}
		}
		return true
	})
	// The package must also declare no function that takes or returns a command
	// shaped value. The whole executable vocabulary is the operation enum.
	ast.Inspect(file, func(node ast.Node) bool {
		function, isFunction := node.(*ast.FuncDecl)
		if !isFunction {
			return true
		}
		lowered := strings.ToLower(function.Name.Name)
		for _, banned := range []string{"run", "exec", "command", "shell", "spawn", "invoke", "dial", "connect"} {
			if lowered == banned {
				t.Fatalf("executor.go declares %s, which is not part of a simulated boundary", function.Name.Name)
			}
		}
		return true
	})
}

// TestSimulatedExecutorHasNoWritableStateBeyondItsRecord asserts the adapter
// holds nothing but a compiled script and a replay record. A field that could
// hold a connection, a client or a path would be the point at which this
// adapter stopped being simulated.
func TestSimulatedExecutorHasNoWritableStateBeyondItsRecord(t *testing.T) {
	structure := reflect.TypeOf(SimulatedExecutor{})
	permitted := map[string]bool{"mutex": true, "script": true, "recorded": true, "catalog": true}
	for index := 0; index < structure.NumField(); index++ {
		field := structure.Field(index)
		if !permitted[field.Name] {
			t.Fatalf("SimulatedExecutor.%s is state the simulated boundary does not account for", field.Name)
		}
		if field.Type.Kind() == reflect.Interface || field.Type.Kind() == reflect.Func {
			t.Fatalf("SimulatedExecutor.%s could hold an arbitrary implementation", field.Name)
		}
	}
	// A scripted outcome names an operation, a target and an outcome: three
	// closed vocabularies and nothing else.
	scriptType := reflect.TypeOf(ScriptedOutcome{})
	if scriptType.NumField() != 3 {
		t.Fatalf("ScriptedOutcome has %d fields; the script must stay operation, target and outcome", scriptType.NumField())
	}
	for index := 0; index < scriptType.NumField(); index++ {
		if scriptType.Field(index).Type.Kind() != reflect.String {
			t.Fatalf("ScriptedOutcome.%s is not a closed vocabulary value", scriptType.Field(index).Name)
		}
	}
}
