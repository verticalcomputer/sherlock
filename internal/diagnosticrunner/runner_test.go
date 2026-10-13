package diagnosticrunner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/commandpack"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

func TestRunnerUsesExactArgvWithoutShellExpansion(t *testing.T) {
	runner := testRunner(t)
	identity := testExecutableIdentity(t)
	injected := filepath.Join(t.TempDir(), "injected")
	malicious := "; touch " + injected + "; $(id)"
	request := testRequest(identity, []targetPlan{{TargetID: "node-1", Args: helperArgs("echo", malicious)}})

	result, err := runner.execute(context.Background(), request)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if result.Targets[0].ErrorCode != "" || string(result.Targets[0].Stdout) != malicious {
		t.Fatalf("target = %#v", result.Targets[0])
	}
	if _, err := os.Stat(injected); !os.IsNotExist(err) {
		t.Fatal("argument was interpreted by a shell")
	}
}

func TestExecuteVerifiedAcceptsOnlySealedCommandpackPlan(t *testing.T) {
	runner := testRunner(t)
	identity := testExecutableIdentity(t)
	plan := testVerifiedPlan(t, identity, helperArgs("echo", "sealed"), []string{"node-1"})
	result, err := runner.ExecuteVerified(context.Background(), "attempt-1", plan, nil)
	if err != nil {
		t.Fatalf("ExecuteVerified() error = %v", err)
	}
	if len(result.Targets) != 1 || result.Targets[0].ErrorCode != "" || string(result.Targets[0].Stdout) != "sealed" {
		t.Fatalf("result = %#v", result)
	}
	if _, err := runner.ExecuteVerified(context.Background(), "attempt-1", commandpack.ExecutionPlan{}, nil); err == nil {
		t.Fatal("zero/unverified plan was accepted")
	}
}

func TestExecuteVerifiedRejectsExpiredPlanBeforeLaunch(t *testing.T) {
	identity := testExecutableIdentity(t)
	plan := testVerifiedPlan(t, identity, helperArgs("echo", "must-not-run"), []string{"node-1"})
	runner := testRunnerAt(t, fixedRunnerClock{now: runnerTestNow.Add(2 * time.Hour)})
	if _, err := runner.ExecuteVerified(context.Background(), "attempt-1", plan, nil); err == nil {
		t.Fatal("expired sealed plan was accepted")
	}
}

func TestRunnerRechecksExpiryImmediatelyBeforeProcessStart(t *testing.T) {
	identity := testExecutableIdentity(t)
	clock := &sequenceRunnerClock{values: []time.Time{runnerTestNow, runnerTestNow.Add(2 * time.Hour)}}
	runner := testRunnerAt(t, clock)
	request := testRequest(identity, []targetPlan{{TargetID: "node-1", Args: helperArgs("echo", "must-not-run")}})
	result, err := runner.execute(context.Background(), request)
	if err != nil {
		t.Fatalf("execute() error = %v", err)
	}
	if result.Targets[0].Started || result.Targets[0].ErrorCode != CodeDefinitionInactive {
		t.Fatalf("target = %#v", result.Targets[0])
	}
}

func TestRunnerRejectsUnsafeRequests(t *testing.T) {
	runner := testRunner(t)
	identity := testExecutableIdentity(t)
	tests := map[string]func(*executionRequest){
		"relative executable": func(request *executionRequest) { request.Executable.Path = "bin/tool" },
		"unclean executable": func(request *executionRequest) {
			request.Executable.Path = filepath.Dir(identity.Path) + "/../" + filepath.Base(filepath.Dir(identity.Path)) + "/" + filepath.Base(identity.Path)
		},
		"shell executable": func(request *executionRequest) { request.Executable.Path = "/bin/sh" },
		"sudo executable":  func(request *executionRequest) { request.Executable.Path = "/usr/bin/sudo" },
		"nul argument":     func(request *executionRequest) { request.Targets[0].Args = []string{"bad\x00arg"} },
		"target expansion": func(request *executionRequest) { request.Targets[0].TargetID = "node-*" },
		"duplicate target": func(request *executionRequest) { request.Targets = append(request.Targets, request.Targets[0]) },
		"excess targets": func(request *executionRequest) {
			request.Targets = append(request.Targets, targetPlan{TargetID: "node-2"}, targetPlan{TargetID: "node-3"})
		},
		"excess concurrency": func(request *executionRequest) { request.Concurrency = 3 },
		"excess timeout":     func(request *executionRequest) { request.Timeout = 6 * time.Second },
		"excess output":      func(request *executionRequest) { request.MaxOutputBytes = 2049 },
		"excess input":       func(request *executionRequest) { request.Targets[0].input = make([]byte, 1025) },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			request := testRequest(identity, []targetPlan{{TargetID: "node-1", Args: helperArgs("echo", "safe")}})
			mutate(&request)
			if _, err := runner.execute(context.Background(), request); err == nil {
				t.Fatal("Execute() error = nil")
			}
		})
	}
}

func TestRunnerBoundsSuppliedSecrets(t *testing.T) {
	runner := testRunner(t)
	identity := testExecutableIdentity(t)
	tests := map[string][][]byte{
		"too many":  {[]byte("a"), []byte("b"), []byte("c"), []byte("d"), []byte("e")},
		"too large": {[]byte(strings.Repeat("x", 129))},
		"empty":     {[]byte{}},
	}
	for name, secrets := range tests {
		t.Run(name, func(t *testing.T) {
			request := testRequest(identity, []targetPlan{{TargetID: "node-1", Args: helperArgs("echo", "safe")}})
			request.SuppliedSecrets = secrets
			if _, err := runner.execute(context.Background(), request); err == nil {
				t.Fatal("execute() error = nil")
			}
		})
	}
}

func TestRunnerRejectsSymlinkAndPathReplacement(t *testing.T) {
	runner := testRunner(t)
	identity := testExecutableIdentity(t)

	t.Run("symlink", func(t *testing.T) {
		link := filepath.Join(t.TempDir(), "tool")
		if err := os.Symlink(identity.Path, link); err != nil {
			t.Fatal(err)
		}
		request := testRequest(ExecutableIdentity{Path: link, SHA256: identity.SHA256}, []targetPlan{{TargetID: "node-1", Args: helperArgs("echo", "safe")}})
		result, err := runner.execute(context.Background(), request)
		if err != nil {
			t.Fatalf("Execute() error = %v", err)
		}
		if result.Targets[0].ErrorCode != CodeExecutableReplaced || result.Targets[0].Started {
			t.Fatalf("target = %#v", result.Targets[0])
		}
	})

	t.Run("digest mismatch", func(t *testing.T) {
		request := testRequest(identity, []targetPlan{{TargetID: "node-1", Args: helperArgs("echo", "safe")}})
		request.Executable.SHA256 = strings.Repeat("0", 64)
		result, err := runner.execute(context.Background(), request)
		if err != nil {
			t.Fatalf("Execute() error = %v", err)
		}
		if result.Targets[0].ErrorCode != CodeExecutableReplaced || result.Targets[0].Started {
			t.Fatalf("target = %#v", result.Targets[0])
		}
	})

	t.Run("replaced file", func(t *testing.T) {
		payload, err := os.ReadFile(identity.Path)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "diagnostic-tool")
		if err := os.WriteFile(path, payload, 0700); err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(payload)
		replacedIdentity := ExecutableIdentity{Path: path, SHA256: hex.EncodeToString(digest[:])}
		payload[0] ^= 0xff
		if err := os.WriteFile(path, payload, 0700); err != nil {
			t.Fatal(err)
		}
		request := testRequest(replacedIdentity, []targetPlan{{TargetID: "node-1", Args: helperArgs("echo", "safe")}})
		result, err := runner.execute(context.Background(), request)
		if err != nil {
			t.Fatalf("Execute() error = %v", err)
		}
		if result.Targets[0].ErrorCode != CodeExecutableReplaced || result.Targets[0].Started {
			t.Fatalf("target = %#v", result.Targets[0])
		}
	})
}

func TestRunnerRedactsMaliciousOutputAndBoundsCapture(t *testing.T) {
	runner := testRunner(t)
	identity := testExecutableIdentity(t)
	secret := []byte("top-secret-token")
	output := "prefix\x1b" + string(secret) + strings.Repeat("x", 100)
	request := testRequest(identity, []targetPlan{{TargetID: "node-1", Args: helperArgs("split-echo", output)}})
	request.MaxOutputBytes = 48
	request.SuppliedSecrets = [][]byte{secret}

	result, err := runner.execute(context.Background(), request)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	target := result.Targets[0]
	if strings.Contains(string(target.Stdout), string(secret)) || !strings.Contains(string(target.Stdout), redactedMarker) {
		t.Fatalf("stdout was not redacted: %q", target.Stdout)
	}
	if !strings.Contains(string(target.Stdout), controlCharacterMarker) {
		t.Fatalf("control character was not sanitized: %q", target.Stdout)
	}
	if !target.StdoutTruncated || len(target.Stdout) != 48 || target.StdoutBytes != int64(len(output)) {
		t.Fatalf("target = %#v", target)
	}
	if target.StdoutTransformationState != domain.StdoutTransformationTransformed {
		t.Fatalf("screened stdout state = %s", target.StdoutTransformationState)
	}
	if strings.Contains(fmt.Sprintf("%#v", target), string(secret)) {
		t.Fatal("secret leaked through result formatting")
	}
}

func TestSafeCaptureTransformationProofTracksScreeningWithoutRawDigest(t *testing.T) {
	for _, fixture := range []struct {
		name, input, output string
		secrets             [][]byte
		state               domain.StdoutTransformationState
	}{
		{"unmodified", "plain text", "plain text", nil, domain.StdoutTransformationUnmodified},
		{"literal marker is not proof", redactedMarker, redactedMarker, nil, domain.StdoutTransformationUnmodified},
		{"same-length redaction", "0123456789", redactedMarker, [][]byte{[]byte("0123456789")}, domain.StdoutTransformationTransformed},
		{"control character", "a\x1bb", "a" + controlCharacterMarker + "b", nil, domain.StdoutTransformationTransformed},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			capture := newSafeCapture(&outputBudget{remaining: 1024}, fixture.secrets)
			// Split writes exercise the pending-secret boundary as well as screening.
			_, _ = capture.Write([]byte(fixture.input[:1]))
			_, _ = capture.Write([]byte(fixture.input[1:]))
			capture.finish()
			output, rawBytes, truncated, digest, state := capture.result()
			if string(output) != fixture.output || rawBytes != int64(len(fixture.input)) || truncated || state != fixture.state {
				t.Fatalf("capture output=%q bytes=%d truncated=%t state=%s", output, rawBytes, truncated, state)
			}
			want := sha256.Sum256([]byte(fixture.output))
			if digest != fmt.Sprintf("%x", want[:]) {
				t.Fatalf("digest did not cover emitted output")
			}
		})
	}
}

func TestRunnerReturnsPerTargetPartialResults(t *testing.T) {
	runner := testRunner(t)
	identity := testExecutableIdentity(t)
	request := testRequest(identity, []targetPlan{
		{TargetID: "node-1", Args: helperArgs("echo", "ok")},
		{TargetID: "node-2", Args: helperArgs("exit", "7")},
	})
	request.Concurrency = 2

	result, err := runner.execute(context.Background(), request)
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if len(result.Targets) != 2 || result.Targets[0].ErrorCode != "" || result.Targets[1].ErrorCode != CodeExitNonZero || result.Targets[1].ExitCode != 7 {
		t.Fatalf("targets = %#v", result.Targets)
	}
}

func TestRunnerAppliesOneOutputBudgetAcrossStreams(t *testing.T) {
	runner := testRunner(t)
	request := testRequest(testExecutableIdentity(t), []targetPlan{{TargetID: "node-1", Args: helperArgs("both", "40")}})
	request.MaxOutputBytes = 32
	result, err := runner.execute(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	target := result.Targets[0]
	if len(target.Stdout)+len(target.Stderr) != 32 {
		t.Fatalf("combined retained output = %d", len(target.Stdout)+len(target.Stderr))
	}
	if !target.StdoutTruncated && !target.StderrTruncated {
		t.Fatalf("neither stream reported truncation: %#v", target)
	}
	if target.StdoutBytes != 40 || target.StderrBytes != 40 {
		t.Fatalf("raw byte counts = %d, %d", target.StdoutBytes, target.StderrBytes)
	}
}

func TestRunnerCancellationAndTimeout(t *testing.T) {
	runner := testRunner(t)
	identity := testExecutableIdentity(t)

	t.Run("cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		request := testRequest(identity, []targetPlan{{TargetID: "node-1", Args: helperArgs("sleep", "5s")}})
		done := make(chan Result, 1)
		go func() {
			result, _ := runner.execute(ctx, request)
			done <- result
		}()
		time.Sleep(50 * time.Millisecond)
		cancel()
		select {
		case result := <-done:
			if !result.Targets[0].Cancelled || result.Targets[0].ErrorCode != CodeCancelled {
				t.Fatalf("target = %#v", result.Targets[0])
			}
		case <-time.After(time.Second):
			t.Fatal("Execute did not join the cancelled process")
		}
	})

	t.Run("timed out", func(t *testing.T) {
		request := testRequest(identity, []targetPlan{{TargetID: "node-1", Args: helperArgs("sleep", "5s")}})
		request.Timeout = 25 * time.Millisecond
		result, err := runner.execute(context.Background(), request)
		if err != nil {
			t.Fatalf("Execute() error = %v", err)
		}
		if !result.Targets[0].TimedOut || result.Targets[0].ErrorCode != CodeTimedOut {
			t.Fatalf("target = %#v", result.Targets[0])
		}
	})
}

func TestRunnerDoesNotInheritAmbientEnvironment(t *testing.T) {
	t.Setenv("SHERLOCK_RUNNER_SECRET", "must-not-leak")
	runner := testRunner(t)
	request := testRequest(testExecutableIdentity(t), []targetPlan{{TargetID: "node-1", Args: helperArgs("environment", "SHERLOCK_RUNNER_SECRET")}})
	result, err := runner.execute(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if string(result.Targets[0].Stdout) != "" {
		t.Fatalf("inherited environment: %q", result.Targets[0].Stdout)
	}
}

func TestDiagnosticRunnerHelperProcess(t *testing.T) {
	separator := -1
	for index, argument := range os.Args {
		if argument == "--diagnostic-runner-helper" {
			separator = index
			break
		}
	}
	if separator < 0 {
		return
	}
	arguments := os.Args[separator+1:]
	if len(arguments) < 1 {
		os.Exit(2)
	}
	switch arguments[0] {
	case "echo":
		if len(arguments) > 1 {
			_, _ = os.Stdout.WriteString(arguments[1])
		}
	case "split-echo":
		if len(arguments) > 1 {
			value := []byte(arguments[1])
			for _, character := range value {
				_, _ = os.Stdout.Write([]byte{character})
			}
		}
	case "exit":
		if len(arguments) > 1 && arguments[1] == "7" {
			os.Exit(7)
		}
		os.Exit(3)
	case "sleep":
		duration, _ := time.ParseDuration(arguments[1])
		time.Sleep(duration)
	case "environment":
		_, _ = os.Stdout.WriteString(os.Getenv(arguments[1]))
	case "both":
		payload := strings.Repeat("x", 40)
		_, _ = os.Stdout.WriteString(payload)
		_, _ = os.Stderr.WriteString(payload)
	default:
		os.Exit(4)
	}
	os.Exit(0)
}

func testRunner(t *testing.T) *Runner {
	return testRunnerAt(t, fixedRunnerClock{now: runnerTestNow})
}

func testRunnerAt(t *testing.T, clock Clock) *Runner {
	t.Helper()
	runner, err := New(Config{
		MaxTimeout: 5 * time.Second, MaxOutputBytes: 2048, MaxInputBytes: 1024,
		MaxTargets: 2, MaxConcurrency: 2, MaxSuppliedSecrets: 4, MaxSecretBytes: 128,
		Clock: clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	if testing.CoverMode() != "" {
		runner.env = append(runner.env, "GOCOVERDIR="+t.TempDir())
	}
	return runner
}

func testExecutableIdentity(t *testing.T) ExecutableIdentity {
	t.Helper()
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(payload)
	return ExecutableIdentity{Path: path, SHA256: hex.EncodeToString(digest[:])}
}

func helperArgs(operation string, values ...string) []string {
	arguments := []string{"-test.run=^TestDiagnosticRunnerHelperProcess$", "--", "--diagnostic-runner-helper", operation}
	return append(arguments, values...)
}

func testRequest(identity ExecutableIdentity, targets []targetPlan) executionRequest {
	return executionRequest{
		DefinitionID: "definition-1", DefinitionVersion: "v1", AttemptID: "attempt-1",
		DefinitionDigest: strings.Repeat("d", 64),
		Executable:       identity, Targets: targets, Timeout: 4 * time.Second,
		MaxOutputBytes: 1024, Concurrency: 1,
		ValidNotBefore: runnerTestNow.Add(-time.Hour), ValidBefore: runnerTestNow.Add(time.Hour),
	}
}

var runnerTestNow = time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)

type fixedRunnerClock struct{ now time.Time }

func (clock fixedRunnerClock) Now() time.Time { return clock.now }

type sequenceRunnerClock struct {
	mutex  sync.Mutex
	values []time.Time
}

func (clock *sequenceRunnerClock) Now() time.Time {
	clock.mutex.Lock()
	defer clock.mutex.Unlock()
	if len(clock.values) == 1 {
		return clock.values[0]
	}
	value := clock.values[0]
	clock.values = clock.values[1:]
	return value
}
