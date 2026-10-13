// Package diagnosticrunner executes sealed, verified command-pack plans without
// a shell. Signature and argument-policy verification deliberately live in the
// commandpack package.
package diagnosticrunner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/verticalcomputer/sherlock/internal/commandpack"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

const (
	CodeInvalidRequest     = "INVALID_REQUEST"
	CodeStartFailed        = "START_FAILED"
	CodeExitNonZero        = "EXIT_NON_ZERO"
	CodeTimedOut           = "TIMED_OUT"
	CodeCancelled          = "CANCELLED"
	CodeExecutableReplaced = "EXECUTABLE_REPLACED"
	CodeDefinitionInactive = "DEFINITION_INACTIVE"
	redactedMarker         = "[REDACTED]"
	controlCharacterMarker = "[CONTROL]"
)

// ExecutableIdentity pins an approved executable to its content. SHA256 must
// come from the verified command definition, not from request input supplied by
// an operator or model.
type ExecutableIdentity struct {
	Path   string
	SHA256 string
}

// targetPlan is an exact argv for one explicit target. Its private input is
// populated only by RestrictedSSH with a structured remote-runner envelope.
type targetPlan struct {
	TargetID string
	Args     []string
	input    []byte
}

// executionRequest can only be produced inside this package from a sealed
// commandpack.ExecutionPlan or by the restricted SSH adapter.
type executionRequest struct {
	DefinitionID               string
	DefinitionVersion          string
	DefinitionDigest           string
	AttemptID                  string
	Executable                 ExecutableIdentity
	Targets                    []targetPlan
	Timeout                    time.Duration
	MaxOutputBytes             int64
	RemoteResultMaxOutputBytes int64
	Concurrency                int
	SuppliedSecrets            [][]byte
	ValidNotBefore             time.Time
	ValidBefore                time.Time
}

type Clock interface{ Now() time.Time }

type wallClock struct{}

func (wallClock) Now() time.Time { return time.Now() }

// Config applies process-local ceilings. Environment is restricted to a small
// deterministic allow-list and does not inherit the runner's ambient values.
type Config struct {
	MaxTimeout         time.Duration
	MaxOutputBytes     int64
	MaxInputBytes      int64
	MaxTargets         int
	MaxConcurrency     int
	MaxSuppliedSecrets int
	MaxSecretBytes     int
	Environment        map[string]string
	Clock              Clock
}

type Runner struct {
	config Config
	env    []string
	clock  Clock
}

type Result struct {
	DefinitionID      string
	DefinitionVersion string
	DefinitionDigest  string
	AttemptID         string
	Targets           []TargetResult
}

type TargetResult struct {
	TargetID                  string
	Started                   bool
	ExitCode                  int
	Signal                    string
	TimedOut                  bool
	Cancelled                 bool
	ErrorCode                 string
	Stdout                    []byte
	Stderr                    []byte
	StdoutBytes               int64
	StderrBytes               int64
	StdoutTruncated           bool
	StderrTruncated           bool
	StdoutSHA256              string
	StdoutTransformationState domain.StdoutTransformationState
	StderrSHA256              string
	Duration                  time.Duration
}

func New(config Config) (*Runner, error) {
	if config.MaxTimeout <= 0 || config.MaxOutputBytes <= 0 || config.MaxInputBytes < 0 || config.MaxTargets <= 0 || config.MaxConcurrency <= 0 || config.MaxSuppliedSecrets <= 0 || config.MaxSecretBytes <= 0 {
		return nil, errors.New("diagnostic runner: all limits must be positive")
	}
	clock := config.Clock
	if clock == nil {
		clock = wallClock{}
	}
	environment := map[string]string{"LANG": "C", "LC_ALL": "C", "TZ": "UTC"}
	for key, value := range config.Environment {
		if key != "LANG" && key != "LC_ALL" && key != "TZ" {
			return nil, fmt.Errorf("diagnostic runner: environment key %q is not allowed", key)
		}
		if strings.ContainsAny(key+value, "\x00\r\n") {
			return nil, errors.New("diagnostic runner: invalid environment value")
		}
		environment[key] = value
	}
	keys := make([]string, 0, len(environment))
	for key := range environment {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	env := make([]string, 0, len(keys))
	for _, key := range keys {
		env = append(env, key+"="+environment[key])
	}
	return &Runner{config: config, env: env, clock: clock}, nil
}

// ExecuteVerified is the only local command execution entry point. ExecutionPlan
// has unexported state and can only be created by a verified command catalog.
func (r *Runner) ExecuteVerified(ctx context.Context, attemptID string, plan commandpack.ExecutionPlan, suppliedSecrets [][]byte) (Result, error) {
	if err := r.validateSuppliedSecrets(suppliedSecrets); err != nil {
		return Result{}, err
	}
	request, err := requestFromVerifiedPlan(attemptID, plan, suppliedSecrets)
	if err != nil {
		return Result{}, err
	}
	return r.execute(ctx, request)
}

func requestFromVerifiedPlan(attemptID string, plan commandpack.ExecutionPlan, suppliedSecrets [][]byte) (executionRequest, error) {
	definitionID, definitionVersion, definitionDigest := plan.DefinitionIdentity()
	executablePath, executableSHA256 := plan.ExecutableIdentity()
	argv := plan.Argv()
	targets := plan.Targets()
	limits := plan.Limits()
	validNotBefore, validBefore := plan.Validity()
	if len(argv) == 0 || argv[0] != executablePath {
		return executionRequest{}, errors.New("diagnostic runner: verified plan argv does not match executable")
	}
	if plan.RequiresPrivilege() || plan.SudoRule() != "" {
		return executionRequest{}, errors.New("diagnostic runner: privileged plan requires a dedicated privilege adapter")
	}
	targetPlans := make([]targetPlan, len(targets))
	for index, target := range targets {
		targetPlans[index] = targetPlan{TargetID: target.Name, Args: append([]string(nil), argv[1:]...)}
	}
	return executionRequest{
		DefinitionID: definitionID, DefinitionVersion: definitionVersion, DefinitionDigest: definitionDigest,
		AttemptID: attemptID, Executable: ExecutableIdentity{Path: executablePath, SHA256: executableSHA256},
		Targets: targetPlans, Timeout: time.Duration(limits.TimeoutSeconds) * time.Second,
		MaxOutputBytes: int64(limits.MaximumOutputBytes), Concurrency: limits.MaximumConcurrency,
		SuppliedSecrets: suppliedSecrets, ValidNotBefore: validNotBefore, ValidBefore: validBefore,
	}, nil
}

func (r *Runner) execute(ctx context.Context, request executionRequest) (Result, error) {
	if ctx == nil {
		return Result{}, errors.New("diagnostic runner: nil context")
	}
	if err := r.validate(request); err != nil {
		return Result{}, err
	}

	result := Result{
		DefinitionID: request.DefinitionID, DefinitionVersion: request.DefinitionVersion,
		DefinitionDigest: request.DefinitionDigest, AttemptID: request.AttemptID,
		Targets: make([]TargetResult, len(request.Targets)),
	}
	jobs := make(chan int, len(request.Targets))
	for index := range request.Targets {
		jobs <- index
	}
	close(jobs)

	var group sync.WaitGroup
	for range request.Concurrency {
		group.Add(1)
		go func() {
			defer group.Done()
			for index := range jobs {
				result.Targets[index] = r.executeTarget(ctx, request, request.Targets[index])
			}
		}()
	}
	group.Wait()
	return result, nil
}

func (r *Runner) validate(request executionRequest) error {
	if !safeIdentifier(request.DefinitionID) || !safeIdentifier(request.DefinitionVersion) || !safeIdentifier(request.AttemptID) {
		return errors.New("diagnostic runner: invalid definition or attempt identity")
	}
	if !validSHA256(request.DefinitionDigest) {
		return errors.New("diagnostic runner: invalid definition digest")
	}
	if !definitionActive(request.ValidNotBefore, request.ValidBefore, r.clock.Now()) {
		return errors.New("diagnostic runner: verified definition is not currently active")
	}
	if request.Timeout <= 0 || request.Timeout > r.config.MaxTimeout {
		return errors.New("diagnostic runner: timeout exceeds policy")
	}
	if request.MaxOutputBytes <= 0 || request.MaxOutputBytes > r.config.MaxOutputBytes {
		return errors.New("diagnostic runner: output limit exceeds policy")
	}
	if request.Concurrency <= 0 || request.Concurrency > r.config.MaxConcurrency {
		return errors.New("diagnostic runner: concurrency exceeds policy")
	}
	if len(request.Targets) == 0 || len(request.Targets) > r.config.MaxTargets {
		return errors.New("diagnostic runner: target count exceeds policy")
	}
	if err := validateExecutable(request.Executable); err != nil {
		return err
	}
	seen := make(map[string]struct{}, len(request.Targets))
	for _, target := range request.Targets {
		if !safeIdentifier(target.TargetID) {
			return errors.New("diagnostic runner: invalid target identity")
		}
		if _, exists := seen[target.TargetID]; exists {
			return errors.New("diagnostic runner: duplicate target identity")
		}
		seen[target.TargetID] = struct{}{}
		var inputSize int64
		if len(target.input) > 0 {
			inputSize = int64(len(target.input))
		}
		if inputSize > r.config.MaxInputBytes {
			return errors.New("diagnostic runner: input limit exceeds policy")
		}
		for _, argument := range target.Args {
			if strings.ContainsRune(argument, '\x00') {
				return errors.New("diagnostic runner: argument contains NUL")
			}
		}
	}
	return r.validateSuppliedSecrets(request.SuppliedSecrets)
}

func (r *Runner) validateSuppliedSecrets(secrets [][]byte) error {
	if len(secrets) > r.config.MaxSuppliedSecrets {
		return errors.New("diagnostic runner: supplied secret count exceeds policy")
	}
	for _, secret := range secrets {
		if len(secret) == 0 || len(secret) > r.config.MaxSecretBytes {
			return errors.New("diagnostic runner: supplied secret size exceeds policy")
		}
	}
	return nil
}

func (r *Runner) executeTarget(parent context.Context, request executionRequest, target targetPlan) (result TargetResult) {
	startedAt := time.Now()
	result = TargetResult{TargetID: target.TargetID, ExitCode: -1}
	budget := &outputBudget{remaining: request.MaxOutputBytes}
	stdout := newSafeCapture(budget, request.SuppliedSecrets)
	stderr := newSafeCapture(budget, request.SuppliedSecrets)
	defer func() {
		stdout.finish()
		stderr.finish()
		result.Stdout, result.StdoutBytes, result.StdoutTruncated, result.StdoutSHA256, result.StdoutTransformationState = stdout.result()
		result.Stderr, result.StderrBytes, result.StderrTruncated, result.StderrSHA256, _ = stderr.result()
		result.Duration = time.Since(startedAt)
	}()

	initialInfo, err := verifyExecutable(request.Executable)
	if err != nil {
		result.ErrorCode = CodeExecutableReplaced
		return result
	}
	if parent.Err() != nil {
		result.Cancelled = true
		result.ErrorCode = CodeCancelled
		return result
	}

	command := exec.Command(request.Executable.Path, target.Args...)
	command.Env = append([]string(nil), r.env...)
	command.Dir = "/"
	command.Stdin = bytes.NewReader(target.input)
	command.Stdout = stdout
	command.Stderr = stderr
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if !definitionActive(request.ValidNotBefore, request.ValidBefore, r.clock.Now()) {
		result.ErrorCode = CodeDefinitionInactive
		return result
	}

	if err := command.Start(); err != nil {
		result.ErrorCode = CodeStartFailed
		return result
	}
	result.Started = true
	if !sameExecutable(request.Executable, initialInfo) {
		killProcessGroup(command.Process.Pid)
		_ = command.Wait()
		result.ErrorCode = CodeExecutableReplaced
		return result
	}

	targetContext, cancel := context.WithTimeout(parent, request.Timeout)
	defer cancel()
	waited := make(chan error, 1)
	go func() { waited <- command.Wait() }()
	select {
	case err = <-waited:
	case <-targetContext.Done():
		killProcessGroup(command.Process.Pid)
		err = <-waited
		if parent.Err() != nil {
			result.Cancelled = true
			result.ErrorCode = CodeCancelled
		} else {
			result.TimedOut = true
			result.ErrorCode = CodeTimedOut
		}
	}

	setProcessState(&result, command.ProcessState)
	if !sameExecutable(request.Executable, initialInfo) {
		result.ErrorCode = CodeExecutableReplaced
		return result
	}
	if result.ErrorCode == "" && err != nil {
		result.ErrorCode = CodeExitNonZero
	}
	return result
}

func definitionActive(notBefore, before, now time.Time) bool {
	return !notBefore.IsZero() && !before.IsZero() && before.After(notBefore) && !now.Before(notBefore) && now.Before(before)
}

func validateExecutable(identity ExecutableIdentity) error {
	if !filepath.IsAbs(identity.Path) || filepath.Clean(identity.Path) != identity.Path {
		return errors.New("diagnostic runner: executable path must be absolute and clean")
	}
	base := filepath.Base(identity.Path)
	switch base {
	case "sh", "bash", "dash", "zsh", "ksh", "csh", "tcsh", "fish", "sudo", "su", "env":
		return errors.New("diagnostic runner: shell or privilege trampoline is prohibited")
	}
	if !validSHA256(identity.SHA256) {
		return errors.New("diagnostic runner: invalid executable digest")
	}
	return nil
}

func validSHA256(value string) bool {
	digest, err := hex.DecodeString(value)
	return err == nil && len(digest) == sha256.Size && value == strings.ToLower(value)
}

func verifyExecutable(identity ExecutableIdentity) (os.FileInfo, error) {
	info, err := os.Lstat(identity.Path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode()&0111 == 0 {
		return nil, errors.New("invalid executable file")
	}
	file, err := os.Open(identity.Path)
	if err != nil {
		return nil, errors.New("open executable")
	}
	hasher := sha256.New()
	_, copyErr := file.WriteTo(hasher)
	closeErr := file.Close()
	if copyErr != nil || closeErr != nil || hex.EncodeToString(hasher.Sum(nil)) != identity.SHA256 {
		return nil, errors.New("executable identity mismatch")
	}
	return info, nil
}

func sameExecutable(identity ExecutableIdentity, initial os.FileInfo) bool {
	current, err := os.Lstat(identity.Path)
	if err != nil || !os.SameFile(initial, current) {
		return false
	}
	_, err = verifyExecutable(identity)
	return err == nil
}

func killProcessGroup(pid int) {
	_ = syscall.Kill(-pid, syscall.SIGKILL)
}

func setProcessState(result *TargetResult, state *os.ProcessState) {
	if state == nil {
		return
	}
	result.ExitCode = state.ExitCode()
	if status, ok := state.Sys().(syscall.WaitStatus); ok && status.Signaled() {
		result.Signal = status.Signal().String()
	}
}

func safeIdentifier(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for index, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || (index > 0 && (character == '.' || character == '_' || character == '-')) {
			continue
		}
		return false
	}
	return true
}

type safeCapture struct {
	budget      *outputBudget
	secrets     [][]byte
	pending     []byte
	output      bytes.Buffer
	hasher      hash.Hash
	rawBytes    int64
	truncated   bool
	transformed bool
	finished    bool
}

type outputBudget struct {
	mutex     sync.Mutex
	remaining int64
}

func newSafeCapture(budget *outputBudget, secrets [][]byte) *safeCapture {
	copied := make([][]byte, len(secrets))
	for index := range secrets {
		copied[index] = append([]byte(nil), secrets[index]...)
	}
	return &safeCapture{budget: budget, secrets: copied, hasher: sha256.New()}
}

func (capture *safeCapture) Write(payload []byte) (int, error) {
	capture.rawBytes += int64(len(payload))
	capture.pending = append(capture.pending, payload...)
	capture.drain(false)
	return len(payload), nil
}

func (capture *safeCapture) finish() {
	if capture.finished {
		return
	}
	capture.drain(true)
	for index := range capture.secrets {
		clear(capture.secrets[index])
	}
	clear(capture.pending)
	capture.pending = nil
	capture.finished = true
}

func (capture *safeCapture) drain(final bool) {
	for len(capture.pending) > 0 {
		matched := false
		partial := false
		for _, secret := range capture.secrets {
			if len(capture.pending) >= len(secret) && bytes.Equal(capture.pending[:len(secret)], secret) {
				capture.transformed = true
				capture.emit([]byte(redactedMarker))
				capture.pending = capture.pending[len(secret):]
				matched = true
				break
			}
			if !final && len(capture.pending) < len(secret) && bytes.Equal(capture.pending, secret[:len(capture.pending)]) {
				partial = true
			}
		}
		if matched {
			continue
		}
		if partial {
			return
		}
		value := capture.pending[0]
		capture.pending = capture.pending[1:]
		if (value < 0x20 && value != '\n' && value != '\t') || value == 0x7f {
			capture.transformed = true
			capture.emit([]byte(controlCharacterMarker))
		} else {
			capture.emit([]byte{value})
		}
	}
}

func (capture *safeCapture) emit(value []byte) {
	_, _ = capture.hasher.Write(value)
	capture.budget.mutex.Lock()
	defer capture.budget.mutex.Unlock()
	if capture.budget.remaining <= 0 {
		capture.truncated = true
		return
	}
	if int64(len(value)) > capture.budget.remaining {
		_, _ = capture.output.Write(value[:capture.budget.remaining])
		capture.budget.remaining = 0
		capture.truncated = true
		return
	}
	_, _ = capture.output.Write(value)
	capture.budget.remaining -= int64(len(value))
}

func (capture *safeCapture) result() ([]byte, int64, bool, string, domain.StdoutTransformationState) {
	state := domain.StdoutTransformationUnmodified
	if capture.transformed {
		state = domain.StdoutTransformationTransformed
	}
	return append([]byte(nil), capture.output.Bytes()...), capture.rawBytes, capture.truncated, hex.EncodeToString(capture.hasher.Sum(nil)), state
}

func (capture *safeCapture) destroy() {
	capture.finish()
	clear(capture.output.Bytes())
	capture.output.Reset()
}
