package domain

import (
	"crypto/sha256"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

const DiagnosticSchemaVersion = 1

type DiagnosticRunID string
type DiagnosticWorkID string
type DiagnosticApprovalID string
type DiagnosticDefinitionID string
type DiagnosticTarget string

type DiagnosticPrivilege string

const (
	DiagnosticUnprivileged DiagnosticPrivilege = "UNPRIVILEGED"
	DiagnosticPrivileged   DiagnosticPrivilege = "PRIVILEGED"
)

func (p DiagnosticPrivilege) Validate() error {
	switch p {
	case DiagnosticUnprivileged, DiagnosticPrivileged:
		return nil
	default:
		return fmt.Errorf("unknown diagnostic privilege %q", p)
	}
}

type DiagnosticRunStatus string

const (
	DiagnosticAwaitingApproval DiagnosticRunStatus = "AWAITING_APPROVAL"
	DiagnosticQueued           DiagnosticRunStatus = "QUEUED"
	DiagnosticRunning          DiagnosticRunStatus = "RUNNING"
	DiagnosticSucceeded        DiagnosticRunStatus = "SUCCEEDED"
	DiagnosticPartial          DiagnosticRunStatus = "PARTIAL"
	DiagnosticFailed           DiagnosticRunStatus = "FAILED"
	DiagnosticCancelled        DiagnosticRunStatus = "CANCELLED"
)

func (s DiagnosticRunStatus) Terminal() bool {
	return s == DiagnosticSucceeded || s == DiagnosticPartial || s == DiagnosticFailed || s == DiagnosticCancelled
}

func (s DiagnosticRunStatus) Validate() error {
	switch s {
	case DiagnosticAwaitingApproval, DiagnosticQueued, DiagnosticRunning, DiagnosticSucceeded,
		DiagnosticPartial, DiagnosticFailed, DiagnosticCancelled:
		return nil
	default:
		return fmt.Errorf("unknown diagnostic run status %q", s)
	}
}

type DiagnosticDefinitionRef struct {
	PackID            string
	PackVersion       string
	DefinitionID      DiagnosticDefinitionID
	DefinitionVersion string
	DefinitionDigest  SHA256
}

func (r DiagnosticDefinitionRef) Validate() error {
	if !validDiagnosticToken(r.PackID) || !validDiagnosticToken(r.PackVersion) || !validDiagnosticToken(string(r.DefinitionID)) || !validDiagnosticToken(r.DefinitionVersion) {
		return fmt.Errorf("diagnostic definition identity is invalid")
	}
	if r.DefinitionDigest == (SHA256{}) {
		return fmt.Errorf("diagnostic definition digest is required")
	}
	return nil
}

// DiagnosticArgument is safe, non-secret definition input. Credential values
// are delivered through the separate ephemeral credential subsystem and must
// never be represented by this type.
type DiagnosticArgument struct {
	Name  string
	Value string
}

type DiagnosticRequest struct {
	RunID          DiagnosticRunID
	ClusterID      ClusterID
	Definition     DiagnosticDefinitionRef
	Privilege      DiagnosticPrivilege
	Targets        []DiagnosticTarget
	Arguments      []DiagnosticArgument
	RequestedBy    string
	IdempotencyKey string
	RequestedAt    time.Time
	Deadline       time.Time
	MaxAttempts    int
}

func (r DiagnosticRequest) Validate() error {
	if !validDiagnosticToken(string(r.RunID)) || r.ClusterID == "" || !validDiagnosticToken(r.RequestedBy) || !validDiagnosticToken(r.IdempotencyKey) {
		return fmt.Errorf("diagnostic request identifiers are invalid")
	}
	if err := r.Definition.Validate(); err != nil {
		return err
	}
	if err := r.Privilege.Validate(); err != nil {
		return err
	}
	if len(r.Targets) < 1 || len(r.Targets) > 256 {
		return fmt.Errorf("diagnostic request must contain between 1 and 256 targets")
	}
	seenTargets := make(map[DiagnosticTarget]struct{}, len(r.Targets))
	for _, target := range r.Targets {
		if !validDiagnosticTarget(string(target)) {
			return fmt.Errorf("diagnostic target is invalid")
		}
		if _, exists := seenTargets[target]; exists {
			return fmt.Errorf("diagnostic targets must be unique")
		}
		seenTargets[target] = struct{}{}
	}
	if len(r.Arguments) > 32 {
		return fmt.Errorf("diagnostic request has too many arguments")
	}
	seenArguments := make(map[string]struct{}, len(r.Arguments))
	for _, argument := range r.Arguments {
		if !validDiagnosticToken(argument.Name) || len(argument.Value) > 512 || strings.IndexByte(argument.Value, 0) >= 0 {
			return fmt.Errorf("diagnostic argument is invalid")
		}
		if credentialArgumentName(argument.Name) {
			return fmt.Errorf("credential values cannot be diagnostic arguments")
		}
		if _, exists := seenArguments[argument.Name]; exists {
			return fmt.Errorf("diagnostic argument names must be unique")
		}
		seenArguments[argument.Name] = struct{}{}
	}
	if r.RequestedAt.IsZero() || r.Deadline.IsZero() || !r.Deadline.After(r.RequestedAt) || r.Deadline.Sub(r.RequestedAt) > time.Hour {
		return fmt.Errorf("diagnostic deadline must be after request time and within one hour")
	}
	if r.MaxAttempts < 1 || r.MaxAttempts > 3 {
		return fmt.Errorf("diagnostic maximum attempts must be between 1 and 3")
	}
	return nil
}

type DiagnosticRun struct {
	request DiagnosticRequest
	status  DiagnosticRunStatus
	version int
}

func NewDiagnosticRun(request DiagnosticRequest, approvalRequired bool) (DiagnosticRun, error) {
	if err := request.Validate(); err != nil {
		return DiagnosticRun{}, err
	}
	status := DiagnosticQueued
	if approvalRequired {
		status = DiagnosticAwaitingApproval
	}
	return DiagnosticRun{request: cloneDiagnosticRequest(request), status: status, version: 1}, nil
}

func ReconstituteDiagnosticRun(request DiagnosticRequest, status DiagnosticRunStatus, version int) (DiagnosticRun, error) {
	if err := request.Validate(); err != nil {
		return DiagnosticRun{}, err
	}
	if err := status.Validate(); err != nil {
		return DiagnosticRun{}, err
	}
	if version < 1 {
		return DiagnosticRun{}, fmt.Errorf("diagnostic run version must be positive")
	}
	return DiagnosticRun{request: cloneDiagnosticRequest(request), status: status, version: version}, nil
}

func (r DiagnosticRun) Request() DiagnosticRequest  { return cloneDiagnosticRequest(r.request) }
func (r DiagnosticRun) Status() DiagnosticRunStatus { return r.status }
func (r DiagnosticRun) Version() int                { return r.version }

func (r DiagnosticRun) Approve(approval DiagnosticApproval, now time.Time) (DiagnosticRun, error) {
	if r.status != DiagnosticAwaitingApproval {
		return DiagnosticRun{}, fmt.Errorf("diagnostic run is not awaiting approval")
	}
	if err := approval.ValidateFor(r, now); err != nil {
		return DiagnosticRun{}, err
	}
	r.status = DiagnosticQueued
	r.version++
	return r, nil
}

func (r DiagnosticRun) Start() (DiagnosticRun, error) {
	if r.status != DiagnosticQueued {
		return DiagnosticRun{}, fmt.Errorf("only a queued diagnostic run can start")
	}
	r.status = DiagnosticRunning
	r.version++
	return r, nil
}

func (r DiagnosticRun) Complete(results []DiagnosticTargetResult) (DiagnosticRun, error) {
	if r.status != DiagnosticRunning && r.status != DiagnosticQueued {
		return DiagnosticRun{}, fmt.Errorf("diagnostic run cannot complete from %s", r.status)
	}
	if err := ValidateDiagnosticTargetResults(r.request.Targets, results); err != nil {
		return DiagnosticRun{}, err
	}
	succeeded := 0
	for _, result := range results {
		if result.Status == DiagnosticTargetSucceeded {
			succeeded++
		}
	}
	switch {
	case succeeded == len(results):
		r.status = DiagnosticSucceeded
	case succeeded == 0:
		r.status = DiagnosticFailed
	default:
		r.status = DiagnosticPartial
	}
	r.version++
	return r, nil
}

type DiagnosticApproval struct {
	ApprovalID       DiagnosticApprovalID
	RunID            DiagnosticRunID
	DefinitionDigest SHA256
	TargetDigest     SHA256
	ApprovedBy       string
	ApprovedAt       time.Time
	ExpiresAt        time.Time
	RunVersion       int
}

func (a DiagnosticApproval) ValidateFor(run DiagnosticRun, now time.Time) error {
	if !validDiagnosticToken(string(a.ApprovalID)) || !validDiagnosticToken(a.ApprovedBy) {
		return fmt.Errorf("diagnostic approval identity is invalid")
	}
	if a.RunID != run.request.RunID || a.DefinitionDigest != run.request.Definition.DefinitionDigest || a.TargetDigest != DiagnosticTargetsDigest(run.request.Targets) {
		return fmt.Errorf("diagnostic approval does not match the requested action")
	}
	if a.RunVersion != run.version {
		return fmt.Errorf("diagnostic approval run version is stale")
	}
	if a.ApprovedAt.IsZero() || a.ExpiresAt.IsZero() || a.ExpiresAt.Before(a.ApprovedAt) || !a.ExpiresAt.After(now.UTC()) || a.ExpiresAt.Sub(a.ApprovedAt) > 15*time.Minute {
		return fmt.Errorf("diagnostic approval is expired or exceeds fifteen minutes")
	}
	return nil
}

func DiagnosticTargetsDigest(targets []DiagnosticTarget) SHA256 {
	values := make([]string, len(targets))
	for index, target := range targets {
		values[index] = string(target)
	}
	slices.Sort(values)
	return sha256.Sum256([]byte(strings.Join(values, "\x00")))
}

type DiagnosticAttemptStatus string

const (
	DiagnosticAttemptClaimed   DiagnosticAttemptStatus = "CLAIMED"
	DiagnosticAttemptRunning   DiagnosticAttemptStatus = "RUNNING"
	DiagnosticAttemptSucceeded DiagnosticAttemptStatus = "SUCCEEDED"
	DiagnosticAttemptPartial   DiagnosticAttemptStatus = "PARTIAL"
	DiagnosticAttemptFailed    DiagnosticAttemptStatus = "FAILED"
	DiagnosticAttemptExpired   DiagnosticAttemptStatus = "EXPIRED"
)

type DiagnosticWork struct {
	WorkID      DiagnosticWorkID
	Run         DiagnosticRun
	AvailableAt time.Time
	Deadline    time.Time
	MaxAttempts int
}

type DiagnosticWorkLease struct {
	Work         DiagnosticWork
	Attempt      int
	RunnerID     string
	LeaseToken   string
	LeaseExpires time.Time
}

type DiagnosticTargetStatus string

// StdoutTransformationState is producer provenance for the emitted stdout.
// UNKNOWN includes results written before this contract existed.
type StdoutTransformationState string

const (
	StdoutTransformationUnknown     StdoutTransformationState = "UNKNOWN"
	StdoutTransformationUnmodified  StdoutTransformationState = "UNMODIFIED"
	StdoutTransformationTransformed StdoutTransformationState = "TRANSFORMED"
)

// NormalizeStdoutTransformationState fails closed at legacy and transport
// boundaries. Only an exact reviewed producer value can assert UNMODIFIED.
func NormalizeStdoutTransformationState(value string) StdoutTransformationState {
	switch StdoutTransformationState(value) {
	case StdoutTransformationUnmodified, StdoutTransformationTransformed:
		return StdoutTransformationState(value)
	default:
		return StdoutTransformationUnknown
	}
}

const (
	DiagnosticTargetSucceeded DiagnosticTargetStatus = "SUCCEEDED"
	DiagnosticTargetFailed    DiagnosticTargetStatus = "FAILED"
	DiagnosticTargetTimedOut  DiagnosticTargetStatus = "TIMED_OUT"
	DiagnosticTargetRejected  DiagnosticTargetStatus = "REJECTED"
)

type DiagnosticTargetResult struct {
	Target                    DiagnosticTarget
	Status                    DiagnosticTargetStatus
	Retryable                 bool
	ExitCode                  *int
	Signal                    string
	TimedOut                  bool
	StdoutTruncated           bool
	StderrTruncated           bool
	StdoutBytes               int64
	StderrBytes               int64
	StdoutSHA256              SHA256
	StdoutTransformationState StdoutTransformationState
	StderrSHA256              SHA256
	ErrorCode                 string
	// StdoutExcerpt is a bounded, sanitized prefix of what the probe printed.
	//
	// Without it a diagnostic reaches the model as provenance only: that a probe
	// ran and exited zero, but not what it found. A byte count and a digest
	// cannot answer the question the diagnostic was run to answer, so a report
	// built on one can say a check succeeded and nothing about its result.
	//
	// This is untrusted output from a cluster host. It is carried in the
	// evidence excerpt channel, which the context builder renders as
	// untrusted_excerpt and the prompt names as a place hostile instructions may
	// appear. It is never promoted into a trusted summary.
	StdoutExcerpt string
}

// MaxDiagnosticStdoutExcerptBytes bounds one target's excerpt. It is half the
// context builder's per-evidence excerpt budget, so a fan-out across several
// hosts still yields readable output from more than one of them after the
// builder truncates the assembled excerpt.
const MaxDiagnosticStdoutExcerptBytes = 1024

func ValidateDiagnosticTargetResults(expected []DiagnosticTarget, results []DiagnosticTargetResult) error {
	if len(results) != len(expected) || len(results) == 0 {
		return fmt.Errorf("diagnostic results must cover every requested target exactly once")
	}
	wanted := make(map[DiagnosticTarget]struct{}, len(expected))
	for _, target := range expected {
		wanted[target] = struct{}{}
	}
	for _, result := range results {
		if _, ok := wanted[result.Target]; !ok {
			return fmt.Errorf("diagnostic result target is outside requested scope")
		}
		delete(wanted, result.Target)
		switch result.Status {
		case DiagnosticTargetSucceeded, DiagnosticTargetFailed, DiagnosticTargetTimedOut, DiagnosticTargetRejected:
		default:
			return fmt.Errorf("unknown diagnostic target result status %q", result.Status)
		}
		if result.StdoutBytes < 0 || result.StderrBytes < 0 || len(result.Signal) > 64 || len(result.ErrorCode) > 64 {
			return fmt.Errorf("diagnostic target result metadata is invalid")
		}
		// The excerpt crosses the perimeter from a host the control plane does
		// not trust, so it is bounded and screened here rather than wherever it
		// is eventually rendered.
		if len(result.StdoutExcerpt) > MaxDiagnosticStdoutExcerptBytes || !utf8.ValidString(result.StdoutExcerpt) || strings.IndexByte(result.StdoutExcerpt, 0) >= 0 {
			return fmt.Errorf("diagnostic target stdout excerpt is invalid")
		}
		if result.TimedOut != (result.Status == DiagnosticTargetTimedOut) {
			return fmt.Errorf("diagnostic timeout metadata is inconsistent")
		}
		if result.Retryable && (result.Status == DiagnosticTargetSucceeded || result.Status == DiagnosticTargetRejected) {
			return fmt.Errorf("successful or policy-rejected diagnostic result cannot be retryable")
		}
	}
	return nil
}

type DiagnosticAttemptResult struct {
	WorkID      DiagnosticWorkID
	RunID       DiagnosticRunID
	Attempt     int
	RunnerID    string
	PlanDigest  SHA256
	StartedAt   time.Time
	CompletedAt time.Time
	Targets     []DiagnosticTargetResult
}

func (r DiagnosticAttemptResult) Validate(expected []DiagnosticTarget) error {
	if !validDiagnosticToken(string(r.WorkID)) || !validDiagnosticToken(string(r.RunID)) || !validDiagnosticToken(r.RunnerID) || r.Attempt < 1 || r.PlanDigest == (SHA256{}) {
		return fmt.Errorf("diagnostic attempt attribution is invalid")
	}
	if r.StartedAt.IsZero() || r.CompletedAt.Before(r.StartedAt) {
		return fmt.Errorf("diagnostic attempt time range is invalid")
	}
	return ValidateDiagnosticTargetResults(expected, r.Targets)
}

// CanRetry reports whether retrying the entire target set is safe. M5 fails
// closed once any target succeeds, because a whole-work retry could otherwise
// repeat already-successful privileged execution.
func (r DiagnosticAttemptResult) CanRetry(maxAttempts int) bool {
	if r.Attempt >= maxAttempts || len(r.Targets) == 0 {
		return false
	}
	for _, target := range r.Targets {
		if target.Status == DiagnosticTargetSucceeded || !target.Retryable {
			return false
		}
	}
	return true
}

func cloneDiagnosticRequest(request DiagnosticRequest) DiagnosticRequest {
	request.Targets = slices.Clone(request.Targets)
	request.Arguments = slices.Clone(request.Arguments)
	request.RequestedAt = request.RequestedAt.UTC()
	request.Deadline = request.Deadline.UTC()
	return request
}

func validDiagnosticToken(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') && character != '.' && character != '_' && character != ':' && character != '-' {
			return false
		}
	}
	return true
}

func validDiagnosticTarget(value string) bool {
	return len(value) <= 256 && validDiagnosticToken(value)
}

func credentialArgumentName(name string) bool {
	normalized := strings.NewReplacer("-", "", "_", "", ".", "").Replace(strings.ToLower(name))
	switch normalized {
	case "credential", "credentials", "password", "passwd", "secret", "token", "apikey", "privatekey", "username", "user":
		return true
	default:
		return false
	}
}
