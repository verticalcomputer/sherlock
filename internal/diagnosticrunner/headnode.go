package diagnosticrunner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"time"
	"unicode/utf8"

	"github.com/verticalcomputer/sherlock/internal/adapters/kernelxid"
	"github.com/verticalcomputer/sherlock/internal/commandpack"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

// ErrDiagnosticLeaseLost tells the head journal that the control plane
// authoritatively rejected a lease. Transport failures do not carry this
// sentinel, so their completed result remains ready for replay.
var ErrDiagnosticLeaseLost = errors.New("diagnostic work lease is invalid or expired")

var errTargetRoleUnavailable = errors.New("target has no confirmed diagnostic role")

// DiagnosticWorkSource is the pull side of the collector's diagnostic endpoint
// family. The head node claims work; nothing outside the perimeter initiates
// execution.
//
// This is why sherlock-investigator is deployed outside the cluster and never
// needs to be inside it. A cluster denies inbound traffic, so the control plane
// cannot reach a compute node; the investigator enqueues a reviewed invocation
// and parks the investigation in AWAITING_EVIDENCE, and this loop -- running
// inside -- claims the work and reports the result back out. The direction of
// the connection is the whole design, so treat any proposal that has the
// control plane calling into the cluster as a change to the perimeter model
// rather than an implementation detail.
type DiagnosticWorkSource interface {
	ClaimDiagnosticWork(ctx context.Context, wait time.Duration) (domain.DiagnosticWorkLease, bool, error)
	RecordDiagnosticAttempt(ctx context.Context, lease domain.DiagnosticWorkLease, result domain.DiagnosticAttemptResult) error
}

// LocalInvoker executes one verified invocation from the head node. In
// production this is RestrictedSSH reaching a compute node's sealed runner; the
// interface exists so the head-node loop is testable without a network.
type LocalInvoker interface {
	ExecuteInvocation(ctx context.Context, runner *Runner, catalog *commandpack.Catalog, attemptID string, invocation commandpack.Invocation, suppliedSecrets [][]byte) (Result, error)
}

type HeadNodeConfig struct {
	// ClusterID is the head node's local deployment boundary. A lease carrying
	// any other cluster is rejected before role resolution or execution.
	ClusterID domain.ClusterID
	RunnerID  string
	// PollWait bounds one long poll against the control plane.
	PollWait time.Duration
}

// HeadNode claims reviewed diagnostic work and executes it locally through the
// SSH adapter.
//
// The head node reaches compute nodes directly, inside the perimeter, so no
// bastion traversal is required. It resolves the argv from the pack it verifies
// itself: the control plane transmits a definition reference, never a command,
// and the target's sealed runner verifies the same pack a third time.
//
// It also carries a bounded excerpt of what each probe printed. The runner
// captures stdout, and this loop used to record only its length and digest, so
// a diagnostic arrived at the model as evidence that a check had run rather
// than as its result. The excerpt is untrusted host output and travels in the
// evidence excerpt channel, never in a trusted summary.
type HeadNode struct {
	source  DiagnosticWorkSource
	invoker LocalInvoker
	runner  *Runner
	catalog *commandpack.Catalog
	roles   func(domain.DiagnosticTarget) (commandpack.TargetRole, bool)
	clock   func() time.Time
	journal *DiagnosticJournal
	config  HeadNodeConfig
}

func NewHeadNode(source DiagnosticWorkSource, invoker LocalInvoker, runner *Runner, catalog *commandpack.Catalog, roles func(domain.DiagnosticTarget) (commandpack.TargetRole, bool), clock func() time.Time, journal *DiagnosticJournal, config HeadNodeConfig) (*HeadNode, error) {
	if source == nil || invoker == nil || runner == nil || catalog == nil || roles == nil || clock == nil || journal == nil {
		return nil, errors.New("head node diagnostic dependencies are required")
	}
	if config.ClusterID == "" || config.RunnerID == "" || config.PollWait <= 0 || config.PollWait > 30*time.Second {
		return nil, errors.New("head node diagnostic configuration is invalid")
	}
	return &HeadNode{source: source, invoker: invoker, runner: runner, catalog: catalog, roles: roles, clock: clock, journal: journal, config: config}, nil
}

// RunOnce claims at most one unit of diagnostic work and carries it to a
// recorded attempt. It reports whether work was claimed, so a caller can back
// off when the queue is empty.
//
// An execution failure is recorded as a failed attempt rather than dropped: the
// investigation that dispatched it is parked waiting for an answer, and "the
// command failed" is an answer. Only a failure to claim or to record is
// returned as an error, because those leave the queue's own state uncertain.
func (head *HeadNode) RunOnce(ctx context.Context) (bool, error) {
	if pending, exists := head.journal.pending(); exists {
		if err := head.processJournalRecord(ctx, pending); err != nil {
			return true, err
		}
		return true, nil
	}
	lease, found, err := head.source.ClaimDiagnosticWork(ctx, head.config.PollWait)
	if err != nil {
		return false, fmt.Errorf("claim diagnostic work: %w", err)
	}
	if !found {
		return false, nil
	}
	request := lease.Work.Run.Request()
	if request.ClusterID != head.config.ClusterID || lease.RunnerID != head.config.RunnerID {
		return true, errors.New("claimed diagnostic lease does not match this head node")
	}
	record, err := head.journal.begin(lease)
	if err != nil {
		return true, fmt.Errorf("begin diagnostic attempt journal: %w", err)
	}
	if err := head.processJournalRecord(ctx, record); err != nil {
		return true, err
	}
	return true, nil
}

func (head *HeadNode) processJournalRecord(ctx context.Context, record diagnosticJournalRecord) error {
	lease, err := record.lease()
	if err != nil {
		return fmt.Errorf("reconstruct journaled diagnostic lease: %w", err)
	}
	request := lease.Work.Run.Request()
	if request.ClusterID != head.config.ClusterID || lease.RunnerID != head.config.RunnerID {
		return errors.New("journaled diagnostic lease does not match this head node")
	}
	if record.State == diagnosticJournalReady {
		return head.deliverJournaledAttempt(ctx, lease, *record.Result)
	}
	if record.State == diagnosticJournalStarted {
		attempt := head.uncertainAttempt(lease, "PRIOR_EXECUTION_OUTCOME_UNKNOWN")
		if err := head.journal.storeResult(lease.Work.WorkID, lease.Attempt, attempt); err != nil {
			return fmt.Errorf("journal interrupted diagnostic attempt: %w", err)
		}
		return head.deliverJournaledAttempt(ctx, lease, attempt)
	}
	if record.State != diagnosticJournalClaimed {
		return errors.New("diagnostic journal record is not processable")
	}
	if record.DoNotExecute {
		attempt := head.uncertainAttempt(lease, "PRIOR_EXECUTION_NOT_REPEATED")
		if err := head.journal.storeResult(lease.Work.WorkID, lease.Attempt, attempt); err != nil {
			return fmt.Errorf("journal suppressed diagnostic retry: %w", err)
		}
		return head.deliverJournaledAttempt(ctx, lease, attempt)
	}
	if err := head.journal.markStarted(lease.Work.WorkID, lease.Attempt); err != nil {
		return fmt.Errorf("mark diagnostic execution started: %w", err)
	}
	startedAt := head.clock().UTC()
	result, executeErr := head.execute(ctx, lease)
	attempt := domain.DiagnosticAttemptResult{
		WorkID: lease.Work.WorkID, RunID: request.RunID, Attempt: lease.Attempt, RunnerID: head.config.RunnerID,
		StartedAt: startedAt, CompletedAt: head.clock().UTC(),
	}
	if attempt.CompletedAt.Before(attempt.StartedAt) {
		attempt.CompletedAt = attempt.StartedAt
	}
	if executeErr != nil {
		attempt.PlanDigest = domain.ChecksumSHA256([]byte("dispatch-failed\x00" + string(lease.Work.WorkID)))
		attempt.Targets = refusedTargets(request.Targets, safeDispatchFailure(executeErr))
	} else {
		digest, err := domain.ParseSHA256(result.DefinitionDigest)
		if err != nil {
			return fmt.Errorf("verified definition digest is unreadable: %w", err)
		}
		attempt.PlanDigest = digest
		normalized, err := normalizedKernelXIDExcerpts(head.catalog, request, result, attempt.StartedAt, attempt.CompletedAt)
		if err != nil {
			return fmt.Errorf("normalize kernel XID diagnostic evidence: %w", err)
		}
		attempt.Targets = attemptTargets(request.Targets, result)
		for index := range attempt.Targets {
			if excerpt, found := normalized[string(attempt.Targets[index].Target)]; found {
				attempt.Targets[index].StdoutExcerpt = excerpt
			}
		}
	}
	if err := attempt.Validate(request.Targets); err != nil {
		return fmt.Errorf("head node produced an invalid attempt: %w", err)
	}
	if err := head.journal.storeResult(lease.Work.WorkID, lease.Attempt, attempt); err != nil {
		return fmt.Errorf("store completed diagnostic attempt: %w", err)
	}
	return head.deliverJournaledAttempt(ctx, lease, attempt)
}

// normalizedKernelXIDExcerpts parses full screened runner output before the
// generic 1 KiB display excerpt is projected. Selection is fail-closed against
// the locally verified definition: an exact kernel-XID request with drift is
// refused before raw output can be projected; unrelated definitions retain
// ordinary diagnostic handling.
func normalizedKernelXIDExcerpts(catalog *commandpack.Catalog, request domain.DiagnosticRequest, result Result, startedAt, completedAt time.Time) (map[string]string, error) {
	if !kernelxid.VerifiedDefinition(catalog, request, result.DefinitionID, result.DefinitionVersion, result.DefinitionDigest) {
		if request.Definition.DefinitionID == kernelxid.DefinitionID && request.Definition.DefinitionVersion == kernelxid.DefinitionVersion {
			return nil, errors.New("kernel XID definition does not match the locally verified catalog")
		}
		return nil, nil
	}
	byTarget := make(map[string]TargetResult, len(result.Targets))
	for _, target := range result.Targets {
		byTarget[target.TargetID] = target
	}
	sources := make([]kernelxid.SourceTarget, 0, len(request.Targets))
	for _, target := range request.Targets {
		observed, found := byTarget[string(target)]
		if !found {
			// The runner omitted this target. That is a coverage failure, not an
			// access decision; attemptTargets independently records NO_RESULT_REPORTED.
			sources = append(sources, kernelxid.SourceTarget{Target: target})
			continue
		}
		sources = append(sources, kernelxid.SourceTarget{
			Target: target, Status: diagnosticTargetStatus(observed), Stdout: observed.Stdout,
			StdoutTruncated: observed.StdoutTruncated, StdoutTransformationState: domain.NormalizeStdoutTransformationState(string(observed.StdoutTransformationState)),
		})
	}
	normalized, err := kernelxid.Normalize(request, startedAt, completedAt, sources)
	if err != nil {
		return nil, err
	}
	if len(normalized.Targets) != len(request.Targets) {
		return nil, fmt.Errorf("kernel XID normalizer returned incomplete target coverage")
	}
	excerpts := make(map[string]string, len(normalized.Targets))
	for index, target := range normalized.Targets {
		if target.Target != string(request.Targets[index]) {
			return nil, fmt.Errorf("kernel XID normalizer changed target order")
		}
		encoded, err := kernelxid.RenderTarget(target)
		if err != nil {
			return nil, err
		}
		excerpts[target.Target] = encoded
	}
	return excerpts, nil
}

func (head *HeadNode) deliverJournaledAttempt(ctx context.Context, lease domain.DiagnosticWorkLease, attempt domain.DiagnosticAttemptResult) error {
	if err := head.source.RecordDiagnosticAttempt(ctx, lease, attempt); err != nil {
		if errors.Is(err, ErrDiagnosticLeaseLost) {
			if journalErr := head.journal.markLeaseLost(lease.Work.WorkID, lease.Attempt); journalErr != nil {
				return fmt.Errorf("record diagnostic attempt: %v; mark lease lost: %w", err, journalErr)
			}
		}
		return fmt.Errorf("record diagnostic attempt: %w", err)
	}
	if err := head.journal.markFinalized(lease.Work.WorkID, lease.Attempt); err != nil {
		return fmt.Errorf("finalize diagnostic attempt journal: %w", err)
	}
	return nil
}

func (head *HeadNode) uncertainAttempt(lease domain.DiagnosticWorkLease, errorCode string) domain.DiagnosticAttemptResult {
	now := head.clock().UTC()
	request := lease.Work.Run.Request()
	return domain.DiagnosticAttemptResult{
		WorkID: lease.Work.WorkID, RunID: request.RunID, Attempt: lease.Attempt, RunnerID: head.config.RunnerID,
		PlanDigest: domain.ChecksumSHA256([]byte(errorCode + "\x00" + string(lease.Work.WorkID))),
		StartedAt:  now, CompletedAt: now, Targets: refusedTargets(request.Targets, errorCode),
	}
}

func (head *HeadNode) execute(ctx context.Context, lease domain.DiagnosticWorkLease) (Result, error) {
	request := lease.Work.Run.Request()
	targets := make([]commandpack.Target, 0, len(request.Targets))
	var refused []TargetResult
	for _, target := range request.Targets {
		// Role resolution stays on the head node and comes from derived, expiring
		// entries. A target whose role is not currently confirmed is not reached.
		role, eligible := head.roles(target)
		if !eligible {
			refused = append(refused, TargetResult{TargetID: string(target), ErrorCode: "TARGET_ROLE_UNAVAILABLE"})
			continue
		}
		targets = append(targets, commandpack.Target{Name: string(target), Role: role})
	}
	arguments := make([]commandpack.ArgumentValue, 0, len(request.Arguments))
	for _, argument := range request.Arguments {
		value := argument.Value
		arguments = append(arguments, commandpack.ArgumentValue{Name: argument.Name, String: &value})
	}
	invocation := commandpack.Invocation{
		DefinitionID: string(request.Definition.DefinitionID), DefinitionVersion: request.Definition.DefinitionVersion,
		Arguments: arguments, Targets: targets,
	}
	attemptID := fmt.Sprintf("%s-%d", lease.Work.WorkID, lease.Attempt)
	if len(targets) == 0 {
		return Result{}, errTargetRoleUnavailable
	}
	result, err := head.invoker.ExecuteInvocation(ctx, head.runner, head.catalog, attemptID, invocation, nil)
	if err != nil && len(refused) == 0 {
		return Result{}, err
	}
	if err != nil {
		// Preserve inventory refusals even if dispatch of the eligible subset
		// also fails. No transport text enters any target result.
		result = Result{DefinitionID: string(request.Definition.DefinitionID), DefinitionVersion: request.Definition.DefinitionVersion, DefinitionDigest: domain.ChecksumSHA256([]byte("dispatch-failed\x00" + string(lease.Work.WorkID))).String(), AttemptID: attemptID}
		for _, target := range targets {
			result.Targets = append(result.Targets, TargetResult{TargetID: target.Name, ErrorCode: safeDispatchFailure(err)})
		}
	}
	result.Targets = append(result.Targets, refused...)
	return result, nil
}

// attemptTargets maps runner output onto the requested target set. Every
// requested target must appear exactly once, so a target the runner did not
// report is recorded as a failure rather than silently omitted.
func attemptTargets(requested []domain.DiagnosticTarget, result Result) []domain.DiagnosticTargetResult {
	byTarget := make(map[string]TargetResult, len(result.Targets))
	for _, target := range result.Targets {
		byTarget[target.TargetID] = target
	}
	results := make([]domain.DiagnosticTargetResult, 0, len(requested))
	for _, target := range requested {
		observed, reported := byTarget[string(target)]
		if !reported {
			results = append(results, refusedTarget(target, "NO_RESULT_REPORTED"))
			continue
		}
		status := diagnosticTargetStatus(observed)
		exitCode := observed.ExitCode
		entry := domain.DiagnosticTargetResult{
			Target: target, Status: status, TimedOut: observed.TimedOut, Signal: observed.Signal,
			StdoutTransformationState: domain.NormalizeStdoutTransformationState(string(observed.StdoutTransformationState)),
			StdoutTruncated:           observed.StdoutTruncated, StderrTruncated: observed.StderrTruncated,
			StdoutBytes: observed.StdoutBytes, StderrBytes: observed.StderrBytes, ErrorCode: observed.ErrorCode,
			StdoutExcerpt: stdoutExcerpt(observed.Stdout),
		}
		if observed.Started {
			entry.ExitCode = &exitCode
		}
		// A timeout or a transport failure may succeed later; a non-zero exit and
		// a policy rejection will not, and M5 already refuses to retry a work unit
		// once any target succeeded.
		entry.Retryable = status == domain.DiagnosticTargetTimedOut
		if digest, err := domain.ParseSHA256(observed.StdoutSHA256); err == nil {
			entry.StdoutSHA256 = digest
		}
		if digest, err := domain.ParseSHA256(observed.StderrSHA256); err == nil {
			entry.StderrSHA256 = digest
		}
		results = append(results, entry)
	}
	return results
}

func diagnosticTargetStatus(observed TargetResult) domain.DiagnosticTargetStatus {
	switch {
	case observed.TimedOut:
		return domain.DiagnosticTargetTimedOut
	case observed.Started && observed.ExitCode == 0 && observed.Signal == "" && observed.ErrorCode == "":
		return domain.DiagnosticTargetSucceeded
	case !observed.Started:
		return domain.DiagnosticTargetRejected
	default:
		return domain.DiagnosticTargetFailed
	}
}

// excerptElisionReserve is the budget held back from the excerpt for the notice
// that says what the elision dropped. A notice carrying two counts of a
// four-megabyte output cannot approach this, and selectedExcerpt still trims the
// tail if a notice ever did.
const excerptElisionReserve = 80

// stdoutExcerpt bounds and screens one target's output before it leaves the
// perimeter. Invalid UTF-8 and NUL bytes are rejected outright rather than
// repaired: a probe under a reviewed definition emits text, and something that
// does not is not output worth showing to a model. Truncation is on a rune
// boundary so the excerpt stays valid UTF-8.
//
// Output that overruns the bound is sampled from both ends rather than cut off
// after its opening bytes. A head-only excerpt describes whichever event a probe
// printed first, which for a chronological log is the oldest one. A seven-day
// kernel journal on a pilot node ran 197 lines: 80 historical XID 137 entries
// followed by the 117 XID 94 entries the investigation had been raised to
// explain. The excerpt held the first eight lines, so the model was shown only
// the XID 137s and correctly reported that the kernel text did not establish XID
// 94 -- a conclusion drawn from the four percent of the output that happened to
// be least relevant to the question asked.
func stdoutExcerpt(stdout []byte) string {
	if len(stdout) == 0 {
		return ""
	}
	trimmed := stdout
	if len(trimmed) > domain.MaxDiagnosticStdoutExcerptBytes {
		trimmed = selectedExcerpt(trimmed, domain.MaxDiagnosticStdoutExcerptBytes)
	}
	if !utf8.Valid(trimmed) || bytes.IndexByte(trimmed, 0) >= 0 {
		return ""
	}
	return string(trimmed)
}

// selectedExcerpt keeps whole lines from the start and the end of an oversized
// output and replaces the middle with a notice naming what it dropped.
//
// Everything kept is verbatim host text: the notice states two counts and
// interprets nothing, and the result stays in the untrusted excerpt channel. The
// counts matter on their own -- an excerpt that silently ends after eight of 197
// lines invites a reader to treat eight events as the whole record.
//
// Output with no line structure has no honest sampling point, so it falls back
// to the opening bytes trimmed to a rune boundary.
func selectedExcerpt(stdout []byte, maximum int) []byte {
	budget := maximum - excerptElisionReserve
	head := leadingLines(stdout, budget/2)
	tail := trailingLines(stdout[len(head):], budget-len(head))
	if len(head) == 0 && len(tail) == 0 {
		return runeBoundedPrefix(stdout, maximum)
	}
	omitted := stdout[len(head) : len(stdout)-len(tail)]
	notice := []byte(fmt.Sprintf("[... %d lines omitted, %d bytes ...]\n", bytes.Count(omitted, []byte{'\n'}), len(omitted)))
	// The reserve is sized so this cannot bind, but a bound that depends on the
	// width of a formatted number is not one worth trusting unchecked.
	for len(head)+len(notice)+len(tail) > maximum {
		shortened := trailingLines(tail, len(tail)-1)
		if len(shortened) == len(tail) {
			tail = nil
			break
		}
		tail = shortened
	}
	return slices.Concat(head, notice, tail)
}

// leadingLines returns the longest run of whole lines at the start of data that
// fits in limit bytes. A first line longer than limit yields nothing rather than
// a fragment.
func leadingLines(data []byte, limit int) []byte {
	kept := 0
	for kept < len(data) {
		breakAt := bytes.IndexByte(data[kept:], '\n')
		if breakAt < 0 || kept+breakAt+1 > limit {
			break
		}
		kept += breakAt + 1
	}
	return data[:kept]
}

// trailingLines returns the longest run of whole lines at the end of data that
// fits in limit bytes. A trailing fragment with no newline before it is a line.
func trailingLines(data []byte, limit int) []byte {
	start := len(data)
	for start > 0 {
		begin := bytes.LastIndexByte(data[:start-1], '\n') + 1
		if len(data)-begin > limit {
			break
		}
		start = begin
	}
	return data[start:]
}

// runeBoundedPrefix cuts data to at most maximum bytes on a rune boundary, so a
// multi-byte character split by the cap cannot leave invalid UTF-8 behind.
func runeBoundedPrefix(data []byte, maximum int) []byte {
	trimmed := data[:maximum]
	for len(trimmed) > 0 && !utf8.Valid(trimmed) {
		trimmed = trimmed[:len(trimmed)-1]
	}
	return trimmed
}

func refusedTargets(requested []domain.DiagnosticTarget, errorCode string) []domain.DiagnosticTargetResult {
	results := make([]domain.DiagnosticTargetResult, 0, len(requested))
	for _, target := range requested {
		results = append(results, refusedTarget(target, errorCode))
	}
	return results
}

func refusedTarget(target domain.DiagnosticTarget, errorCode string) domain.DiagnosticTargetResult {
	return domain.DiagnosticTargetResult{Target: target, Status: domain.DiagnosticTargetRejected, ErrorCode: errorCode}
}

// safeDispatchFailure classifies a dispatch failure at the point it occurs and
// never carries the underlying message, which can contain a host name, a path,
// or transport detail that does not belong in a durable audit record.
func safeDispatchFailure(err error) string {
	switch {
	case errors.Is(err, errTargetRoleUnavailable):
		return "TARGET_ROLE_UNAVAILABLE"
	case errors.Is(err, context.DeadlineExceeded):
		return "DISPATCH_DEADLINE_EXCEEDED"
	case errors.Is(err, context.Canceled):
		return "DISPATCH_CANCELLED"
	default:
		return "DISPATCH_FAILED"
	}
}
