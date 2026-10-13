package diagnosticrunner

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/verticalcomputer/sherlock/internal/commandpack"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

type headNodeSource struct {
	lease     domain.DiagnosticWorkLease
	available bool
	claims    int
	recorded  []domain.DiagnosticAttemptResult
	claimErr  error
	recordErr error
}

func (source *headNodeSource) ClaimDiagnosticWork(context.Context, time.Duration) (domain.DiagnosticWorkLease, bool, error) {
	source.claims++
	if source.claimErr != nil {
		return domain.DiagnosticWorkLease{}, false, source.claimErr
	}
	if !source.available {
		return domain.DiagnosticWorkLease{}, false, nil
	}
	source.available = false
	return source.lease, true, nil
}

func (source *headNodeSource) RecordDiagnosticAttempt(_ context.Context, _ domain.DiagnosticWorkLease, result domain.DiagnosticAttemptResult) error {
	source.recorded = append(source.recorded, result)
	return source.recordErr
}

type recordingInvoker struct {
	invocations []commandpack.Invocation
	result      Result
	err         error
}

func (invoker *recordingInvoker) ExecuteInvocation(_ context.Context, _ *Runner, _ *commandpack.Catalog, _ string, invocation commandpack.Invocation, _ [][]byte) (Result, error) {
	invoker.invocations = append(invoker.invocations, invocation)
	return invoker.result, invoker.err
}

func headNodeFixture(t *testing.T, targets ...string) (*headNodeSource, *commandpack.Catalog, domain.DiagnosticWorkLease) {
	t.Helper()
	catalog := diagnosticHeadCatalog(t)
	now := time.Date(2026, 8, 22, 10, 0, 0, 0, time.UTC)
	_, digest, found := catalog.Lookup("gpu.ecc_counters", "1.0.0")
	if !found {
		t.Fatal("the reviewed ECC definition is missing from the verified pack")
	}
	parsed, err := domain.ParseSHA256(digest)
	if err != nil {
		t.Fatal(err)
	}
	diagnosticTargets := make([]domain.DiagnosticTarget, 0, len(targets))
	for _, target := range targets {
		diagnosticTargets = append(diagnosticTargets, domain.DiagnosticTarget(target))
	}
	request := domain.DiagnosticRequest{
		RunID: "run-1", ClusterID: "cluster-a",
		Definition: domain.DiagnosticDefinitionRef{PackID: "standard.readonly", PackVersion: "1.1.0", DefinitionID: "gpu.ecc_counters", DefinitionVersion: "1.0.0", DefinitionDigest: parsed},
		Privilege:  domain.DiagnosticUnprivileged, Targets: diagnosticTargets, RequestedBy: "investigator", IdempotencyKey: "key-1",
		RequestedAt: now, Deadline: now.Add(10 * time.Minute), MaxAttempts: 1,
	}
	run, err := domain.NewDiagnosticRun(request, false)
	if err != nil {
		t.Fatal(err)
	}
	lease := domain.DiagnosticWorkLease{Work: domain.DiagnosticWork{WorkID: "work-1", Run: run, Deadline: request.Deadline, MaxAttempts: 1}, Attempt: 1, RunnerID: "head-1", LeaseToken: strings.Repeat("t", 32), LeaseExpires: now.Add(time.Minute)}
	return &headNodeSource{lease: lease, available: true}, catalog, lease
}

func newHeadNode(t *testing.T, source *headNodeSource, invoker LocalInvoker, catalog *commandpack.Catalog, eligible map[string]commandpack.TargetRole) *HeadNode {
	t.Helper()
	clock := time.Date(2026, 8, 22, 10, 0, 0, 0, time.UTC)
	journal, err := OpenDiagnosticJournal(filepath.Join(t.TempDir(), "diagnostic-journal.json"), func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	return newHeadNodeWithJournal(t, source, invoker, catalog, eligible, journal)
}

func newHeadNodeWithJournal(t *testing.T, source *headNodeSource, invoker LocalInvoker, catalog *commandpack.Catalog, eligible map[string]commandpack.TargetRole, journal *DiagnosticJournal) *HeadNode {
	t.Helper()
	runner, err := New(Config{MaxTimeout: time.Minute, MaxOutputBytes: 1 << 20, MaxInputBytes: 1 << 16, MaxTargets: 8, MaxConcurrency: 2, MaxSuppliedSecrets: 4, MaxSecretBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Date(2026, 8, 22, 10, 0, 0, 0, time.UTC)
	head, err := NewHeadNode(source, invoker, runner, catalog, func(target domain.DiagnosticTarget) (commandpack.TargetRole, bool) {
		role, ok := eligible[string(target)]
		return role, ok
	}, func() time.Time { clock = clock.Add(time.Second); return clock }, journal, HeadNodeConfig{ClusterID: "cluster-a", RunnerID: "head-1", PollWait: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return head
}

func TestHeadNodeReplaysCompletedResultAfterAcknowledgementLossWithoutReexecution(t *testing.T) {
	journalPath := filepath.Join(t.TempDir(), "diagnostic-journal.json")
	journalClock := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	journal, err := OpenDiagnosticJournal(journalPath, func() time.Time {
		journalClock = journalClock.Add(time.Second)
		return journalClock
	})
	if err != nil {
		t.Fatal(err)
	}
	source, catalog, lease := headNodeFixture(t, "comp001")
	source.recordErr = errors.New("acknowledgement lost")
	invoker := &recordingInvoker{result: Result{
		DefinitionID: "gpu.ecc_counters", DefinitionVersion: "1.0.0", DefinitionDigest: lease.Work.Run.Request().Definition.DefinitionDigest.String(),
		Targets: []TargetResult{{TargetID: "comp001", Started: true, ExitCode: 0, Stdout: []byte("volatile output\n"), StdoutBytes: 16, StdoutSHA256: strings.Repeat("b", 64), StderrSHA256: strings.Repeat("0", 64)}},
	}}
	head := newHeadNodeWithJournal(t, source, invoker, catalog, map[string]commandpack.TargetRole{"comp001": commandpack.TargetCompute}, journal)
	if claimed, err := head.RunOnce(context.Background()); !claimed || err == nil {
		t.Fatalf("first cycle claimed=%t err=%v", claimed, err)
	}
	if len(invoker.invocations) != 1 {
		t.Fatalf("remote executions = %d, want one", len(invoker.invocations))
	}

	reopened, err := OpenDiagnosticJournal(journalPath, func() time.Time {
		journalClock = journalClock.Add(time.Second)
		return journalClock
	})
	if err != nil {
		t.Fatal(err)
	}
	restartedSource := &headNodeSource{lease: lease}
	restarted := newHeadNodeWithJournal(t, restartedSource, invoker, catalog, map[string]commandpack.TargetRole{"comp001": commandpack.TargetCompute}, reopened)
	if claimed, err := restarted.RunOnce(context.Background()); !claimed || err != nil {
		t.Fatalf("restart replay claimed=%t err=%v", claimed, err)
	}
	if restartedSource.claims != 0 {
		t.Fatalf("restart claimed new work before replay: %d", restartedSource.claims)
	}
	if len(invoker.invocations) != 1 {
		t.Fatalf("acknowledgement loss executed the command %d times", len(invoker.invocations))
	}
	if len(restartedSource.recorded) != 1 || restartedSource.recorded[0].Targets[0].StdoutExcerpt != "volatile output\n" {
		t.Fatalf("replayed result = %#v", restartedSource.recorded)
	}
	if _, pending := reopened.pending(); pending {
		t.Fatal("acknowledged result remained pending")
	}
}

func TestHeadNodeDoesNotRepeatExecutionAfterCrashInStartedWindow(t *testing.T) {
	journalPath := filepath.Join(t.TempDir(), "diagnostic-journal.json")
	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	journal, err := OpenDiagnosticJournal(journalPath, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	source, catalog, lease := headNodeFixture(t, "comp001")
	if _, err := journal.begin(lease); err != nil {
		t.Fatal(err)
	}
	if err := journal.markStarted(lease.Work.WorkID, lease.Attempt); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenDiagnosticJournal(journalPath, func() time.Time { return now.Add(time.Second) })
	if err != nil {
		t.Fatal(err)
	}
	invoker := &recordingInvoker{}
	source.available = false
	head := newHeadNodeWithJournal(t, source, invoker, catalog, map[string]commandpack.TargetRole{"comp001": commandpack.TargetCompute}, reopened)
	if claimed, err := head.RunOnce(context.Background()); !claimed || err != nil {
		t.Fatalf("recovery claimed=%t err=%v", claimed, err)
	}
	if len(invoker.invocations) != 0 {
		t.Fatal("ambiguous started attempt was executed again")
	}
	if len(source.recorded) != 1 || source.recorded[0].Targets[0].ErrorCode != "PRIOR_EXECUTION_OUTCOME_UNKNOWN" {
		t.Fatalf("recovery result = %#v", source.recorded)
	}
}

func TestHeadNodeDoesNotExecuteAReplacementLeaseAfterAmbiguousLeaseLoss(t *testing.T) {
	journalPath := filepath.Join(t.TempDir(), "diagnostic-journal.json")
	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	journal, err := OpenDiagnosticJournal(journalPath, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	source, catalog, lease := headNodeFixture(t, "comp001")
	request := lease.Work.Run.Request()
	request.MaxAttempts = 2
	run, err := domain.ReconstituteDiagnosticRun(request, domain.DiagnosticRunning, 2)
	if err != nil {
		t.Fatal(err)
	}
	lease.Work.Run, lease.Work.MaxAttempts = run, 2
	if _, err := journal.begin(lease); err != nil {
		t.Fatal(err)
	}
	if err := journal.markStarted(lease.Work.WorkID, lease.Attempt); err != nil {
		t.Fatal(err)
	}
	prior := domain.DiagnosticAttemptResult{
		WorkID: lease.Work.WorkID, RunID: request.RunID, Attempt: 1, RunnerID: lease.RunnerID,
		PlanDigest: domain.ChecksumSHA256([]byte("prior-plan")), StartedAt: now, CompletedAt: now.Add(time.Second),
		Targets: refusedTargets(request.Targets, "PRIOR_RESULT_NOT_ACKNOWLEDGED"),
	}
	if err := journal.storeResult(lease.Work.WorkID, 1, prior); err != nil {
		t.Fatal(err)
	}
	if err := journal.markLeaseLost(lease.Work.WorkID, 1); err != nil {
		t.Fatal(err)
	}

	replacement := lease
	replacement.Attempt = 2
	replacement.LeaseToken = strings.Repeat("u", 32)
	source.lease, source.available = replacement, true
	invoker := &recordingInvoker{}
	head := newHeadNodeWithJournal(t, source, invoker, catalog, map[string]commandpack.TargetRole{"comp001": commandpack.TargetCompute}, journal)
	if claimed, err := head.RunOnce(context.Background()); !claimed || err != nil {
		t.Fatalf("replacement claimed=%t err=%v", claimed, err)
	}
	if len(invoker.invocations) != 0 {
		t.Fatal("replacement lease repeated an ambiguously completed command")
	}
	if len(source.recorded) != 1 || source.recorded[0].Attempt != 2 || source.recorded[0].Targets[0].ErrorCode != "PRIOR_EXECUTION_NOT_REPEATED" {
		t.Fatalf("replacement result = %#v", source.recorded)
	}
}

// The head node claims work, resolves the argv from the pack it verifies
// itself, executes locally, and records a per-target attempt. The control plane
// transmits a definition reference; it never dictates a command.
func TestHeadNodeClaimsExecutesAndRecordsPerTargetResults(t *testing.T) {
	source, catalog, _ := headNodeFixture(t, "comp001", "comp002")
	invoker := &recordingInvoker{result: Result{
		DefinitionID: "gpu.ecc_counters", DefinitionVersion: "1.0.0", DefinitionDigest: strings.Repeat("a", 64), AttemptID: "work-1-1",
		Targets: []TargetResult{
			{TargetID: "comp001", Started: true, ExitCode: 0, StdoutBytes: 256, StdoutSHA256: strings.Repeat("b", 64), StderrSHA256: strings.Repeat("0", 64)},
			{TargetID: "comp002", Started: true, ExitCode: 1, ErrorCode: "EXIT_NONZERO", StdoutBytes: 0, StdoutSHA256: strings.Repeat("c", 64), StderrSHA256: strings.Repeat("0", 64)},
		},
	}}
	head := newHeadNode(t, source, invoker, catalog, map[string]commandpack.TargetRole{"comp001": commandpack.TargetCompute, "comp002": commandpack.TargetCompute})
	claimed, err := head.RunOnce(context.Background())
	if err != nil || !claimed {
		t.Fatalf("claimed=%t err=%v", claimed, err)
	}
	if len(invoker.invocations) != 1 {
		t.Fatalf("invocations = %d", len(invoker.invocations))
	}
	invocation := invoker.invocations[0]
	if invocation.DefinitionID != "gpu.ecc_counters" || invocation.DefinitionVersion != "1.0.0" {
		t.Fatalf("invocation = %+v", invocation)
	}
	if len(invocation.Targets) != 2 || invocation.Targets[0].Role != commandpack.TargetCompute {
		t.Fatalf("targets = %+v", invocation.Targets)
	}
	if len(source.recorded) != 1 {
		t.Fatalf("recorded attempts = %d", len(source.recorded))
	}
	attempt := source.recorded[0]
	if attempt.RunID != "run-1" || attempt.WorkID != "work-1" || attempt.Attempt != 1 || attempt.RunnerID != "head-1" {
		t.Fatalf("attempt attribution = %+v", attempt)
	}
	byTarget := map[domain.DiagnosticTarget]domain.DiagnosticTargetResult{}
	for _, target := range attempt.Targets {
		byTarget[target.Target] = target
	}
	if byTarget["comp001"].Status != domain.DiagnosticTargetSucceeded || byTarget["comp001"].StdoutBytes != 256 {
		t.Fatalf("comp001 = %+v", byTarget["comp001"])
	}
	if byTarget["comp002"].Status != domain.DiagnosticTargetFailed || byTarget["comp002"].ErrorCode != "EXIT_NONZERO" {
		t.Fatalf("comp002 = %+v", byTarget["comp002"])
	}

	// The recorded attempt must project straight into an evidence envelope: a
	// diagnostic result is an ordinary envelope, and that is what makes the rest
	// of the loop work without special cases.
	envelope, err := domain.DiagnosticEvidenceForAttempt(source.lease.Work.Run.Request(), attempt, 0)
	if err != nil {
		t.Fatalf("the recorded attempt did not project into evidence: %v", err)
	}
	if envelope.Status() != domain.EvidencePartial {
		t.Fatalf("envelope status = %s, want PARTIAL for one failed host", envelope.Status())
	}
	if len(envelope.Coverage().Covered) != 1 || envelope.Coverage().Covered[0].ID != "comp001" {
		t.Fatalf("coverage = %+v", envelope.Coverage())
	}
}

// A host whose role is not currently confirmed must not be reached, and the
// refusal must still be recorded: the investigation that dispatched this work
// is parked waiting for an answer.
func TestHeadNodeRefusesUnconfirmedHostsAndStillRecords(t *testing.T) {
	source, catalog, _ := headNodeFixture(t, "comp001")
	invoker := &recordingInvoker{}
	head := newHeadNode(t, source, invoker, catalog, map[string]commandpack.TargetRole{})
	claimed, err := head.RunOnce(context.Background())
	if err != nil || !claimed {
		t.Fatalf("claimed=%t err=%v", claimed, err)
	}
	if len(invoker.invocations) != 0 {
		t.Fatal("a host with no confirmed role was reached")
	}
	if len(source.recorded) != 1 || source.recorded[0].Targets[0].Status != domain.DiagnosticTargetRejected {
		t.Fatalf("recorded = %+v", source.recorded)
	}
	if source.recorded[0].Targets[0].ErrorCode != "TARGET_ROLE_UNAVAILABLE" {
		t.Fatalf("the refusal was not classified where it happened: %+v", source.recorded[0].Targets[0])
	}
}

// A dispatch failure is an answer, not a dropped unit of work. It must be
// recorded with a classified code and must never carry transport detail.
func TestHeadNodeRecordsDispatchFailureWithoutLeakingDetail(t *testing.T) {
	source, catalog, _ := headNodeFixture(t, "comp001")
	invoker := &recordingInvoker{err: errors.New("ssh: connect to host comp001 port 22: no route to host")}
	head := newHeadNode(t, source, invoker, catalog, map[string]commandpack.TargetRole{"comp001": commandpack.TargetCompute})
	claimed, err := head.RunOnce(context.Background())
	if err != nil || !claimed {
		t.Fatalf("claimed=%t err=%v", claimed, err)
	}
	if len(source.recorded) != 1 {
		t.Fatalf("a failed dispatch was dropped instead of recorded: %+v", source.recorded)
	}
	target := source.recorded[0].Targets[0]
	if target.Status != domain.DiagnosticTargetRejected || target.ErrorCode != "DISPATCH_FAILED" {
		t.Fatalf("target = %+v", target)
	}
	if strings.Contains(target.ErrorCode, "comp001") || strings.Contains(target.ErrorCode, "ssh") {
		t.Fatalf("the durable record carries transport detail: %q", target.ErrorCode)
	}
	// A total failure projects to UNAVAILABLE evidence rather than to nothing,
	// so the investigation learns that the probe was attempted and did not land.
	envelope, err := domain.DiagnosticEvidenceForAttempt(source.lease.Work.Run.Request(), source.recorded[0], 0)
	if err != nil {
		t.Fatal(err)
	}
	if envelope.Status() != domain.EvidenceUnavailable {
		t.Fatalf("envelope status = %s, want UNAVAILABLE", envelope.Status())
	}
}

// An empty queue is not an error, so a head node polls without spinning on
// failures it cannot distinguish from real ones.
func TestHeadNodeReportsAnEmptyQueue(t *testing.T) {
	source, catalog, _ := headNodeFixture(t, "comp001")
	source.available = false
	head := newHeadNode(t, source, &recordingInvoker{}, catalog, map[string]commandpack.TargetRole{"comp001": commandpack.TargetCompute})
	claimed, err := head.RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if claimed {
		t.Fatal("an empty queue reported work")
	}
	source.claimErr = errors.New("control plane unreachable")
	if _, err := head.RunOnce(context.Background()); err == nil {
		t.Fatal("a claim failure must surface, because it leaves the queue state uncertain")
	}
}

func TestHeadNodeRejectsCrossClusterAndForeignRunnerLeasesBeforeExecution(t *testing.T) {
	for name, mutate := range map[string]func(*domain.DiagnosticWorkLease){
		"cluster": func(lease *domain.DiagnosticWorkLease) {
			request := lease.Work.Run.Request()
			request.ClusterID = "cluster-b"
			run, err := domain.ReconstituteDiagnosticRun(request, domain.DiagnosticRunning, lease.Work.Run.Version())
			if err != nil {
				t.Fatal(err)
			}
			lease.Work.Run = run
		},
		"runner": func(lease *domain.DiagnosticWorkLease) { lease.RunnerID = "foreign-head" },
	} {
		t.Run(name, func(t *testing.T) {
			source, catalog, _ := headNodeFixture(t, "comp001")
			mutate(&source.lease)
			invoker := &recordingInvoker{}
			head := newHeadNode(t, source, invoker, catalog, map[string]commandpack.TargetRole{"comp001": commandpack.TargetCompute})
			claimed, err := head.RunOnce(context.Background())
			if !claimed || err == nil {
				t.Fatalf("claimed=%t err=%v", claimed, err)
			}
			if len(invoker.invocations) != 0 || len(source.recorded) != 0 {
				t.Fatalf("mismatched lease reached execution or result recording: invocations=%d records=%d", len(invoker.invocations), len(source.recorded))
			}
		})
	}
}

func diagnosticHeadCatalog(t *testing.T) *commandpack.Catalog {
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

// A diagnostic used to reach the model as provenance only: the runner captured
// stdout and this loop recorded its length and digest, so a report could say a
// probe succeeded and nothing about what it found.
func TestStdoutExcerptIsCarriedBoundedAndScreened(t *testing.T) {
	if got := stdoutExcerpt([]byte("retired_pages_pending: 3\n")); got != "retired_pages_pending: 3\n" {
		t.Fatalf("probe output was not carried: %q", got)
	}
	if got := stdoutExcerpt(nil); got != "" {
		t.Fatalf("absent output became %q", got)
	}

	// The excerpt crosses the perimeter, so it is bounded at the point of
	// capture rather than wherever it is eventually rendered.
	oversized := bytes.Repeat([]byte("a"), domain.MaxDiagnosticStdoutExcerptBytes*3)
	got := stdoutExcerpt(oversized)
	if len(got) != domain.MaxDiagnosticStdoutExcerptBytes {
		t.Fatalf("excerpt was not bounded: %d bytes", len(got))
	}

	// Truncation lands on a rune boundary, so a multi-byte character split by
	// the cap cannot leave invalid UTF-8 behind.
	multibyte := bytes.Repeat([]byte("é"), domain.MaxDiagnosticStdoutExcerptBytes)
	if got := stdoutExcerpt(multibyte); !utf8.ValidString(got) || len(got) > domain.MaxDiagnosticStdoutExcerptBytes {
		t.Fatalf("rune-boundary truncation failed: valid=%v len=%d", utf8.ValidString(got), len(got))
	}

	// Binary output is refused rather than repaired: a reviewed definition emits
	// text, and anything else is not output worth showing a model.
	if got := stdoutExcerpt([]byte{0x41, 0x00, 0x42}); got != "" {
		t.Fatalf("NUL-bearing output was not refused: %q", got)
	}
	if got := stdoutExcerpt([]byte{0xff, 0xfe, 0xfd}); got != "" {
		t.Fatalf("invalid UTF-8 was not refused: %q", got)
	}
}

// The domain is the last gate before the excerpt becomes durable.
func TestDiagnosticTargetResultRejectsUnscreenedExcerpt(t *testing.T) {
	targets := []domain.DiagnosticTarget{"comp001"}
	base := domain.DiagnosticTargetResult{Target: "comp001", Status: domain.DiagnosticTargetSucceeded}
	base.StdoutExcerpt = "ecc_errors: 0"
	if err := domain.ValidateDiagnosticTargetResults(targets, []domain.DiagnosticTargetResult{base}); err != nil {
		t.Fatalf("screened excerpt was refused: %v", err)
	}
	for name, excerpt := range map[string]string{
		"oversized":    string(bytes.Repeat([]byte("a"), domain.MaxDiagnosticStdoutExcerptBytes+1)),
		"nul byte":     "A\x00B",
		"invalid utf8": string([]byte{0xff, 0xfe}),
	} {
		invalid := base
		invalid.StdoutExcerpt = excerpt
		if err := domain.ValidateDiagnosticTargetResults(targets, []domain.DiagnosticTargetResult{invalid}); err == nil {
			t.Fatalf("%s excerpt was accepted into the durable record", name)
		}
	}
}

func TestHeadNodeUnknownTargetDoesNotRejectRegisteredPeer(t *testing.T) {
	source, catalog, _ := headNodeFixture(t, "comp001", "comp002")
	invoker := &recordingInvoker{result: Result{DefinitionID: "gpu.ecc_counters", DefinitionVersion: "1.0.0", DefinitionDigest: strings.Repeat("a", 64), AttemptID: "work-1-1", Targets: []TargetResult{{TargetID: "comp002", Started: true, StdoutBytes: 4, StdoutSHA256: strings.Repeat("b", 64)}}}}
	head := newHeadNode(t, source, invoker, catalog, map[string]commandpack.TargetRole{"comp002": commandpack.TargetCompute})
	if _, err := head.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(invoker.invocations) != 1 || len(invoker.invocations[0].Targets) != 1 || invoker.invocations[0].Targets[0].Name != "comp002" {
		t.Fatalf("invocations=%+v", invoker.invocations)
	}
	targets := source.recorded[0].Targets
	if targets[0].Status != domain.DiagnosticTargetRejected || targets[0].ErrorCode != "TARGET_ROLE_UNAVAILABLE" || targets[1].Status != domain.DiagnosticTargetSucceeded {
		t.Fatalf("targets=%+v", targets)
	}
}

func TestHeadNodePreservesInventoryReasonWhenEligibleDispatchAlsoFails(t *testing.T) {
	source, catalog, _ := headNodeFixture(t, "comp001", "comp002")
	invoker := &recordingInvoker{err: errors.New("private transport detail")}
	head := newHeadNode(t, source, invoker, catalog, map[string]commandpack.TargetRole{"comp002": commandpack.TargetCompute})
	if _, err := head.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	targets := source.recorded[0].Targets
	if targets[0].ErrorCode != "TARGET_ROLE_UNAVAILABLE" || targets[1].ErrorCode != "DISPATCH_FAILED" {
		t.Fatalf("target classifications=%+v", targets)
	}
}

// A diagnostic's excerpt used to be the opening bytes of its output, so a
// chronological log reached the model as its oldest entries. A seven-day kernel
// journal on a pilot node held 80 historical XID 137 lines ahead of the 117 XID
// 94 lines the investigation existed to explain; the excerpt carried the first
// eight, and the report concluded the kernel text did not establish XID 94.
func TestOversizedExcerptIsSampledFromBothEndsAndNamesWhatItDropped(t *testing.T) {
	var output bytes.Buffer
	const lines = 200
	for index := range lines {
		fmt.Fprintf(&output, "2026-09-10T03:08:%02d fixture1-zone1-comp003 kernel: NVRM: Xid (PCI:0000:87:00): %d, entry %d\n", index%60, 137+57*(index/100), index)
	}
	if output.Len() <= domain.MaxDiagnosticStdoutExcerptBytes {
		t.Fatalf("fixture no longer overruns the bound: %d bytes", output.Len())
	}

	got := stdoutExcerpt(output.Bytes())
	if len(got) > domain.MaxDiagnosticStdoutExcerptBytes {
		t.Fatalf("excerpt was not bounded: %d bytes", len(got))
	}
	if !strings.Contains(got, "entry 0,") && !strings.HasPrefix(got, "2026-09-10T03:08:00") {
		t.Fatalf("excerpt dropped the start of the output: %q", got)
	}
	// The final line is what a head-only excerpt could never reach, and on a
	// chronological log it is the most recent event.
	if !strings.Contains(got, fmt.Sprintf("entry %d\n", lines-1)) {
		t.Fatalf("excerpt dropped the end of the output: %q", got)
	}
	// A reader told only that output was cut cannot tell eight events from 200,
	// so the notice carries the counts and they have to be true.
	var omittedLines, omittedBytes int
	if _, err := fmt.Sscanf(elisionNotice(t, got), "[... %d lines omitted, %d bytes ...]", &omittedLines, &omittedBytes); err != nil {
		t.Fatalf("elision notice is unreadable: %v", err)
	}
	kept := strings.Count(got, "\n") - 1
	if kept+omittedLines != lines {
		t.Fatalf("notice misstates the elision: kept %d, omitted %d, total %d", kept, omittedLines, lines)
	}
	verbatim := len(got) - len(elisionNotice(t, got)) - len("\n")
	if omittedBytes != output.Len()-verbatim {
		t.Fatalf("notice misstates the elided bytes: said %d, dropped %d", omittedBytes, output.Len()-verbatim)
	}
}

// Output with no line structure has no honest sampling point, so it keeps the
// opening bytes rather than splicing a notice into the middle of a single line.
func TestUnlinedOversizedExcerptKeepsABoundedPrefix(t *testing.T) {
	unlined := bytes.Repeat([]byte("é"), domain.MaxDiagnosticStdoutExcerptBytes)
	got := stdoutExcerpt(unlined)
	if len(got) > domain.MaxDiagnosticStdoutExcerptBytes || !utf8.ValidString(got) {
		t.Fatalf("prefix fallback failed: len=%d valid=%v", len(got), utf8.ValidString(got))
	}
	if strings.Contains(got, "omitted") {
		t.Fatalf("a single line was spliced: %q", got)
	}
	if !strings.HasPrefix(string(unlined), got) {
		t.Fatalf("prefix fallback did not keep verbatim opening bytes")
	}
}

// Sampling cuts on newline boundaries, so multi-byte characters adjacent to the
// cut survive intact and the excerpt crossing the perimeter stays valid UTF-8.
func TestSampledExcerptStaysValidUTF8(t *testing.T) {
	var output bytes.Buffer
	for index := range 200 {
		fmt.Fprintf(&output, "%d é→漢 réplica ligne avec des caractères multi-octets\n", index)
	}
	got := stdoutExcerpt(output.Bytes())
	if !utf8.ValidString(got) || len(got) > domain.MaxDiagnosticStdoutExcerptBytes {
		t.Fatalf("sampled excerpt was invalid: valid=%v len=%d", utf8.ValidString(got), len(got))
	}
	for _, line := range strings.Split(strings.TrimSuffix(got, "\n"), "\n") {
		if !strings.Contains(line, "omitted") && !strings.HasSuffix(line, "multi-octets") {
			t.Fatalf("a line was cut mid-way: %q", line)
		}
	}
}

func elisionNotice(t *testing.T, excerpt string) string {
	t.Helper()
	for _, line := range strings.Split(excerpt, "\n") {
		if strings.HasPrefix(line, "[... ") {
			return line
		}
	}
	t.Fatalf("excerpt carries no elision notice: %q", excerpt)
	return ""
}
