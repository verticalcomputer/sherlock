package diagnosticrunner

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/commandpack"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

// scriptedSource answers a fixed sequence of claim outcomes, so a test states
// exactly what the control plane did and asserts how the loop paced itself.
type scriptedSource struct {
	lease    domain.DiagnosticWorkLease
	outcomes []claimOutcome
	claims   int
	recorded int
}

type claimOutcome struct {
	found bool
	err   error
}

func (source *scriptedSource) ClaimDiagnosticWork(context.Context, time.Duration) (domain.DiagnosticWorkLease, bool, error) {
	outcome := claimOutcome{}
	if source.claims < len(source.outcomes) {
		outcome = source.outcomes[source.claims]
	}
	source.claims++
	switch {
	case outcome.err != nil:
		return domain.DiagnosticWorkLease{}, false, outcome.err
	case outcome.found:
		return source.lease, true, nil
	default:
		return domain.DiagnosticWorkLease{}, false, nil
	}
}

func (source *scriptedSource) RecordDiagnosticAttempt(context.Context, domain.DiagnosticWorkLease, domain.DiagnosticAttemptResult) error {
	source.recorded++
	return nil
}

// pacedLoop wires a head node to a scripted source and replaces sleeping with a
// recorder that ends the run after the expected number of pauses.
func pacedLoop(t *testing.T, source *scriptedSource, config ClaimLoopConfig, pauses int) (*ClaimLoop, context.Context, *[]time.Duration) {
	t.Helper()
	invoker := &recordingInvoker{result: Result{
		DefinitionID: "gpu.ecc_counters", DefinitionVersion: "1.0.0", DefinitionDigest: strings.Repeat("a", 64),
		Targets: []TargetResult{{TargetID: "comp001", Started: true, ExitCode: 0, StdoutBytes: 16, StdoutSHA256: strings.Repeat("b", 64), StderrSHA256: strings.Repeat("0", 64)}},
	}}
	runner, err := New(Config{MaxTimeout: time.Minute, MaxOutputBytes: 1 << 20, MaxInputBytes: 1 << 16, MaxTargets: 8, MaxConcurrency: 8, MaxSuppliedSecrets: 4, MaxSecretBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Date(2026, 8, 22, 10, 0, 0, 0, time.UTC)
	journal, err := OpenDiagnosticJournal(filepath.Join(t.TempDir(), "diagnostic-journal.json"), func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	head, err := NewHeadNode(source, invoker, runner, diagnosticHeadCatalog(t), func(target domain.DiagnosticTarget) (commandpack.TargetRole, bool) {
		role, eligible := map[domain.DiagnosticTarget]commandpack.TargetRole{"comp001": commandpack.TargetCompute}[target]
		return role, eligible
	}, func() time.Time { clock = clock.Add(time.Second); return clock }, journal, HeadNodeConfig{ClusterID: "cluster-a", RunnerID: "head-1", PollWait: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	loop, err := NewClaimLoop(head, config)
	if err != nil {
		t.Fatal(err)
	}
	// Jitter is fixed so a delay is asserted exactly; its spread is covered
	// separately.
	loop.jitter = func() float64 { return 0 }
	ctx, cancel := context.WithCancel(context.Background())
	delays := make([]time.Duration, 0, pauses)
	loop.sleep = func(ctx context.Context, delay time.Duration) error {
		delays = append(delays, delay)
		if len(delays) >= pauses {
			cancel()
			return ctx.Err()
		}
		return nil
	}
	t.Cleanup(cancel)
	return loop, ctx, &delays
}

func headLease(t *testing.T) domain.DiagnosticWorkLease {
	t.Helper()
	_, _, lease := headNodeFixture(t, "comp001")
	return lease
}

// A queue holding work must drain: the loop claims again immediately after a
// recorded attempt and pauses only when the queue is empty.
func TestClaimLoopDrainsWorkAndPausesOnlyWhenIdle(t *testing.T) {
	source := &scriptedSource{lease: headLease(t), outcomes: []claimOutcome{{found: true}}}
	config := ClaimLoopConfig{IdleBackoff: 2 * time.Second, FailureBackoffMinimum: time.Second, FailureBackoffMaximum: 30 * time.Second}
	loop, ctx, delays := pacedLoop(t, source, config, 1)

	if err := loop.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("the loop ended with %v, want the context error", err)
	}
	if source.recorded != 1 {
		t.Fatalf("recorded attempts = %d, want the claimed unit executed", source.recorded)
	}
	if len(*delays) != 1 || (*delays)[0] != config.IdleBackoff {
		t.Fatalf("delays = %v, want exactly one idle pause after the queue emptied", *delays)
	}
}

// A control plane that is unreachable or refusing must not be hammered, and a
// recovery must return the loop to normal pacing immediately.
func TestClaimLoopBacksOffOnConsecutiveFailuresAndResetsOnSuccess(t *testing.T) {
	failure := errors.New("control plane is unreachable")
	source := &scriptedSource{lease: headLease(t), outcomes: []claimOutcome{
		{err: failure}, {err: failure}, {err: failure}, {found: true}, {},
	}}
	config := ClaimLoopConfig{IdleBackoff: 500 * time.Millisecond, FailureBackoffMinimum: time.Second, FailureBackoffMaximum: 3 * time.Second}
	loop, ctx, delays := pacedLoop(t, source, config, 4)

	if err := loop.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("the loop ended with %v, want the context error", err)
	}
	want := []time.Duration{time.Second, 2 * time.Second, 3 * time.Second, config.IdleBackoff}
	if len(*delays) != len(want) {
		t.Fatalf("delays = %v, want %v", *delays, want)
	}
	for index, expected := range want {
		if (*delays)[index] != expected {
			t.Fatalf("delay %d = %s, want %s (delays %v)", index, (*delays)[index], expected, *delays)
		}
	}
	if source.recorded != 1 {
		t.Fatalf("recorded attempts = %d, want the one unit that was claimable", source.recorded)
	}
}

// Several head nodes recovering from one outage must not resynchronize, so the
// backoff spreads across the upper half of its delay.
func TestClaimLoopSpreadsRetriesWithinBounds(t *testing.T) {
	source := &scriptedSource{lease: headLease(t)}
	config := ClaimLoopConfig{IdleBackoff: time.Second, FailureBackoffMinimum: 4 * time.Second, FailureBackoffMaximum: 30 * time.Second}
	loop, _, _ := pacedLoop(t, source, config, 1)
	for _, fraction := range []float64{0, 0.5, 0.999} {
		loop.jitter = func() float64 { return fraction }
		delay := loop.failureBackoff(1)
		if delay > 4*time.Second || delay < 2*time.Second {
			t.Fatalf("jitter %v produced %s, want a delay within the upper half of four seconds", fraction, delay)
		}
	}
	loop.jitter = func() float64 { return 0 }
	if delay := loop.failureBackoff(12); delay != config.FailureBackoffMaximum {
		t.Fatalf("a long outage produced %s, want the configured ceiling %s", delay, config.FailureBackoffMaximum)
	}
}

// The loop must never exit on its own: a head node that stopped claiming would
// park every dispatched investigation until its deadline with nothing able to
// tell that from a quiet queue.
func TestClaimLoopRunsUntilItsContextEnds(t *testing.T) {
	source := &scriptedSource{lease: headLease(t)}
	config := ClaimLoopConfig{IdleBackoff: time.Millisecond, FailureBackoffMinimum: time.Millisecond, FailureBackoffMaximum: time.Millisecond}
	loop, ctx, _ := pacedLoop(t, source, config, 25)
	if err := loop.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("the loop ended with %v, want the context error", err)
	}
	if source.claims != 25 {
		t.Fatalf("claims = %d, want the loop to have kept polling an empty queue", source.claims)
	}
}

func TestNewClaimLoopValidatesItsDependenciesAndBounds(t *testing.T) {
	valid := ClaimLoopConfig{IdleBackoff: time.Second, FailureBackoffMinimum: time.Second, FailureBackoffMaximum: 2 * time.Second}
	if _, err := NewClaimLoop(nil, valid); err == nil {
		t.Fatal("a loop without a head node was constructed")
	}
	source := &scriptedSource{lease: headLease(t)}
	loop, _, _ := pacedLoop(t, source, valid, 1)
	for name, config := range map[string]ClaimLoopConfig{
		"no idle backoff":    {IdleBackoff: 0, FailureBackoffMinimum: time.Second, FailureBackoffMaximum: time.Second},
		"no failure backoff": {IdleBackoff: time.Second, FailureBackoffMinimum: 0, FailureBackoffMaximum: time.Second},
		"inverted ceiling":   {IdleBackoff: time.Second, FailureBackoffMinimum: 2 * time.Second, FailureBackoffMaximum: time.Second},
	} {
		if _, err := NewClaimLoop(loop.head, config); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
}
