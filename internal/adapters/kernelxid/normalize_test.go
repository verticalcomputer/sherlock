package kernelxid

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

func TestNormalizePreservesRepeatedEventsFromScrubbedFixture(t *testing.T) {
	output, err := os.ReadFile("testdata/kernel-xid-short-iso.txt")
	if err != nil {
		t.Fatal(err)
	}
	attempt := testAttempt(string(output), int64(len(output)), false, domain.StdoutTransformationUnmodified)
	result, err := Normalize(testRequest(), attempt.StartedAt, attempt.CompletedAt, sourcesForAttempt(attempt))
	if err != nil {
		t.Fatal(err)
	}
	target := result.Targets[0]
	if target.Disposition != DispositionBounded || len(target.Events) != 3 {
		t.Fatalf("target=%+v", target)
	}
	if target.Events[0].XIDCode != 94 || target.Events[1].XIDCode != 94 || !target.Events[0].ObservedAt.Equal(target.Events[1].ObservedAt) || target.Events[2].XIDCode != 79 {
		t.Fatalf("events lost source order or duplicate rows: %+v", target.Events)
	}
	if !target.SourceOutputUnmodified || !slicesEqual(target.Gaps, nil) || !limitsEqual(target.DeclaredLimits, []DeclaredLimit{LimitFixedWindow, LimitLineCap, LimitOutputCap}) {
		t.Fatalf("normalization provenance=%+v", target)
	}
	encoded, err := RenderTarget(target)
	if err != nil || strings.Contains(encoded, "PCI:") || strings.Contains(encoded, "scrubbed-host") || strings.Contains(encoded, "NVRM:") {
		t.Fatalf("encoded=%q err=%v", encoded, err)
	}
}

func TestNormalizeMakesEveryLossExplicit(t *testing.T) {
	cases := []struct {
		name       string
		output     string
		bytes      int64
		truncated  bool
		state      domain.StdoutTransformationState
		status     domain.DiagnosticTargetStatus
		want       []Gap
		wantStatus Disposition
	}{
		{"empty bounded", "", 0, false, domain.StdoutTransformationUnmodified, domain.DiagnosticTargetSucceeded, nil, DispositionNoData},
		{"malformed", "not a journal line", 18, false, domain.StdoutTransformationUnmodified, domain.DiagnosticTargetSucceeded, []Gap{GapMalformedRecord}, DispositionPartial},
		{"invalid timestamp", "not-a-time scrubbed-host kernel: NVRM: Xid (PCI:0000:01:00): 94, malformed", -1, false, domain.StdoutTransformationUnmodified, domain.DiagnosticTargetSucceeded, []Gap{GapMalformedRecord}, DispositionPartial},
		{"outside window", "2026-08-01T00:00:00+0000 scrubbed-host kernel: NVRM: Xid (PCI:0000:01:00): 94, stale", -1, false, domain.StdoutTransformationUnmodified, domain.DiagnosticTargetSucceeded, []Gap{GapOutsideWindow}, DispositionPartial},
		{"truncated transformed", "2026-09-22T10:00:00+0000 scrubbed-host kernel: NVRM: Xid (PCI:0000:01:00): 94, recovered", 1000, true, domain.StdoutTransformationTransformed, domain.DiagnosticTargetSucceeded, []Gap{GapOutputTruncated, GapOutputTransformed}, DispositionPartial},
		{"unknown transformation", "2026-09-22T10:00:00+0000 scrubbed-host kernel: NVRM: Xid (PCI:0000:01:00): 94, recovered", -1, false, domain.StdoutTransformationUnknown, domain.DiagnosticTargetSucceeded, []Gap{GapOutputUnknown}, DispositionPartial},
		{"journal command failed", "", 0, false, domain.StdoutTransformationUnknown, domain.DiagnosticTargetFailed, []Gap{GapTargetUnavailable, GapTargetFailed}, DispositionUnavailable},
		{"journal command timed out", "", 0, false, domain.StdoutTransformationUnknown, domain.DiagnosticTargetTimedOut, []Gap{GapTargetUnavailable, GapTargetTimedOut}, DispositionUnavailable},
		{"target access rejected", "", 0, false, domain.StdoutTransformationUnknown, domain.DiagnosticTargetRejected, []Gap{GapTargetUnavailable, GapTargetRejected}, DispositionUnavailable},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			bytes := test.bytes
			if bytes < 0 {
				bytes = int64(len(test.output))
			}
			attempt := testAttempt(test.output, bytes, test.truncated, test.state)
			attempt.Targets[0].Status = test.status
			attempt.Targets[0].TimedOut = test.status == domain.DiagnosticTargetTimedOut
			result, err := Normalize(testRequest(), attempt.StartedAt, attempt.CompletedAt, sourcesForAttempt(attempt))
			if err != nil {
				t.Fatal(err)
			}
			target := result.Targets[0]
			if target.Disposition != test.wantStatus || !slicesEqual(target.Gaps, test.want) {
				t.Fatalf("target=%+v want gaps=%v status=%s", target, test.want, test.wantStatus)
			}
		})
	}
}

func TestNormalizeRejectsWrongDefinitionAndDoesNotInventIdentity(t *testing.T) {
	request := testRequest()
	request.Definition.DefinitionVersion = "1.0.0"
	attempt := testAttempt("", 0, false, domain.StdoutTransformationUnmodified)
	if _, err := Normalize(request, attempt.StartedAt, attempt.CompletedAt, sourcesForAttempt(attempt)); err == nil {
		t.Fatal("wrong definition version was accepted")
	}

	target := TargetEvidence{ParserVersion: ParserVersion, SourceDefinition: string(DefinitionID), SourceDefinitionVersion: DefinitionVersion, Target: "node-1", ObservedFrom: time.Now().UTC(), ObservedTo: time.Now().UTC(), DeclaredLimits: []DeclaredLimit{LimitFixedWindow, LimitLineCap, LimitOutputCap}, Disposition: DispositionBounded, Events: make([]Event, 80), SourceOutputUnmodified: true}
	for index := range target.Events {
		target.Events[index] = Event{ObservedAt: target.ObservedTo, XIDCode: 94}
	}
	encoded, err := RenderTarget(target)
	if err != nil || len(encoded) > domain.MaxDiagnosticStdoutExcerptBytes || !strings.Contains(encoded, string(GapEventLimit)) {
		t.Fatalf("encoded bound/gap failed: len=%d err=%v value=%q", len(encoded), err, encoded)
	}
}

func TestNormalizeUsesConservativeExecutionWindowAndAnchoredRecords(t *testing.T) {
	completed := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	started := completed.Add(-time.Minute)
	output := "2026-09-15T11:59:30+0000 scrubbed-host kernel: NVRM: Xid (PCI:0000:01:00.0): 94, accepted early boundary\n" +
		"prefix 2026-09-22T10:00:00+0000 scrubbed-host kernel: NVRM: Xid (PCI:0000:02:00): 79, embedded"
	result, err := Normalize(testRequest(), started, completed, []SourceTarget{{Target: "node-1", Status: domain.DiagnosticTargetSucceeded, Stdout: []byte(output), StdoutTransformationState: domain.StdoutTransformationUnmodified}})
	if err != nil {
		t.Fatal(err)
	}
	target := result.Targets[0]
	if len(target.Events) != 1 || target.Events[0].PCIBDF != "0000:01:00.0" || !slicesEqual(target.Gaps, []Gap{GapMalformedRecord}) || target.Disposition != DispositionPartial {
		t.Fatalf("target=%+v", target)
	}
}

func TestNormalizeMarksPotentialLineCapBinding(t *testing.T) {
	line := "2026-09-22T10:00:00+0000 scrubbed-host kernel: NVRM: Xid (PCI:0000:01:00): 94, bounded\n"
	result, err := Normalize(testRequest(), time.Date(2026, 9, 22, 11, 0, 0, 0, time.UTC), time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC), []SourceTarget{{Target: "node-1", Status: domain.DiagnosticTargetSucceeded, Stdout: []byte(strings.Repeat(line, 2000)), StdoutTransformationState: domain.StdoutTransformationUnmodified}})
	if err != nil {
		t.Fatal(err)
	}
	target := result.Targets[0]
	if target.Disposition != DispositionPartial || !slicesEqual(target.Gaps, []Gap{GapLineCapReached}) || len(target.Events) != 2000 {
		t.Fatalf("target=%+v", target)
	}
}

func testRequest() domain.DiagnosticRequest {
	now := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	return domain.DiagnosticRequest{RunID: "kernel-run", ClusterID: "pilot-cluster", Definition: domain.DiagnosticDefinitionRef{PackID: "pilot", PackVersion: "1.0.0", DefinitionID: DefinitionID, DefinitionVersion: DefinitionVersion, DefinitionDigest: domain.ChecksumSHA256([]byte("kernel-definition"))}, Privilege: domain.DiagnosticUnprivileged, Targets: []domain.DiagnosticTarget{"node-1"}, RequestedBy: "test", IdempotencyKey: "kernel-xid-test", RequestedAt: now.Add(-time.Minute), Deadline: now.Add(time.Minute), MaxAttempts: 1}
}

func testAttempt(output string, bytes int64, truncated bool, state domain.StdoutTransformationState) domain.DiagnosticAttemptResult {
	now := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	exit := 0
	return domain.DiagnosticAttemptResult{WorkID: "kernel-work", RunID: "kernel-run", Attempt: 1, RunnerID: "test-runner", PlanDigest: domain.ChecksumSHA256([]byte("kernel-plan")), StartedAt: now.Add(-time.Minute), CompletedAt: now, Targets: []domain.DiagnosticTargetResult{{Target: "node-1", Status: domain.DiagnosticTargetSucceeded, ExitCode: &exit, StdoutBytes: bytes, StdoutSHA256: domain.ChecksumSHA256([]byte(output)), StderrSHA256: domain.ChecksumSHA256(nil), StdoutTruncated: truncated, StdoutExcerpt: output, StdoutTransformationState: state}}}
}

func sourcesForAttempt(attempt domain.DiagnosticAttemptResult) []SourceTarget {
	sources := make([]SourceTarget, 0, len(attempt.Targets))
	for _, target := range attempt.Targets {
		sources = append(sources, SourceTarget{Target: target.Target, Status: target.Status, Stdout: []byte(target.StdoutExcerpt), StdoutTruncated: target.StdoutTruncated, StdoutTransformationState: target.StdoutTransformationState})
	}
	return sources
}

func slicesEqual(left, right []Gap) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func limitsEqual(left, right []DeclaredLimit) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
