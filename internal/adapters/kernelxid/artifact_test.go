package kernelxid

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

func TestBuildArtifactRetainsOnlyStructuredFactsAndBindsCanonicalBytes(t *testing.T) {
	start := time.Date(2026, 9, 22, 9, 0, 0, 0, time.UTC)
	line := "2026-09-22T09:00:00+0000 journal-host kernel: NVRM: Xid (PCI:0000:01:00.0): 94, secret=hunter2 path=/var/log/private"
	normalized, err := Normalize(kernelArtifactRequest(start), start, start.Add(time.Minute), []SourceTarget{{
		Target: "comp001", Status: domain.DiagnosticTargetSucceeded, Stdout: []byte(line), StdoutTransformationState: domain.StdoutTransformationUnmodified,
	}})
	if err != nil {
		t.Fatal(err)
	}
	binding := kernelArtifactBinding("comp001", line)
	artifact, err := BuildArtifact(normalized.Targets[0], binding)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := domain.BindKernelXIDArtifact(artifact, binding)
	if err != nil {
		t.Fatal(err)
	}
	payload := string(bound.Bytes())
	for _, forbidden := range []string{"journal-host", "hunter2", "/var/log/private", "secret="} {
		if strings.Contains(payload, forbidden) {
			t.Fatalf("artifact leaked %q: %s", forbidden, payload)
		}
	}
	if !strings.Contains(payload, `"xid_code":94`) || !strings.Contains(payload, `"pci_bdf":"0000:01:00.0"`) || !strings.Contains(payload, `"work_id":"work-1"`) || !strings.Contains(payload, `"source_stdout_sha256"`) {
		t.Fatalf("canonical artifact omitted reviewed fact or binding: %s", payload)
	}
	parsed, err := domain.ParseKernelXIDArtifact(bound.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if parsed.SHA256() != bound.SHA256() {
		t.Fatal("canonical parse changed checksum")
	}
	if _, err := domain.BindKernelXIDArtifact(bound, kernelArtifactBinding("comp002", line)); err == nil {
		t.Fatal("bound artifact was silently rebound to another target")
	}
}

func TestBuildArtifactCapsEventsAndFailsClosedOnUnsafeStructuredInput(t *testing.T) {
	start := time.Date(2026, 9, 22, 9, 0, 0, 0, time.UTC)
	source := TargetEvidence{ParserVersion: ParserVersion, SourceDefinition: string(DefinitionID), SourceDefinitionVersion: DefinitionVersion, Target: "comp001", ObservedFrom: start, ObservedTo: start.Add(time.Hour), DeclaredLimits: []DeclaredLimit{LimitFixedWindow, LimitLineCap, LimitOutputCap}, Disposition: DispositionBounded}
	for index := 0; index < domain.MaxKernelXIDArtifactEvents+1; index++ {
		source.Events = append(source.Events, Event{ObservedAt: start.Add(time.Duration(index) * time.Second), XIDCode: 94, PCIBDF: "0000:01:00.0"})
	}
	binding := kernelArtifactBinding("comp001", "source")
	artifact, err := BuildArtifact(source, binding)
	if err != nil {
		t.Fatal(err)
	}
	if artifact.EventCount() != domain.MaxKernelXIDArtifactEvents || !artifact.Truncated() || !artifact.HasGap(domain.KernelXIDArtifactGapArtifactLimit) {
		t.Fatalf("event cap was not explicit: count=%d truncated=%t", artifact.EventCount(), artifact.Truncated())
	}
	source.Events[0].PCIBDF = "/var/log/private"
	if _, err := BuildArtifact(source, binding); !errors.Is(err, ErrArtifactScreeningFailed) {
		t.Fatalf("unsafe PCI/path input err=%v, want screening failure", err)
	}
	failure, err := ScreeningFailureArtifact(start, start.Add(time.Hour), binding)
	if err != nil || !failure.HasGap(domain.KernelXIDArtifactGapScreeningFailure) || strings.Contains(string(failure.Bytes()), "/var/log/private") {
		t.Fatalf("screening failure artifact=%s err=%v", failure.Bytes(), err)
	}
	if _, err := domain.ParseKernelXIDArtifact(append(artifact.Bytes(), []byte(` {"unexpected":true}`)...)); err == nil {
		t.Fatal("trailing top-level JSON was accepted")
	}
	if _, err := domain.NewKernelXIDArtifact(domain.KernelXIDArtifactInput{ObservedFrom: start, ObservedTo: start.Add(time.Hour), Disposition: domain.KernelXIDArtifactPartial, DeclaredLimits: []string{string(LimitFixedWindow), string(LimitLineCap), string(LimitOutputCap)}, Gaps: []domain.KernelXIDArtifactGap{domain.KernelXIDArtifactGapExpired}, Binding: &binding}); err == nil {
		t.Fatal("persisted artifact accepted a read-lifecycle gap")
	}
}

func TestKernelXIDArtifactDispositionInvariants(t *testing.T) {
	start := time.Date(2026, 9, 22, 9, 0, 0, 0, time.UTC)
	binding := kernelArtifactBinding("comp001", "source")
	limits := []string{string(LimitFixedWindow), string(LimitLineCap), string(LimitOutputCap)}
	event := domain.KernelXIDArtifactEvent{ObservedAt: start, XIDCode: 94, PCIBDF: "0000:01:00.0"}
	base := domain.KernelXIDArtifactInput{ObservedFrom: start, ObservedTo: start.Add(time.Hour), DeclaredLimits: limits, Binding: &binding}

	cases := []struct {
		name  string
		input domain.KernelXIDArtifactInput
		want  bool
	}{
		{name: "bounded needs an event", input: withArtifactDisposition(base, domain.KernelXIDArtifactBounded, nil, nil), want: false},
		{name: "bounded event is valid", input: withArtifactDisposition(base, domain.KernelXIDArtifactBounded, nil, []domain.KernelXIDArtifactEvent{event}), want: true},
		{name: "no rows has no events or gaps", input: withArtifactDisposition(base, domain.KernelXIDArtifactNoRows, nil, nil), want: true},
		{name: "no rows rejects event", input: withArtifactDisposition(base, domain.KernelXIDArtifactNoRows, nil, []domain.KernelXIDArtifactEvent{event}), want: false},
		{name: "unavailable has no events", input: withArtifactDisposition(base, domain.KernelXIDArtifactUnavailable, []domain.KernelXIDArtifactGap{domain.KernelXIDArtifactGapTargetUnavailable}, []domain.KernelXIDArtifactEvent{event}), want: false},
		{name: "target unavailable rejects events", input: withArtifactDisposition(base, domain.KernelXIDArtifactPartial, []domain.KernelXIDArtifactGap{domain.KernelXIDArtifactGapTargetUnavailable}, []domain.KernelXIDArtifactEvent{event}), want: false},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			_, err := domain.NewKernelXIDArtifact(test.input)
			if (err == nil) != test.want {
				t.Fatalf("NewKernelXIDArtifact error=%v want valid=%t", err, test.want)
			}
		})
	}
}

func withArtifactDisposition(base domain.KernelXIDArtifactInput, disposition domain.KernelXIDArtifactDisposition, gaps []domain.KernelXIDArtifactGap, events []domain.KernelXIDArtifactEvent) domain.KernelXIDArtifactInput {
	base.Disposition = disposition
	base.Gaps = gaps
	base.Events = events
	return base
}

func kernelArtifactBinding(target domain.DiagnosticTarget, source string) domain.KernelXIDArtifactBinding {
	return domain.KernelXIDArtifactBinding{ClusterID: "cluster-1", RunID: "run-1", WorkID: "work-1", Attempt: 1, Target: target, PackID: "standard.readonly", PackVersion: "1.3.0", DefinitionID: DefinitionID, DefinitionVersion: DefinitionVersion, DefinitionDigest: domain.ChecksumSHA256([]byte("definition")), SourceStdoutSHA256: domain.ChecksumSHA256([]byte(source))}
}

func kernelArtifactRequest(now time.Time) domain.DiagnosticRequest {
	return domain.DiagnosticRequest{RunID: "run-1", ClusterID: "cluster-1", Definition: domain.DiagnosticDefinitionRef{PackID: "standard.readonly", PackVersion: "1.3.0", DefinitionID: DefinitionID, DefinitionVersion: DefinitionVersion, DefinitionDigest: domain.ChecksumSHA256([]byte("definition"))}, Privilege: domain.DiagnosticUnprivileged, Targets: []domain.DiagnosticTarget{"comp001"}, RequestedBy: "test", IdempotencyKey: "artifact-test", RequestedAt: now, Deadline: now.Add(time.Minute), MaxAttempts: 1}
}
