package postgres

import (
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

func TestArtifactMatchesDiagnosticTargetStatus(t *testing.T) {
	start := time.Date(2026, 9, 22, 9, 0, 0, 0, time.UTC)
	event := []domain.KernelXIDArtifactEvent{{ObservedAt: start, XIDCode: 94, PCIBDF: "0000:01:00.0"}}
	cases := []struct {
		name        string
		status      domain.DiagnosticTargetStatus
		disposition domain.KernelXIDArtifactDisposition
		gaps        []domain.KernelXIDArtifactGap
		events      []domain.KernelXIDArtifactEvent
		want        bool
	}{
		{name: "succeeded bounded", status: domain.DiagnosticTargetSucceeded, disposition: domain.KernelXIDArtifactBounded, events: event, want: true},
		{name: "succeeded no rows", status: domain.DiagnosticTargetSucceeded, disposition: domain.KernelXIDArtifactNoRows, want: true},
		{name: "succeeded unavailable rejected", status: domain.DiagnosticTargetSucceeded, disposition: domain.KernelXIDArtifactUnavailable, gaps: []domain.KernelXIDArtifactGap{domain.KernelXIDArtifactGapTargetUnavailable}, want: false},
		{name: "failed unavailable", status: domain.DiagnosticTargetFailed, disposition: domain.KernelXIDArtifactUnavailable, gaps: []domain.KernelXIDArtifactGap{domain.KernelXIDArtifactGapTargetUnavailable, domain.KernelXIDArtifactGapTargetFailed}, want: true},
		{name: "failed bounded rejected", status: domain.DiagnosticTargetFailed, disposition: domain.KernelXIDArtifactBounded, events: event, want: false},
		{name: "failed extra gap rejected", status: domain.DiagnosticTargetFailed, disposition: domain.KernelXIDArtifactUnavailable, gaps: []domain.KernelXIDArtifactGap{domain.KernelXIDArtifactGapTargetUnavailable, domain.KernelXIDArtifactGapTargetFailed, domain.KernelXIDArtifactGapOutputUnknown}, want: false},
		{name: "timed out unavailable", status: domain.DiagnosticTargetTimedOut, disposition: domain.KernelXIDArtifactUnavailable, gaps: []domain.KernelXIDArtifactGap{domain.KernelXIDArtifactGapTargetUnavailable, domain.KernelXIDArtifactGapTargetTimedOut}, want: true},
		{name: "rejected unavailable", status: domain.DiagnosticTargetRejected, disposition: domain.KernelXIDArtifactUnavailable, gaps: []domain.KernelXIDArtifactGap{domain.KernelXIDArtifactGapTargetUnavailable, domain.KernelXIDArtifactGapTargetRejected}, want: true},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			artifact, err := domain.NewKernelXIDArtifact(domain.KernelXIDArtifactInput{
				ObservedFrom: start,
				ObservedTo:   start.Add(time.Hour),
				Disposition:  test.disposition,
				DeclaredLimits: []string{
					"FIXED_WINDOW_7D_NOT_CONTINUOUS",
					"SOURCE_LINE_CAP_2000",
					"SOURCE_OUTPUT_CAP_4_MIB",
				},
				Gaps:   test.gaps,
				Events: test.events,
				Binding: &domain.KernelXIDArtifactBinding{
					ClusterID: "cluster-1", RunID: "run-1", WorkID: "work-1", Attempt: 1, Target: "comp001",
					PackID: "standard.readonly", PackVersion: "1.3.0", DefinitionID: "node.kernel_xid", DefinitionVersion: "2.0.0",
					DefinitionDigest: domain.ChecksumSHA256([]byte("definition")), SourceStdoutSHA256: domain.ChecksumSHA256([]byte("source")),
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			if got := artifactMatchesDiagnosticTargetStatus(artifact, test.status); got != test.want {
				t.Fatalf("artifactMatchesDiagnosticTargetStatus=%t want %t", got, test.want)
			}
		})
	}
}
