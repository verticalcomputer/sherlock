package diagnosticrunner

import (
	"strings"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/adapters/kernelxid"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

func TestNormalizeKernelXIDEvidenceReplacesOnlyFixedDiagnosticExcerpt(t *testing.T) {
	now := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	catalog := diagnosticHeadCatalog(t)
	_, digest, found := catalog.Lookup(string(kernelxid.DefinitionID), kernelxid.DefinitionVersion)
	if !found {
		t.Fatal("kernel XID definition missing")
	}
	parsed, err := domain.ParseSHA256(digest)
	if err != nil {
		t.Fatal(err)
	}
	request := domain.DiagnosticRequest{
		RunID: "kernel-run", ClusterID: "pilot-cluster",
		Definition: domain.DiagnosticDefinitionRef{
			PackID: "standard.readonly", PackVersion: "1.1.0", DefinitionID: kernelxid.DefinitionID,
			DefinitionVersion: kernelxid.DefinitionVersion, DefinitionDigest: parsed,
		},
		Privilege: domain.DiagnosticUnprivileged, Targets: []domain.DiagnosticTarget{"node-1"},
		RequestedBy: "test", IdempotencyKey: "kernel-xid-test", RequestedAt: now.Add(-time.Minute), Deadline: now.Add(time.Minute), MaxAttempts: 1,
	}
	raw := "2026-09-22T10:00:00+0000 scrubbed-host kernel: NVRM: Xid (PCI:0000:01:00): 94, pid=1234\n" +
		"2026-09-22T10:00:00+0000 scrubbed-host kernel: NVRM: Xid (PCI:0000:01:00): 94, pid=1234\n"
	result := Result{DefinitionID: string(kernelxid.DefinitionID), DefinitionVersion: kernelxid.DefinitionVersion, DefinitionDigest: digest, Targets: []TargetResult{{
		TargetID: "node-1", Started: true, ExitCode: 0, Stdout: []byte(raw), StdoutBytes: int64(len(raw)), StdoutSHA256: domain.ChecksumSHA256([]byte(raw)).String(), StderrSHA256: domain.ChecksumSHA256(nil).String(), StdoutTransformationState: domain.StdoutTransformationUnmodified,
	}}}
	excerpts, err := normalizedKernelXIDExcerpts(catalog, request, result, now.Add(-time.Minute), now)
	if err != nil {
		t.Fatal(err)
	}
	stored, found := excerpts["node-1"]
	if !found {
		t.Fatal("kernel XID evidence was not normalized")
	}
	if strings.Contains(stored, "NVRM:") || strings.Contains(stored, "PCI:") || strings.Contains(stored, "scrubbed-host") || strings.Contains(stored, "pid=") {
		t.Fatalf("raw kernel data reached stored excerpt: %q", stored)
	}
	if strings.Count(stored, `"xid_code":94`) != 2 || !strings.Contains(stored, `"pci_bdf":"0000:01:00"`) || !strings.Contains(stored, `"parser_version":"`+kernelxid.ParserVersion+`"`) || !strings.Contains(stored, `"SOURCE_LINE_CAP_2000"`) {
		t.Fatalf("stored normalized evidence lost typed values or limits: %q", stored)
	}
}

func TestNormalizeKernelXIDEvidenceUsesFullCaptureBeforeExcerptSampling(t *testing.T) {
	now := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	catalog := diagnosticHeadCatalog(t)
	_, digest, found := catalog.Lookup(string(kernelxid.DefinitionID), kernelxid.DefinitionVersion)
	if !found {
		t.Fatal("kernel XID definition missing")
	}
	parsed, err := domain.ParseSHA256(digest)
	if err != nil {
		t.Fatal(err)
	}
	request := domain.DiagnosticRequest{RunID: "kernel-middle", ClusterID: "pilot-cluster", Definition: domain.DiagnosticDefinitionRef{PackID: "standard.readonly", PackVersion: "1.1.0", DefinitionID: kernelxid.DefinitionID, DefinitionVersion: kernelxid.DefinitionVersion, DefinitionDigest: parsed}, Privilege: domain.DiagnosticUnprivileged, Targets: []domain.DiagnosticTarget{"node-1"}, RequestedBy: "test", IdempotencyKey: "kernel-middle", RequestedAt: now.Add(-time.Minute), Deadline: now.Add(time.Minute), MaxAttempts: 1}
	raw := strings.Repeat("\n", 900) + "2026-09-22T10:00:00+0000 scrubbed-host kernel: NVRM: Xid (PCI:0000:01:00): 94, first middle\n" + "2026-09-22T10:01:00+0000 scrubbed-host kernel: NVRM: Xid (PCI:0000:02:00): 79, second middle\n" + strings.Repeat("\n", 900)
	if excerpt := stdoutExcerpt([]byte(raw)); strings.Contains(excerpt, "Xid") {
		t.Fatalf("fixture did not place XID records outside generic excerpt: %q", excerpt)
	}
	result := Result{DefinitionID: string(kernelxid.DefinitionID), DefinitionVersion: kernelxid.DefinitionVersion, DefinitionDigest: digest, Targets: []TargetResult{{TargetID: "node-1", Started: true, Stdout: []byte(raw), StdoutBytes: int64(len(raw)), StdoutSHA256: domain.ChecksumSHA256([]byte(raw)).String(), StderrSHA256: domain.ChecksumSHA256(nil).String(), StdoutTransformationState: domain.StdoutTransformationUnmodified}}}
	excerpts, err := normalizedKernelXIDExcerpts(catalog, request, result, now.Add(time.Minute*-1), now)
	if err != nil {
		t.Fatal(err)
	}
	stored := excerpts["node-1"]
	if strings.Count(stored, `"xid_code":`) != 2 || !strings.Contains(stored, `"xid_code":94`) || !strings.Contains(stored, `"xid_code":79`) {
		t.Fatalf("middle XID rows were lost: %q", stored)
	}
}

func TestNormalizeKernelXIDEvidenceRejectsDefinitionDrift(t *testing.T) {
	now := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	catalog := diagnosticHeadCatalog(t)
	_, digest, found := catalog.Lookup(string(kernelxid.DefinitionID), kernelxid.DefinitionVersion)
	if !found {
		t.Fatal("kernel XID definition missing")
	}
	parsed, err := domain.ParseSHA256(digest)
	if err != nil {
		t.Fatal(err)
	}
	request := domain.DiagnosticRequest{RunID: "kernel-drift", ClusterID: "pilot-cluster", Definition: domain.DiagnosticDefinitionRef{PackID: "standard.readonly", PackVersion: "1.1.0", DefinitionID: kernelxid.DefinitionID, DefinitionVersion: kernelxid.DefinitionVersion, DefinitionDigest: parsed}, Privilege: domain.DiagnosticUnprivileged, Targets: []domain.DiagnosticTarget{"node-1"}, RequestedBy: "test", IdempotencyKey: "kernel-drift", RequestedAt: now.Add(-time.Minute), Deadline: now.Add(time.Minute), MaxAttempts: 1}
	result := Result{DefinitionID: string(kernelxid.DefinitionID), DefinitionVersion: kernelxid.DefinitionVersion, DefinitionDigest: digest, Targets: []TargetResult{{TargetID: "node-1", Started: true, StdoutTransformationState: domain.StdoutTransformationUnmodified}}}
	for _, drift := range []struct{ packID, packVersion, requestDigest, resultID, resultVersion, resultDigest string }{
		{packID: "different-pack", packVersion: "1.1.0", requestDigest: digest, resultID: result.DefinitionID, resultVersion: result.DefinitionVersion, resultDigest: digest},
		{packID: request.Definition.PackID, packVersion: request.Definition.PackVersion, requestDigest: strings.Repeat("a", 64), resultID: result.DefinitionID, resultVersion: result.DefinitionVersion, resultDigest: digest},
		{packID: request.Definition.PackID, packVersion: request.Definition.PackVersion, requestDigest: digest, resultID: result.DefinitionID, resultVersion: "2.0.1", resultDigest: digest},
		{packID: request.Definition.PackID, packVersion: request.Definition.PackVersion, requestDigest: digest, resultID: result.DefinitionID, resultVersion: result.DefinitionVersion, resultDigest: strings.Repeat("b", 64)},
	} {
		req := request
		parsed, err := domain.ParseSHA256(drift.requestDigest)
		if err != nil {
			t.Fatal(err)
		}
		req.Definition.DefinitionDigest = parsed
		req.Definition.PackID, req.Definition.PackVersion = drift.packID, drift.packVersion
		candidate := result
		candidate.DefinitionID, candidate.DefinitionVersion, candidate.DefinitionDigest = drift.resultID, drift.resultVersion, drift.resultDigest
		excerpts, err := normalizedKernelXIDExcerpts(catalog, req, candidate, now.Add(-time.Minute), now)
		if err == nil || len(excerpts) != 0 {
			t.Fatalf("drift did not fail closed: excerpts=%v err=%v", excerpts, err)
		}
	}
}

func TestNormalizeKernelXIDEvidenceKeepsMissingTargetsTyped(t *testing.T) {
	now := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	catalog := diagnosticHeadCatalog(t)
	_, digest, found := catalog.Lookup(string(kernelxid.DefinitionID), kernelxid.DefinitionVersion)
	if !found {
		t.Fatal("kernel XID definition missing")
	}
	parsed, err := domain.ParseSHA256(digest)
	if err != nil {
		t.Fatal(err)
	}
	request := domain.DiagnosticRequest{RunID: "kernel-missing", ClusterID: "pilot-cluster", Definition: domain.DiagnosticDefinitionRef{PackID: "standard.readonly", PackVersion: "1.1.0", DefinitionID: kernelxid.DefinitionID, DefinitionVersion: kernelxid.DefinitionVersion, DefinitionDigest: parsed}, Privilege: domain.DiagnosticUnprivileged, Targets: []domain.DiagnosticTarget{"node-1", "node-2"}, RequestedBy: "test", IdempotencyKey: "kernel-missing", RequestedAt: now.Add(-time.Minute), Deadline: now.Add(time.Minute), MaxAttempts: 1}
	raw := "2026-09-22T10:00:00+0000 scrubbed-host kernel: NVRM: Xid (PCI:0000:01:00): 94, present"
	result := Result{DefinitionID: string(kernelxid.DefinitionID), DefinitionVersion: kernelxid.DefinitionVersion, DefinitionDigest: digest, Targets: []TargetResult{{TargetID: "node-1", Started: true, Stdout: []byte(raw), StdoutTransformationState: domain.StdoutTransformationUnmodified}}}
	excerpts, err := normalizedKernelXIDExcerpts(catalog, request, result, now.Add(-time.Minute), now)
	if err != nil || len(excerpts) != 2 {
		t.Fatalf("typed coverage excerpts=%v err=%v", excerpts, err)
	}
	if strings.Contains(excerpts["node-1"], "NVRM:") || !strings.Contains(excerpts["node-2"], `"TARGET_UNAVAILABLE"`) || strings.Contains(excerpts["node-2"], `"TARGET_ACCESS_REJECTED"`) {
		t.Fatalf("missing target lost typed refusal: %q", excerpts["node-2"])
	}
}
