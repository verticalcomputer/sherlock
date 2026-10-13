package gpuprocess

import (
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

func fixture(t *testing.T) (Config, Input) {
	t.Helper()
	read := func(name string) string {
		b, err := os.ReadFile("testdata/synthetic-v1/" + name)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	node := domain.EntityIdentity{ClusterID: "cluster-a", Kind: domain.EntityNode, NodeID: "node-a"}
	gpu := node
	gpu.Kind = domain.EntityGPU
	gpu.PhysicalGPUUUID = "GPU-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	cfg := Config{ClusterID: node.ClusterID, SourceID: "gpu-source", Node: &node, GPUs: []domain.EntityIdentity{gpu}, PIDNamespace: "pid:[4026531836]", CompleteComputeVisibility: true, PhysicalOnly: true, MembershipSourceID: "task-source", SchedulerNamespace: "slurm-a"}
	at := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	input := Input{Format: Format, CSV: read("compute.csv"), QuerySucceeded: true, StartedAt: at, FinishedAt: at.Add(time.Second), ObservedAt: at.Add(2 * time.Second)}
	for _, process := range []struct {
		pid  uint32
		stat string
	}{{42, read("42.stat")}, {43, read("43.stat")}} {
		before := ProcSample{Node: node, At: at.Add(-time.Second), BootID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", PIDNamespace: cfg.PIDNamespace, Stat: process.stat}
		after := before
		after.At = input.ObservedAt
		input.Processes = append(input.Processes, ProcessEvidence{PID: process.pid, Before: before, After: after})
	}
	input.Memberships = []TaskMembership{{SourceID: cfg.MembershipSourceID,
		Process:   domain.GPUProcessIdentity{Node: node, BootID: input.Processes[0].Before.BootID, PIDNamespace: cfg.PIDNamespace, PID: 42, StartTicks: 100},
		Job:       domain.JobIdentity{SchedulerNamespace: cfg.SchedulerNamespace, JobID: "job-17", SubmitAt: at.Add(-time.Hour), Attempt: 2},
		ValidFrom: at.Add(-time.Second), ValidThrough: input.ObservedAt, EvidenceID: "receipt-1"}}
	return cfg, input
}

func TestManagedAndUnmanaged(t *testing.T) {
	cfg, input := fixture(t)
	result, err := Normalize(cfg, input)
	if err != nil {
		t.Fatal(err)
	}
	if result.ComputeVisibility != domain.SourceCoverageComplete || len(result.Gaps) != 0 || len(result.Observations) != 2 {
		t.Fatalf("unexpected result: %+v", result)
	}
	managed, unmanaged := result.Observations[0], result.Observations[1]
	if managed.Process == nil || managed.Process.StartTicks != 100 || managed.Membership == nil || managed.Membership.Job.Attempt != 2 || managed.GPU == nil {
		t.Fatalf("managed evidence lost: %+v", managed)
	}
	if unmanaged.Process == nil || unmanaged.Membership != nil || unmanaged.Process.StartTicks != 200 {
		t.Fatalf("unmanaged process mishandled: %+v", unmanaged)
	}
	input.Memberships[0].EvidenceID = "modified"
	cfg.GPUs[0].NodeID = "modified"
	if managed.Membership.EvidenceID != "receipt-1" || managed.GPU.NodeID != "node-a" {
		t.Fatal("result aliases caller mutable data")
	}
}

func TestPilotTwoColumnProcessQuery(t *testing.T) {
	cfg, input := fixture(t)
	input.Format = FormatV2
	input.CSV = "GPU-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee, 42\nGPU-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee, 43\n"
	result, err := Normalize(cfg, input)
	if err != nil || result.Format != FormatV2 || len(result.Observations) != 2 || result.ComputeVisibility != domain.SourceCoverageComplete {
		t.Fatalf("two-column query lost process evidence: %+v %v", result, err)
	}
	for _, observation := range result.Observations {
		if observation.GPU == nil || observation.Process == nil || observation.GPUInstanceID != nil || observation.ComputeInstanceID != nil {
			t.Fatalf("two-column process row invalid: %+v", observation)
		}
	}
	cfg.PhysicalOnly = false
	result, err = Normalize(cfg, input)
	if err != nil || result.ComputeVisibility == domain.SourceCoverageComplete || !slices.Contains(result.Gaps, MIGAmbiguous) {
		t.Fatalf("unproven physical-only scope lost MIG gap: %+v %v", result, err)
	}
	input.CSV += "GPU-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee, 44, 0, 0\n"
	result, err = Normalize(cfg, input)
	if err != nil || !slices.Contains(result.Gaps, Malformed) {
		t.Fatalf("mixed output shape accepted: %+v %v", result, err)
	}
}

func TestMembershipCanonicalJobIdentity(t *testing.T) {
	cfg, input := fixture(t)
	canonicalJob, err := domain.CreateJobIdentity(input.Memberships[0].Job)
	if err != nil {
		t.Fatal(err)
	}
	utcResult, err := Normalize(cfg, input)
	if err != nil {
		t.Fatal(err)
	}
	input.Memberships[0].Job.SubmitAt = input.Memberships[0].Job.SubmitAt.In(time.FixedZone("IST", 5*3600+30*60))
	originalReceipt := input.Memberships[0]
	zoneResult, err := Normalize(cfg, input)
	if err != nil {
		t.Fatal(err)
	}
	if zoneResult.Observations[0].Membership == nil || utcResult.Observations[0].Membership == nil {
		t.Fatal("valid membership disappeared")
	}
	retained := zoneResult.Observations[0].Membership
	if retained.Job != canonicalJob || retained.Job != utcResult.Observations[0].Membership.Job || retained.Job.SubmitAt.Location() != time.UTC {
		t.Fatal("equivalent submit instants produced different job identities")
	}
	if input.Memberships[0] != originalReceipt {
		t.Fatal("normalization changed caller receipt")
	}
	input.Memberships[0].Job.SubmitAt = input.Memberships[0].Job.SubmitAt.Add(time.Hour)
	input.Memberships[0].Job.JobID = "changed"
	if retained.Job != canonicalJob {
		t.Fatal("retained job aliases caller receipt")
	}
	retained.Job.Attempt++
	if input.Memberships[0].Job.Attempt != originalReceipt.Job.Attempt {
		t.Fatal("caller receipt aliases retained job")
	}
}

func TestProcessVisibilityGaps(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config, *Input)
		gap    Gap
	}{
		{"missing_start", func(c *Config, i *Input) { i.Processes = nil }, StartUnknown},
		{"reuse", func(c *Config, i *Input) {
			i.Processes[0].After.Stat = strings.Replace(i.Processes[0].After.Stat, "100", "101", 1)
		}, PIDReused},
		{"reboot", func(c *Config, i *Input) { i.Processes[0].After.BootID = "bbbbbbbb-bbbb-cccc-dddd-eeeeeeeeeeee" }, PIDReused},
		{"late_pre_read", func(c *Config, i *Input) { i.Processes[0].Before.At = i.FinishedAt }, StartUnknown},
		{"early_post_read", func(c *Config, i *Input) { i.Processes[0].After.At = i.StartedAt }, StartUnknown},
		{"foreign_namespace", func(c *Config, i *Input) { i.Processes[0].Before.PIDNamespace = "pid:[2]" }, StartUnknown},
		{"missing_namespace", func(c *Config, i *Input) { c.PIDNamespace = "" }, StartUnknown},
		{"proc_permission", func(c *Config, i *Input) { i.Processes[0].Before.Failure = PermissionDenied }, PermissionDenied},
		{"bad_stat", func(c *Config, i *Input) { i.Processes[0].Before.Stat = "SECRET_MALFORMED" }, Malformed},
		{"unknown_gpu", func(c *Config, i *Input) { i.CSV = strings.ReplaceAll(i.CSV, "GPU-aaaaaaaa", "GPU-bbbbbbbb") }, GPUUnknown},
		{"absent_gpu", func(c *Config, i *Input) { i.CSV = strings.ReplaceAll(i.CSV, string(c.GPUs[0].PhysicalGPUUUID), "N/A") }, GPUUnknown},
		{"unknown_node", func(c *Config, i *Input) { c.Node = nil; c.GPUs = nil; i.Processes = nil; i.Memberships = nil }, NodeUnknown},
		{"mig", func(c *Config, i *Input) { i.CSV = strings.ReplaceAll(i.CSV, "N/A, N/A", "0, 1") }, MIGAmbiguous},
		{"mig_unknown", func(c *Config, i *Input) { c.PhysicalOnly = false }, MIGAmbiguous},
		{"unsupported_fields", func(c *Config, i *Input) { i.CSV = strings.ReplaceAll(i.CSV, "N/A", "[Not Supported]") }, Unsupported},
		{"stale", func(c *Config, i *Input) { i.ObservedAt = i.ObservedAt.Add(MaxAge) }, Stale},
		{"bad_csv", func(c *Config, i *Input) { i.CSV += "SECRET,malformed\n" }, Malformed},
		{"bad_pid", func(c *Config, i *Input) { i.CSV = strings.ReplaceAll(i.CSV, ", 42,", ", 0,") }, Malformed},
		{"duplicate_row", func(c *Config, i *Input) { i.CSV += i.CSV }, Malformed},
		{"incomplete", func(c *Config, i *Input) { c.CompleteComputeVisibility = false }, VisibilityUnknown},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg, input := fixture(t)
			test.mutate(&cfg, &input)
			result, err := Normalize(cfg, input)
			if err != nil {
				t.Fatal(err)
			}
			if result.ComputeVisibility == domain.SourceCoverageComplete || !slices.Contains(result.Gaps, test.gap) {
				t.Fatalf("gap %s not preserved: %+v", test.gap, result)
			}
			if test.gap == PIDReused && (result.Observations[0].Process != nil || result.Observations[0].Membership != nil) {
				t.Fatal("PID reuse associated an incarnation")
			}
		})
	}
}

func TestEmptyCompleteVersusUnavailable(t *testing.T) {
	cfg, input := fixture(t)
	input.CSV = ""
	input.Processes = nil
	input.Memberships = nil
	complete, err := Normalize(cfg, input)
	if err != nil || complete.ComputeVisibility != domain.SourceCoverageComplete || len(complete.Observations) != 0 {
		t.Fatalf("empty compute membership: %+v %v", complete, err)
	}
	if complete.Node == nil || *complete.Node != *cfg.Node || complete.PIDNamespace != cfg.PIDNamespace || complete.Scope != "NVIDIA_COMPUTE_APPS" {
		t.Fatal("empty result lost source/target scope")
	}
	for _, failure := range []Gap{Missing, Truncated, Malformed, PermissionDenied, Unsupported, Timeout} {
		input.Failure = failure
		result, err := Normalize(cfg, input)
		if err != nil || result.ComputeVisibility == domain.SourceCoverageComplete || !slices.Contains(result.Gaps, failure) {
			t.Fatalf("failure treated as empty complete: %+v %v", result, err)
		}
	}
	input.Failure = ""
	input.QuerySucceeded = false
	missing, err := Normalize(cfg, input)
	if err != nil || !slices.Contains(missing.Gaps, Missing) || missing.ComputeVisibility == domain.SourceCoverageComplete {
		t.Fatal("absent response became complete empty")
	}
	input.QuerySucceeded = true
	input.Format = "future-format"
	result, err := Normalize(cfg, input)
	if err != nil || result.ComputeVisibility != domain.SourceCoverageUnsupported {
		t.Fatalf("unsupported format: %+v %v", result, err)
	}
	input.Format = Format
	cfg.CompleteComputeVisibility = false
	result, err = Normalize(cfg, input)
	if err != nil || result.ComputeVisibility == domain.SourceCoverageComplete {
		t.Fatal("incomplete empty became complete")
	}
}

func TestAssociationNeedsFullScopedEvidence(t *testing.T) {
	for _, mutate := range []func(*Input){
		func(i *Input) { i.Memberships[0].Process.StartTicks++ },
		func(i *Input) { i.Memberships[0].Process.BootID = "bbbbbbbb-bbbb-cccc-dddd-eeeeeeeeeeee" },
		func(i *Input) { i.Memberships[0].ValidFrom = i.FinishedAt },
		func(i *Input) { i.Memberships[0].ValidThrough = i.StartedAt },
		func(i *Input) { i.Memberships = append(i.Memberships, i.Memberships[0]) },
	} {
		cfg, input := fixture(t)
		mutate(&input)
		result, err := Normalize(cfg, input)
		if err != nil {
			t.Fatal(err)
		}
		if result.Observations[0].Membership != nil || !slices.Contains(result.Gaps, AssociationUnproven) {
			t.Fatal("unproven association retained")
		}
	}
	// Matching process names, PIDs and timestamps without a receipt remain unmanaged.
	cfg, input := fixture(t)
	input.Memberships = nil
	result, err := Normalize(cfg, input)
	if err != nil || result.Observations[0].Membership != nil {
		t.Fatal("association invented")
	}
}

func TestForeignIdentityRejection(t *testing.T) {
	for _, mutate := range []func(*Config, *Input){
		func(c *Config, i *Input) { c.Node.ClusterID = "foreign" },
		func(c *Config, i *Input) { c.GPUs[0].NodeID = "foreign" },
		func(c *Config, i *Input) { i.Processes[0].Before.Node.NodeID = "foreign" },
		func(c *Config, i *Input) { i.Memberships[0].Process.Node.ClusterID = "foreign" },
		func(c *Config, i *Input) { i.Memberships[0].SourceID = "foreign" },
		func(c *Config, i *Input) { i.Memberships[0].Job.SchedulerNamespace = "foreign" },
		func(c *Config, i *Input) { i.Memberships[0].Job.Attempt = -1 },
		func(c *Config, i *Input) { i.Memberships[0].Job.SubmitAt = time.Time{} },
		func(c *Config, i *Input) { i.Memberships[0].EvidenceID = "SECRET\ninvalid" },
	} {
		cfg, input := fixture(t)
		mutate(&cfg, &input)
		if _, err := Normalize(cfg, input); err == nil {
			t.Fatal("foreign or malformed identity accepted")
		}
	}
}

func TestLimitsAndRedaction(t *testing.T) {
	for _, mutate := range []func(*Input){
		func(i *Input) { i.CSV = strings.Repeat("SECRET", MaxBytes/6+1) },
		func(i *Input) { i.CSV = strings.Repeat(strings.SplitAfter(i.CSV, "\n")[0], MaxRecords+1) },
		func(i *Input) { i.Processes = make([]ProcessEvidence, MaxRecords+1) },
		func(i *Input) { i.Memberships = make([]TaskMembership, MaxRecords+1) },
		func(i *Input) { i.Processes[0].Before.Stat = strings.Repeat("SECRET", 700) },
	} {
		cfg, input := fixture(t)
		mutate(&input)
		result, err := Normalize(cfg, input)
		if err != nil || !slices.Contains(result.Gaps, OutputLimit) || len(result.Observations) > MaxRecords || result.ComputeVisibility == domain.SourceCoverageComplete {
			t.Fatalf("bounds lost: %v %+v", err, result.Gaps)
		}
	}
	cfg, input := fixture(t)
	result, err := Normalize(cfg, input)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(result)
	if strings.Contains(string(encoded), "SECRET") || strings.Contains(string(encoded), "python") {
		t.Fatal("process name leaked")
	}
	input.CSV = "SECRET_CSV,not-a-pid,N/A,N/A\n"
	result, err = Normalize(cfg, input)
	encoded, _ = json.Marshal(result)
	if err != nil || strings.Contains(string(encoded), "SECRET") {
		t.Fatal("malformed raw output leaked")
	}
}

func TestPinnedProcStatLayout(t *testing.T) {
	_, input := fixture(t)
	stat := input.Processes[0].Before.Stat
	for _, malformed := range []string{
		strings.Replace(stat, ") S ", ") NOT_A_STATE ", 1),
		strings.Replace(stat, " 18 100 ", " SECRET 100 ", 1),
		strings.TrimSuffix(strings.TrimSpace(stat), " 0"),
		strings.Replace(stat, "42 (", "43 (", 1),
		stat + " 0",
	} {
		if _, ok := startTicks(malformed, 42); ok {
			t.Fatal("malformed stat asserted start identity")
		}
	}
	trickyName := strings.Replace(stat, "python SECRET_PROCESS_NAME", "python ) nested (name)", 1)
	if ticks, ok := startTicks(trickyName, 42); !ok || ticks != 100 {
		t.Fatal("parenthesized comm broke field22 parsing")
	}
}

func TestNormalizedOutputBound(t *testing.T) {
	cfg, input := fixture(t)
	row := strings.SplitAfter(input.CSV, "\n")[0]
	input.CSV = strings.Repeat(row, MaxRecords)
	result, err := Normalize(cfg, input)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(result)
	if err != nil || len(encoded) > MaxBytes || len(result.Observations) != 0 || !slices.Contains(result.Gaps, OutputLimit) {
		t.Fatal("normalized evidence escaped byte bound")
	}
}
