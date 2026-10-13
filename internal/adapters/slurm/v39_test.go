package slurm

import (
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

// Reduced examples of the four read-only Slurm 23.02.8 CLI responses observed
// on fixture2 on 2026-09-23. No user, job name, command or path is retained.
func TestV39LiveShapeNormalizesBoundedMembershipAndPreservesAttemptGap(t *testing.T) {
	meta := `"meta":{"plugins":{"data_parser":"data_parser/v0.0.39"},"Slurm":{"version":{"major":23,"minor":2,"micro":8}}},"errors":[],"warnings":[]`
	read := func(kind, rows string) Result {
		t.Helper()
		body := []byte(`{` + meta + `,` + rows + `}`)
		records, metadata, err := normalize(kind, body, defaultMaxRecords)
		if err != nil {
			t.Fatal(err)
		}
		if metadata.DataParserVersion != domain.SlurmSnapshotDataParserVersion2302 || metadata.SlurmVersion != "23.2.8" {
			t.Fatalf("metadata = %#v", metadata)
		}
		return Result{Records: records, BytesRead: len(body), DataParserVersion: metadata.DataParserVersion, SlurmVersion: metadata.SlurmVersion, SchemaSupport: SchemaSupportSupported}
	}
	nodes := read("node", `"nodes":[{"name":"comp007","state":["ALLOCATED"]},{"name":"comp008","state":["IDLE"]}]`)
	partitions := read("partition", `"partitions":[{"name":"defq","nodes":{"configured":"comp[007-008]","total":2}}]`)
	jobs := read("job", `"jobs":[{"job_id":42,"job_state":"RUNNING","submit_time":1787130000,"start_time":1787130100,"end_time":1788000000,"restart_cnt":0,"nodes":"comp[007-008]","cluster":"cluster-a"}]`)
	accounting := read("accounting_job", `"jobs":[{"job_id":42,"state":{"current":"RUNNING"},"time":{"submission":1787130000,"start":1787130100,"end":0},"nodes":"comp[007-008]","cluster":"cluster-a"}]`)
	if recordFieldQuality(jobs.Records[0], "end_time") != FieldUnset || recordFieldQuality(accounting.Records[0], "end_time") != FieldUnset {
		t.Fatal("projected/zero v0.0.39 end time must remain unset")
	}
	now := time.Unix(1787133600, 0).UTC()
	got, err := testNormalizer(t, true).Normalize(NormalizationInput{Nodes: nodes, Partitions: partitions, Jobs: jobs, Accounting: []AccountingWindow{{Start: now.Add(-time.Hour), End: now, SourceAt: now, Result: accounting}}, SourceAt: now, ObservedAt: now})
	if err != nil {
		t.Fatal(err)
	}
	if got.Inventory == nil || len(got.Allocations) != 1 || len(got.Allocations[0].Entities) != 2 || len(got.UnresolvedAccounting) != 1 || !hasIssue(got.Issues, "JOB_ATTEMPT_UNSUPPORTED") {
		t.Fatalf("v0.0.39 observation = %#v", got)
	}
}

func TestHostlistExpansionRejectsAmbiguousOrExcessiveRanges(t *testing.T) {
	for _, raw := range []string{"comp[008-007]", "comp[007-008],comp007", "comp[001-999]", "comp[007-008", "comp[007-008]tail", "comp[007-x]"} {
		if names, ok := expandHostlist(raw, 20); ok {
			t.Fatalf("accepted %q as %v", raw, names)
		}
	}
	if names, ok := expandHostlist("comp[001-002,004],comp005", 4); !ok || len(names) != 4 || names[0] != "comp001" || names[2] != "comp004" {
		t.Fatalf("bounded hostlist = %v, %v", names, ok)
	}
}
