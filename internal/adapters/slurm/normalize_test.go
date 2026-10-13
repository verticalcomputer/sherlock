package slurm

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/adapters/source"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

const pinnedDataParserVersion = "data_parser/v0.0.40"

func pinnedResult(t *testing.T, kind, name string) Result {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("testdata", "upstream-data-parser-v0.0.40-hand-authored", name))
	if err != nil {
		t.Fatal(err)
	}
	records, metadata, err := normalize(kind, body, defaultMaxRecords)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.DataParserVersion != pinnedDataParserVersion || metadata.SlurmVersion != "23.11.10" {
		t.Fatalf("metadata = %#v", metadata)
	}
	return Result{Records: records, BytesRead: len(body), DataParserVersion: metadata.DataParserVersion, SlurmVersion: metadata.SlurmVersion, SchemaSupport: SchemaSupportSupported}
}

func testNormalizer(t *testing.T, trusted bool) *Normalizer {
	t.Helper()
	n, err := NewNormalizer(NormalizationConfig{ClusterID: "cluster-a", SourceID: "slurm-a", SchedulerNamespace: "cluster-a/slurm", SchedulerCluster: "cluster-a", TrustedCurrentJobVisibility: trusted, TrustedAccountingVisibility: trusted,
		Nodes: map[domain.StableNodeID]string{"node-007": "comp007", "node-008": "comp008"}, MaxRecords: 100})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestNormalizePinnedV0040SchemaIntoGP02ContractsAndDeduplicatesOverlap(t *testing.T) {
	sourceAt := time.Unix(1787133600, 0).UTC()
	observedAt := sourceAt.Add(time.Second)
	accounting := pinnedResult(t, "accounting_job", "accounting.json")
	current := pinnedResult(t, "job", "jobs.json")
	if got := recordAttribute(current.Records[0], "submit_time"); got != "1787126400" {
		t.Fatalf("wrapped submit_time = %q", got)
	}
	if got := recordFieldQuality(current.Records[0], "end_time"); got != FieldUnset {
		t.Fatalf("wrapped unset end_time quality = %q", got)
	}
	if recordFieldQuality(accounting.Records[0], "restart_cnt") != FieldUnsupported {
		t.Fatalf("v0.0.40 accounting attempt quality = %q", recordFieldQuality(accounting.Records[0], "restart_cnt"))
	}
	input := NormalizationInput{
		Nodes: pinnedResult(t, "node", "nodes.json"), Partitions: pinnedResult(t, "partition", "partitions.json"), Jobs: current,
		SourceAt: sourceAt, ObservedAt: observedAt,
		Accounting: []AccountingWindow{
			{Start: sourceAt.Add(-2 * time.Hour), End: sourceAt.Add(-time.Hour), SourceAt: sourceAt, Result: accounting},
			{Start: sourceAt.Add(-90 * time.Minute), End: sourceAt.Add(-30 * time.Minute), SourceAt: sourceAt.Add(time.Second), Result: accounting},
		},
	}
	got, err := testNormalizer(t, true).Normalize(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Issues) != 1 || !hasIssue(got.Issues, "JOB_ATTEMPT_UNSUPPORTED") || got.Inventory == nil || len(got.Allocations) != 1 || len(got.Lifecycles) != 1 || len(got.UnresolvedAccounting) != 1 {
		t.Fatalf("normalized = %#v", got)
	}
	if _, err := domain.CreateInventoryRevision(*got.Inventory); err != nil {
		t.Fatalf("inventory contract: %v", err)
	}
	for _, allocation := range got.Allocations {
		if _, err := domain.CreateAllocationSnapshot(allocation); err != nil {
			t.Fatalf("allocation contract: %v", err)
		}
	}
	if got.Allocations[0].Job.JobID != "42" || got.Allocations[0].State != domain.AllocationRunning {
		t.Fatalf("allocations = %#v", got.Allocations)
	}
	if !got.UnresolvedAccounting[0].EndAt.Equal(time.Unix(1787126000, 0)) || got.UnresolvedAccounting[0].RecordIdentity == "" || got.UnresolvedAccounting[0].JobID != "41" {
		t.Fatalf("unresolved accounting identity = %#v", got.UnresolvedAccounting[0])
	}
	unresolved := got.UnresolvedAccounting[0]
	if unresolved.ClusterID != "cluster-a" || unresolved.SourceID != "slurm-a" || len(unresolved.Provenance) != 2 || !unresolved.Provenance[0].SourceAt.Equal(sourceAt) || !unresolved.Provenance[1].SourceAt.Equal(sourceAt.Add(time.Second)) || !unresolved.Provenance[0].ObservedAt.Equal(observedAt) {
		t.Fatalf("unresolved accounting provenance = %#v", unresolved)
	}
	if got.Coverage[0].State != domain.SourceCoverageComplete || got.Coverage[1].State != domain.SourceCoverageUnknown {
		t.Fatalf("coverage = %#v", got.Coverage)
	}
}

func TestNormalizeLossyStateEvidenceSurvivesFactDedupInEitherOrder(t *testing.T) {
	now := time.Unix(1787133600, 0).UTC()
	plain := validCurrentRecord("50", "RUNNING", "1787130000", "1787130100", "0", "comp007")
	configuring := validCurrentRecord("50", "RUNNING+CONFIGURING", "1787130000", "1787130100", "0", "comp007")
	for _, test := range []struct {
		name    string
		records []Record
	}{{name: "plain-first", records: []Record{plain, configuring}}, {name: "configuring-first", records: []Record{configuring, plain}}} {
		t.Run(test.name, func(t *testing.T) {
			got, err := testNormalizer(t, true).Normalize(completeInput(t, now, test.records, nil))
			if err != nil {
				t.Fatal(err)
			}
			if len(got.Allocations) != 1 || len(got.Lifecycles) != 2 || !hasIssue(got.Issues, "LOSSY_STATE_PROJECTION") || got.Coverage[1].State != domain.SourceCoverageUnknown {
				t.Fatalf("deduplicated transitional evidence = %#v", got)
			}
		})
	}
}

func TestNormalizePreservesOccupyingTransitionalStatesWithoutClaimingCompleteness(t *testing.T) {
	now := time.Unix(1787133600, 0).UTC()
	jobs := pinnedResult(t, "job", "jobs.json")
	jobs.Records = []Record{
		record("job", "50", "RUNNING+CONFIGURING", map[string]string{"submit_time": "1787130000", "start_time": "1787130100", "restart_cnt": "0", "nodes": "comp007"}),
		record("job", "51", "RUNNING+COMPLETING", map[string]string{"submit_time": "1787130001", "start_time": "1787130101", "restart_cnt": "0", "nodes": "comp008"}),
		record("job", "52", "SUSPENDED", map[string]string{"submit_time": "1787130002", "start_time": "1787130102", "restart_cnt": "0", "nodes": "comp007"}),
	}
	got, err := testNormalizer(t, true).Normalize(NormalizationInput{Nodes: pinnedResult(t, "node", "nodes.json"), Partitions: pinnedResult(t, "partition", "partitions.json"), Jobs: jobs, SourceAt: now, ObservedAt: now.Add(time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	states := []domain.AllocationState{got.Allocations[0].State, got.Allocations[1].State, got.Allocations[2].State}
	if !slices.Equal(states, []domain.AllocationState{domain.AllocationRunning, domain.AllocationCompleting, domain.AllocationSuspended}) {
		t.Fatalf("states = %#v", states)
	}
	if got.Lifecycles[0].RawState != "RUNNING+CONFIGURING" || got.Coverage[1].State != domain.SourceCoverageUnknown || !hasIssue(got.Issues, "LOSSY_STATE_PROJECTION") {
		t.Fatalf("transitional normalization = %#v", got)
	}
}

func TestNormalizePreservesSameJobStateTransitionIdentity(t *testing.T) {
	now := time.Unix(1787133600, 0).UTC()
	emptyAccounting := []AccountingWindow{{Start: now.Add(-time.Hour), End: now, SourceAt: now, Result: Result{SchemaSupport: SchemaSupportSupported}}}
	base := NormalizationInput{Nodes: pinnedResult(t, "node", "nodes.json"), Partitions: pinnedResult(t, "partition", "partitions.json"), SourceAt: now, ObservedAt: now.Add(time.Second), Accounting: emptyAccounting}
	base.Jobs = Result{SchemaSupport: SchemaSupportSupported, Records: []Record{record("job", "80", "RUNNING", map[string]string{"submit_time": "1787130000", "start_time": "1787130100", "restart_cnt": "2", "nodes": "comp007"})}}
	running, err := testNormalizer(t, true).Normalize(base)
	if err != nil {
		t.Fatal(err)
	}
	base.SourceAt = now.Add(time.Minute)
	base.ObservedAt = base.SourceAt.Add(time.Second)
	base.Accounting[0].SourceAt = base.SourceAt
	base.Jobs.Records[0].State = "SUSPENDED"
	base.Jobs.Records[0].Attributes = replaceAttribute(base.Jobs.Records[0].Attributes, "job_state", "SUSPENDED")
	suspended, err := testNormalizer(t, true).Normalize(base)
	if err != nil {
		t.Fatal(err)
	}
	if running.Allocations[0].State != domain.AllocationRunning || suspended.Allocations[0].State != domain.AllocationSuspended || running.Allocations[0].Job != suspended.Allocations[0].Job || !suspended.Allocations[0].EffectiveAt.After(running.Allocations[0].EffectiveAt) {
		t.Fatalf("running=%#v suspended=%#v", running.Allocations, suspended.Allocations)
	}
}

func TestNormalizeDoesNotBorrowRequeuedCurrentAttemptForHistoricalAccounting(t *testing.T) {
	now := time.Unix(1787133600, 0).UTC()
	current := record("job", "90", "RUNNING", map[string]string{"submit_time": "1787130000", "start_time": "1787130100", "restart_cnt": "3", "nodes": "comp007", "cluster": "cluster-a"})
	current.Fields = replaceFieldQuality(current.Fields, "end_time", FieldUnset)
	accounting := record("accounting_job", "90", "COMPLETED", map[string]string{"time/submission": "1787130000", "time/start": "1787130100", "time/end": "1787133500", "nodes": "comp007", "cluster": "cluster-a"})
	got, err := testNormalizer(t, true).Normalize(NormalizationInput{Nodes: pinnedResult(t, "node", "nodes.json"), Partitions: pinnedResult(t, "partition", "partitions.json"), Jobs: Result{SchemaSupport: SchemaSupportSupported, Records: []Record{current}}, SourceAt: now, ObservedAt: now.Add(time.Second),
		Accounting: []AccountingWindow{{Start: now.Add(-time.Hour), End: now, SourceAt: now, Result: Result{SchemaSupport: SchemaSupportSupported, Records: []Record{accounting}}}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Issues) != 1 || !hasIssue(got.Issues, "JOB_ATTEMPT_UNSUPPORTED") || len(got.UnresolvedAccounting) != 1 || len(got.Allocations) != 1 || got.Allocations[0].Job.Attempt != 3 || got.UnresolvedAccounting[0].JobID != "90" || got.Coverage[1].State != domain.SourceCoverageUnknown {
		t.Fatalf("requeued accounting = %#v", got)
	}
}

func TestNormalizeAccountingOverlapProvenanceIsStableAndScoped(t *testing.T) {
	now := time.Unix(1787133600, 0).UTC()
	accounting := pinnedResult(t, "accounting_job", "accounting.json")
	windows := []AccountingWindow{
		{Start: now.Add(-2 * time.Hour), End: now.Add(-time.Hour), SourceAt: now, Result: accounting},
		{Start: now.Add(-90 * time.Minute), End: now.Add(-30 * time.Minute), SourceAt: now.Add(time.Second), Result: accounting},
	}
	input := completeInput(t, now, nil, windows)
	first, err := testNormalizer(t, true).Normalize(input)
	if err != nil {
		t.Fatal(err)
	}
	input.Accounting = slices.Clone(windows)
	slices.Reverse(input.Accounting)
	reversed, err := testNormalizer(t, true).Normalize(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.UnresolvedAccounting) != 1 || len(reversed.UnresolvedAccounting) != 1 || first.UnresolvedAccounting[0].RecordIdentity != reversed.UnresolvedAccounting[0].RecordIdentity || !slices.Equal(first.UnresolvedAccounting[0].Provenance, reversed.UnresolvedAccounting[0].Provenance) {
		t.Fatalf("first=%#v reversed=%#v", first.UnresolvedAccounting, reversed.UnresolvedAccounting)
	}
	other, err := NewNormalizer(NormalizationConfig{ClusterID: "cluster-b", SourceID: "slurm-b", SchedulerNamespace: "cluster-a/slurm", SchedulerCluster: "cluster-a", TrustedCurrentJobVisibility: true, TrustedAccountingVisibility: true, Nodes: map[domain.StableNodeID]string{"node-007": "comp007", "node-008": "comp008"}})
	if err != nil {
		t.Fatal(err)
	}
	otherResult, err := other.Normalize(input)
	if err != nil {
		t.Fatal(err)
	}
	if first.UnresolvedAccounting[0].RecordIdentity == otherResult.UnresolvedAccounting[0].RecordIdentity || otherResult.UnresolvedAccounting[0].ClusterID != "cluster-b" || otherResult.UnresolvedAccounting[0].SourceID != "slurm-b" {
		t.Fatalf("unresolved identity not scoped: first=%#v other=%#v", first.UnresolvedAccounting[0], otherResult.UnresolvedAccounting[0])
	}
}

func TestNormalizeAccountingTransitionKeyIncludesSubmitTime(t *testing.T) {
	now := time.Unix(1787133600, 0).UTC()
	first := record("accounting_job", "91", "COMPLETED", map[string]string{"time/submission": "1787120000", "time/start": "1787120100", "time/end": "1787126000", "restart_cnt": "0", "nodes": "comp007", "cluster": "cluster-a"})
	second := record("accounting_job", "91", "COMPLETED", map[string]string{"time/submission": "1787121000", "time/start": "1787121100", "time/end": "1787126000", "restart_cnt": "0", "nodes": "comp007", "cluster": "cluster-a"})
	accounting := []AccountingWindow{{Start: now.Add(-2 * time.Hour), End: now, SourceAt: now, Result: Result{SchemaSupport: SchemaSupportSupported, Records: []Record{first, second}}}}
	got, err := testNormalizer(t, true).Normalize(completeInput(t, now, nil, accounting))
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Allocations) != 2 || hasIssue(got.Issues, "ACCOUNTING_TRANSITION_CONFLICT") || got.Allocations[0].Job.SubmitAt == got.Allocations[1].Job.SubmitAt {
		t.Fatalf("reused job identities = %#v issues=%#v", got.Allocations, got.Issues)
	}
}

func TestNormalizeUnresolvedAccountingPreservesLifecycleQuality(t *testing.T) {
	now := time.Unix(1787133600, 0).UTC()
	for _, test := range []struct {
		name      string
		quality   FieldQuality
		value     string
		issueCode string
	}{
		{name: "missing", quality: FieldMissing, issueCode: "LIFECYCLE_TIME_INCOMPLETE"},
		{name: "malformed", quality: FieldPresent, value: "not-a-time", issueCode: "LIFECYCLE_TIME_INVALID"},
		{name: "unset", quality: FieldUnset, issueCode: "LIFECYCLE_TIME_INCOMPLETE"},
		{name: "infinite", quality: FieldInfinite, issueCode: "LIFECYCLE_TIME_INVALID"},
	} {
		t.Run(test.name, func(t *testing.T) {
			rec := record("accounting_job", "94", "COMPLETED", map[string]string{"time/submission": "1787130000", "time/start": "1787130100", "time/end": "1787130200", "nodes": "comp007", "cluster": "cluster-a"})
			rec.Fields = replaceFieldQuality(rec.Fields, "start_time", test.quality)
			if test.value != "" {
				rec.Attributes = replaceAttribute(rec.Attributes, "time/start", test.value)
			}
			accounting := []AccountingWindow{{Start: now.Add(-time.Hour), End: now, SourceAt: now, Result: Result{SchemaSupport: SchemaSupportSupported, Records: []Record{rec}}}}
			got, err := testNormalizer(t, true).Normalize(completeInput(t, now, nil, accounting))
			if err != nil {
				t.Fatal(err)
			}
			if len(got.UnresolvedAccounting) != 1 || len(got.Allocations) != 0 || got.UnresolvedAccounting[0].SubmitQuality != FieldPresent || got.UnresolvedAccounting[0].StartQuality != mapExpectedTimeQuality(test.quality) || got.UnresolvedAccounting[0].EndQuality != FieldPresent || !hasIssue(got.Issues, test.issueCode) || got.Coverage[1].State != domain.SourceCoverageUnknown {
				t.Fatalf("unresolved lifecycle = %#v", got)
			}
		})
	}
}

func TestNormalizeUnresolvedAccountingReportsInvalidChronology(t *testing.T) {
	now := time.Unix(1787133600, 0).UTC()
	for _, test := range []struct {
		name   string
		submit string
		start  string
		end    string
	}{
		{name: "start-before-submit", submit: "1787130000", start: "1787129999", end: "1787130200"},
		{name: "end-before-start", submit: "1787130000", start: "1787130100", end: "1787130099"},
	} {
		t.Run(test.name, func(t *testing.T) {
			rec := record("accounting_job", "95", "COMPLETED", map[string]string{"time/submission": test.submit, "time/start": test.start, "time/end": test.end, "nodes": "comp007", "cluster": "cluster-a"})
			accounting := []AccountingWindow{{Start: now.Add(-time.Hour), End: now, SourceAt: now, Result: Result{SchemaSupport: SchemaSupportSupported, Records: []Record{rec}}}}
			got, err := testNormalizer(t, true).Normalize(completeInput(t, now, nil, accounting))
			if err != nil {
				t.Fatal(err)
			}
			if len(got.UnresolvedAccounting) != 1 || len(got.Allocations) != 0 || got.UnresolvedAccounting[0].StartQuality != FieldPresent || got.UnresolvedAccounting[0].EndQuality != FieldPresent || !hasIssue(got.Issues, "LIFECYCLE_TIME_ORDER_INVALID") {
				t.Fatalf("unresolved chronology = %#v", got)
			}
		})
	}
}

func TestNormalizeLifecycleQualityAndOrderingFailClosed(t *testing.T) {
	now := time.Unix(1787133600, 0).UTC()
	valid, err := testNormalizer(t, true).Normalize(completeInput(t, now, []Record{validCurrentRecord("92", "RUNNING", "1787130000", "1787130100", "0", "comp007")}, nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(valid.Allocations) != 1 || valid.Lifecycles[0].EndQuality != FieldUnset || valid.Coverage[1].State != domain.SourceCoverageComplete {
		t.Fatalf("valid running lifecycle = %#v", valid)
	}

	for _, test := range []struct {
		name      string
		field     string
		value     string
		quality   FieldQuality
		issueCode string
		wantFact  bool
	}{
		{name: "malformed-start", field: "start_time", value: "not-a-time", quality: FieldPresent, issueCode: "LIFECYCLE_TIME_INVALID"},
		{name: "malformed-end", field: "end_time", value: "not-a-time", quality: FieldPresent, issueCode: "LIFECYCLE_TIME_INVALID"},
		{name: "infinite-end", field: "end_time", quality: FieldInfinite, issueCode: "LIFECYCLE_TIME_INVALID"},
		{name: "start-before-submit", field: "start_time", value: "1787129999", quality: FieldPresent, issueCode: "LIFECYCLE_TIME_ORDER_INVALID"},
		{name: "missing-start", field: "start_time", quality: FieldMissing, issueCode: "LIFECYCLE_TIME_INCOMPLETE", wantFact: true},
		{name: "unsupported-start", field: "start_time", quality: FieldUnsupported, issueCode: "LIFECYCLE_TIME_INCOMPLETE", wantFact: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			rec := validCurrentRecord("93", "RUNNING", "1787130000", "1787130100", "0", "comp007")
			rec.Fields = replaceFieldQuality(rec.Fields, test.field, test.quality)
			if test.value != "" {
				rec.Attributes = replaceAttribute(rec.Attributes, test.field, test.value)
			}
			got, err := testNormalizer(t, true).Normalize(completeInput(t, now, []Record{rec}, nil))
			if err != nil {
				t.Fatal(err)
			}
			if (len(got.Allocations) == 1) != test.wantFact || len(got.Lifecycles) != 1 || !hasIssue(got.Issues, test.issueCode) || got.Coverage[1].State != domain.SourceCoverageUnknown {
				t.Fatalf("lifecycle evidence = %#v", got)
			}
		})
	}
}

func TestNormalizeValidEmptyIsDistinctFromFailureButCannotInferVisibility(t *testing.T) {
	now := time.Unix(1787133600, 0).UTC()
	empty := pinnedResult(t, "job", "jobs.json")
	empty.Records = nil
	input := NormalizationInput{Nodes: pinnedResult(t, "node", "nodes.json"), Partitions: pinnedResult(t, "partition", "partitions.json"), Jobs: empty, SourceAt: now, ObservedAt: now.Add(time.Second),
		Accounting: []AccountingWindow{{Start: now.Add(-time.Hour), End: now, SourceAt: now, Result: Result{SchemaSupport: SchemaSupportSupported}}}}
	trusted, err := testNormalizer(t, true).Normalize(input)
	if err != nil {
		t.Fatal(err)
	}
	if !trusted.ValidEmptyJobs || !trusted.ValidEmptyAccounting || len(trusted.Allocations) != 0 || trusted.Coverage[1].State != domain.SourceCoverageComplete {
		t.Fatalf("trusted empty = %#v", trusted)
	}
	untrusted, err := testNormalizer(t, false).Normalize(input)
	if err != nil {
		t.Fatal(err)
	}
	if untrusted.Coverage[1].State != domain.SourceCoverageUnknown || !hasIssue(untrusted.Issues, "CURRENT_JOB_VISIBILITY_NOT_ESTABLISHED") || !hasIssue(untrusted.Issues, "ACCOUNTING_VISIBILITY_NOT_ESTABLISHED") {
		t.Fatalf("untrusted empty = %#v", untrusted)
	}
	warnedInput := input
	warnedInput.Jobs.ReportedWarnings = 1
	warned, err := testNormalizer(t, true).Normalize(warnedInput)
	if err != nil {
		t.Fatal(err)
	}
	if warned.ValidEmptyJobs || warned.Coverage[1].State != domain.SourceCoverageUnknown || !hasIssue(warned.Issues, "SOURCE_REPORTED_WARNING") {
		t.Fatalf("warned empty = %#v", warned)
	}
}

func TestNormalizeMissingUnknownUnsupportedAndCrossClusterNeverEstablishIdle(t *testing.T) {
	now := time.Unix(1787133600, 0).UTC()
	jobs := pinnedResult(t, "job", "jobs.json")
	jobs.Records = []Record{
		record("job", "60", "FUTURE_STATE", map[string]string{"submit_time": "1787130000", "restart_cnt": "0", "nodes": "comp007"}),
		record("job", "61", "RUNNING", map[string]string{"submit_time": "1787130001", "nodes": "comp008"}),
	}
	jobs.Records[1].Fields = append(jobs.Records[1].Fields, FieldObservation{Name: "restart_cnt", Quality: FieldUnsupported})
	accounting := pinnedResult(t, "accounting_job", "accounting.json")
	accounting.Records[0].Attributes = replaceAttribute(accounting.Records[0].Attributes, "cluster", "cluster-b")
	got, err := testNormalizer(t, true).Normalize(NormalizationInput{Nodes: pinnedResult(t, "node", "nodes.json"), Partitions: pinnedResult(t, "partition", "partitions.json"), Jobs: jobs, SourceAt: now, ObservedAt: now.Add(time.Second),
		Accounting: []AccountingWindow{{Start: now.Add(-time.Hour), End: now, SourceAt: now, Result: accounting}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Allocations) != 0 || got.Coverage[1].State != domain.SourceCoverageUnknown || !hasIssue(got.Issues, "JOB_STATE_UNKNOWN") || !hasIssue(got.Issues, "JOB_IDENTITY_INCOMPLETE") || !hasIssue(got.Issues, "ACCOUNTING_CLUSTER_MISMATCH") {
		t.Fatalf("incomplete normalization = %#v", got)
	}
}

func TestNormalizeUnknownSchemaAndMalformedPartitionMembershipFailClosed(t *testing.T) {
	now := time.Unix(1787133600, 0).UTC()
	nodes := pinnedResult(t, "node", "nodes.json")
	nodes.SchemaSupport = SchemaSupportUnsupported
	partitions := pinnedResult(t, "partition", "partitions.json")
	partitions.Records[0].Attributes = replaceAttribute(partitions.Records[0].Attributes, "nodes", "comp[008-007]")
	got, err := testNormalizer(t, true).Normalize(NormalizationInput{Nodes: nodes, Partitions: partitions, Jobs: Result{SchemaSupport: SchemaSupportUnknown}, SourceAt: now, ObservedAt: now.Add(time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	if got.Inventory != nil || got.Coverage[0].State != domain.SourceCoverageUnknown || got.Coverage[1].State != domain.SourceCoverageUnknown || !hasIssue(got.Issues, "SCHEMA_NOT_SUPPORTED") || !hasIssue(got.Issues, "PARTITION_NODES_INCOMPLETE") {
		t.Fatalf("unsupported schema = %#v", got)
	}
}

func TestNormalizeBoundsAccountingWindowsEvenWhenEmpty(t *testing.T) {
	now := time.Unix(1787133600, 0).UTC()
	windows := make([]AccountingWindow, maxAccountingWindows+1)
	for index := range windows {
		windows[index] = AccountingWindow{Start: now.Add(-time.Hour), End: now, SourceAt: now, Result: Result{SchemaSupport: SchemaSupportSupported}}
	}
	_, err := testNormalizer(t, true).Normalize(NormalizationInput{SourceAt: now, ObservedAt: now, Accounting: windows})
	if err == nil {
		t.Fatal("unbounded empty accounting windows accepted")
	}
}

func TestClientTracksVersionStateArraysAndUnsupportedFields(t *testing.T) {
	runner := &fixtureRunner{body: []byte(`{"meta":{"plugin":{"data_parser":"data_parser/v0.0.40"},"slurm":{"version":{"major":"23","minor":"11","micro":"10"}}},"jobs":[{"job_id":"70","job_state":["RUNNING","CONFIGURING"],"submit_time":{"set":true,"infinite":false,"number":1787130000},"start_time":{"set":false,"infinite":false,"number":0},"end_time":{"set":false,"infinite":true,"number":0},"restart_cnt":0,"nodes":{"set":false}}]}`)}
	client, err := NewClient(Config{Timeout: time.Second, Runner: runner, SupportedDataParserVersions: []string{pinnedDataParserVersion}})
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.Jobs(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.SchemaSupport != SchemaSupportSupported || result.DataParserVersion != pinnedDataParserVersion || result.SlurmVersion != "23.11.10" || result.Records[0].State != "RUNNING+CONFIGURING" || recordFieldQuality(result.Records[0], "nodes") != FieldUnsupported || recordFieldQuality(result.Records[0], "submit_time") != FieldPresent || recordFieldQuality(result.Records[0], "start_time") != FieldUnset || recordFieldQuality(result.Records[0], "end_time") != FieldInfinite {
		t.Fatalf("result = %#v", result)
	}
	unknown, _ := NewClient(Config{Timeout: time.Second, Runner: runner})
	unknownResult, err := unknown.Jobs(t.Context(), nil)
	if err != nil || unknownResult.SchemaSupport != SchemaSupportUnknown {
		t.Fatalf("unknown support result = %#v err=%v", unknownResult, err)
	}
}

func TestClientV0040TimestampWrapperQualityIsStrict(t *testing.T) {
	for _, test := range []struct {
		name    string
		value   string
		quality FieldQuality
		attr    string
	}{
		{name: "present", value: `{"set":true,"infinite":false,"number":1787130000}`, quality: FieldPresent, attr: "1787130000"},
		{name: "unset", value: `{"set":false,"infinite":false,"number":0}`, quality: FieldUnset},
		{name: "infinite", value: `{"set":false,"infinite":true,"number":0}`, quality: FieldInfinite},
		{name: "scalar-is-malformed", value: `1787130000`, quality: FieldMalformed},
		{name: "missing-member", value: `{"set":true,"number":1787130000}`, quality: FieldMalformed},
		{name: "inconsistent-unset", value: `{"set":false,"infinite":false,"number":1}`, quality: FieldMalformed},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := fmt.Sprintf(`{"meta":{"plugin":{"data_parser":"data_parser/v0.0.40"}},"jobs":[{"job_id":"70","job_state":["RUNNING"],"submit_time":%s}]}`, test.value)
			records, _, err := normalize("job", []byte(body), 1)
			if err != nil {
				t.Fatal(err)
			}
			if got := recordFieldQuality(records[0], "submit_time"); got != test.quality {
				t.Fatalf("quality = %q", got)
			}
			if got := recordAttribute(records[0], "submit_time"); got != test.attr {
				t.Fatalf("attribute = %q", got)
			}
		})
	}
}

func TestClientIgnoresUnknownNestedObjectsWithoutAttributeAmplification(t *testing.T) {
	nested := `"leaf":"value"`
	for range 256 {
		nested = `"unknown":{` + nested + `}`
	}
	body := fmt.Sprintf(`{"meta":{"plugin":{"data_parser":"data_parser/v0.0.40"}},"jobs":[{"job_id":"70","job_state":["RUNNING"],"submit_time":{"set":true,"infinite":false,"number":1787130000},"legacy_scalar":"kept","future":{%s}}]}`, nested)
	records, _, err := normalize("job", []byte(body), 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(records[0].Attributes) != 4 || recordAttribute(records[0], "legacy_scalar") != "kept" {
		t.Fatalf("bounded attributes = %#v", records[0].Attributes)
	}
	for _, attribute := range records[0].Attributes {
		if len(attribute.Name) >= len("future") && attribute.Name[:len("future")] == "future" {
			t.Fatalf("unknown nested attribute retained: %#v", attribute)
		}
	}
}

func TestClientClassifiesTruncatedTimeoutFailureAndOversize(t *testing.T) {
	for _, test := range []struct {
		name string
		body []byte
		err  error
		code domain.FailureCode
	}{
		{name: "truncated", body: []byte(`{"jobs":[`), code: domain.FailureMalformedResponse},
		{name: "timeout", err: context.DeadlineExceeded, code: domain.FailureDeadlineExceeded},
		{name: "failure", err: errors.New("command failed"), code: domain.FailureSourceUnavailable},
		{name: "oversize", err: errOutputLimit, code: domain.FailureResultLimit},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, err := NewClient(Config{Timeout: time.Second, Runner: &fixtureRunner{body: test.body, err: test.err}})
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.Jobs(t.Context(), nil)
			var classified *source.Error
			if !errors.As(err, &classified) || classified.Code != test.code {
				t.Fatalf("error = %#v", err)
			}
		})
	}
}

func record(kind, id, state string, attributes map[string]string) Record {
	attributes["job_id"] = id
	attributes["job_state"] = state
	fields := make([]FieldObservation, 0, len(attributes))
	for name := range attributes {
		canonical := name
		switch name {
		case "time/submission":
			canonical = "submit_time"
		case "time/start":
			canonical = "start_time"
		case "time/end":
			canonical = "end_time"
		}
		fields = replaceFieldQuality(fields, canonical, FieldPresent)
	}
	return Record{Kind: kind, ID: id, State: state, Attributes: domain.SortedLabels(attributes), Fields: fields}
}

func validCurrentRecord(id, state, submit, start, attempt, nodes string) Record {
	record := record("job", id, state, map[string]string{"submit_time": submit, "start_time": start, "restart_cnt": attempt, "nodes": nodes})
	record.Fields = replaceFieldQuality(record.Fields, "end_time", FieldUnset)
	return record
}

func mapExpectedTimeQuality(quality FieldQuality) FieldQuality {
	if quality == FieldPresent {
		return FieldMalformed
	}
	return quality
}

func completeInput(t *testing.T, now time.Time, current []Record, accounting []AccountingWindow) NormalizationInput {
	t.Helper()
	if accounting == nil {
		accounting = []AccountingWindow{{Start: now.Add(-time.Hour), End: now, SourceAt: now, Result: Result{SchemaSupport: SchemaSupportSupported}}}
	}
	return NormalizationInput{
		Nodes:      pinnedResult(t, "node", "nodes.json"),
		Partitions: pinnedResult(t, "partition", "partitions.json"),
		Jobs:       Result{SchemaSupport: SchemaSupportSupported, Records: current},
		Accounting: accounting,
		SourceAt:   now,
		ObservedAt: now.Add(time.Second),
	}
}

func replaceFieldQuality(fields []FieldObservation, name string, quality FieldQuality) []FieldObservation {
	result := slices.Clone(fields)
	for index := range result {
		if result[index].Name == name {
			result[index].Quality = quality
			return result
		}
	}
	return append(result, FieldObservation{Name: name, Quality: quality})
}

func replaceAttribute(attributes []domain.Label, name, value string) []domain.Label {
	result := slices.Clone(attributes)
	for index := range result {
		if result[index].Name == name {
			result[index].Value = value
			return result
		}
	}
	return append(result, domain.Label{Name: name, Value: value})
}

func hasIssue(issues []NormalizationIssue, code string) bool {
	return slices.ContainsFunc(issues, func(issue NormalizationIssue) bool { return issue.Code == code })
}
