package slurmfailures

import (
	"github.com/verticalcomputer/sherlock/internal/domain"
	"testing"
	"time"
)

func TestDistinctAttemptsCancellationsConflictsAndIdentity(t *testing.T) {
	now := time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC)
	p := Policy{ID: "p", ClusterID: "c", SourceID: "s", SchedulerNamespace: "slurm", NodeID: "n", Threshold: 3, WindowSeconds: 1800, FreshForSeconds: 300}
	makeRecord := func(attempt int, state string) Record {
		return Record{RunID: "r", Lifecycle: domain.SlurmJobLifecycle{ClusterID: "c", SourceID: "s", Job: domain.JobIdentity{SchedulerNamespace: "slurm", JobID: "42", SubmitAt: now.Add(-time.Hour), Attempt: attempt}, RecordIdentity: state + string(rune('a'+attempt)), RawState: state, EndAt: now.Add(-time.Minute), EndQuality: domain.SlurmFieldPresent, SubmitQuality: domain.SlurmFieldPresent, NodeIDs: []domain.StableNodeID{"n"}}}
	}
	a, b, c := makeRecord(0, "FAILED"), makeRecord(1, "FAILED"), makeRecord(2, "OUT_OF_MEMORY")
	for _, tc := range []struct {
		name     string
		records  []Record
		failures int
	}{
		{"repeated poll", []Record{a, a, a}, 1},
		{"distinct attempts", []Record{a, b, c}, 3},
		{"cancellation and preemption", []Record{makeRecord(0, "CANCELLED by 123"), makeRecord(1, "PREEMPTED"), c}, 1},
		{"conflicting outcome", []Record{a, makeRecord(0, "CANCELLED"), b, c}, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, err := Evaluate(p, tc.records, now)
			if err != nil || len(e.Failures) != tc.failures {
				t.Fatalf("%+v %v", e, err)
			}
		})
	}
	for _, change := range []func(*Record){func(r *Record) { r.Lifecycle.Job.Attempt = -1 }, func(r *Record) { r.Lifecycle.SubmitQuality = domain.SlurmFieldUnsupported }, func(r *Record) { r.Lifecycle.EndQuality = domain.SlurmFieldMissing }, func(r *Record) { r.Lifecycle.ClusterID = "foreign" }, func(r *Record) { r.Lifecycle.NodeIDs = []domain.StableNodeID{"foreign"} }, func(r *Record) { r.Lifecycle.Job.SchedulerNamespace = "foreign" }, func(r *Record) { r.Lifecycle.EndAt = now.Add(-time.Hour) }, func(r *Record) { r.Lifecycle.EndAt = now.Add(time.Minute) }} {
		x := a
		change(&x)
		e, err := Evaluate(p, []Record{x}, now)
		if err != nil || len(e.Failures) != 0 {
			t.Fatalf("unknown or foreign attempt counted: %+v %v", e, err)
		}
	}
	if _, err := Evaluate(p, make([]Record, MaxRecords+1), now); err == nil {
		t.Fatal("unbounded scan admitted")
	}
	reused := a
	reused.Lifecycle.Job.SubmitAt = reused.Lifecycle.Job.SubmitAt.Add(-time.Hour)
	e, err := Evaluate(p, []Record{a, reused}, now)
	if err != nil || len(e.Failures) != 2 {
		t.Fatal("reused job ID collapsed")
	}
}
