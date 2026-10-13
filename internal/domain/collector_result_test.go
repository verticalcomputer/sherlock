package domain

import (
	"bytes"
	"testing"
	"time"
)

func TestCollectorResultCanonicalEncodingAndValidation(t *testing.T) {
	work, document := validCollectorResultFixture()
	encoded, err := EncodeCollectorResult(document)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeCollectorResult(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateCollectorResult(decoded, work, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeCollectorResult(append(encoded, '\n')); err == nil {
		t.Fatal("expected non-canonical JSON to be rejected")
	}
	unknown := bytes.Replace(encoded, []byte(`"schema_version":1`), []byte(`"unknown":true,"schema_version":1`), 1)
	if _, err := DecodeCollectorResult(unknown); err == nil {
		t.Fatal("expected unknown field to be rejected")
	}
}

func TestCollectorResultStatusSemantics(t *testing.T) {
	work, succeeded := validCollectorResultFixture()
	tests := []struct {
		name   string
		mutate func(*CollectorResultDocument)
		valid  bool
	}{
		{name: "succeeded", valid: true},
		{name: "no data", valid: true, mutate: func(document *CollectorResultDocument) {
			document.Result.Status = ResultNoData
			document.Result.Coverage = Coverage{Complete: true}
			document.Result.Observations = nil
		}},
		{name: "partial", valid: true, mutate: func(document *CollectorResultDocument) {
			document.Result.Status = ResultPartial
			document.Result.Coverage.Complete = false
			document.Result.Failures = []CollectionFailure{{Code: FailurePartialData, Message: "partial upstream response"}}
		}},
		{name: "failed", valid: true, mutate: func(document *CollectorResultDocument) {
			document.Result.Status = ResultFailed
			document.Result.Coverage = Coverage{BytesRead: 20}
			document.Result.Observations = nil
			document.Result.Failures = []CollectionFailure{{Code: FailureSourceUnavailable, Message: "source unavailable", Retryable: true}}
		}},
		{name: "no data with observation", mutate: func(document *CollectorResultDocument) {
			document.Result.Status = ResultNoData
		}},
		{name: "mismatched task", mutate: func(document *CollectorResultDocument) {
			document.Result.Task.SourceID = "different"
		}},
		{name: "coverage over limit", mutate: func(document *CollectorResultDocument) {
			document.Result.Coverage.BytesRead = work.Task.MaxBytes + 1
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			document := succeeded
			document.Result.Observations = append([]Observation(nil), succeeded.Result.Observations...)
			if test.mutate != nil {
				test.mutate(&document)
			}
			err := ValidateCollectorResult(document, work, 1)
			if test.valid && err != nil {
				t.Fatalf("expected valid result: %v", err)
			}
			if !test.valid && err == nil {
				t.Fatal("expected invalid result")
			}
		})
	}
}

func validCollectorResultFixture() (CollectorWork, CollectorResultDocument) {
	now := time.Date(2026, time.August, 19, 8, 0, 0, 0, time.UTC)
	task := CollectionTask{
		RunID: "run-result", ClusterID: "cluster-result", SourceID: "source-result",
		Query: QueryGPUUtilization, ScheduledFor: now, Deadline: now.Add(time.Minute),
		MaxSeries: 100, MaxBytes: 1 << 20, IdempotencyKey: "result/one",
	}
	work := CollectorWork{WorkID: "work-result", Task: task, Status: WorkLeased, AvailableAt: now.Add(-time.Minute), WorkExpiresAt: now.Add(time.Hour)}
	completed := now.Add(2 * time.Second)
	result := CollectionResult{
		Task: task, Status: ResultSucceeded, StartedAt: now.Add(time.Second), CompletedAt: completed,
		Coverage: Coverage{SeriesReturned: 1, BytesRead: 20, Complete: true},
		Observations: []Observation{{
			ID: "observation-result", SchemaVersion: 1, ClusterID: task.ClusterID, SourceID: task.SourceID,
			Kind: "gpu_metric", EntityKey: "node/comp001/gpu/0", Metric: "DCGM_FI_DEV_GPU_UTIL",
			Labels: []Label{{Name: "gpu", Value: "0"}}, Value: 42, Unit: "percent",
			ObservedAt: now, CollectedAt: completed, SourceReference: "prometheus:dcgm_gpu_utilization",
		}},
	}
	return work, CollectorResultDocument{SchemaVersion: CollectorResultSchemaVersion, WorkID: work.WorkID, Attempt: 1, Result: result}
}
