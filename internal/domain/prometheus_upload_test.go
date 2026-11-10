package domain

import (
	"testing"
	"time"
)

func TestPrometheusReportBindsProfileScopeAndTime(t *testing.T) {
	slot := time.Unix(1800000000, 0).UTC()
	task := PrometheusUploadTask("cluster", "source", QueryGPUXID, slot)
	report := PrometheusReport{Version: PrometheusUploadVersion, Result: CollectionResult{
		Task: task, Status: ResultNoData, StartedAt: slot, CompletedAt: slot.Add(time.Second), Coverage: Coverage{Complete: true},
	}}
	now := slot.Add(2 * time.Second)
	if err := report.Validate("cluster", "source", now); err != nil {
		t.Fatal(err)
	}
	if err := report.Validate("cluster", "other-source", now); err == nil {
		t.Fatal("accepted another source")
	}
	if err := report.Validate("cluster", "source", slot.Add(-time.Second)); err == nil {
		t.Fatal("accepted future report")
	}
	if err := report.Validate("cluster", "source", slot.Add(PrometheusUploadRetention+time.Second)); err == nil {
		t.Fatal("accepted expired report")
	}
	outside := report
	outside.Result.Task = PrometheusUploadTask("cluster", "source", QuerySourceHealth, slot)
	if err := outside.Validate("cluster", "source", now); err == nil {
		t.Fatal("accepted query outside profile")
	}
	expected := 1
	report.Result.Coverage.SeriesExpected = &expected
	if err := report.Validate("cluster", "source", now); err == nil {
		t.Fatal("accepted collector-supplied expected coverage")
	}
}
