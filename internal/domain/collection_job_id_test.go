package domain

import (
	"strings"
	"testing"
	"time"
)

func TestCollectionJobIDBoundaries(t *testing.T) {
	for _, id := range []string{"job-1", "m1/head-prometheus/dcgm_gpu_utilization"} {
		if !ValidCollectionJobID(id) || !ValidRemediationTarget(id) {
			t.Fatalf("rejected %q", id)
		}
	}
	for _, id := range []string{"", "/job", "job/", "a//b", "a/../b", "a/./b", "a\\b", "a/b c", "a/%2f/b", "a/\x00b", strings.Repeat("a", 129)} {
		if ValidCollectionJobID(id) {
			t.Fatalf("accepted %q", id)
		}
	}
	id := "m1/head-prometheus/dcgm_gpu_utilization"
	if validDiagnosticToken(id) || validDiagnosticTarget(id) || ValidRemediationToken(id) {
		t.Fatal("generic security token validation widened")
	}
	now := time.Now()
	scope := InvestigationScope{EntityKind: "collection_job", EntityIDs: []string{id}, Start: now, End: now}
	if err := scope.Validate(); err != nil {
		t.Fatal(err)
	}
	scope.EntityKind = "node"
	if scope.Validate() == nil {
		t.Fatal("diagnostic node scope accepted job path")
	}
	action := InvestigationAction{ID: "action-1", ToolID: "cluster.source_freshness.v1", Digest: ChecksumSHA256([]byte("test")), Targets: []string{id}, FanOut: 1, Start: now, End: now}
	if err := action.Validate(); err != nil {
		t.Fatal(err)
	}
	action.ToolID = "gpu.ecc_counters"
	if action.Validate() == nil {
		t.Fatal("diagnostic action accepted job path")
	}
}

func TestNamespacedRepairWorkIDs(t *testing.T) {
	for _, id := range []string{"work-1", "repair-work-attempt-m1/head-prometheus/dcgm_gpu_utilization"} {
		if !ValidCollectorWorkID(id) {
			t.Fatalf("rejected %q", id)
		}
	}
	for _, id := range []string{"unsafe/work", "repair-work-a/../b", "repair-work-a//b", strings.Repeat("x", 257)} {
		if ValidCollectorWorkID(id) {
			t.Fatalf("accepted %q", id)
		}
	}
}
