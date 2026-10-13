package domain

import (
	"testing"
	"time"
)

func TestValidateGPUProcessSnapshotAllowsExplicitUnsupportedHostFields(t *testing.T) {
	now := time.Now().UTC()
	plan := CollectionPlan{Scope: CollectionScope{Nodes: []StableNodeID{"node-1"}}, ScheduledFor: now.Add(-time.Second), Deadline: now.Add(time.Second), Limits: CollectionLimits{MaxRecords: 4, MaxBytes: 1024}}
	payload := GPUProcessSnapshotPayload{Nodes: []GPUProcessNodeObservation{{NodeID: "node-1", ObservedAt: now, ComputeVisibility: SourceCoveragePartial, Gaps: []GPUProcessSourceGap{GPUProcessGapUnsupported}, HostStats: []GPUHostStat{{GPUUUID: "GPU-11111111-2222-3333-4444-555555555555"}}}}}
	coverage := SourceCoverage{Expected: 1, Observed: 1}
	if _, err := ValidateGPUProcessSnapshotPayload(payload, plan, coverage); err != nil {
		t.Fatalf("explicit unsupported host fields rejected: %v", err)
	}
}
