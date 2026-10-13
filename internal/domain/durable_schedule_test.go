package domain

import "testing"

func TestGPUProcessDurableExecutionNodeBound(t *testing.T) {
	base := DurableExecution{ScheduleKey: ScheduleKey{ClusterID: "cluster", SourceID: "source", Operation: OperationGPUProcessObservations}, Revision: 1, CollectorID: "collector"}
	for count := 1; count <= 16; count++ {
		candidate := base
		candidate.Nodes = make([]StableNodeID, count)
		for index := range candidate.Nodes {
			candidate.Nodes[index] = StableNodeID("node-" + string(rune('a'+index)))
		}
		if err := candidate.Validate(); err != nil {
			t.Fatalf("node count %d rejected: %v", count, err)
		}
	}
	candidate := base
	candidate.Nodes = make([]StableNodeID, 17)
	for index := range candidate.Nodes {
		candidate.Nodes[index] = StableNodeID("node-" + string(rune('a'+index)))
	}
	if err := candidate.Validate(); err == nil {
		t.Fatal("seventeen-node GPU process execution accepted")
	}
}
