package domain

import (
	"fmt"
	"time"
)

// DurableExecution is protected operator configuration, bound to one exact
// desired revision. Changing its collector or scope requires a schedule CAS.
// It is not inferred from the reviewed operation registry or a heartbeat.
type DurableExecution struct {
	ScheduleKey
	Revision    int64
	CollectorID CollectorID
	Nodes       []StableNodeID
}

func (g DurableExecution) Validate() error {
	if g.Revision < 1 || !validControlID(string(g.ClusterID)) || !validControlID(string(g.SourceID)) || !validControlID(string(g.CollectorID)) {
		return fmt.Errorf("durable execution requires exact schedule and collector identity")
	}
	op, ok := ReviewedCollectionOperation(g.Operation)
	if !ok || (op.Query == "" && g.Operation != OperationSlurmInventory && g.Operation != OperationSlurmSnapshot && g.Operation != OperationGPUProcessObservations) {
		return fmt.Errorf("durable operation has no installed executor")
	}
	if op.Query != "" {
		if len(g.Nodes) != 0 {
			return fmt.Errorf("v1 Prometheus scope is the configured source")
		}
		return nil
	}
	maxNodes := 1024
	if g.Operation == OperationGPUProcessObservations {
		maxNodes = 16
	}
	if len(g.Nodes) == 0 || len(g.Nodes) > maxNodes {
		return fmt.Errorf("typed collection requires bounded configured nodes")
	}
	seen := map[StableNodeID]bool{}
	for _, node := range g.Nodes {
		if !validControlID(string(node)) || seen[node] {
			return fmt.Errorf("invalid or duplicate configured node")
		}
		seen[node] = true
	}
	return nil
}

type DurableAdmissionPolicy struct{ GlobalLimit, ClusterLimit int }

func (p DurableAdmissionPolicy) Validate() error {
	if p.GlobalLimit < 1 || p.GlobalLimit > 10000 || p.ClusterLimit < 1 || p.ClusterLimit > p.GlobalLimit {
		return fmt.Errorf("invalid durable admission quotas")
	}
	return nil
}

type ScheduleAdmission struct {
	ScheduleKey
	// QuotaRejection identifies one otherwise eligible candidate denied this
	// admission turn. It is an attempt outcome, not a lost interval.
	QuotaRejection                           string
	Revision, Occurrence, CoalescedIntervals int64
	DueAt, NextDueAt                         time.Time
	WorkID                                   WorkID
}

// CollectionDispatchPolicy reserves Floor of each Period successful v1 lease
// grants for ordinary collection when claimable. Idle class turns are borrowed.
// This bounds dispatch opportunities, not execution time or throughput.
type CollectionDispatchPolicy struct{ Floor, Period int }

func (p CollectionDispatchPolicy) Validate() error {
	if p.Floor < 1 || p.Period < 2 || p.Period > 100 || p.Floor >= p.Period {
		return fmt.Errorf("collection dispatch floor must be positive and smaller than period (2..100)")
	}
	return nil
}
