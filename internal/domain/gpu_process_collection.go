package domain

import (
	"fmt"
	"slices"
	"time"
)

const GPUProcessCollectionSchema CollectionPayloadSchema = "sherlock.collection.gpu_process_observations.v1"

// GPU process observations carry a process row and a host-stat row in one
// bounded result. Keep the record budget below the general typed-collection
// ceiling and reserve enough encoded-byte budget for every permitted record.
// The byte estimate is deliberately conservative and is enforced at both the
// desired-schedule and typed-plan boundaries.
const (
	GPUProcessMaxRecords           = 4096
	GPUProcessBaseBytes      int64 = 64 << 10
	GPUProcessBytesPerRecord int64 = 256
)

func validateGPUProcessLimits(maxRecords int, maxBytes int64) error {
	if maxRecords < 1 || maxRecords > GPUProcessMaxRecords || maxBytes < GPUProcessBaseBytes+GPUProcessBytesPerRecord*int64(maxRecords) {
		return fmt.Errorf("GPU process output budget is too small for its record limit")
	}
	return nil
}

// GPUProcessSnapshotPayload retains bounded GPU/process facts only. Scheduler
// and job attribution are deliberately absent: this pilot has no Slurm and a
// process row never supplies a trusted task-membership receipt.
type GPUProcessSnapshotPayload struct {
	Nodes []GPUProcessNodeObservation `json:"nodes"`
}

type GPUProcessNodeObservation struct {
	NodeID            StableNodeID          `json:"node_id"`
	ObservedAt        time.Time             `json:"observed_at"`
	ComputeVisibility SourceCoverageState   `json:"compute_visibility"`
	Processes         []GPUProcessFact      `json:"processes"`
	HostStats         []GPUHostStat         `json:"host_stats"`
	Gaps              []GPUProcessSourceGap `json:"gaps"`
}

// GPUProcessFact has no process name, argv, environment, hostname, or job.
// Start identity is optional and remains unknown when the fixed remote query
// cannot collect trusted pre/post proc evidence.
type GPUProcessFact struct {
	GPUUUID    PhysicalGPUUUID `json:"gpu_uuid"`
	PID        uint32          `json:"pid"`
	StartKnown bool            `json:"start_known"`
}

// GPUHostStat is the narrow reviewed companion query. Nil values mean the
// exact driver field was unavailable or unsupported; zero is a real value.
type GPUHostStat struct {
	GPUUUID      PhysicalGPUUUID `json:"gpu_uuid"`
	TemperatureC *float64        `json:"temperature_c,omitempty"`
	PowerWatts   *float64        `json:"power_watts,omitempty"`
	MemoryMiB    *float64        `json:"memory_mib,omitempty"`
}

type GPUProcessSourceGap string

const (
	GPUProcessGapAuthUnavailable  GPUProcessSourceGap = "AUTH_UNAVAILABLE"
	GPUProcessGapPrivilegeDenied  GPUProcessSourceGap = "PRIVILEGE_DENIED"
	GPUProcessGapTimeout          GPUProcessSourceGap = "TIMEOUT"
	GPUProcessGapOutputLimit      GPUProcessSourceGap = "OUTPUT_LIMIT"
	GPUProcessGapUnsupported      GPUProcessSourceGap = "UNSUPPORTED"
	GPUProcessGapMalformed        GPUProcessSourceGap = "MALFORMED"
	GPUProcessGapInventoryStale   GPUProcessSourceGap = "INVENTORY_STALE"
	GPUProcessGapInventoryMissing GPUProcessSourceGap = "INVENTORY_MISSING"
	GPUProcessGapStartUnknown     GPUProcessSourceGap = "START_UNKNOWN"
)

func ValidateGPUProcessSnapshotPayload(payload GPUProcessSnapshotPayload, plan CollectionPlan, coverage SourceCoverage) (int, error) {
	if len(payload.Nodes) == 0 || len(payload.Nodes) > plan.Limits.MaxRecords {
		return 0, fmt.Errorf("GPU process payload node count is invalid")
	}
	seenNodes := map[StableNodeID]bool{}
	records := 0
	for _, node := range payload.Nodes {
		if !slices.Contains(plan.Scope.Nodes, node.NodeID) || seenNodes[node.NodeID] || node.ObservedAt.IsZero() || node.ObservedAt.Before(plan.ScheduledFor) || node.ObservedAt.After(plan.Deadline) {
			return 0, fmt.Errorf("GPU process payload node scope or time is invalid")
		}
		seenNodes[node.NodeID] = true
		if node.ComputeVisibility != SourceCoverageComplete && node.ComputeVisibility != SourceCoveragePartial && node.ComputeVisibility != SourceCoverageUnavailable && node.ComputeVisibility != SourceCoverageUnknown && node.ComputeVisibility != SourceCoverageUnsupported {
			return 0, fmt.Errorf("GPU process visibility is invalid")
		}
		if len(node.Processes)+len(node.HostStats) > plan.Limits.MaxRecords {
			return 0, fmt.Errorf("GPU process payload record bound is invalid")
		}
		processes := map[string]bool{}
		for _, process := range node.Processes {
			key := string(process.GPUUUID) + "/" + fmt.Sprint(process.PID)
			if process.PID == 0 || process.GPUUUID == "" || processes[key] {
				return 0, fmt.Errorf("GPU process identity is invalid")
			}
			processes[key] = true
		}
		stats := map[PhysicalGPUUUID]bool{}
		unsupported := slices.Contains(node.Gaps, GPUProcessGapUnsupported)
		for _, stat := range node.HostStats {
			if stat.GPUUUID == "" || stats[stat.GPUUUID] || (stat.TemperatureC == nil && stat.PowerWatts == nil && stat.MemoryMiB == nil && !unsupported) {
				return 0, fmt.Errorf("GPU host stat is invalid")
			}
			stats[stat.GPUUUID] = true
		}
		if !validGPUProcessGaps(node.Gaps) {
			return 0, fmt.Errorf("GPU process gaps are invalid")
		}
		records += len(node.Processes) + len(node.HostStats)
	}
	if coverage.Expected != 0 && (coverage.Expected != len(plan.Scope.Nodes) || coverage.Observed != len(payload.Nodes)) {
		return 0, fmt.Errorf("GPU process payload coverage is inconsistent")
	}
	return records, nil
}

func validGPUProcessGaps(gaps []GPUProcessSourceGap) bool {
	if len(gaps) > 16 {
		return false
	}
	seen := map[GPUProcessSourceGap]bool{}
	for _, gap := range gaps {
		switch gap {
		case GPUProcessGapAuthUnavailable, GPUProcessGapPrivilegeDenied, GPUProcessGapTimeout, GPUProcessGapOutputLimit, GPUProcessGapUnsupported, GPUProcessGapMalformed, GPUProcessGapInventoryStale, GPUProcessGapInventoryMissing, GPUProcessGapStartUnknown:
		default:
			return false
		}
		if seen[gap] {
			return false
		}
		seen[gap] = true
	}
	return true
}
