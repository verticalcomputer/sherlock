package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"
)

type SlurmFieldQuality string

const (
	SlurmFieldPresent     SlurmFieldQuality = "PRESENT"
	SlurmFieldMissing     SlurmFieldQuality = "MISSING"
	SlurmFieldUnsupported SlurmFieldQuality = "UNSUPPORTED"
	SlurmFieldUnset       SlurmFieldQuality = "UNSET"
	SlurmFieldInfinite    SlurmFieldQuality = "INFINITE"
	SlurmFieldMalformed   SlurmFieldQuality = "MALFORMED"
)

func (q SlurmFieldQuality) valid() bool {
	switch q {
	case SlurmFieldPresent, SlurmFieldMissing, SlurmFieldUnsupported, SlurmFieldUnset, SlurmFieldInfinite, SlurmFieldMalformed:
		return true
	default:
		return false
	}
}

func validSlurmObservedTime(value time.Time, quality SlurmFieldQuality) bool {
	if quality == SlurmFieldPresent {
		return !value.IsZero()
	}
	return value.IsZero()
}

func validSlurmState(value string) bool {
	if len(value) < 1 || len(value) > 256 || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if (character < 'A' || character > 'Z') && (character < '0' || character > '9') && character != '_' && character != '+' && character != ',' && character != ' ' {
			return false
		}
	}
	return true
}

type SlurmSchemaSupport string

const (
	SlurmSchemaSupported               SlurmSchemaSupport = "SUPPORTED"
	SlurmSchemaUnsupported             SlurmSchemaSupport = "UNSUPPORTED"
	SlurmSchemaUnknown                 SlurmSchemaSupport = "UNKNOWN"
	SlurmSnapshotDataParserVersion                        = "data_parser/v0.0.40"
	SlurmSnapshotDataParserVersion2302                    = "data_parser/v0.0.39"
	SlurmSnapshotMaxAccountingOverlap                     = 24 * time.Hour
)

type SlurmSourceObservation struct {
	Kind              string             `json:"kind"`
	DataParserVersion string             `json:"data_parser_version,omitempty"`
	SlurmVersion      string             `json:"slurm_version,omitempty"`
	SchemaSupport     SlurmSchemaSupport `json:"schema_support"`
	ReportedErrors    int                `json:"reported_errors"`
	ReportedWarnings  int                `json:"reported_warnings"`
	BytesRead         int                `json:"bytes_read"`
	WindowStart       time.Time          `json:"window_start,omitempty"`
	WindowEnd         time.Time          `json:"window_end,omitempty"`
	SourceAt          time.Time          `json:"source_at"`
}

type SlurmNormalizationIssue struct {
	Code       string            `json:"code"`
	RecordKind string            `json:"record_kind,omitempty"`
	RecordID   string            `json:"record_id,omitempty"`
	Field      string            `json:"field,omitempty"`
	Quality    SlurmFieldQuality `json:"quality,omitempty"`
}

type SlurmAllocationFact struct {
	RecordIdentity string             `json:"record_identity"`
	Snapshot       AllocationSnapshot `json:"snapshot"`
}

type SlurmJobLifecycle struct {
	ClusterID      ClusterID         `json:"cluster_id"`
	SourceID       SourceID          `json:"source_id"`
	RecordIdentity string            `json:"record_identity"`
	Job            JobIdentity       `json:"job"`
	RawState       string            `json:"raw_state"`
	SubmitQuality  SlurmFieldQuality `json:"submit_quality"`
	StartAt        time.Time         `json:"start_at,omitempty"`
	StartQuality   SlurmFieldQuality `json:"start_quality"`
	EndAt          time.Time         `json:"end_at,omitempty"`
	EndQuality     SlurmFieldQuality `json:"end_quality"`
	NodeIDs        []StableNodeID    `json:"node_ids"`
	Origin         string            `json:"origin"`
}

type SlurmAccountingProvenance struct {
	WindowStart time.Time `json:"window_start"`
	WindowEnd   time.Time `json:"window_end"`
	SourceAt    time.Time `json:"source_at"`
	ObservedAt  time.Time `json:"observed_at"`
}

type SlurmUnresolvedAccounting struct {
	ClusterID          ClusterID                   `json:"cluster_id"`
	SourceID           SourceID                    `json:"source_id"`
	RecordIdentity     string                      `json:"record_identity"`
	SchedulerNamespace SchedulerNamespace          `json:"scheduler_namespace"`
	JobID              SchedulerJobID              `json:"job_id"`
	SubmitAt           time.Time                   `json:"submit_at"`
	SubmitQuality      SlurmFieldQuality           `json:"submit_quality"`
	SchedulerCluster   string                      `json:"scheduler_cluster"`
	RawState           string                      `json:"raw_state"`
	StartAt            time.Time                   `json:"start_at,omitempty"`
	StartQuality       SlurmFieldQuality           `json:"start_quality"`
	EndAt              time.Time                   `json:"end_at,omitempty"`
	EndQuality         SlurmFieldQuality           `json:"end_quality"`
	NodeIDs            []StableNodeID              `json:"node_ids"`
	MembershipQuality  SlurmFieldQuality           `json:"membership_quality"`
	MembershipDigest   string                      `json:"membership_digest"`
	AttemptQuality     SlurmFieldQuality           `json:"attempt_quality"`
	Provenance         []SlurmAccountingProvenance `json:"provenance"`
}

type SlurmSnapshotPayload struct {
	Inventory            *InventoryRevision          `json:"inventory,omitempty"`
	Allocations          []SlurmAllocationFact       `json:"allocations"`
	Lifecycles           []SlurmJobLifecycle         `json:"lifecycles"`
	UnresolvedAccounting []SlurmUnresolvedAccounting `json:"unresolved_accounting"`
	Issues               []SlurmNormalizationIssue   `json:"issues"`
	Sources              []SlurmSourceObservation    `json:"sources"`
	InventoryCoverage    SourceCoverage              `json:"inventory_coverage"`
	AllocationCoverage   SourceCoverage              `json:"allocation_coverage"`
	ValidEmptyJobs       bool                        `json:"valid_empty_jobs"`
	ValidEmptyAccounting bool                        `json:"valid_empty_accounting"`
}

func CanonicalSlurmAllocationRecordID(snapshot AllocationSnapshot) string {
	entities := slices.Clone(snapshot.Entities)
	slices.SortFunc(entities, func(a, b EntityIdentity) int { return strings.Compare(a.Key(), b.Key()) })
	parts := []string{string(snapshot.ClusterID), string(snapshot.SourceID), string(snapshot.Job.SchedulerNamespace), string(snapshot.Job.JobID), snapshot.Job.SubmitAt.UTC().Format(time.RFC3339Nano), fmt.Sprint(snapshot.Job.Attempt), string(snapshot.State), snapshot.EffectiveAt.UTC().Format(time.RFC3339Nano)}
	for _, entity := range entities {
		parts = append(parts, entity.Key())
	}
	digest := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return "slurm-allocation-" + hex.EncodeToString(digest[:])
}

func CanonicalSlurmLifecycleRecordID(lifecycle SlurmJobLifecycle) string {
	copy := lifecycle
	copy.RecordIdentity = ""
	copy.NodeIDs = slices.Clone(copy.NodeIDs)
	slices.Sort(copy.NodeIDs)
	encoded, _ := json.Marshal(copy)
	digest := sha256.Sum256(encoded)
	return "slurm-lifecycle-" + hex.EncodeToString(digest[:])
}

func CanonicalSlurmUnresolvedRecordID(record SlurmUnresolvedAccounting) string {
	copy := record
	copy.RecordIdentity = ""
	copy.Provenance = nil
	copy.NodeIDs = slices.Clone(copy.NodeIDs)
	slices.Sort(copy.NodeIDs)
	encoded, _ := json.Marshal(copy)
	digest := sha256.Sum256(encoded)
	return "slurm-accounting-unresolved-" + hex.EncodeToString(digest[:])
}

func ValidateSlurmSnapshotPayload(payload SlurmSnapshotPayload, plan CollectionPlan, envelope SourceCoverage, status ResultStatus, startedAt, completedAt time.Time) (int, error) {
	if plan.Interval == nil {
		return 0, fmt.Errorf("slurm snapshot requires an assigned interval")
	}
	for _, coverage := range []SourceCoverage{payload.InventoryCoverage, payload.AllocationCoverage} {
		if _, err := CreateSourceCoverage(coverage); err != nil || coverage.ClusterID != plan.ClusterID || coverage.SourceID != plan.SourceID {
			return 0, fmt.Errorf("slurm snapshot coverage is invalid")
		}
	}
	if payload.InventoryCoverage.Scope != CoverageInventory || payload.AllocationCoverage.Scope != CoverageAllocations || payload.AllocationCoverage != envelope {
		return 0, fmt.Errorf("slurm snapshot coverage scopes are invalid")
	}
	configuredNodes := len(plan.Scope.Nodes)
	if payload.InventoryCoverage.State == SourceCoverageComplete && (payload.InventoryCoverage.Expected != configuredNodes || payload.InventoryCoverage.Observed != configuredNodes) {
		return 0, fmt.Errorf("complete Slurm inventory coverage does not match plan scope")
	}
	if payload.AllocationCoverage.State == SourceCoverageComplete && (payload.AllocationCoverage.Expected != configuredNodes || payload.AllocationCoverage.Observed != configuredNodes || payload.InventoryCoverage.State != SourceCoverageComplete || payload.Inventory == nil) {
		return 0, fmt.Errorf("complete Slurm allocation coverage requires complete plan inventory proof")
	}
	if status == ResultFailed {
		if payload.Inventory != nil || len(payload.Allocations)+len(payload.Lifecycles)+len(payload.UnresolvedAccounting)+len(payload.Issues)+len(payload.Sources) != 0 {
			return 0, fmt.Errorf("failed Slurm snapshot cannot contain source evidence")
		}
		return 0, nil
	}
	if startedAt.Before(plan.ScheduledFor) || completedAt.After(plan.Deadline) {
		return 0, fmt.Errorf("slurm snapshot execution timestamps exceed the assigned window")
	}
	collectionTime := func(value time.Time) bool {
		return !value.Before(startedAt) && !value.After(completedAt)
	}
	for _, coverage := range []SourceCoverage{payload.InventoryCoverage, payload.AllocationCoverage} {
		if !collectionTime(coverage.SourceAt) || !collectionTime(coverage.EffectiveAt) || !collectionTime(coverage.ObservedAt) {
			return 0, fmt.Errorf("slurm snapshot coverage timestamps exceed the result envelope")
		}
	}
	var accountingWindowStart, accountingWindowEnd time.Time
	for _, source := range payload.Sources {
		if source.Kind == "accounting" {
			accountingWindowStart, accountingWindowEnd = source.WindowStart, source.WindowEnd
			break
		}
	}
	count := len(payload.Allocations) + len(payload.Lifecycles) + len(payload.UnresolvedAccounting) + len(payload.Issues) + len(payload.Sources)
	if payload.Inventory == nil {
		if payload.InventoryCoverage.State == SourceCoverageComplete {
			return 0, fmt.Errorf("complete Slurm inventory requires a revision")
		}
	} else {
		if payload.InventoryCoverage.State != SourceCoverageComplete {
			return 0, fmt.Errorf("incomplete Slurm inventory cannot replace the observed revision")
		}
		if _, err := CreateInventoryRevision(*payload.Inventory); err != nil || payload.Inventory.ClusterID != plan.ClusterID || payload.Inventory.SourceID != plan.SourceID {
			return 0, fmt.Errorf("slurm inventory revision is invalid")
		}
		if !collectionTime(payload.Inventory.SourceAt) || !collectionTime(payload.Inventory.EffectiveAt) || !collectionTime(payload.Inventory.ObservedAt) {
			return 0, fmt.Errorf("slurm inventory timestamps exceed the result envelope")
		}
		count += len(payload.Inventory.Entities)
		if len(payload.Inventory.Entities) != len(plan.Scope.Nodes) {
			return 0, fmt.Errorf("complete Slurm inventory does not match plan scope")
		}
		for _, entity := range payload.Inventory.Entities {
			if entity.Kind != EntityNode || !slices.Contains(plan.Scope.Nodes, entity.NodeID) {
				return 0, fmt.Errorf("slurm inventory entity is outside plan scope")
			}
		}
	}
	seen := map[string]bool{}
	checkNodes := func(nodes []StableNodeID) bool {
		if !slices.IsSorted(nodes) {
			return false
		}
		var previous StableNodeID
		for _, node := range nodes {
			if node == previous || !slices.Contains(plan.Scope.Nodes, node) {
				return false
			}
			previous = node
		}
		return true
	}
	for _, fact := range payload.Allocations {
		if _, err := CreateAllocationSnapshot(fact.Snapshot); err != nil || fact.Snapshot.ClusterID != plan.ClusterID || fact.Snapshot.SourceID != plan.SourceID || fact.RecordIdentity != CanonicalSlurmAllocationRecordID(fact.Snapshot) || seen[fact.RecordIdentity] {
			return 0, fmt.Errorf("slurm allocation fact is invalid")
		}
		if !collectionTime(fact.Snapshot.SourceAt) || !collectionTime(fact.Snapshot.ObservedAt) || fact.Snapshot.EffectiveAt.After(completedAt) || fact.Snapshot.Job.SubmitAt.After(completedAt) {
			return 0, fmt.Errorf("slurm allocation timestamps exceed the result envelope")
		}
		for _, entity := range fact.Snapshot.Entities {
			if entity.Kind != EntityNode || !slices.Contains(plan.Scope.Nodes, entity.NodeID) {
				return 0, fmt.Errorf("slurm allocation fact is outside plan scope")
			}
		}
		seen[fact.RecordIdentity] = true
		count += len(fact.Snapshot.Entities)
	}
	for _, lifecycle := range payload.Lifecycles {
		if _, err := CreateJobIdentity(lifecycle.Job); err != nil {
			return 0, fmt.Errorf("slurm lifecycle job identity is invalid")
		}
		if lifecycle.ClusterID != plan.ClusterID || lifecycle.SourceID != plan.SourceID || len(lifecycle.NodeIDs) == 0 || !validSlurmState(lifecycle.RawState) || lifecycle.SubmitQuality != SlurmFieldPresent || !lifecycle.StartQuality.valid() || !validSlurmObservedTime(lifecycle.StartAt, lifecycle.StartQuality) || !lifecycle.EndQuality.valid() || !validSlurmObservedTime(lifecycle.EndAt, lifecycle.EndQuality) || lifecycle.Job.SubmitAt.After(completedAt) || lifecycle.StartAt.After(completedAt) || lifecycle.EndAt.After(completedAt) || (lifecycle.Origin != "CURRENT" && lifecycle.Origin != "ACCOUNTING") || !checkNodes(lifecycle.NodeIDs) || lifecycle.RecordIdentity != CanonicalSlurmLifecycleRecordID(lifecycle) || seen[lifecycle.RecordIdentity] {
			return 0, fmt.Errorf("slurm lifecycle evidence is invalid")
		}
		seen[lifecycle.RecordIdentity] = true
		count += len(lifecycle.NodeIDs)
	}
	for _, record := range payload.UnresolvedAccounting {
		_, digestErr := hex.DecodeString(record.MembershipDigest)
		if record.ClusterID != plan.ClusterID || record.SourceID != plan.SourceID || !validGoodputIdentifier(string(record.SchedulerNamespace)) || !validControlID(string(record.JobID)) || record.SubmitAt.IsZero() || !validControlID(record.SchedulerCluster) || !validSlurmState(record.RawState) || record.SubmitQuality != SlurmFieldPresent || !record.StartQuality.valid() || !validSlurmObservedTime(record.StartAt, record.StartQuality) || !record.EndQuality.valid() || !validSlurmObservedTime(record.EndAt, record.EndQuality) || record.SubmitAt.After(completedAt) || record.StartAt.After(completedAt) || record.EndAt.After(completedAt) || !record.MembershipQuality.valid() || !record.AttemptQuality.valid() || len(record.MembershipDigest) != 64 || digestErr != nil || !checkNodes(record.NodeIDs) || len(record.Provenance) == 0 || record.RecordIdentity != CanonicalSlurmUnresolvedRecordID(record) || seen[record.RecordIdentity] {
			return 0, fmt.Errorf("unresolved Slurm accounting evidence is invalid")
		}
		seen[record.RecordIdentity] = true
		count += len(record.NodeIDs) + len(record.Provenance)
		for _, provenance := range record.Provenance {
			if !provenance.WindowStart.Equal(accountingWindowStart) || !provenance.WindowEnd.Equal(accountingWindowEnd) || !collectionTime(provenance.SourceAt) || !collectionTime(provenance.ObservedAt) || provenance.ObservedAt.Before(provenance.SourceAt) {
				return 0, fmt.Errorf("slurm accounting provenance is invalid")
			}
		}
	}
	for _, issue := range payload.Issues {
		validRecordID := issue.RecordID == "" || (len(issue.RecordID) == len("record-")+64 && strings.HasPrefix(issue.RecordID, "record-") && func() bool {
			_, err := hex.DecodeString(strings.TrimPrefix(issue.RecordID, "record-"))
			return err == nil
		}())
		if !validControlID(issue.Code) || (issue.RecordKind != "" && !validControlID(issue.RecordKind)) || !validRecordID || (issue.Field != "" && !validControlID(issue.Field)) || (issue.Quality != "" && !issue.Quality.valid()) {
			return 0, fmt.Errorf("slurm snapshot issue is invalid")
		}
	}
	seenSources := map[string]bool{}
	for _, source := range payload.Sources {
		validVersion := func(value string) bool {
			return len(value) <= 128 && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r\n\t")
		}
		if !slices.Contains([]string{"nodes", "partitions", "jobs", "accounting"}, source.Kind) || seenSources[source.Kind] || source.BytesRead < 0 || source.ReportedErrors < 0 || source.ReportedWarnings < 0 || source.SourceAt.IsZero() || !validVersion(source.DataParserVersion) || !validVersion(source.SlurmVersion) || !slices.Contains([]SlurmSchemaSupport{SlurmSchemaSupported, SlurmSchemaUnsupported, SlurmSchemaUnknown}, source.SchemaSupport) || source.SchemaSupport == SlurmSchemaSupported && !slices.Contains([]string{SlurmSnapshotDataParserVersion, SlurmSnapshotDataParserVersion2302}, source.DataParserVersion) {
			return 0, fmt.Errorf("slurm source provenance is invalid")
		}
		if !collectionTime(source.SourceAt) {
			return 0, fmt.Errorf("slurm source timestamp exceeds the result envelope")
		}
		if source.Kind == "accounting" {
			if !source.WindowEnd.Equal(plan.Interval.End) || source.WindowStart.After(plan.Interval.Start) || source.WindowStart.Before(plan.Interval.Start.Add(-SlurmSnapshotMaxAccountingOverlap)) {
				return 0, fmt.Errorf("slurm accounting source window is invalid")
			}
		} else if !source.WindowStart.IsZero() || !source.WindowEnd.IsZero() {
			return 0, fmt.Errorf("non-accounting Slurm source cannot claim an accounting window")
		}
		seenSources[source.Kind] = true
	}
	if len(payload.Sources) != 4 {
		return 0, fmt.Errorf("slurm snapshot requires all source provenance")
	}
	if payload.InventoryCoverage.State == SourceCoverageComplete {
		for _, kind := range []string{"nodes", "partitions"} {
			for _, source := range payload.Sources {
				if source.Kind == kind && (source.SchemaSupport != SlurmSchemaSupported || source.ReportedErrors != 0 || source.ReportedWarnings != 0) {
					return 0, fmt.Errorf("complete Slurm inventory requires clean supported membership sources")
				}
			}
		}
	}
	if payload.AllocationCoverage.State == SourceCoverageComplete {
		if len(payload.Issues) != 0 || len(payload.UnresolvedAccounting) != 0 {
			return 0, fmt.Errorf("complete Slurm coverage conflicts with preserved gaps")
		}
		for _, source := range payload.Sources {
			if source.SchemaSupport != SlurmSchemaSupported || source.ReportedErrors != 0 || source.ReportedWarnings != 0 {
				return 0, fmt.Errorf("complete Slurm coverage requires clean supported sources")
			}
		}
	}
	if count > plan.Limits.MaxRecords {
		return 0, fmt.Errorf("slurm snapshot evidence limit exceeded")
	}
	return count, nil
}
