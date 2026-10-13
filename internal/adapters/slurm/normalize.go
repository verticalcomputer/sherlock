package slurm

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

const (
	defaultNormalizationRecords = 10_000
	maxNormalizationNodes       = 1_024
	maxAccountingWindows        = 128
)

// NormalizationConfig is local reviewed authority. Command output cannot
// select a cluster, source, scheduler namespace, node identity, or visibility
// guarantee.
type NormalizationConfig struct {
	ClusterID                   domain.ClusterID
	SourceID                    domain.SourceID
	SchedulerNamespace          domain.SchedulerNamespace
	SchedulerCluster            string
	Nodes                       map[domain.StableNodeID]string
	TrustedCurrentJobVisibility bool
	TrustedAccountingVisibility bool
	MaxRecords                  int
}

// AccountingWindow keeps the queried interval separate from lifecycle times
// in each record. Overlapping windows are expected and deduplicated by fact
// identity, never by window position.
type AccountingWindow struct {
	Start    time.Time
	End      time.Time
	SourceAt time.Time
	Result   Result
}

type NormalizationInput struct {
	Nodes      Result
	Partitions Result
	Jobs       Result
	Accounting []AccountingWindow
	SourceAt   time.Time
	ObservedAt time.Time
}

type NormalizationIssue struct {
	Code       string
	RecordKind string
	RecordID   string
	Field      string
	Quality    FieldQuality
}

// JobLifecycle retains Slurm lifecycle evidence that has no field in the
// existing GP-02 AllocationSnapshot contract.
type JobLifecycle struct {
	Job           domain.JobIdentity
	RawState      string
	SubmitQuality FieldQuality
	StartAt       time.Time
	StartQuality  FieldQuality
	EndAt         time.Time
	EndQuality    FieldQuality
	NodeNames     []string
	Origin        string
	// RecordIdentity is stable across overlapping accounting reads. It omits
	// collection/receipt timestamps; GP-05b must bind it to durable dedup rather
	// than relying on AllocationSnapshot storage digests.
	RecordIdentity string
}

// NormalizedObservation contains only existing GP-02 facts plus adapter-local
// support evidence. Issues mean coverage is not complete; individual facts may
// still be valid but cannot establish idle capacity or an all-clear snapshot.
type NormalizedObservation struct {
	Inventory            *domain.InventoryRevision
	Allocations          []domain.AllocationSnapshot
	Coverage             []domain.SourceCoverage
	Lifecycles           []JobLifecycle
	UnresolvedAccounting []UnresolvedAccountingRecord
	Issues               []NormalizationIssue
	ValidEmptyJobs       bool
	ValidEmptyAccounting bool
}

// UnresolvedAccountingRecord preserves a bounded accounting row that cannot
// safely become a GP-02 AllocationSnapshot because the schema did not establish
// the scheduler attempt. No default attempt is invented.
type UnresolvedAccountingRecord struct {
	ClusterID          domain.ClusterID
	SourceID           domain.SourceID
	SchedulerNamespace domain.SchedulerNamespace
	JobID              domain.SchedulerJobID
	SubmitAt           time.Time
	SubmitQuality      FieldQuality
	SchedulerCluster   string
	RawState           string
	RawNodes           string
	StartAt            time.Time
	StartQuality       FieldQuality
	EndAt              time.Time
	EndQuality         FieldQuality
	NodeNames          []string
	AttemptQuality     FieldQuality
	RecordIdentity     string
	Provenance         []AccountingProvenance
}

type AccountingProvenance struct {
	WindowStart time.Time
	WindowEnd   time.Time
	SourceAt    time.Time
	ObservedAt  time.Time
}

type Normalizer struct {
	clusterID          domain.ClusterID
	sourceID           domain.SourceID
	namespace          domain.SchedulerNamespace
	schedulerCluster   string
	stableByName       map[string]domain.StableNodeID
	configuredEntities []domain.EntityIdentity
	trustedJobs        bool
	trustedAccounting  bool
	maxRecords         int
}

func NewNormalizer(cfg NormalizationConfig) (*Normalizer, error) {
	if cfg.ClusterID == "" || cfg.SourceID == "" || cfg.SchedulerNamespace == "" || !identifierPattern.MatchString(cfg.SchedulerCluster) || len(cfg.Nodes) == 0 || len(cfg.Nodes) > maxNormalizationNodes {
		return nil, fmt.Errorf("slurm normalization requires bounded local identities")
	}
	if cfg.MaxRecords == 0 {
		cfg.MaxRecords = defaultNormalizationRecords
	}
	if cfg.MaxRecords < 1 || cfg.MaxRecords > defaultNormalizationRecords {
		return nil, fmt.Errorf("slurm normalization record limit is invalid")
	}
	n := &Normalizer{clusterID: cfg.ClusterID, sourceID: cfg.SourceID, namespace: cfg.SchedulerNamespace, schedulerCluster: cfg.SchedulerCluster, stableByName: make(map[string]domain.StableNodeID, len(cfg.Nodes)), trustedJobs: cfg.TrustedCurrentJobVisibility, trustedAccounting: cfg.TrustedAccountingVisibility, maxRecords: cfg.MaxRecords}
	for stable, name := range cfg.Nodes {
		entity, err := domain.CreateEntityIdentity(domain.EntityIdentity{ClusterID: cfg.ClusterID, Kind: domain.EntityNode, NodeID: stable})
		if err != nil || !identifierPattern.MatchString(name) {
			return nil, fmt.Errorf("slurm normalization node mapping is invalid")
		}
		if _, duplicate := n.stableByName[name]; duplicate {
			return nil, fmt.Errorf("slurm normalization node mapping is ambiguous")
		}
		n.stableByName[name] = stable
		n.configuredEntities = append(n.configuredEntities, entity)
	}
	slices.SortFunc(n.configuredEntities, func(a, b domain.EntityIdentity) int { return strings.Compare(a.Key(), b.Key()) })
	return n, nil
}

func (n *Normalizer) Normalize(input NormalizationInput) (NormalizedObservation, error) {
	if input.SourceAt.IsZero() || input.ObservedAt.IsZero() {
		return NormalizedObservation{}, fmt.Errorf("slurm normalization fact timestamps are required")
	}
	total := len(input.Nodes.Records) + len(input.Partitions.Records) + len(input.Jobs.Records)
	if len(input.Accounting) > maxAccountingWindows {
		return NormalizedObservation{}, fmt.Errorf("slurm accounting window count exceeded")
	}
	for _, window := range input.Accounting {
		if window.Start.IsZero() || window.End.IsZero() || !window.End.After(window.Start) || window.End.Sub(window.Start) > maxWindow || window.SourceAt.IsZero() {
			return NormalizedObservation{}, fmt.Errorf("slurm accounting normalization window is invalid")
		}
		total += len(window.Result.Records)
	}
	if total > n.maxRecords {
		return NormalizedObservation{}, fmt.Errorf("slurm normalization record limit exceeded")
	}

	out := NormalizedObservation{ValidEmptyJobs: resultIsSupportedClean(input.Jobs) && len(input.Jobs.Records) == 0, ValidEmptyAccounting: len(input.Accounting) > 0}
	for _, window := range input.Accounting {
		out.ValidEmptyAccounting = out.ValidEmptyAccounting && resultIsSupportedClean(window.Result) && len(window.Result.Records) == 0
	}

	inventoryComplete := n.normalizeInventory(input, &out)
	allocationStart := len(out.Issues)
	seenFacts := make(map[string]struct{})
	seenTransitions := make(map[string]string)
	seenAttemptGaps := make(map[string]struct{})
	seenUnresolved := make(map[string]int)
	seenLifecycles := make(map[string]struct{})
	n.normalizeJobs(input.Jobs, time.Time{}, time.Time{}, input.SourceAt, input.ObservedAt, false, &out, seenFacts, seenTransitions, seenAttemptGaps, seenUnresolved, seenLifecycles)
	if len(input.Accounting) == 0 {
		out.Issues = append(out.Issues, NormalizationIssue{Code: "ACCOUNTING_SOURCE_MISSING", RecordKind: "accounting_job"})
	}
	for _, window := range input.Accounting {
		n.normalizeJobs(window.Result, window.Start, window.End, window.SourceAt, input.ObservedAt, true, &out, seenFacts, seenTransitions, seenAttemptGaps, seenUnresolved, seenLifecycles)
	}
	allocationComplete := inventoryComplete && n.trustedJobs && n.trustedAccounting && len(out.Issues) == allocationStart
	if !n.trustedJobs {
		out.Issues = append(out.Issues, NormalizationIssue{Code: "CURRENT_JOB_VISIBILITY_NOT_ESTABLISHED", RecordKind: "job"})
	}
	if !n.trustedAccounting {
		out.Issues = append(out.Issues, NormalizationIssue{Code: "ACCOUNTING_VISIBILITY_NOT_ESTABLISHED", RecordKind: "accounting_job"})
	}

	nowSource, nowObserved := input.SourceAt.UTC(), input.ObservedAt.UTC()
	if inventoryComplete {
		out.Coverage = append(out.Coverage, domain.SourceCoverage{SchemaVersion: domain.InventoryContractSchemaVersion, ClusterID: n.clusterID, SourceID: n.sourceID, Scope: domain.CoverageInventory, State: domain.SourceCoverageComplete, Expected: len(n.configuredEntities), Observed: len(n.configuredEntities), SourceAt: nowSource, EffectiveAt: nowSource, ObservedAt: nowObserved})
	} else {
		out.Coverage = append(out.Coverage, unknownCoverage(n.clusterID, n.sourceID, domain.CoverageInventory, nowSource, nowObserved))
	}
	if allocationComplete {
		out.Coverage = append(out.Coverage, domain.SourceCoverage{SchemaVersion: domain.InventoryContractSchemaVersion, ClusterID: n.clusterID, SourceID: n.sourceID, Scope: domain.CoverageAllocations, State: domain.SourceCoverageComplete, Expected: len(n.configuredEntities), Observed: len(n.configuredEntities), SourceAt: nowSource, EffectiveAt: nowSource, ObservedAt: nowObserved})
	} else {
		out.Coverage = append(out.Coverage, unknownCoverage(n.clusterID, n.sourceID, domain.CoverageAllocations, nowSource, nowObserved))
	}
	return out, nil
}

func (n *Normalizer) normalizeInventory(input NormalizationInput, out *NormalizedObservation) bool {
	complete := true
	for _, item := range []struct {
		kind   string
		result Result
	}{{kind: "node", result: input.Nodes}, {kind: "partition", result: input.Partitions}} {
		kind, result := item.kind, item.result
		if !supportedCleanResult(result, kind, out) {
			complete = false
		}
	}
	seenNodes := make(map[string]struct{}, len(input.Nodes.Records))
	for _, record := range input.Nodes.Records {
		if record.Kind != "node" {
			out.Issues = append(out.Issues, NormalizationIssue{Code: "UNEXPECTED_RECORD_KIND", RecordKind: record.Kind, RecordID: record.ID})
			complete = false
			continue
		}
		if _, configured := n.stableByName[record.ID]; !configured {
			out.Issues = append(out.Issues, NormalizationIssue{Code: "UNEXPECTED_NODE", RecordKind: record.Kind, RecordID: record.ID})
			complete = false
			continue
		}
		if _, duplicate := seenNodes[record.ID]; duplicate {
			out.Issues = append(out.Issues, NormalizationIssue{Code: "DUPLICATE_NODE", RecordKind: record.Kind, RecordID: record.ID})
			complete = false
		}
		seenNodes[record.ID] = struct{}{}
	}
	if len(seenNodes) != len(n.stableByName) {
		out.Issues = append(out.Issues, NormalizationIssue{Code: "NODE_MEMBERSHIP_INCOMPLETE", RecordKind: "node"})
		complete = false
	}
	partitionNodes := make(map[string]struct{})
	for _, record := range input.Partitions.Records {
		if record.Kind != "partition" {
			out.Issues = append(out.Issues, NormalizationIssue{Code: "UNEXPECTED_RECORD_KIND", RecordKind: record.Kind, RecordID: record.ID})
			complete = false
			continue
		}
		names, ok := recordNodeNames(record)
		if !ok {
			quality := recordFieldQuality(record, "nodes")
			out.Issues = append(out.Issues, NormalizationIssue{Code: "PARTITION_NODES_INCOMPLETE", RecordKind: record.Kind, RecordID: record.ID, Field: "nodes", Quality: quality})
			complete = false
			continue
		}
		for _, name := range names {
			if _, configured := n.stableByName[name]; !configured {
				out.Issues = append(out.Issues, NormalizationIssue{Code: "FOREIGN_PARTITION_NODE", RecordKind: record.Kind, RecordID: record.ID, Field: "nodes"})
				complete = false
				continue
			}
			partitionNodes[name] = struct{}{}
		}
	}
	if len(partitionNodes) != len(n.stableByName) {
		out.Issues = append(out.Issues, NormalizationIssue{Code: "PARTITION_MEMBERSHIP_INCOMPLETE", RecordKind: "partition"})
		complete = false
	}
	if complete {
		digest := sha256.New()
		_, _ = fmt.Fprintf(digest, "%s\x00%s\x00%s", n.clusterID, n.sourceID, input.SourceAt.UTC().Format(time.RFC3339Nano))
		for _, entity := range n.configuredEntities {
			_, _ = fmt.Fprintf(digest, "\x00%s", entity.Key())
		}
		out.Inventory = &domain.InventoryRevision{SchemaVersion: domain.InventoryContractSchemaVersion, ID: domain.InventoryRevisionID("slurm-" + hex.EncodeToString(digest.Sum(nil))), ClusterID: n.clusterID, SourceID: n.sourceID, SourceAt: input.SourceAt.UTC(), EffectiveAt: input.SourceAt.UTC(), ObservedAt: input.ObservedAt.UTC(), Entities: slices.Clone(n.configuredEntities)}
	}
	return complete
}

func (n *Normalizer) normalizeJobs(result Result, windowStart, windowEnd, sourceAt, observedAt time.Time, accounting bool, out *NormalizedObservation, seenFacts map[string]struct{}, seenTransitions map[string]string, seenAttemptGaps map[string]struct{}, seenUnresolved map[string]int, seenLifecycles map[string]struct{}) {
	kind := "job"
	origin := "CURRENT"
	if accounting {
		kind, origin = "accounting_job", "ACCOUNTING"
	}
	if !supportedCleanResult(result, kind, out) {
		return
	}
	for _, record := range result.Records {
		if record.Kind != kind {
			out.Issues = append(out.Issues, NormalizationIssue{Code: "UNEXPECTED_RECORD_KIND", RecordKind: record.Kind, RecordID: record.ID})
			continue
		}
		cluster := recordAttribute(record, "cluster")
		if accounting {
			if cluster == "" || cluster != n.schedulerCluster {
				out.Issues = append(out.Issues, NormalizationIssue{Code: "ACCOUNTING_CLUSTER_MISMATCH", RecordKind: kind, RecordID: record.ID, Field: "cluster", Quality: recordFieldQuality(record, "cluster")})
				continue
			}
		} else if cluster != "" && cluster != n.schedulerCluster {
			out.Issues = append(out.Issues, NormalizationIssue{Code: "CURRENT_JOB_CLUSTER_MISMATCH", RecordKind: kind, RecordID: record.ID, Field: "cluster", Quality: recordFieldQuality(record, "cluster")})
			continue
		}
		if strings.Contains(record.ID, ".") {
			out.Issues = append(out.Issues, NormalizationIssue{Code: "ACCOUNTING_STEP_EXCLUDED", RecordKind: kind, RecordID: record.ID})
			continue
		}
		submit := recordTimeObservation(record, "submit_time")
		if submit.Quality != FieldPresent {
			out.Issues = append(out.Issues, NormalizationIssue{Code: "JOB_IDENTITY_INCOMPLETE", RecordKind: kind, RecordID: record.ID, Field: "submit_time", Quality: submit.Quality})
			continue
		}
		submitAt := submit.Value
		identityKey := record.ID + "\x00" + submitAt.Format(time.RFC3339Nano)
		attempt := 0
		attemptValue := recordAttribute(record, "restart_cnt")
		if attemptValue == "" && accounting {
			// data_parser/v0.0.40 accounting JOB does not expose restart_cnt.
			// Requeues can retain job ID and submit time, so even an exact current
			// job match cannot safely supply the historical attempt.
			if _, duplicate := seenAttemptGaps[identityKey]; !duplicate {
				seenAttemptGaps[identityKey] = struct{}{}
				out.Issues = append(out.Issues, NormalizationIssue{Code: "JOB_ATTEMPT_UNSUPPORTED", RecordKind: kind, RecordID: record.ID, Field: "restart_cnt", Quality: recordFieldQuality(record, "restart_cnt")})
			}
			n.preserveUnresolvedAccounting(record, submitAt, AccountingProvenance{WindowStart: windowStart.UTC(), WindowEnd: windowEnd.UTC(), SourceAt: sourceAt.UTC(), ObservedAt: observedAt.UTC()}, out, seenUnresolved)
			continue
		} else {
			var err error
			attempt, err = strconv.Atoi(attemptValue)
			if err != nil || attempt < 0 {
				out.Issues = append(out.Issues, NormalizationIssue{Code: "JOB_IDENTITY_INCOMPLETE", RecordKind: kind, RecordID: record.ID, Field: "restart_cnt", Quality: recordFieldQuality(record, "restart_cnt")})
				continue
			}
		}
		job, err := domain.CreateJobIdentity(domain.JobIdentity{SchedulerNamespace: n.namespace, JobID: domain.SchedulerJobID(record.ID), SubmitAt: submitAt, Attempt: attempt})
		if err != nil {
			out.Issues = append(out.Issues, NormalizationIssue{Code: "JOB_IDENTITY_INVALID", RecordKind: kind, RecordID: record.ID})
			continue
		}
		state, lossy, ok := allocationState(record.State)
		if !ok {
			out.Issues = append(out.Issues, NormalizationIssue{Code: "JOB_STATE_UNKNOWN", RecordKind: kind, RecordID: record.ID, Field: "job_state", Quality: recordFieldQuality(record, "job_state")})
			continue
		}
		names, ok := recordNodeNames(record)
		if !ok || len(names) == 0 {
			out.Issues = append(out.Issues, NormalizationIssue{Code: "ALLOCATION_MEMBERSHIP_INCOMPLETE", RecordKind: kind, RecordID: record.ID, Field: "nodes", Quality: recordFieldQuality(record, "nodes")})
			continue
		}
		entities := make([]domain.EntityIdentity, 0, len(names))
		membershipValid := true
		for _, name := range names {
			stable, configured := n.stableByName[name]
			if !configured {
				membershipValid = false
				break
			}
			entities = append(entities, domain.EntityIdentity{ClusterID: n.clusterID, Kind: domain.EntityNode, NodeID: stable})
		}
		if !membershipValid {
			out.Issues = append(out.Issues, NormalizationIssue{Code: "ALLOCATION_FOREIGN_NODE", RecordKind: kind, RecordID: record.ID, Field: "nodes"})
			continue
		}
		slices.SortFunc(entities, func(a, b domain.EntityIdentity) int { return strings.Compare(a.Key(), b.Key()) })
		start, end, lifecycleIssues, lifecycleFatal := validateLifecycle(record, state, submitAt)
		out.Issues = append(out.Issues, lifecycleIssues...)
		lifecycleAt := sourceAt.UTC()
		if accounting && end.Quality == FieldPresent {
			lifecycleAt = end.Value
		}
		lifecycleKey := allocationLifecycleKey(job, record.State, lifecycleAt, names, start, end, origin)
		if _, duplicate := seenLifecycles[lifecycleKey]; !duplicate {
			seenLifecycles[lifecycleKey] = struct{}{}
			identityDigest := sha256.Sum256([]byte(lifecycleKey))
			out.Lifecycles = append(out.Lifecycles, JobLifecycle{Job: job, RawState: record.State, SubmitQuality: submit.Quality, StartAt: start.Value, StartQuality: start.Quality, EndAt: end.Value, EndQuality: end.Quality, NodeNames: slices.Clone(names), Origin: origin, RecordIdentity: "slurm-allocation-" + hex.EncodeToString(identityDigest[:])})
		}
		if lossy {
			out.Issues = append(out.Issues, NormalizationIssue{Code: "LOSSY_STATE_PROJECTION", RecordKind: kind, RecordID: record.ID, Field: "job_state", Quality: FieldPresent})
		}
		if lifecycleFatal {
			continue
		}
		effectiveAt := sourceAt.UTC()
		if accounting {
			var effectiveOK bool
			effectiveAt, effectiveOK = accountingEffectiveAt(state, end)
			if !effectiveOK {
				out.Issues = append(out.Issues, NormalizationIssue{Code: "ACCOUNTING_EFFECTIVE_TIME_MISSING", RecordKind: kind, RecordID: record.ID})
				continue
			}
		}
		snapshot, err := domain.CreateAllocationSnapshot(domain.AllocationSnapshot{SchemaVersion: domain.InventoryContractSchemaVersion, ClusterID: n.clusterID, SourceID: n.sourceID, Job: job, State: state, SourceAt: sourceAt.UTC(), EffectiveAt: effectiveAt, ObservedAt: observedAt.UTC(), Entities: entities})
		if err != nil {
			out.Issues = append(out.Issues, NormalizationIssue{Code: "ALLOCATION_CONTRACT_INVALID", RecordKind: kind, RecordID: record.ID})
			continue
		}
		factKey := allocationFactKey(snapshot)
		transitionKey := fmt.Sprintf("%s\x00%s\x00%s\x00%d\x00%s", job.SchedulerNamespace, job.JobID, job.SubmitAt.Format(time.RFC3339Nano), job.Attempt, effectiveAt.Format(time.RFC3339Nano))
		if previous, exists := seenTransitions[transitionKey]; exists && previous != factKey {
			out.Issues = append(out.Issues, NormalizationIssue{Code: "ACCOUNTING_TRANSITION_CONFLICT", RecordKind: kind, RecordID: record.ID})
			continue
		}
		seenTransitions[transitionKey] = factKey
		if _, duplicate := seenFacts[factKey]; duplicate {
			continue
		}
		seenFacts[factKey] = struct{}{}
		out.Allocations = append(out.Allocations, snapshot)
	}
}

func allocationState(raw string) (domain.AllocationState, bool, bool) {
	tokens := strings.FieldsFunc(strings.ToUpper(raw), func(r rune) bool { return r == '+' || r == ',' || r == ' ' })
	contains := func(value string) bool { return slices.Contains(tokens, value) }
	if contains("COMPLETING") {
		return domain.AllocationCompleting, contains("RUNNING") || len(tokens) > 1, true
	}
	if contains("SUSPENDED") {
		return domain.AllocationSuspended, len(tokens) > 1, true
	}
	if contains("CONFIGURING") {
		return domain.AllocationRunning, true, true
	}
	for _, token := range tokens {
		switch token {
		case "PENDING":
			return domain.AllocationPending, len(tokens) > 1, true
		case "RUNNING":
			return domain.AllocationRunning, len(tokens) > 1, true
		case "COMPLETED":
			return domain.AllocationCompleted, len(tokens) > 1, true
		case "CANCELLED", "PREEMPTED":
			return domain.AllocationCancelled, len(tokens) > 1, true
		case "FAILED", "TIMEOUT", "NODE_FAIL", "OUT_OF_MEMORY", "BOOT_FAIL", "DEADLINE":
			return domain.AllocationFailed, len(tokens) > 1, true
		}
	}
	return "", false, false
}

type timeObservation struct {
	Value   time.Time
	Quality FieldQuality
}

func accountingEffectiveAt(state domain.AllocationState, end timeObservation) (time.Time, bool) {
	switch state {
	case domain.AllocationCompleted, domain.AllocationCancelled, domain.AllocationFailed, domain.AllocationCompleting:
		return end.Value, end.Quality == FieldPresent
	default:
		return time.Time{}, false
	}
}

func validateLifecycle(record Record, state domain.AllocationState, submitAt time.Time) (timeObservation, timeObservation, []NormalizationIssue, bool) {
	start := recordTimeObservation(record, "start_time")
	end := recordTimeObservation(record, "end_time")
	issues := make([]NormalizationIssue, 0, 2)
	fatal := false
	check := func(name string, observation timeObservation, unsetAllowed bool) {
		switch observation.Quality {
		case FieldPresent:
		case FieldUnset:
			if !unsetAllowed {
				issues = append(issues, NormalizationIssue{Code: "LIFECYCLE_TIME_INCOMPLETE", RecordKind: record.Kind, RecordID: record.ID, Field: name, Quality: observation.Quality})
			}
		case FieldMissing, FieldUnsupported:
			issues = append(issues, NormalizationIssue{Code: "LIFECYCLE_TIME_INCOMPLETE", RecordKind: record.Kind, RecordID: record.ID, Field: name, Quality: observation.Quality})
		case FieldMalformed, FieldInfinite:
			issues = append(issues, NormalizationIssue{Code: "LIFECYCLE_TIME_INVALID", RecordKind: record.Kind, RecordID: record.ID, Field: name, Quality: observation.Quality})
			fatal = true
		}
	}
	startUnsetAllowed := state == domain.AllocationPending
	endUnsetAllowed := state == domain.AllocationPending || state == domain.AllocationRunning || state == domain.AllocationSuspended
	check("start_time", start, startUnsetAllowed)
	check("end_time", end, endUnsetAllowed)
	if start.Quality == FieldPresent && start.Value.Before(submitAt) {
		issues = append(issues, NormalizationIssue{Code: "LIFECYCLE_TIME_ORDER_INVALID", RecordKind: record.Kind, RecordID: record.ID, Field: "start_time", Quality: FieldMalformed})
		fatal = true
	}
	if start.Quality == FieldPresent && end.Quality == FieldPresent && end.Value.Before(start.Value) {
		issues = append(issues, NormalizationIssue{Code: "LIFECYCLE_TIME_ORDER_INVALID", RecordKind: record.Kind, RecordID: record.ID, Field: "end_time", Quality: FieldMalformed})
		fatal = true
	}
	return start, end, issues, fatal
}

func (n *Normalizer) preserveUnresolvedAccounting(record Record, submitAt time.Time, provenance AccountingProvenance, out *NormalizedObservation, seen map[string]int) {
	start := recordTimeObservation(record, "start_time")
	end := recordTimeObservation(record, "end_time")
	names, _ := recordNodeNames(record)
	rawNodes := recordAttribute(record, "nodes", "node_list", "nodes_alloc")
	rawIdentity := strings.Join([]string{string(n.clusterID), string(n.sourceID), string(n.namespace), n.schedulerCluster, record.ID, submitAt.Format(time.RFC3339Nano), start.Value.Format(time.RFC3339Nano), end.Value.Format(time.RFC3339Nano), string(start.Quality), string(end.Quality), record.State, rawNodes}, "\x00")
	digest := sha256.Sum256([]byte(rawIdentity))
	identity := "slurm-accounting-unresolved-" + hex.EncodeToString(digest[:])
	if index, duplicate := seen[identity]; duplicate {
		appendAccountingProvenance(&out.UnresolvedAccounting[index], provenance)
		return
	}
	state, _, stateKnown := allocationState(record.State)
	if !stateKnown {
		state = domain.AllocationUnknown
	}
	_, _, lifecycleIssues, _ := validateLifecycle(record, state, submitAt)
	out.Issues = append(out.Issues, lifecycleIssues...)
	recordEvidence := UnresolvedAccountingRecord{ClusterID: n.clusterID, SourceID: n.sourceID, SchedulerNamespace: n.namespace, JobID: domain.SchedulerJobID(record.ID), SubmitAt: submitAt, SubmitQuality: recordFieldQuality(record, "submit_time"), SchedulerCluster: n.schedulerCluster, RawState: record.State, RawNodes: rawNodes, StartAt: start.Value, StartQuality: start.Quality, EndAt: end.Value, EndQuality: end.Quality, NodeNames: slices.Clone(names), AttemptQuality: recordFieldQuality(record, "restart_cnt"), RecordIdentity: identity}
	appendAccountingProvenance(&recordEvidence, provenance)
	seen[identity] = len(out.UnresolvedAccounting)
	out.UnresolvedAccounting = append(out.UnresolvedAccounting, recordEvidence)
}

func appendAccountingProvenance(record *UnresolvedAccountingRecord, provenance AccountingProvenance) {
	if slices.Contains(record.Provenance, provenance) {
		return
	}
	record.Provenance = append(record.Provenance, provenance)
	slices.SortFunc(record.Provenance, func(a, b AccountingProvenance) int {
		for _, comparison := range []int{a.SourceAt.Compare(b.SourceAt), a.ObservedAt.Compare(b.ObservedAt), a.WindowStart.Compare(b.WindowStart), a.WindowEnd.Compare(b.WindowEnd)} {
			if comparison != 0 {
				return comparison
			}
		}
		return 0
	})
}

func recordNodeNames(record Record) ([]string, bool) {
	raw := recordAttribute(record, "nodes", "nodes/configured", "node_list", "nodes_alloc")
	if raw == "" {
		return nil, false
	}
	return expandHostlist(raw, maxNormalizationNodes)
}

// expandHostlist supports the single numeric bracket form emitted by the
// reviewed 23.02 sources. Unsupported syntax and duplicates fail closed.
func expandHostlist(raw string, maximum int) ([]string, bool) {
	var result []string
	seen := make(map[string]bool)
	add := func(name string) bool {
		if !identifierPattern.MatchString(name) || seen[name] || len(result) >= maximum {
			return false
		}
		seen[name] = true
		result = append(result, name)
		return true
	}
	for raw != "" {
		depth, cut := 0, len(raw)
		for i, r := range raw {
			switch r {
			case '[':
				depth++
			case ']':
				depth--
			}
			if depth < 0 || depth > 1 {
				return nil, false
			}
			if r == ',' && depth == 0 {
				cut = i
				break
			}
		}
		if depth != 0 {
			return nil, false
		}
		token := raw[:cut]
		if cut == len(raw) {
			raw = ""
		} else {
			raw = raw[cut+1:]
			if raw == "" {
				return nil, false
			}
		}
		open := strings.IndexByte(token, '[')
		if open < 0 {
			if !add(token) {
				return nil, false
			}
			continue
		}
		close := strings.IndexByte(token, ']')
		if close <= open+1 || close != len(token)-1 || strings.ContainsAny(token[:open], "[]") || !identifierPattern.MatchString(token[:open]) {
			return nil, false
		}
		prefix := token[:open]
		for _, part := range strings.Split(token[open+1:close], ",") {
			lo, hi, ranged := strings.Cut(part, "-")
			if lo == "" || strings.Trim(lo, "0123456789") != "" {
				return nil, false
			}
			if !ranged {
				if !add(prefix + lo) {
					return nil, false
				}
				continue
			}
			if hi == "" || strings.Trim(hi, "0123456789") != "" || len(lo) != len(hi) {
				return nil, false
			}
			start, e1 := strconv.Atoi(lo)
			end, e2 := strconv.Atoi(hi)
			if e1 != nil || e2 != nil || end < start || end-start >= maximum-len(result) {
				return nil, false
			}
			for n := start; n <= end; n++ {
				if !add(fmt.Sprintf("%s%0*d", prefix, len(lo), n)) {
					return nil, false
				}
			}
		}
	}
	return result, len(result) > 0
}

func recordAttribute(record Record, names ...string) string {
	for _, name := range names {
		for _, attribute := range record.Attributes {
			if attribute.Name == name {
				return attribute.Value
			}
		}
	}
	return ""
}

func recordFieldQuality(record Record, name string) FieldQuality {
	for _, field := range record.Fields {
		if field.Name == name {
			return field.Quality
		}
	}
	return FieldMissing
}

func recordTimeObservation(record Record, name string) timeObservation {
	quality := recordFieldQuality(record, name)
	if quality != FieldPresent {
		return timeObservation{Quality: quality}
	}
	aliases := []string{name}
	switch name {
	case "submit_time":
		aliases = append(aliases, "time/submission")
	case "start_time":
		aliases = append(aliases, "time/start")
	case "end_time":
		aliases = append(aliases, "time/end")
	}
	value := recordAttribute(record, aliases...)
	if value == "" {
		return timeObservation{Quality: FieldMalformed}
	}
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil && seconds > 0 {
		return timeObservation{Value: time.Unix(seconds, 0).UTC(), Quality: FieldPresent}
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || parsed.IsZero() {
		return timeObservation{Quality: FieldMalformed}
	}
	return timeObservation{Value: parsed.UTC(), Quality: FieldPresent}
}

func allocationLifecycleKey(job domain.JobIdentity, rawState string, effectiveAt time.Time, nodeNames []string, start, end timeObservation, origin string) string {
	parts := []string{string(job.SchedulerNamespace), string(job.JobID), job.SubmitAt.Format(time.RFC3339Nano), strconv.Itoa(job.Attempt), rawState, effectiveAt.Format(time.RFC3339Nano), string(start.Quality), start.Value.Format(time.RFC3339Nano), string(end.Quality), end.Value.Format(time.RFC3339Nano), origin}
	parts = append(parts, nodeNames...)
	return strings.Join(parts, "\x00")
}

func allocationFactKey(snapshot domain.AllocationSnapshot) string {
	parts := []string{string(snapshot.ClusterID), string(snapshot.SourceID), string(snapshot.Job.SchedulerNamespace), string(snapshot.Job.JobID), snapshot.Job.SubmitAt.Format(time.RFC3339Nano), strconv.Itoa(snapshot.Job.Attempt), string(snapshot.State), snapshot.EffectiveAt.Format(time.RFC3339Nano)}
	for _, entity := range snapshot.Entities {
		parts = append(parts, entity.Key())
	}
	return strings.Join(parts, "\x00")
}

func unknownCoverage(clusterID domain.ClusterID, sourceID domain.SourceID, scope domain.CoverageScope, sourceAt, observedAt time.Time) domain.SourceCoverage {
	return domain.SourceCoverage{SchemaVersion: domain.InventoryContractSchemaVersion, ClusterID: clusterID, SourceID: sourceID, Scope: scope, State: domain.SourceCoverageUnknown, SourceAt: sourceAt, EffectiveAt: sourceAt, ObservedAt: observedAt}
}

func supportedCleanResult(result Result, kind string, out *NormalizedObservation) bool {
	complete := true
	if result.SchemaSupport != SchemaSupportSupported {
		out.Issues = append(out.Issues, NormalizationIssue{Code: "SCHEMA_NOT_SUPPORTED", RecordKind: kind})
		complete = false
	}
	if result.ReportedErrors > 0 {
		out.Issues = append(out.Issues, NormalizationIssue{Code: "SOURCE_REPORTED_ERROR", RecordKind: kind})
		complete = false
	}
	if result.ReportedWarnings > 0 {
		out.Issues = append(out.Issues, NormalizationIssue{Code: "SOURCE_REPORTED_WARNING", RecordKind: kind})
		complete = false
	}
	return complete
}

func resultIsSupportedClean(result Result) bool {
	return result.SchemaSupport == SchemaSupportSupported && result.ReportedErrors == 0 && result.ReportedWarnings == 0
}
