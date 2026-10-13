// Package slurm bridges bounded local Slurm inventory and snapshot sources to
// typed collection. Only operations wired by local configuration are exposed.
package slurm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	adapter "github.com/verticalcomputer/sherlock/internal/adapters/slurm"
	"github.com/verticalcomputer/sherlock/internal/adapters/source"
	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

type Nodes interface {
	Nodes(context.Context, []string) (adapter.Result, error)
}

type SnapshotSource interface {
	Nodes(context.Context, []string) (adapter.Result, error)
	Partitions(context.Context, []string) (adapter.Result, error)
	Jobs(context.Context, []string) (adapter.Result, error)
	AccountingAllocations(context.Context, time.Time, time.Time, string, []string) (adapter.Result, error)
}

type SnapshotConfig struct {
	ClusterID                   domain.ClusterID
	SourceID                    domain.SourceID
	SchedulerNamespace          domain.SchedulerNamespace
	SchedulerCluster            string
	Nodes                       map[domain.StableNodeID]string
	TrustedCurrentJobVisibility bool
	TrustedAccountingVisibility bool
	AccountingOverlap           time.Duration
}

type Executor struct {
	client           Nodes
	snapshot         SnapshotSource
	normalizer       *adapter.Normalizer
	clock            application.Clock
	nodes            map[domain.StableNodeID]string
	stableByName     map[string]domain.StableNodeID
	schedulerCluster string
	overlap          time.Duration
	clusterID        domain.ClusterID
	sourceID         domain.SourceID
}

var nodeName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
var issueToken = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

func New(client Nodes, clock application.Clock, nodes map[domain.StableNodeID]string) (*Executor, error) {
	if client == nil || clock == nil || len(nodes) == 0 || len(nodes) > 1024 {
		return nil, fmt.Errorf("slurm inventory requires a client, clock and bounded local node mapping")
	}
	e := &Executor{client: client, clock: clock, nodes: make(map[domain.StableNodeID]string, len(nodes)), stableByName: make(map[string]domain.StableNodeID, len(nodes))}
	seen := map[string]bool{}
	for stable, name := range nodes {
		if !nodeName.MatchString(string(stable)) || !nodeName.MatchString(name) || seen[name] {
			return nil, fmt.Errorf("slurm node mapping is invalid or ambiguous")
		}
		e.nodes[stable], e.stableByName[name], seen[name] = name, stable, true
	}
	return e, nil
}

func NewSnapshot(client SnapshotSource, clock application.Clock, cfg SnapshotConfig) (*Executor, error) {
	if client == nil || cfg.AccountingOverlap <= 0 || cfg.AccountingOverlap > domain.SlurmSnapshotMaxAccountingOverlap {
		return nil, fmt.Errorf("slurm snapshot requires a source and bounded accounting overlap")
	}
	e, err := New(client, clock, cfg.Nodes)
	if err != nil {
		return nil, err
	}
	normalizer, err := adapter.NewNormalizer(adapter.NormalizationConfig{ClusterID: cfg.ClusterID, SourceID: cfg.SourceID,
		SchedulerNamespace: cfg.SchedulerNamespace, SchedulerCluster: cfg.SchedulerCluster, Nodes: cfg.Nodes,
		TrustedCurrentJobVisibility: cfg.TrustedCurrentJobVisibility, TrustedAccountingVisibility: cfg.TrustedAccountingVisibility})
	if err != nil {
		return nil, err
	}
	e.snapshot, e.normalizer, e.schedulerCluster, e.overlap, e.clusterID, e.sourceID = client, normalizer, cfg.SchedulerCluster, cfg.AccountingOverlap, cfg.ClusterID, cfg.SourceID
	return e, nil
}

func (e *Executor) ExecuteTyped(ctx context.Context, lease domain.TypedWorkLease) domain.TypedCollectorResult {
	if lease.Plan.Operation == domain.OperationSlurmSnapshot {
		return e.executeSnapshot(ctx, lease)
	}
	started := e.clock.Now().UTC()
	fail := func(code domain.FailureCode, message string) domain.TypedCollectorResult {
		return application.FailedTypedCollection(lease, e.clock.Now(), code, message)
	}
	p := lease.Plan
	if err := domain.ValidateTypedWorkLease(lease); err != nil || p.Operation != domain.OperationSlurmInventory || p.Cursor != "" || len(p.Scope.Nodes) > p.Limits.MaxRecords {
		return fail(domain.FailureInvalidArgument, "Slurm inventory requires a bounded interval and supported node scope")
	}
	// Inventory revisions replace a source's current snapshot. A subset must
	// not remove the other locally mapped nodes from that projection.
	if len(p.Scope.Nodes) != len(e.nodes) {
		return fail(domain.FailureInvalidArgument, "Slurm inventory requires the complete locally configured node scope")
	}
	if !p.Deadline.After(started) {
		return fail(domain.FailureDeadlineExceeded, "Slurm inventory deadline expired")
	}
	names := make([]string, 0, len(p.Scope.Nodes))
	requested := make(map[string]domain.StableNodeID, len(p.Scope.Nodes))
	for _, stable := range p.Scope.Nodes {
		name, exists := e.nodes[stable]
		if !exists {
			return fail(domain.FailureInvalidArgument, "Slurm node scope is not locally configured")
		}
		names = append(names, name)
		requested[name] = stable
	}
	bounded, cancel := context.WithDeadline(ctx, p.Deadline)
	defer cancel()
	result, err := e.client.Nodes(bounded, names)
	if err != nil {
		code := domain.FailureInternal
		var classified *source.Error
		if errors.As(err, &classified) {
			code = classified.Code
		}
		return fail(code, "Slurm inventory collection failed")
	}
	if result.BytesRead < 0 || int64(result.BytesRead) > p.Limits.MaxBytes || len(result.Records) > p.Limits.MaxRecords {
		return fail(domain.FailureResultLimit, "Slurm inventory exceeds assigned limits")
	}
	if result.ReportedErrors > 0 || result.ReportedWarnings > 0 {
		return fail(domain.FailurePartialData, "Slurm inventory reported incomplete source output")
	}
	seen := make(map[string]bool, len(result.Records))
	for _, record := range result.Records {
		if _, ok := requested[record.ID]; !ok || record.Kind != "node" || seen[record.ID] {
			return fail(domain.FailureMalformedResponse, "Slurm inventory contains an unexpected or duplicate node")
		}
		seen[record.ID] = true
	}
	// A partial node snapshot cannot safely replace the current source inventory.
	if len(seen) != len(requested) {
		return fail(domain.FailurePartialData, "Slurm inventory is missing requested nodes")
	}
	entities := make([]domain.EntityIdentity, 0, len(p.Scope.Nodes))
	for _, stable := range p.Scope.Nodes {
		entities = append(entities, domain.EntityIdentity{ClusterID: p.ClusterID, Kind: domain.EntityNode, NodeID: stable})
	}
	completed := e.clock.Now().UTC()
	digest := sha256.Sum256([]byte(string(p.ClusterID) + "\x00" + string(p.SourceID) + "\x00" + string(p.RunID)))
	revision := domain.InventoryRevision{SchemaVersion: domain.InventoryContractSchemaVersion, ID: domain.InventoryRevisionID("slurm-" + hex.EncodeToString(digest[:])),
		ClusterID: p.ClusterID, SourceID: p.SourceID, SourceAt: completed, EffectiveAt: completed, ObservedAt: completed, Entities: entities}
	// This is a current CLI snapshot, so collection time is the fact time. Slurm
	// last_busy/start_time values are not inventory observation timestamps.
	return domain.TypedCollectorResult{SchemaVersion: domain.CollectionProtocolVersion, WorkID: lease.Lease.Work.WorkID, Attempt: lease.Lease.Attempt, Plan: p,
		Status: domain.ResultSucceeded, StartedAt: started, CompletedAt: completed,
		Coverage: domain.SourceCoverage{SchemaVersion: 1, ClusterID: p.ClusterID, SourceID: p.SourceID, Scope: domain.CoverageInventory, State: domain.SourceCoverageComplete,
			Expected: len(entities), Observed: len(entities), SourceAt: completed, EffectiveAt: completed, ObservedAt: completed},
		Payload: domain.CollectionPayload{Kind: domain.CollectionPayloadInventory, Inventory: &domain.CollectionInventoryPayload{Revisions: []domain.InventoryRevision{revision}}}}
}

func (e *Executor) executeSnapshot(ctx context.Context, lease domain.TypedWorkLease) domain.TypedCollectorResult {
	started := e.clock.Now().UTC()
	fail := func(code domain.FailureCode, message string) domain.TypedCollectorResult {
		return application.FailedTypedCollection(lease, e.clock.Now(), code, message)
	}
	p := lease.Plan
	if err := domain.ValidateTypedWorkLease(lease); err != nil || p.ClusterID != e.clusterID || p.SourceID != e.sourceID || p.SourceKind != domain.CollectionSourceSlurm || p.PayloadSchema != domain.CollectionSlurmSnapshotSchema || e.snapshot == nil || e.normalizer == nil || p.Cursor != "" || p.Interval == nil || len(p.Scope.Nodes) != len(e.nodes) || len(p.Scope.Nodes) > p.Limits.MaxRecords {
		return fail(domain.FailureInvalidArgument, "Slurm snapshot requires a bounded interval and the complete configured node scope")
	}
	if !p.Deadline.After(started) {
		return fail(domain.FailureDeadlineExceeded, "Slurm snapshot deadline expired")
	}
	names := make([]string, 0, len(p.Scope.Nodes))
	for _, stable := range p.Scope.Nodes {
		name, ok := e.nodes[stable]
		if !ok {
			return fail(domain.FailureInvalidArgument, "Slurm snapshot node scope is not locally configured")
		}
		names = append(names, name)
	}
	slices.Sort(names)
	bounded, cancel := context.WithDeadline(ctx, p.Deadline)
	defer cancel()
	type fetched struct {
		kind        string
		result      adapter.Result
		sourceAt    time.Time
		windowStart time.Time
		windowEnd   time.Time
	}
	fetches := make([]fetched, 0, 4)
	failures := make([]domain.CollectionFailure, 0, 4)
	var totalBytes int64
	totalRecords := 0
	budgetExceeded := false
	collect := func(kind string, result adapter.Result, err error, windowStart, windowEnd time.Time) adapter.Result {
		now := e.clock.Now().UTC()
		if err != nil {
			code := domain.FailureSourceUnavailable
			var classified *source.Error
			if errors.As(err, &classified) {
				code = classified.Code
			}
			failures = append(failures, domain.CollectionFailure{Code: code, Target: kind, Message: "Slurm " + kind + " source unavailable or invalid"})
			fetches = append(fetches, fetched{kind: kind, result: adapter.Result{}, sourceAt: now, windowStart: windowStart, windowEnd: windowEnd})
			return adapter.Result{}
		}
		totalBytes += int64(result.BytesRead)
		totalRecords += len(result.Records)
		budgetExceeded = result.BytesRead < 0 || totalBytes > p.Limits.MaxBytes || totalRecords > p.Limits.MaxRecords
		fetches = append(fetches, fetched{kind: kind, result: result, sourceAt: now, windowStart: windowStart, windowEnd: windowEnd})
		return result
	}
	nodes, err := e.snapshot.Nodes(bounded, names)
	nodes = collect("nodes", nodes, err, time.Time{}, time.Time{})
	if bounded.Err() != nil {
		return fail(domain.FailureDeadlineExceeded, "Slurm snapshot deadline expired")
	}
	if budgetExceeded {
		return fail(domain.FailureResultLimit, "Slurm snapshot source data exceeds assigned limits")
	}
	partitions, err := e.snapshot.Partitions(bounded, nil)
	partitions = collect("partitions", partitions, err, time.Time{}, time.Time{})
	if bounded.Err() != nil {
		return fail(domain.FailureDeadlineExceeded, "Slurm snapshot deadline expired")
	}
	if budgetExceeded {
		return fail(domain.FailureResultLimit, "Slurm snapshot source data exceeds assigned limits")
	}
	jobs, err := e.snapshot.Jobs(bounded, nil)
	jobs = collect("jobs", jobs, err, time.Time{}, time.Time{})
	if bounded.Err() != nil {
		return fail(domain.FailureDeadlineExceeded, "Slurm snapshot deadline expired")
	}
	if budgetExceeded {
		return fail(domain.FailureResultLimit, "Slurm snapshot source data exceeds assigned limits")
	}
	windowEnd := p.Interval.End
	windowStart := p.Interval.Start.Add(-e.overlap)
	accounting, err := e.snapshot.AccountingAllocations(bounded, windowStart, windowEnd, e.schedulerCluster, nil)
	accounting = collect("accounting", accounting, err, windowStart, windowEnd)
	if bounded.Err() != nil {
		return fail(domain.FailureDeadlineExceeded, "Slurm snapshot deadline expired")
	}
	if budgetExceeded {
		return fail(domain.FailureResultLimit, "Slurm snapshot source data exceeds assigned limits")
	}
	accountingAvailable := err == nil
	completed := e.clock.Now().UTC()
	input := adapter.NormalizationInput{Nodes: nodes, Partitions: partitions, Jobs: jobs, SourceAt: completed, ObservedAt: completed}
	if accountingAvailable {
		accountingSourceAt := completed
		for _, item := range fetches {
			if item.kind == "accounting" {
				accountingSourceAt = item.sourceAt
			}
		}
		input.Accounting = []adapter.AccountingWindow{{Start: windowStart, End: windowEnd, SourceAt: accountingSourceAt, Result: accounting}}
	}
	normalized, err := e.normalizer.Normalize(input)
	if err != nil {
		return fail(domain.FailureInternal, "Slurm snapshot normalization failed")
	}
	if bounded.Err() != nil {
		return fail(domain.FailureDeadlineExceeded, "Slurm snapshot deadline expired")
	}
	payload := domain.SlurmSnapshotPayload{ValidEmptyJobs: normalized.ValidEmptyJobs, ValidEmptyAccounting: normalized.ValidEmptyAccounting}
	for _, coverage := range normalized.Coverage {
		switch coverage.Scope {
		case domain.CoverageInventory:
			payload.InventoryCoverage = coverage
		case domain.CoverageAllocations:
			payload.AllocationCoverage = coverage
		}
	}
	if payload.InventoryCoverage.State == domain.SourceCoverageComplete {
		payload.Inventory = normalized.Inventory
	}
	for _, snapshot := range normalized.Allocations {
		payload.Allocations = append(payload.Allocations, domain.SlurmAllocationFact{RecordIdentity: domain.CanonicalSlurmAllocationRecordID(snapshot), Snapshot: snapshot})
	}
	for _, lifecycle := range normalized.Lifecycles {
		nodes := e.stableNodes(lifecycle.NodeNames)
		item := domain.SlurmJobLifecycle{ClusterID: p.ClusterID, SourceID: p.SourceID, Job: lifecycle.Job, RawState: safeState(lifecycle.RawState), SubmitQuality: quality(lifecycle.SubmitQuality), StartAt: lifecycle.StartAt, StartQuality: quality(lifecycle.StartQuality), EndAt: lifecycle.EndAt, EndQuality: quality(lifecycle.EndQuality), NodeIDs: nodes, Origin: lifecycle.Origin}
		item.RecordIdentity = domain.CanonicalSlurmLifecycleRecordID(item)
		payload.Lifecycles = append(payload.Lifecycles, item)
	}
	for _, unresolved := range normalized.UnresolvedAccounting {
		rawMembership := sha256.Sum256([]byte(unresolved.RawNodes))
		mappedNodes := e.stableNodes(unresolved.NodeNames)
		item := domain.SlurmUnresolvedAccounting{ClusterID: p.ClusterID, SourceID: p.SourceID, SchedulerNamespace: unresolved.SchedulerNamespace, JobID: unresolved.JobID, SubmitAt: unresolved.SubmitAt, SubmitQuality: quality(unresolved.SubmitQuality), SchedulerCluster: unresolved.SchedulerCluster, RawState: safeState(unresolved.RawState), StartAt: unresolved.StartAt, StartQuality: quality(unresolved.StartQuality), EndAt: unresolved.EndAt, EndQuality: quality(unresolved.EndQuality), NodeIDs: mappedNodes, MembershipQuality: membershipQuality(unresolved.RawNodes, unresolved.NodeNames, mappedNodes), MembershipDigest: hex.EncodeToString(rawMembership[:]), AttemptQuality: quality(unresolved.AttemptQuality)}
		for _, provenance := range unresolved.Provenance {
			item.Provenance = append(item.Provenance, domain.SlurmAccountingProvenance{WindowStart: provenance.WindowStart, WindowEnd: provenance.WindowEnd, SourceAt: provenance.SourceAt, ObservedAt: provenance.ObservedAt})
		}
		item.RecordIdentity = domain.CanonicalSlurmUnresolvedRecordID(item)
		payload.UnresolvedAccounting = append(payload.UnresolvedAccounting, item)
	}
	for _, issue := range normalized.Issues {
		payload.Issues = append(payload.Issues, domain.SlurmNormalizationIssue{Code: issue.Code, RecordKind: safeIssueToken(issue.RecordKind), RecordID: safeRecordID(issue.RecordID), Field: safeIssueToken(issue.Field), Quality: quality(issue.Quality)})
	}
	for _, item := range fetches {
		payload.Sources = append(payload.Sources, domain.SlurmSourceObservation{Kind: item.kind, DataParserVersion: item.result.DataParserVersion, SlurmVersion: item.result.SlurmVersion, SchemaSupport: schemaSupport(item.result.SchemaSupport), ReportedErrors: item.result.ReportedErrors, ReportedWarnings: item.result.ReportedWarnings, BytesRead: item.result.BytesRead, WindowStart: item.windowStart, WindowEnd: item.windowEnd, SourceAt: item.sourceAt})
	}
	if len(payload.Issues) > 0 && len(failures) == 0 {
		failures = append(failures, domain.CollectionFailure{Code: domain.FailurePartialData, Target: "slurm_snapshot", Message: "Slurm snapshot contains explicit coverage gaps"})
	}
	status := domain.ResultSucceeded
	if len(failures) > 0 {
		status = domain.ResultPartial
	}
	result := domain.TypedCollectorResult{SchemaVersion: domain.CollectionProtocolVersion, WorkID: lease.Lease.Work.WorkID, Attempt: lease.Lease.Attempt, Plan: p, Status: status, StartedAt: started, CompletedAt: completed, Coverage: payload.AllocationCoverage, Payload: domain.CollectionPayload{Kind: domain.CollectionPayloadSlurmSnapshot, SlurmSnapshot: &payload}, Failures: failures}
	if _, err := domain.EncodeTypedCollectorResult(result); err != nil {
		return fail(domain.FailureResultLimit, "Slurm snapshot exceeds assigned evidence limits")
	}
	if bounded.Err() != nil {
		return fail(domain.FailureDeadlineExceeded, "Slurm snapshot deadline expired")
	}
	return result
}

func (e *Executor) stableNodes(names []string) []domain.StableNodeID {
	result := make([]domain.StableNodeID, 0, len(names))
	for _, name := range names {
		if stable, ok := e.stableByName[name]; ok {
			result = append(result, stable)
		}
	}
	slices.Sort(result)
	return slices.Compact(result)
}

func quality(value adapter.FieldQuality) domain.SlurmFieldQuality {
	return domain.SlurmFieldQuality(value)
}
func schemaSupport(value adapter.SchemaSupport) domain.SlurmSchemaSupport {
	if value == "" {
		return domain.SlurmSchemaUnknown
	}
	return domain.SlurmSchemaSupport(value)
}
func safeState(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "UNKNOWN"
	}
	return value
}
func safeRecordID(value string) string {
	if value == "" {
		return ""
	}
	digest := sha256.Sum256([]byte(value))
	return "record-" + hex.EncodeToString(digest[:])
}
func safeIssueToken(value string) string {
	if value == "" || issueToken.MatchString(value) {
		return value
	}
	return "source_field"
}
func membershipQuality(raw string, names []string, mapped []domain.StableNodeID) domain.SlurmFieldQuality {
	if raw == "" {
		return domain.SlurmFieldMissing
	}
	if len(names) == 0 || len(mapped) != len(names) {
		return domain.SlurmFieldUnsupported
	}
	return domain.SlurmFieldPresent
}
