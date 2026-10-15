package application

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

const XIDNonZeroRuleID = "dcgm.xid.nonzero.v1"

type AnomalyObservation struct {
	EntityKey string
	Metric    string
	Labels    map[string]string
	Value     float64
}

// CommittedCollection is loaded only from a durable collection.updated event.
// EvidenceCreatedAt is the PostgreSQL commit-visible boundary used by the
// reconciler; evidence created after the transition is never attached.
type CommittedCollection struct {
	EventID           int64
	ClusterID         domain.ClusterID
	RunID             domain.RunID
	Query             domain.QueryKind
	CompletedAt       time.Time
	EvidenceID        domain.EvidenceID
	EvidenceStatus    domain.EvidenceStatus
	EvidenceCreatedAt time.Time
	Observations      []AnomalyObservation
	// PreviousXIDValues is the last commit-visible value per physical GPU (or
	// source entity when no GPU UUID is present). A non-nil map makes XID
	// evaluation edge-based; an empty map means this is the first observation.
	PreviousXIDValues map[string]float64
}

type AnomalySignal struct {
	RuleID     string
	Severity   string
	EntityIDs  []string
	EntityKey  string
	EvidenceID domain.EvidenceID
	Coverage   domain.EvidenceStatus
	ObservedAt time.Time
}

// EvaluateCommittedAnomaly contains reviewed deterministic rules only. Model
// providers are intentionally absent from this boundary.
func EvaluateCommittedAnomaly(input CommittedCollection) (*AnomalySignal, error) {
	if input.EventID < 1 || input.ClusterID == "" || input.RunID == "" || input.CompletedAt.IsZero() {
		return nil, fmt.Errorf("committed collection identity is incomplete")
	}
	if input.Query != domain.QueryGPUXID {
		return nil, nil
	}
	if input.EvidenceID == "" || input.EvidenceCreatedAt.IsZero() {
		return nil, nil
	}
	entities := make(map[string]struct{})
	for _, observation := range NormalizeXIDObservations(input.Observations) {
		if observation.Value <= 0 {
			continue
		}
		if previous, known := input.PreviousXIDValues[observation.StateKey]; input.PreviousXIDValues != nil && known && previous == observation.Value {
			continue
		}
		entities[observation.Target] = struct{}{}
	}
	if len(entities) == 0 {
		return nil, nil
	}
	ids := make([]string, 0, len(entities))
	for id := range entities {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	if len(ids) > 256 {
		ids = ids[:256]
	}
	return &AnomalySignal{
		RuleID: XIDNonZeroRuleID, Severity: "HIGH", EntityIDs: ids,
		EntityKey: strings.Join(ids, "\x1f"), EvidenceID: input.EvidenceID,
		Coverage: input.EvidenceStatus, ObservedAt: input.CompletedAt.UTC(),
	}, nil
}

// XIDStateObservation separates the physical series identity used for edge
// detection from the node target used by reviewed diagnostics.
type XIDStateObservation struct {
	StateKey string
	Target   string
	Value    float64
}

// NormalizeXIDObservations returns stable per-GPU state keys while retaining
// node-scoped execution targets. Invalid or unrelated samples are omitted.
func NormalizeXIDObservations(values []AnomalyObservation) []XIDStateObservation {
	result := make([]XIDStateObservation, 0, len(values))
	for _, observation := range values {
		if observation.Metric != "DCGM_FI_DEV_XID_ERRORS" {
			continue
		}
		target := firstAnomalyEntity(observation.Labels, "Hostname", "hostname")
		gpu := firstAnomalyEntity(observation.Labels, "UUID", "uuid")
		stateKey := gpu
		if stateKey == "" && validAnomalyEntity(strings.TrimSpace(observation.EntityKey)) {
			stateKey = strings.TrimSpace(observation.EntityKey)
		}
		if target == "" {
			target = gpu
		}
		if target == "" && validAnomalyEntity(strings.TrimSpace(observation.EntityKey)) {
			target = strings.TrimSpace(observation.EntityKey)
		}
		if stateKey == "" {
			stateKey = target
		}
		if stateKey != "" && target != "" {
			result = append(result, XIDStateObservation{StateKey: stateKey, Target: target, Value: observation.Value})
		}
	}
	return result
}

func firstAnomalyEntity(labels map[string]string, keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(labels[key]); validAnomalyEntity(value) {
			return value
		}
	}
	return ""
}

func validAnomalyEntity(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') && (character < '0' || character > '9') && character != '.' && character != '_' && character != ':' && character != '-' {
			return false
		}
	}
	return true
}

type AutomaticInvestigationPolicy struct {
	Enabled              bool
	EnabledRules         map[string]bool
	MinimumSeverity      string
	MaximumEvidenceAge   time.Duration
	AllowPartialCoverage bool
	Cooldown             time.Duration
	MaxConcurrent        int
	DailyTokenBudget     int64
	DailyCostBudget      int64
	InvestigationBudget  domain.InvestigationBudget
	InvestigationTTL     time.Duration
	ServiceActor         string
}

type AutomaticInvestigationFacts struct {
	EvidenceCreatedAt   time.Time
	Coverage            domain.EvidenceStatus
	CooldownElapsed     bool
	IncidentActive      bool
	Concurrent          int
	DailyReservedTokens int64
	DailyReservedCost   int64
}

func EvaluateAutomaticInvestigationPolicy(signal AnomalySignal, policy AutomaticInvestigationPolicy, facts AutomaticInvestigationFacts, now time.Time) string {
	if !policy.Enabled {
		return "POLICY_DISABLED"
	}
	if !policy.EnabledRules[signal.RuleID] {
		return "RULE_DISABLED"
	}
	if anomalySeverityRank(signal.Severity) < anomalySeverityRank(policy.MinimumSeverity) {
		return "SEVERITY_BELOW_MINIMUM"
	}
	if facts.EvidenceCreatedAt.IsZero() || facts.EvidenceCreatedAt.After(now) || now.Sub(facts.EvidenceCreatedAt) > policy.MaximumEvidenceAge {
		return "EVIDENCE_STALE"
	}
	if facts.Coverage != domain.EvidenceComplete && !(policy.AllowPartialCoverage && facts.Coverage == domain.EvidencePartial) {
		return "COVERAGE_INSUFFICIENT"
	}
	if !facts.CooldownElapsed {
		return "COOLDOWN"
	}
	if facts.IncidentActive {
		return "ACTIVE_RUN"
	}
	if facts.Concurrent >= policy.MaxConcurrent {
		return "CONCURRENCY_BUDGET"
	}
	if facts.DailyReservedTokens+policy.InvestigationBudget.MaxModelTokens > policy.DailyTokenBudget {
		return "DAILY_TOKEN_BUDGET"
	}
	if facts.DailyReservedCost+policy.InvestigationBudget.MaxCostMicros > policy.DailyCostBudget {
		return "DAILY_COST_BUDGET"
	}
	return "ELIGIBLE"
}

func anomalySeverityRank(value string) int {
	switch value {
	case "CRITICAL":
		return 5
	case "HIGH":
		return 4
	case "MEDIUM":
		return 3
	case "LOW":
		return 2
	case "INFO":
		return 1
	default:
		return -1
	}
}

type PendingAutomaticInvestigation struct {
	AttemptID string
	Request   domain.InvestigationRequest
}

type AnomalyBridgeStore interface {
	NextCommittedCollection(context.Context, string, domain.ClusterID) (CommittedCollection, bool, error)
	CommitAnomalyEvaluation(context.Context, string, CommittedCollection, *AnomalySignal, AutomaticInvestigationPolicy, time.Time) (*PendingAutomaticInvestigation, error)
	NextPendingAutomaticInvestigation(context.Context, string, domain.ClusterID, time.Time) (*PendingAutomaticInvestigation, error)
	CompleteAutomaticInvestigation(context.Context, string, domain.InvestigationID, time.Time) error
}

type InvestigationStartCommand interface {
	Start(context.Context, StartInvestigationInput) (InvestigationSnapshot, bool, error)
}

type AnomalyBridge struct {
	store    AnomalyBridgeStore
	starter  InvestigationStartCommand
	clock    Clock
	consumer string
	cluster  domain.ClusterID
	policy   AutomaticInvestigationPolicy
}

func NewAnomalyBridge(store AnomalyBridgeStore, starter InvestigationStartCommand, clock Clock, consumer string, cluster domain.ClusterID, policy AutomaticInvestigationPolicy) (*AnomalyBridge, error) {
	if store == nil || starter == nil || clock == nil || consumer == "" || cluster == "" {
		return nil, fmt.Errorf("anomaly bridge dependencies are required")
	}
	if policy.Cooldown <= 0 || policy.MaximumEvidenceAge <= 0 || policy.MaxConcurrent < 1 || policy.InvestigationTTL <= 0 || policy.InvestigationTTL > 24*time.Hour || !validAnomalyEntity(policy.ServiceActor) || anomalySeverityRank(policy.MinimumSeverity) < 0 || len(policy.EnabledRules) == 0 || policy.DailyTokenBudget < 0 || policy.DailyCostBudget < 0 || policy.InvestigationBudget.MaxModelTokens > policy.DailyTokenBudget || policy.InvestigationBudget.MaxCostMicros > policy.DailyCostBudget {
		return nil, fmt.Errorf("automatic investigation policy bounds are invalid")
	}
	if err := policy.InvestigationBudget.Validate(); err != nil {
		return nil, err
	}
	return &AnomalyBridge{store: store, starter: starter, clock: clock, consumer: consumer, cluster: cluster, policy: policy}, nil
}

// RunOnce resumes a reserved start first, then evaluates at most one committed
// collection event. Collection and API callers never depend on this method.
func (bridge *AnomalyBridge) RunOnce(ctx context.Context) (bool, error) {
	now := bridge.clock.Now().UTC()
	if pending, err := bridge.store.NextPendingAutomaticInvestigation(ctx, bridge.consumer, bridge.cluster, now); err != nil {
		return false, err
	} else if pending != nil {
		return true, bridge.start(ctx, *pending, now)
	}
	// Monitoring publishes incidents independently. Optional source bridges only
	// reserve bounded starts after those incidents and their evidence are durable.
	if source, ok := bridge.store.(interface {
		ReserveSlurmFailureInvestigation(context.Context, domain.ClusterID, AutomaticInvestigationPolicy, time.Time) (*PendingAutomaticInvestigation, error)
	}); ok {
		pending, err := source.ReserveSlurmFailureInvestigation(ctx, bridge.cluster, bridge.policy, now)
		if err != nil {
			return false, err
		}
		if pending != nil {
			return true, bridge.start(ctx, *pending, now)
		}
	}
	collection, found, err := bridge.store.NextCommittedCollection(ctx, bridge.consumer, bridge.cluster)
	if err != nil || !found {
		return false, err
	}
	signal, err := EvaluateCommittedAnomaly(collection)
	if err != nil {
		return true, err
	}
	pending, err := bridge.store.CommitAnomalyEvaluation(ctx, bridge.consumer, collection, signal, bridge.policy, now)
	if err != nil || pending == nil {
		return true, err
	}
	return true, bridge.start(ctx, *pending, now)
}

func (bridge *AnomalyBridge) start(ctx context.Context, pending PendingAutomaticInvestigation, now time.Time) error {
	snapshot, _, err := bridge.starter.Start(ctx, StartInvestigationInput{Request: pending.Request})
	if err != nil {
		return fmt.Errorf("start automatic investigation: %w", err)
	}
	return bridge.store.CompleteAutomaticInvestigation(ctx, pending.AttemptID, snapshot.Investigation.Request().ID, now)
}
