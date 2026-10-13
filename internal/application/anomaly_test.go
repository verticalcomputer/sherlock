package application

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

type anomalyStoreFake struct {
	pending   *PendingAutomaticInvestigation
	completed int
}

func (store *anomalyStoreFake) NextCommittedCollection(context.Context, string, domain.ClusterID) (CommittedCollection, bool, error) {
	return CommittedCollection{}, false, nil
}
func (store *anomalyStoreFake) CommitAnomalyEvaluation(context.Context, string, CommittedCollection, *AnomalySignal, AutomaticInvestigationPolicy, time.Time) (*PendingAutomaticInvestigation, error) {
	return nil, nil
}
func (store *anomalyStoreFake) NextPendingAutomaticInvestigation(context.Context, string, domain.ClusterID, time.Time) (*PendingAutomaticInvestigation, error) {
	return store.pending, nil
}
func (store *anomalyStoreFake) CompleteAutomaticInvestigation(context.Context, string, domain.InvestigationID, time.Time) error {
	store.completed++
	return nil
}

type startCommandFake struct {
	err      error
	snapshot InvestigationSnapshot
}

func (starter startCommandFake) Start(context.Context, StartInvestigationInput) (InvestigationSnapshot, bool, error) {
	return starter.snapshot, true, starter.err
}

type anomalyClock struct{ now time.Time }

func (clock anomalyClock) Now() time.Time { return clock.now }

func TestEvaluateCommittedAnomalyIsDeterministic(t *testing.T) {
	now := time.Date(2026, 8, 20, 1, 2, 3, 0, time.UTC)
	input := CommittedCollection{EventID: 7, ClusterID: "cluster-1", RunID: "run-1", Query: domain.QueryGPUXID, CompletedAt: now, EvidenceID: "evidence-1", EvidenceStatus: domain.EvidencePartial, EvidenceCreatedAt: now,
		Observations: []AnomalyObservation{
			{Metric: "DCGM_FI_DEV_XID_ERRORS", Value: 31, Labels: map[string]string{"Hostname": "node-2", "UUID": "gpu-2"}},
			{Metric: "DCGM_FI_DEV_XID_ERRORS", Value: 0, Labels: map[string]string{"Hostname": "ignored"}},
			{Metric: "DCGM_FI_DEV_XID_ERRORS", Value: 13, Labels: map[string]string{"Hostname": "node-1", "UUID": "gpu-1"}},
		}}
	signal, err := EvaluateCommittedAnomaly(input)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"node-1", "node-2"}
	if signal == nil || signal.RuleID != XIDNonZeroRuleID || signal.Severity != "HIGH" || !slicesEqual(signal.EntityIDs, want) {
		t.Fatalf("signal = %+v", signal)
	}
}

func TestEvaluateCommittedAnomalyUsesGPUWhenHostIsUnavailable(t *testing.T) {
	now := time.Date(2026, 8, 20, 1, 2, 3, 0, time.UTC)
	input := CommittedCollection{EventID: 7, ClusterID: "cluster-1", RunID: "run-1", Query: domain.QueryGPUXID, CompletedAt: now, EvidenceID: "evidence-1", EvidenceStatus: domain.EvidencePartial, EvidenceCreatedAt: now,
		Observations: []AnomalyObservation{{Metric: "DCGM_FI_DEV_XID_ERRORS", Value: 31, Labels: map[string]string{"UUID": "gpu-2"}}}}
	signal, err := EvaluateCommittedAnomaly(input)
	if err != nil {
		t.Fatal(err)
	}
	if signal == nil || !slicesEqual(signal.EntityIDs, []string{"gpu-2"}) {
		t.Fatalf("signal = %+v", signal)
	}
}

func TestEvaluateCommittedAnomalyStartsOnlyOnXIDEdges(t *testing.T) {
	now := time.Date(2026, 8, 20, 1, 2, 3, 0, time.UTC)
	base := CommittedCollection{EventID: 7, ClusterID: "cluster-1", RunID: "run-1", Query: domain.QueryGPUXID, CompletedAt: now, EvidenceID: "evidence-1", EvidenceStatus: domain.EvidenceComplete, EvidenceCreatedAt: now,
		Observations:      []AnomalyObservation{{EntityKey: "node-1-gpu-0", Metric: "DCGM_FI_DEV_XID_ERRORS", Value: 94, Labels: map[string]string{"hostname": "node-1", "UUID": "gpu-1"}}},
		PreviousXIDValues: map[string]float64{"gpu-1": 94}}
	signal, err := EvaluateCommittedAnomaly(base)
	if err != nil || signal != nil {
		t.Fatalf("sticky signal=%+v err=%v", signal, err)
	}
	base.EventID++
	base.RunID = "run-2"
	base.EvidenceID = "evidence-2"
	base.Observations[0].Value = 95
	signal, err = EvaluateCommittedAnomaly(base)
	if err != nil || signal == nil || !slicesEqual(signal.EntityIDs, []string{"node-1"}) {
		t.Fatalf("changed-code signal=%+v err=%v", signal, err)
	}
	base.PreviousXIDValues = map[string]float64{"gpu-1": 0}
	base.Observations[0].Value = 94
	signal, err = EvaluateCommittedAnomaly(base)
	if err != nil || signal == nil {
		t.Fatalf("zero-to-nonzero signal=%+v err=%v", signal, err)
	}
}

func TestEvaluateCommittedAnomalyIgnoresNonSignal(t *testing.T) {
	now := time.Now().UTC()
	for _, input := range []CommittedCollection{
		{EventID: 1, ClusterID: "c", RunID: "r", Query: domain.QueryGPUUtilization, CompletedAt: now},
		{EventID: 2, ClusterID: "c", RunID: "r2", Query: domain.QueryGPUXID, CompletedAt: now, EvidenceID: "e", EvidenceCreatedAt: now, Observations: []AnomalyObservation{{Metric: "DCGM_FI_DEV_XID_ERRORS", Value: 0}}},
	} {
		signal, err := EvaluateCommittedAnomaly(input)
		if err != nil || signal != nil {
			t.Fatalf("signal=%+v err=%v", signal, err)
		}
	}
}

func TestAnomalyBridgeLeavesReservationRetryableWhenStartFails(t *testing.T) {
	now := time.Date(2026, 8, 20, 1, 0, 0, 0, time.UTC)
	request := domain.InvestigationRequest{ID: "investigation-1"}
	store := &anomalyStoreFake{pending: &PendingAutomaticInvestigation{AttemptID: "attempt-1", Request: request}}
	policy := AutomaticInvestigationPolicy{EnabledRules: map[string]bool{XIDNonZeroRuleID: true}, MinimumSeverity: "HIGH", Cooldown: time.Hour, MaximumEvidenceAge: time.Minute, MaxConcurrent: 1, InvestigationTTL: time.Hour, ServiceActor: "service", InvestigationBudget: domain.InvestigationBudget{MaxDecisions: 1, MaxToolCalls: 1, MaxFanOut: 1}}
	bridge, err := NewAnomalyBridge(store, startCommandFake{err: errors.New("provider unavailable")}, anomalyClock{now}, "consumer", "cluster", policy)
	if err != nil {
		t.Fatal(err)
	}
	progressed, err := bridge.RunOnce(context.Background())
	if !progressed || err == nil || store.completed != 0 {
		t.Fatalf("progressed=%t err=%v completed=%d", progressed, err, store.completed)
	}
}

func TestAutomaticInvestigationPolicyGatesEveryRequiredDimension(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	signal := AnomalySignal{RuleID: XIDNonZeroRuleID, Severity: "HIGH"}
	policy := AutomaticInvestigationPolicy{Enabled: true, EnabledRules: map[string]bool{XIDNonZeroRuleID: true}, MinimumSeverity: "HIGH", MaximumEvidenceAge: 5 * time.Minute, AllowPartialCoverage: true, Cooldown: time.Hour, MaxConcurrent: 2, DailyTokenBudget: 1000, DailyCostBudget: 1000, InvestigationBudget: domain.InvestigationBudget{MaxDecisions: 1, MaxToolCalls: 1, MaxFanOut: 1, MaxModelTokens: 100, MaxCostMicros: 100}}
	facts := AutomaticInvestigationFacts{EvidenceCreatedAt: now.Add(-time.Minute), Coverage: domain.EvidencePartial, CooldownElapsed: true}
	if got := EvaluateAutomaticInvestigationPolicy(signal, policy, facts, now); got != "ELIGIBLE" {
		t.Fatalf("eligible=%s", got)
	}
	tests := []struct {
		name, want string
		change     func(*AutomaticInvestigationPolicy, *AutomaticInvestigationFacts, *AnomalySignal)
	}{
		{"cluster disabled", "POLICY_DISABLED", func(p *AutomaticInvestigationPolicy, _ *AutomaticInvestigationFacts, _ *AnomalySignal) {
			p.Enabled = false
		}},
		{"rule disabled", "RULE_DISABLED", func(p *AutomaticInvestigationPolicy, _ *AutomaticInvestigationFacts, _ *AnomalySignal) {
			p.EnabledRules = map[string]bool{}
		}},
		{"severity", "SEVERITY_BELOW_MINIMUM", func(p *AutomaticInvestigationPolicy, _ *AutomaticInvestigationFacts, _ *AnomalySignal) {
			p.MinimumSeverity = "CRITICAL"
		}},
		{"freshness", "EVIDENCE_STALE", func(_ *AutomaticInvestigationPolicy, f *AutomaticInvestigationFacts, _ *AnomalySignal) {
			f.EvidenceCreatedAt = now.Add(-6 * time.Minute)
		}},
		{"coverage", "COVERAGE_INSUFFICIENT", func(p *AutomaticInvestigationPolicy, f *AutomaticInvestigationFacts, _ *AnomalySignal) {
			p.AllowPartialCoverage = false
			f.Coverage = domain.EvidencePartial
		}},
		{"cooldown", "COOLDOWN", func(_ *AutomaticInvestigationPolicy, f *AutomaticInvestigationFacts, _ *AnomalySignal) {
			f.CooldownElapsed = false
		}},
		{"active", "ACTIVE_RUN", func(_ *AutomaticInvestigationPolicy, f *AutomaticInvestigationFacts, _ *AnomalySignal) {
			f.IncidentActive = true
		}},
		{"concurrency", "CONCURRENCY_BUDGET", func(_ *AutomaticInvestigationPolicy, f *AutomaticInvestigationFacts, _ *AnomalySignal) {
			f.Concurrent = 2
		}},
		{"tokens", "DAILY_TOKEN_BUDGET", func(_ *AutomaticInvestigationPolicy, f *AutomaticInvestigationFacts, _ *AnomalySignal) {
			f.DailyReservedTokens = 901
		}},
		{"cost", "DAILY_COST_BUDGET", func(_ *AutomaticInvestigationPolicy, f *AutomaticInvestigationFacts, _ *AnomalySignal) {
			f.DailyReservedCost = 901
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			p, f, s := policy, facts, signal
			p.EnabledRules = map[string]bool{XIDNonZeroRuleID: true}
			test.change(&p, &f, &s)
			if got := EvaluateAutomaticInvestigationPolicy(s, p, f, now); got != test.want {
				t.Fatalf("got %s want %s", got, test.want)
			}
		})
	}
}

func slicesEqual(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
