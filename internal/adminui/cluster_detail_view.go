package adminui

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

const recentInvestigationLimit = 5

// evidenceBlockerGroup folds blocking evidence streams that share a source,
// operation, condition, and recommended repair into one operator-facing row.
// Per-scope attempt detail stays available inside the group.
type evidenceBlockerGroup struct {
	SourceID, Operation, Status, Condition, FailureCode, RecommendedAction string
	State                                                                  OperationalState
	LatestAttempt                                                          time.Time
	Targets                                                                []string
	Streams                                                                []EvidenceStreamHealth
}

// clusterAction is the single next step the cluster page leads with.
type clusterAction struct {
	// Kind is "repair-plan", "open-investigation", "rerun", or "none".
	Kind, Title, Detail, Label, InvestigationID string
}

// groupEvidenceBlockers groups streams for display. Listing every scope as its
// own card repeated the same condition and repair once per GPU or node and
// buried the few distinct repairs an operator actually has to make. The safe
// failure reason is deliberately not part of the key: it often varies by scope
// ("3 GPUs returned no series") without changing the repair.
func groupEvidenceBlockers(streams []EvidenceStreamHealth) []evidenceBlockerGroup {
	groups := make([]evidenceBlockerGroup, 0)
	indexByKey := make(map[string]int)
	seenTargets := make(map[int]map[string]struct{})
	for _, stream := range blockingEvidenceStreams(streams) {
		key := strings.Join([]string{stream.SourceID, stream.Operation, stream.Status, stream.Condition, stream.FailureCode, stream.RecommendedAction}, "\x00")
		index, found := indexByKey[key]
		if !found {
			index = len(groups)
			indexByKey[key] = index
			seenTargets[index] = make(map[string]struct{})
			groups = append(groups, evidenceBlockerGroup{
				SourceID: stream.SourceID, Operation: stream.Operation, Status: stream.Status,
				Condition: stream.Condition, FailureCode: stream.FailureCode,
				RecommendedAction: stream.RecommendedAction, State: normalizeState(stream.State),
			})
		}
		group := &groups[index]
		group.State = recoveryWorseState(group.State, normalizeState(stream.State))
		if stream.LatestAttempt.After(group.LatestAttempt) {
			group.LatestAttempt = stream.LatestAttempt
		}
		group.Streams = append(group.Streams, stream)
		for _, target := range stream.MissingTargets {
			if _, exists := seenTargets[index][target]; exists {
				continue
			}
			seenTargets[index][target] = struct{}{}
			group.Targets = append(group.Targets, target)
		}
	}
	sort.SliceStable(groups, func(left, right int) bool {
		if stateRank(groups[left].State) != stateRank(groups[right].State) {
			return stateRank(groups[left].State) > stateRank(groups[right].State)
		}
		return len(groups[left].Targets) > len(groups[right].Targets)
	})
	return groups
}

func blockerStreamCount(groups []evidenceBlockerGroup) int {
	total := 0
	for _, group := range groups {
		total += len(group.Streams)
	}
	return total
}

// buildNextAction picks the one step that moves the cluster toward healthy.
// It only chooses among actions this surface can already perform; it does not
// infer remediation.
func buildNextAction(glance clusterGlance, blockers []evidenceBlockerGroup, rerun investigationForm, investigations []Investigation, now time.Time) clusterAction {
	issue := glance.PrimaryIssue
	if issue != nil && len(blockers) > 0 {
		if existing := latestEvidenceRepairInvestigation(investigations, issue.ID, now, 24*time.Hour); existing != nil && !investigationIsTerminal(existing.Status) {
			return clusterAction{Kind: "open-investigation", InvestigationID: existing.ID, Label: "Follow repair plan run",
				Title:  "A combined repair plan is being generated",
				Detail: fmt.Sprintf("The run is %s. It covers the current evidence blockers; nothing is changed automatically.", existing.Status)}
		}
		streams := blockerStreamCount(blockers)
		return clusterAction{Kind: "repair-plan", Label: "Review repair plan",
			Title:  fmt.Sprintf("Fix %s", countLabel(streams, "blocking evidence stream", "blocking evidence streams")),
			Detail: fmt.Sprintf("One AI run analyzes %s together and returns a reviewable plan. Nothing is changed automatically.", countLabel(len(blockers), "blocker group", "blocker groups"))}
	}
	if latest := glance.LatestInvestigation; latest != nil && !investigationIsTerminal(latest.Status) {
		return clusterAction{Kind: "open-investigation", InvestigationID: latest.ID, Label: "Follow investigation",
			Title: "An investigation is in progress", Detail: "Status " + latest.Status + ". Open the run to follow its evidence and findings."}
	}
	if issue == nil {
		if glance.State == StateHealthy {
			return clusterAction{Kind: "none", Title: "No action needed", Detail: "There is no current incident and every monitoring signal is healthy."}
		}
		if len(blockers) > 0 {
			return clusterAction{Kind: "none", Title: "No current incident", Detail: "Monitoring coverage needs attention. Review the partial streams; older open records remain in incident history."}
		}
		return clusterAction{Kind: "none", Title: "No current incident", Detail: "Review the monitoring and queue signals that need attention; older open records remain in incident history."}
	}
	latest := glance.LatestInvestigation
	if latest != nil && latest.IncidentID == issue.ID && latest.Status == "COMPLETED" {
		return clusterAction{Kind: "open-investigation", InvestigationID: latest.ID, Label: "Open report",
			Title: "Review the completed investigation", Detail: "Confirm its recommended action, then resolve or monitor the incident."}
	}
	if rerun.Available {
		detail := fmt.Sprintf("Uses the latest scope · up to %s model tokens · $%s · %d min deadline.", formatCount(rerun.MaxModelTokens), rerun.MaxCostUSD, rerun.DeadlineMinutes)
		if latest != nil {
			detail = "The last run ended " + latest.Status + ". " + detail
		}
		return clusterAction{Kind: "rerun", Label: "Run investigation", Title: "Investigate this incident", Detail: detail}
	}
	if latest != nil {
		return clusterAction{Kind: "open-investigation", InvestigationID: latest.ID, Label: "Open last report",
			Title: "Review the last investigation", Detail: "It ended " + latest.Status + ". A new run needs a known affected scope."}
	}
	return clusterAction{Kind: "none", Title: "Waiting for an affected scope",
		Detail: "An investigation needs affected entities. They appear once the incident projection or a report records them."}
}

func investigationIsTerminal(status string) bool {
	switch status {
	case "COMPLETED", "PARTIAL", "FAILED", "CANCELLED", "BLOCKED":
		return true
	default:
		return false
	}
}

// openFirstUnmetGate counts only applicable gates and opens the first current
// blocker. Incident-specific gates are not counted when no incident is current.
func openFirstUnmetGate(steps []recoveryStep) (met, applicable int) {
	opened := false
	for index := range steps {
		if steps[index].NotApplicable {
			continue
		}
		applicable++
		if steps[index].State == StateHealthy {
			met++
			continue
		}
		if !opened {
			steps[index].Open, opened = true, true
		}
	}
	return met, applicable
}

func splitRecentInvestigations(investigations []Investigation, limit int) ([]Investigation, []Investigation) {
	if len(investigations) <= limit {
		return investigations, nil
	}
	return investigations[:limit], investigations[limit:]
}

var clusterTabTitles = map[string]string{"summary": "Summary", "gates": "Recovery gates", "investigations": "Investigations", "health": "Monitoring signals"}

// presentTab derives the presentation-only values each cluster view charts.
func (page *clusterDetailPageData) presentTab(tab string, now time.Time) {
	page.Tab, page.TabTitle = tab, clusterTabTitles[tab]
	glance := page.Glance
	page.Signals = []Metric{glance.Connectivity, glance.Freshness, glance.Evidence, glance.Queue}
	if page.Cluster.Network.Enrolled {
		n := page.Cluster.Network
		state := StateHealthy
		ibState := n.InfiniBandState
		if ibState == "" {
			ibState = n.State
		}
		if ibState != "HEALTHY" {
			state = StateDegraded
		}
		page.Signals = append(page.Signals, Metric{Label: "InfiniBand monitoring", Value: fmt.Sprintf("%d / %d healthy", n.HealthyPorts, n.ExpectedPorts), Detail: fmt.Sprintf("every %ds · %d down · %d unknown", n.IntervalSeconds, n.DownPorts, n.UnknownPorts), State: state})

		if n.Management.Enrolled {
			m := n.Management
			state := StateHealthy
			if m.State != "HEALTHY" {
				state = StateDegraded
			}
			page.Signals = append(page.Signals, Metric{Label: "Management links", Value: fmt.Sprintf("%d / %d healthy", m.HealthyLinks, m.ExpectedBonds+m.ExpectedMembers), Detail: fmt.Sprintf("%d bonds · %d members · %d down · %d unknown", m.ExpectedBonds, m.ExpectedMembers, m.DownLinks, m.UnknownLinks), State: state})
		}
	}
	page.WorkflowSignals = []Metric{glance.InvestigationState, glance.ModelUsage, glance.Audit}
	for _, signal := range page.Signals {
		if normalizeState(signal.State) != StateHealthy {
			page.SignalAttention++
		}
	}
	page.EvidenceBar = evidenceStreamBar(page.Cluster.EvidenceStreams)
	page.HistoryBar = evidenceHistoryBar(page.Cluster.EvidenceHistory)
	page.GPUWidth = percentWidth(page.Cluster.Resources.GPUUtilizationPercent)
	page.CPUWidth = percentWidth(page.Cluster.Resources.CPUUtilizationPercent)
	page.Activity = buildActivityWindow(page.Investigations, now)
}
