package adminui

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

const (
	evidenceRepairQuestionPrefix     = "Generate one operator-ready, proposal-only repair plan for all current evidence warnings together."
	evidenceRepairMaxDecisions       = 48
	evidenceRepairMaxToolCalls       = 80
	evidenceRepairMaxDiagnosticCalls = 0
	evidenceRepairMaxModelTokens     = int64(600_000)
	evidenceRepairMaxCostMicrounits  = int64(15_000_000)
	evidenceRepairDeadline           = 90 * time.Minute
	evidenceRepairObservationWindow  = 24 * time.Hour
)

// evidenceRepairBatchKey deduplicates equivalent current repair requests. It
// deliberately excludes attempt timestamps and run IDs: periodic collection
// may refresh those between clicks without changing the repair problem.
func evidenceRepairBatchKey(clusterID string, streams []EvidenceStreamHealth) string {
	streamKeys := make([]string, 0, len(streams))
	for _, stream := range streams {
		if evidenceStreamBlocksCompleteness(stream) {
			streamKeys = append(streamKeys, evidenceRepairStreamKey(clusterID, stream))
		}
	}
	sort.Strings(streamKeys)
	hash := sha256.New()
	_, _ = hash.Write([]byte(clusterID))
	for _, key := range streamKeys {
		_, _ = hash.Write([]byte{0})
		_, _ = hash.Write([]byte(key))
	}
	return hex.EncodeToString(hash.Sum(nil)[:16])
}

func evidenceRepairStreamKey(clusterID string, stream EvidenceStreamHealth) string {
	targets := stream.MissingTargets
	if len(targets) == 0 {
		targets = stream.ExpectedTargets
	}
	targets = append([]string(nil), targets...)
	sort.Strings(targets)
	hash := sha256.New()
	for _, value := range []string{
		clusterID, stream.SourceID, stream.Operation, stream.Scope,
		stream.Condition, stream.FailureCode, strings.Join(targets, "\x1f"),
	} {
		_, _ = hash.Write([]byte(value))
		_, _ = hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil)[:16])
}

func (server *Server) startEvidenceRepairProposal(writer http.ResponseWriter, request *http.Request) {
	key, csrfToken, ok := server.requireAccess(writer, request)
	if !ok {
		return
	}
	if !server.parseAndVerifyCSRF(writer, request, csrfToken) {
		return
	}
	clusterID := strings.TrimSpace(request.PathValue("id"))
	if !validAdminToken(clusterID) {
		http.Error(writer, "invalid AI repair proposal request", http.StatusBadRequest)
		return
	}

	summary, summaryErr := server.provider.GetClusterSummary(request.Context(), clusterID)
	operations, operationsErr := server.provider.LoadClusterOperations(request.Context(), clusterID)
	if summaryErr != nil || operationsErr != nil {
		server.redirectRepairProposalFailure(writer, request, clusterID)
		return
	}
	glance := buildClusterGlance(summary, consolidateTickets(operations.Tickets), operations.Investigations)
	if glance.PrimaryIssue == nil || !validAdminToken(glance.PrimaryIssue.ID) {
		http.Redirect(writer, request, "/admin/clusters/"+url.PathEscape(clusterID)+"?repair_proposal_no_incident=1", http.StatusSeeOther)
		return
	}

	streams := blockingEvidenceStreams(summary.EvidenceStreams)
	if len(streams) == 0 {
		http.Redirect(writer, request, "/admin/clusters/"+url.PathEscape(clusterID)+"?repair_proposal_cleared=1", http.StatusSeeOther)
		return
	}

	previousID := ""
	if previous := latestFinishedEvidenceRepairInvestigation(operations.Investigations, glance.PrimaryIssue.ID); previous != nil {
		previousID = previous.ID
	}
	input := buildEvidenceRepairInvestigation(clusterID, glance.PrimaryIssue.ID, streams, server.clock.Now().UTC(), previousID)
	result, err := server.provider.StartInvestigation(request.Context(), clusterID, input, server.mutationContext(request, key))
	if err != nil || !validAdminToken(result.ID) {
		refreshed, refreshErr := server.provider.LoadClusterOperations(request.Context(), clusterID)
		if refreshErr == nil {
			// Only a still-running investigation can be the durable result of this
			// start. A finished one is an earlier run, not this submission.
			if existing := latestEvidenceRepairInvestigation(refreshed.Investigations, glance.PrimaryIssue.ID, server.clock.Now().UTC(), 15*time.Minute); existing != nil && !investigationIsTerminal(existing.Status) {
				http.Redirect(writer, request, "/admin/clusters/"+url.PathEscape(clusterID)+"?repair_proposal_started="+url.QueryEscape(existing.ID), http.StatusSeeOther)
				return
			}
		}
		server.redirectRepairProposalFailure(writer, request, clusterID)
		return
	}
	http.Redirect(writer, request, "/admin/clusters/"+url.PathEscape(clusterID)+"?repair_proposal_started="+url.QueryEscape(result.ID), http.StatusSeeOther)
}

func (server *Server) redirectRepairProposalFailure(writer http.ResponseWriter, request *http.Request, clusterID string) {
	http.Redirect(writer, request, "/admin/clusters/"+url.PathEscape(clusterID)+"?repair_proposal_failed=1", http.StatusSeeOther)
}

func evidenceStreamBlocksCompleteness(stream EvidenceStreamHealth) bool {
	return stream.Status != "COMPLETE" || !strings.HasPrefix(stream.Condition, "complete ")
}

func blockingEvidenceStreams(streams []EvidenceStreamHealth) []EvidenceStreamHealth {
	result := make([]EvidenceStreamHealth, 0, len(streams))
	for _, stream := range streams {
		if evidenceStreamBlocksCompleteness(stream) {
			result = append(result, stream)
		}
	}
	return result
}

// previousID names the latest finished repair investigation for the incident,
// or is empty. It separates idempotency generations: repeated clicks while a
// run is in progress replay it, but once that run finishes the same warning
// set starts a new investigation instead of replaying the finished one.
func buildEvidenceRepairInvestigation(clusterID, incidentID string, streams []EvidenceStreamHealth, now time.Time, previousID string) InvestigationStart {
	entityKind, entityIDs := "cluster", []string{clusterID}
	maxFanOut := len(entityIDs)
	if maxFanOut < 1 {
		maxFanOut = 1
	}
	if maxFanOut > 256 {
		maxFanOut = 256
		entityIDs = entityIDs[:maxFanOut]
	}
	windowStart := now.Add(-evidenceRepairObservationWindow)
	for _, stream := range streams {
		if !stream.LatestAttempt.IsZero() && stream.LatestAttempt.Before(windowStart) {
			windowStart = stream.LatestAttempt
		}
	}
	proposalKey := evidenceRepairBatchKey(clusterID, streams)
	if previousID != "" {
		generation := sha256.Sum256([]byte(previousID))
		proposalKey += "-" + hex.EncodeToString(generation[:8])
	}
	return InvestigationStart{
		IncidentID: incidentID,
		Purpose:    domain.InvestigationPurposeRepairPlan,
		Question:   evidenceRepairQuestion(streams),
		EntityKind: entityKind,
		EntityIDs:  entityIDs,
		// This projection supplies a window hint. Durable repair admission freezes
		// the exact latest warnings and includes any older current stream omitted
		// by the UI projection. Cluster scope includes mixed node/GPU warnings.
		WindowStart: windowStart,
		WindowEnd:   now,
		SuccessCriteria: []string{
			"Separate cited observed facts, likely causes, unresolved unknowns, and hypotheses.",
			"Produce one deduplicated operator-ready repair plan that resolves as many current evidence warnings as possible in one coordinated change window.",
			"Identify shared root causes and shared dependencies first, then map every proposed action to each warning and target it is expected to resolve.",
			"Include safe read-only prechecks, verification commands or checks, expected results, risks, and rollback guidance.",
			"State explicitly that the output is a proposal only and that no repair or privileged action was executed.",
		},
		MaxDecisions:       evidenceRepairMaxDecisions,
		MaxToolCalls:       evidenceRepairMaxToolCalls,
		MaxDiagnosticCalls: evidenceRepairMaxDiagnosticCalls,
		MaxFanOut:          maxFanOut,
		MaxModelTokens:     evidenceRepairMaxModelTokens,
		MaxCostMicrounits:  evidenceRepairMaxCostMicrounits,
		Deadline:           now.Add(evidenceRepairDeadline),
		// Do not replay older requests that used the diagnostic investigation workflow.
		IdempotencyKey: "admin-ai-repair-v3-" + proposalKey,
	}
}

func evidenceRepairScope(clusterID string, streams []EvidenceStreamHealth) (string, []string) {
	candidates := evidenceRepairTargetCandidates(streams, false)
	if len(candidates) == 0 {
		candidates = evidenceRepairTargetCandidates(streams, true)
	}
	if len(candidates) == 0 {
		return "cluster", []string{clusterID}
	}
	counts := make(map[string]map[string]struct{})
	for _, target := range candidates {
		if counts[target.kind] == nil {
			counts[target.kind] = make(map[string]struct{})
		}
		counts[target.kind][target.id] = struct{}{}
	}
	kind := candidates[0].kind
	if len(counts["node"]) > 0 {
		kind = "node"
	} else {
		for candidateKind, ids := range counts {
			if len(ids) > len(counts[kind]) {
				kind = candidateKind
			}
		}
	}
	seen := make(map[string]struct{}, len(candidates))
	ids := make([]string, 0, len(candidates))
	for _, target := range candidates {
		if target.kind != kind {
			continue
		}
		if _, exists := seen[target.id]; exists {
			continue
		}
		seen[target.id] = struct{}{}
		ids = append(ids, target.id)
	}
	return kind, ids
}

type evidenceRepairTarget struct{ kind, id string }

func evidenceRepairTargetCandidates(streams []EvidenceStreamHealth, includeExpected bool) []evidenceRepairTarget {
	candidates := make([]evidenceRepairTarget, 0)
	for _, stream := range streams {
		targets := stream.MissingTargets
		if includeExpected && len(targets) == 0 {
			targets = stream.ExpectedTargets
		}
		for _, target := range targets {
			kind, id, found := strings.Cut(strings.TrimSpace(target), ":")
			kind, id = strings.ToLower(strings.TrimSpace(kind)), strings.TrimSpace(id)
			if !found || !validAdminToken(kind) || !validAdminToken(id) {
				continue
			}
			candidates = append(candidates, evidenceRepairTarget{kind: kind, id: id})
		}
	}
	return candidates
}

func evidenceRepairQuestion(streams []EvidenceStreamHealth) string {
	groups := groupEvidenceRepairs(streams)
	lines := make([]string, 0, len(groups))
	for index, group := range groups {
		targetText := "missing targets not identified"
		if len(group.targets) > 0 {
			targets := group.targets
			if len(targets) > 24 {
				targets = targets[:24]
			}
			targetText = strings.Join(targets, ", ")
			if len(group.targets) > len(targets) {
				targetText += fmt.Sprintf(", and %d more", len(group.targets)-len(targets))
			}
		}
		line := fmt.Sprintf("%d. %s | source %s | %s | %s | failure %s %s | suggested repair %s | missing targets %s",
			index+1, group.operation, group.sourceID, group.status, group.condition,
			group.failureCode, group.safeFailureReason, group.recommendedAction, targetText)
		lines = append(lines, boundedProposalText(line, 650))
	}
	facts := evidenceRepairQuestionPrefix + " Current blocker groups:\n" + strings.Join(lines, "\n")
	directive := " Find shared root causes and dependencies, deduplicate repeated work, order shared repairs before target-specific repairs, and map each action to every warning it should resolve. Maximize the number of warnings resolved in one safe change window. Include exact application, configuration, connectivity, or collector changes as appropriate, read-only prechecks, verification, risks, and rollback. Clearly name any residual warning that needs a separate change. Do not execute a repair, request privileged execution, or claim that any warning is fixed."
	return boundedProposalText(facts, 3500) + directive
}

type evidenceRepairGroup struct {
	sourceID, operation, status, condition, failureCode, safeFailureReason, recommendedAction string
	targets                                                                                   []string
}

func groupEvidenceRepairs(streams []EvidenceStreamHealth) []evidenceRepairGroup {
	groups := make([]evidenceRepairGroup, 0, len(streams))
	indexByKey := make(map[string]int)
	seenTargets := make(map[string]map[string]struct{})
	for _, stream := range streams {
		key := strings.Join([]string{stream.SourceID, stream.Operation, stream.Status, stream.Condition, stream.FailureCode, stream.SafeFailureReason, stream.RecommendedAction}, "\x00")
		index, found := indexByKey[key]
		if !found {
			index = len(groups)
			indexByKey[key] = index
			groups = append(groups, evidenceRepairGroup{sourceID: stream.SourceID, operation: stream.Operation, status: stream.Status, condition: stream.Condition, failureCode: stream.FailureCode, safeFailureReason: stream.SafeFailureReason, recommendedAction: stream.RecommendedAction})
			seenTargets[key] = make(map[string]struct{})
		}
		for _, target := range stream.MissingTargets {
			if _, exists := seenTargets[key][target]; exists {
				continue
			}
			seenTargets[key][target] = struct{}{}
			groups[index].targets = append(groups[index].targets, target)
		}
	}
	return groups
}

func latestEvidenceRepairInvestigation(investigations []Investigation, incidentID string, now time.Time, maximumAge time.Duration) *Investigation {
	var latest *Investigation
	for index := range investigations {
		investigation := &investigations[index]
		if investigation.IncidentID != incidentID || !strings.HasPrefix(investigation.Question, evidenceRepairQuestionPrefix) || investigation.UpdatedAt.Before(now.Add(-maximumAge)) {
			continue
		}
		if latest == nil || investigation.UpdatedAt.After(latest.UpdatedAt) {
			latest = investigation
		}
	}
	return latest
}

// latestFinishedEvidenceRepairInvestigation ignores age: a finished run keeps
// its idempotency key forever, so any later submission must move past it.
func latestFinishedEvidenceRepairInvestigation(investigations []Investigation, incidentID string) *Investigation {
	var latest *Investigation
	for index := range investigations {
		investigation := &investigations[index]
		if investigation.IncidentID != incidentID || !strings.HasPrefix(investigation.Question, evidenceRepairQuestionPrefix) || !investigationIsTerminal(investigation.Status) {
			continue
		}
		if latest == nil || investigation.UpdatedAt.After(latest.UpdatedAt) {
			latest = investigation
		}
	}
	return latest
}

func boundedProposalText(value string, maximum int) string {
	value = strings.ReplaceAll(value, "\x00", "")
	if len(value) <= maximum {
		return value
	}
	if maximum <= 3 {
		return value[:maximum]
	}
	cut := maximum - 3
	for cut > 0 && (value[cut]&0xc0) == 0x80 {
		cut--
	}
	return value[:cut] + "..."
}
