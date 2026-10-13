package investigationcontext

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

var (
	ErrEvidenceContextUnusable = errors.New("EVIDENCE_CONTEXT_UNUSABLE")
	ErrRequiredContextTooLarge = errors.New("REQUIRED_CONTEXT_EXCEEDS_ALLOWANCE")
)

type ExclusionReason string

const (
	ExcludeCluster              ExclusionReason = "CLUSTER_MISMATCH"
	ExcludeCommitBoundary       ExclusionReason = "COMMIT_BOUNDARY"
	ExcludeScope                ExclusionReason = "SCOPE_MISMATCH"
	ExcludeTime                 ExclusionReason = "TIME_MISMATCH"
	ExcludeRetention            ExclusionReason = "RETENTION"
	ExcludeArtifactAvailability ExclusionReason = "ARTIFACT_UNAVAILABLE"
	ExcludeAuthority            ExclusionReason = "EVIDENCE_AUTHORITY"
	ExcludeSuperseded           ExclusionReason = "SUPERSEDED"
	ExcludeTokenLimit           ExclusionReason = "TOKEN_LIMIT"
	ExcludeDiversity            ExclusionReason = "DIVERSITY_LIMIT"
	// ExcludeCoalesced marks a periodic sample merged into the span that
	// represents it. Nothing was dropped: the observation is still present.
	ExcludeCoalesced ExclusionReason = "COALESCED_PERIODIC_SAMPLE"
)

type RetrievalQuery struct {
	ClusterID       domain.ClusterID
	EntityIDs       []string
	Start           time.Time
	End             time.Time
	CommittedBefore time.Time
	Text            string
	EvidenceClasses []string
	AllowanceTokens int64
	// MaxSummaryBytes and MaxExcerptBytes mirror the context builder's limits.
	// Selection must cost what will actually be sent: an untruncated excerpt can
	// reach tens of kilobytes while the builder emits at most a couple, so
	// estimating the raw shape can price one mandatory item above the whole
	// allowance and fail a transition that would have fitted comfortably.
	MaxSummaryBytes int
	MaxExcerptBytes int
	// Diversity caps apply within an entity, not across the fleet.
	MaximumPerClass  int
	MaximumPerSource int
}

type RankedEvidence struct {
	Input           EvidenceInput
	Score           int64
	EstimatedTokens int64
	Mandatory       bool
}

type EvidenceExclusion struct {
	EvidenceID domain.EvidenceID `json:"evidence_id"`
	Reason     ExclusionReason   `json:"reason"`
}

type RetrievalResult struct {
	Selected   []EvidenceInput
	Ranked     []RankedEvidence
	AnchorIDs  []domain.EvidenceID
	Exclusions []EvidenceExclusion
	Tokens     int64
}

func SelectEvidence(candidates []EvidenceInput, query RetrievalQuery) (RetrievalResult, error) {
	if query.ClusterID == "" || len(query.EntityIDs) == 0 || query.Start.IsZero() || query.End.Before(query.Start) || query.CommittedBefore.IsZero() || query.AllowanceTokens < 1 {
		return RetrievalResult{}, fmt.Errorf("retrieval query is invalid")
	}
	if query.MaximumPerClass == 0 {
		query.MaximumPerClass = 8
	}
	if query.MaximumPerSource == 0 {
		query.MaximumPerSource = 8
	}
	allowedTargets := make(map[string]struct{}, len(query.EntityIDs)+1)
	for _, id := range query.EntityIDs {
		allowedTargets[id] = struct{}{}
	}
	allowedTargets[string(query.ClusterID)] = struct{}{}
	var result RetrievalResult
	seen := map[domain.EvidenceID]struct{}{}
	var authorized []EvidenceInput
	for _, candidate := range candidates {
		if _, duplicate := seen[candidate.EvidenceID]; duplicate {
			return RetrievalResult{}, fmt.Errorf("duplicate retrieval candidate %s", candidate.EvidenceID)
		}
		seen[candidate.EvidenceID] = struct{}{}
		if reason := hardFilter(candidate, query, allowedTargets); reason != "" {
			result.Exclusions = append(result.Exclusions, EvidenceExclusion{candidate.EvidenceID, reason})
			continue
		}
		if err := ValidateSemanticUsability(candidate); err != nil {
			if evidenceMandatory(candidate) {
				return RetrievalResult{}, err
			}
			result.Exclusions = append(result.Exclusions, EvidenceExclusion{candidate.EvidenceID, ExcludeAuthority})
			continue
		}
		authorized = append(authorized, candidate)
	}
	sourceCounts := map[string]int{}
	for _, candidate := range authorized {
		sourceCounts[candidate.Source]++
	}
	for _, candidate := range authorized {
		ranked := RankedEvidence{Input: candidate, Mandatory: evidenceMandatory(candidate)}
		ranked.Score = relevanceScore(candidate, query, sourceCounts[candidate.Source] == 1)
		result.Ranked = append(result.Ranked, ranked)
	}
	slices.SortFunc(result.Ranked, func(a, b RankedEvidence) int {
		if a.Mandatory != b.Mandatory {
			if a.Mandatory {
				return -1
			}
			return 1
		}
		if a.Score != b.Score {
			if a.Score > b.Score {
				return -1
			}
			return 1
		}
		return strings.Compare(string(a.Input.EvidenceID), string(b.Input.EvidenceID))
	})
	rankedInputs := make([]EvidenceInput, 0, len(result.Ranked))
	for _, item := range result.Ranked {
		rankedInputs = append(rankedInputs, item.Input)
	}
	result.AnchorIDs = canonicalAnchors(rankedInputs, query.EntityIDs)
	anchorSet := make(map[domain.EvidenceID]bool, len(result.AnchorIDs))
	for _, id := range result.AnchorIDs {
		anchorSet[id] = true
	}
	costs := map[domain.EvidenceID]int64{}
	for index := range result.Ranked {
		item := &result.Ranked[index]
		summaryLimit, excerptLimit := query.MaxSummaryBytes, query.MaxExcerptBytes
		if len(query.EntityIDs) > 1 && anchorSet[item.Input.EvidenceID] && !item.Mandatory {
			summaryLimit = anchorProjectionLimit(summaryLimit, anchorSummaryBytes)
			excerptLimit = anchorProjectionLimit(excerptLimit, anchorExcerptBytes)
		}
		encoded, _ := json.Marshal(candidatePromptShape(item.Input, summaryLimit, excerptLimit))
		item.EstimatedTokens = int64((len(encoded) + 3) / 4)
		costs[item.Input.EvidenceID] = item.EstimatedTokens
	}
	selectedIDs := map[domain.EvidenceID]bool{}
	for _, item := range result.Ranked {
		if !item.Mandatory {
			continue
		}
		if result.Tokens+item.EstimatedTokens > query.AllowanceTokens {
			return RetrievalResult{}, ErrRequiredContextTooLarge
		}
		result.Selected = append(result.Selected, item.Input)
		selectedIDs[item.Input.EvidenceID] = true
		result.Tokens += item.EstimatedTokens
	}
	for _, id := range result.AnchorIDs {
		if selectedIDs[id] {
			continue
		}
		if result.Tokens+costs[id] > query.AllowanceTokens {
			result.Exclusions = append(result.Exclusions, EvidenceExclusion{id, ExcludeTokenLimit})
			continue
		}
		for _, item := range result.Ranked {
			if item.Input.EvidenceID == id {
				result.Selected = append(result.Selected, item.Input)
				selectedIDs[id] = true
				result.Tokens += costs[id]
				break
			}
		}
	}
	type diversityKey struct{ entity, value string }
	classes, sources := map[diversityKey]int{}, map[diversityKey]int{}
	for _, item := range result.Selected {
		for _, entity := range item.EntityIDs {
			classes[diversityKey{entity, item.EvidenceClass}]++
			sources[diversityKey{entity, item.Source}]++
		}
	}
	var extras []EvidenceInput
	for _, item := range rankedInputs {
		if !anchorSet[item.EvidenceID] && !evidenceMandatory(item) {
			extras = append(extras, item)
		}
	}
	result.Selected = allocateEvidence(extras, query.EntityIDs, query.ClusterID, result.Selected, func(item EvidenceInput) bool {
		capacity := false
		for _, entity := range item.EntityIDs {
			if _, allowed := allowedTargets[entity]; allowed && classes[diversityKey{entity, item.EvidenceClass}] < query.MaximumPerClass && sources[diversityKey{entity, item.Source}] < query.MaximumPerSource {
				capacity = true
			}
		}
		if !capacity {
			result.Exclusions = append(result.Exclusions, EvidenceExclusion{item.EvidenceID, ExcludeDiversity})
			return false
		}
		if result.Tokens+costs[item.EvidenceID] > query.AllowanceTokens {
			result.Exclusions = append(result.Exclusions, EvidenceExclusion{item.EvidenceID, ExcludeTokenLimit})
			return false
		}
		result.Tokens += costs[item.EvidenceID]
		for _, entity := range item.EntityIDs {
			classes[diversityKey{entity, item.EvidenceClass}]++
			sources[diversityKey{entity, item.Source}]++
		}
		return true
	})
	slices.SortFunc(result.Exclusions, func(a, b EvidenceExclusion) int {
		return strings.Compare(string(a.EvidenceID), string(b.EvidenceID))
	})
	return result, nil
}

func ValidateSemanticUsability(input EvidenceInput) error {
	summary := strings.ToLower(strings.TrimSpace(input.Summary))
	generic := summary == "" || summary == "validated immutable evidence is available under this evidence id." || summary == "validated evidence is available under this evidence id."
	if (generic || input.SummaryQuality == "PROVENANCE_ONLY") && strings.TrimSpace(input.Excerpt) == "" {
		return fmt.Errorf("%w: evidence %s has neither a semantic summary nor bounded detail", ErrEvidenceContextUnusable, input.EvidenceID)
	}
	return nil
}

func hardFilter(value EvidenceInput, query RetrievalQuery, targets map[string]struct{}) ExclusionReason {
	if value.ClusterID != query.ClusterID {
		return ExcludeCluster
	}
	// The durable store is the sole authority for the post-request diagnostic
	// exception. It sets AdmittedPostRequestDiagnostic only after reconstructing
	// the exact investigation/action/run/attempt/target/evidence chain. Retrieval
	// preserves that decision, but the marker bypasses no other hard filter.
	if value.CommittedAt.IsZero() || (value.CommittedAt.After(query.CommittedBefore) && !value.AdmittedPostRequestDiagnostic) {
		return ExcludeCommitBoundary
	}
	if !value.CitationEligible {
		return ExcludeAuthority
	}
	if value.Superseded {
		return ExcludeSuperseded
	}
	if !value.Retained {
		return ExcludeRetention
	}
	if strings.TrimSpace(value.Excerpt) != "" && !value.ArtifactAvailable {
		return ExcludeArtifactAvailability
	}
	intersects := false
	for _, id := range value.EntityIDs {
		if _, ok := targets[id]; ok {
			intersects = true
			break
		}
	}
	if !intersects {
		return ExcludeScope
	}
	if !value.AdmittedPostRequestDiagnostic && (value.ObservedTo.Before(query.Start) || value.ObservedFrom.After(query.End)) {
		return ExcludeTime
	}
	return ""
}

func relevanceScore(value EvidenceInput, query RetrievalQuery, sourceNovel bool) int64 {
	var score int64
	if value.Latest {
		score += 1_000_000
	}
	if value.Protected {
		score += 100_000
	}
	if slices.Contains(query.EvidenceClasses, value.EvidenceClass) {
		score += 10_000
	}
	if sourceNovel {
		score += 5
	}
	queryTargets, overlap := map[string]struct{}{}, 0
	for _, id := range query.EntityIDs {
		queryTargets[id] = struct{}{}
	}
	for _, id := range value.EntityIDs {
		if _, ok := queryTargets[id]; ok {
			overlap++
		}
	}
	score += int64(100 * (1000 * overlap / max(1, len(queryTargets))))
	overlapStart, overlapEnd := value.ObservedFrom, value.ObservedTo
	if query.Start.After(overlapStart) {
		overlapStart = query.Start
	}
	if query.End.Before(overlapEnd) {
		overlapEnd = query.End
	}
	if query.End.Equal(query.Start) && !value.ObservedFrom.After(query.Start) && !value.ObservedTo.Before(query.Start) {
		score += 10 * 1000
	} else if !overlapEnd.Before(overlapStart) {
		denominator := max(time.Nanosecond, query.End.Sub(query.Start))
		score += int64(10 * (1000 * overlapEnd.Sub(overlapStart) / denominator))
	}
	age := query.CommittedBefore.Sub(value.CommittedAt)
	switch {
	case age <= time.Hour:
		score += 4
	case age <= 24*time.Hour:
		score += 3
	case age <= 7*24*time.Hour:
		score += 2
	case age <= 30*24*time.Hour:
		score++
	}
	return score
}

// candidatePromptShape approximates the block the builder will emit for this
// evidence, including the truncation the builder always applies. A zero cap
// means the caller did not constrain that field.
func candidatePromptShape(value EvidenceInput, maxSummaryBytes, maxExcerptBytes int) any {
	summary, excerpt := value.Summary, value.Excerpt
	if maxSummaryBytes > 0 {
		summary, _ = truncateUTF8(summary, maxSummaryBytes)
	}
	if maxExcerptBytes > 0 {
		excerpt, _ = truncateUTF8(excerpt, maxExcerptBytes)
	}
	return struct {
		ID, Status, Source, Summary, Detail string
		Targets                             []string
	}{string(value.EvidenceID), string(value.Status), value.Source, summary, excerpt, value.EntityIDs}
}
