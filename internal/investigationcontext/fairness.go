package investigationcontext

import (
	"slices"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

// canonicalAnchors chooses one ranked, eligible item for each named scope
// entity. An item shared by targets is counted once; cluster-only evidence
// never substitutes for a node or GPU anchor.
func canonicalAnchors(candidates []EvidenceInput, scope []string) []domain.EvidenceID {
	entities := slices.Clone(scope)
	slices.Sort(entities)
	entities = slices.Compact(entities)
	var result []domain.EvidenceID
	for _, entity := range entities {
		for _, item := range candidates {
			if slices.Contains(item.EntityIDs, entity) {
				if !slices.Contains(result, item.EvidenceID) {
					result = append(result, item.EvidenceID)
				}
				break
			}
		}
	}
	return result
}

const (
	anchorSummaryBytes = 128
	anchorExcerptBytes = 64
)

func anchorProjectionLimit(configured, anchor int) int {
	if configured <= 0 {
		return configured
	}
	return min(configured, anchor)
}

// allocateEvidence consumes candidates in relevance order within each entity.
// Mandatory items precede allocation and count toward every entity they name.
// The least represented entity gets the next turn; ties use sorted scope IDs.
// A multi-entity item is selected once and credits each explicitly named entity.
// Cluster-only evidence occupies a separate bucket after scope entities on ties:
// it never stands in for evidence about a node. In cluster scope it is the sole
// bucket. Rejected candidates consume no entity budget.
func allocateEvidence(candidates []EvidenceInput, scope []string, cluster domain.ClusterID, initial []EvidenceInput, admit func(EvidenceInput) bool) []EvidenceInput {
	entities := slices.Clone(scope)
	slices.Sort(entities)
	entities = slices.Compact(entities)
	if !slices.Contains(entities, string(cluster)) {
		entities = append(entities, string(cluster))
	}
	counts := map[string]int{}
	used := make([]bool, len(candidates))
	selected := slices.Clone(initial)
	for _, item := range initial {
		for index, candidate := range candidates {
			if candidate.EvidenceID == item.EvidenceID {
				used[index] = true
				break
			}
		}
		for _, entity := range entities {
			if slices.Contains(item.EntityIDs, entity) {
				counts[entity]++
			}
		}
	}
	accept := func(index int) {
		used[index] = true
		item := candidates[index]
		if !admit(item) {
			return
		}
		selected = append(selected, item)
		for _, entity := range entities {
			if slices.Contains(item.EntityIDs, entity) {
				counts[entity]++
			}
		}
	}
	for index, item := range candidates {
		if evidenceMandatory(item) && !used[index] {
			accept(index)
		}
	}
	for {
		next, least := -1, int(^uint(0)>>1)
		for _, entity := range entities {
			if counts[entity] >= least {
				continue
			}
			for index, item := range candidates {
				if !used[index] && slices.Contains(item.EntityIDs, entity) {
					next, least = index, counts[entity]
					break
				}
			}
		}
		if next < 0 {
			return selected
		}
		accept(next)
	}
}

// OptionalEvidenceRemovalIndex reverses allocation without losing an entity's
// only item while another removable item can reduce redundant representation.
// Required items are never removed. If only required duplicates remain, they
// cannot justify removing a singleton either: the context must fail closed.
func (context Context) OptionalEvidenceRemovalIndex() int {
	counts := map[string]int{}
	for _, item := range context.Evidence {
		for _, entity := range item.EntityIDs {
			counts[entity]++
		}
	}
	duplicates := false
	for _, count := range counts {
		duplicates = duplicates || count > 1
	}
	for index := len(context.Evidence) - 1; index >= 0; index-- {
		item := context.Evidence[index]
		if item.Required {
			continue
		}
		removable := true
		for _, entity := range item.EntityIDs {
			if duplicates && counts[entity] == 1 {
				removable = false
				break
			}
		}
		if removable {
			return index
		}
	}
	return -1
}
