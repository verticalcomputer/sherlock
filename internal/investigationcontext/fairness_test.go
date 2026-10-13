package investigationcontext

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

func fleetEvidence(entities, classes int) (Input, RetrievalQuery) {
	now := time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
	input := Input{InvestigationID: "investigation-fleet", ClusterID: "cluster-a", Question: "Assess every node", Scope: domain.InvestigationScope{EntityKind: "node", Start: now.Add(-time.Hour), End: now}}
	for entity := 0; entity < entities; entity++ {
		id := fmt.Sprintf("node-%03d", entity)
		input.Scope.EntityIDs = append(input.Scope.EntityIDs, id)
		for class := 0; class < classes; class++ {
			item := evidenceCandidate(now, fmt.Sprintf("ev-%03d-%03d", entity, class), "shared-source", false)
			item.EntityIDs = []string{id}
			item.EvidenceClass = fmt.Sprintf("class-%d", class)
			item.KeepDistinct = true
			target := domain.EvidenceTarget{Kind: domain.EvidenceTargetNode, ID: domain.EvidenceTargetID(id)}
			item.Coverage = domain.EvidenceCoverage{Expected: []domain.EvidenceTarget{target}, Covered: []domain.EvidenceTarget{target}}
			input.Evidence = append(input.Evidence, item)
		}
	}
	query := RetrievalQuery{ClusterID: input.ClusterID, EntityIDs: input.Scope.EntityIDs, Start: input.Scope.Start, End: now, CommittedBefore: now, AllowanceTokens: 100_000, EvidenceClasses: []string{"class-0"}}
	return input, query
}

func TestFleetRetrievalAllocatesOnePerEntityBeforeSecond(t *testing.T) {
	input, query := fleetEvidence(10, 4)
	all, err := SelectEvidence(input.Evidence, query)
	if err != nil {
		t.Fatal(err)
	}
	if len(all.Selected) != 40 {
		t.Fatalf("fleet hit a global class/source cap: selected %d", len(all.Selected))
	}
	query.AllowanceTokens = all.Ranked[0].EstimatedTokens * 15
	selected, err := SelectEvidence(input.Evidence, query)
	if err != nil {
		t.Fatal(err)
	}
	if len(selected.Selected) != 15 {
		t.Fatalf("selected %d, want 15", len(selected.Selected))
	}
	for index, item := range selected.Selected[:10] {
		if item.EntityIDs[0] != input.Scope.EntityIDs[index] || item.EvidenceClass != "class-0" {
			t.Fatalf("first round did not give each entity its most relevant item: %+v", selected.Selected)
		}
	}
	for seed := int64(0); seed < 20; seed++ {
		shuffled := slices.Clone(input.Evidence)
		rand.New(rand.NewSource(seed)).Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
		got, err := SelectEvidence(shuffled, query)
		if err != nil || !reflect.DeepEqual(got, selected) {
			t.Fatalf("candidate shuffle %d changed retrieval: %v", seed, err)
		}
	}
	input.SelectionLosses = selectionLosses(selected, input.Evidence)
	input.Evidence = selected.Selected
	input.EvidenceAnchors = selected.AnchorIDs
	limits := DefaultLimits()
	limits.MaxEvidence = 15
	context, err := mustBuilder(t, limits).Build(input)
	if err != nil {
		t.Fatal(err)
	}
	assertFleetCoverage(t, context, 10, 15)
	if context.EncodedBytes > 32<<10 {
		t.Fatalf("ten-node first round exceeded existing byte cap: %d", context.EncodedBytes)
	}
}

func TestFleetBuilderPreservesEntityCoverageAtItemAndByteLimits(t *testing.T) {
	for _, entities := range []int{10, 50} {
		t.Run(fmt.Sprintf("entities-%d", entities), func(t *testing.T) {
			input, query := fleetEvidence(entities, 4)
			for index := range input.Evidence {
				input.Evidence[index].Excerpt = strings.Repeat("x", 512)
			}
			selection, err := SelectEvidence(input.Evidence, query)
			if err != nil {
				t.Fatal(err)
			}
			input.Evidence = selection.Selected
			input.EvidenceAnchors = selection.AnchorIDs
			for _, item := range selection.Selected {
				input.EvidenceAllocation = append(input.EvidenceAllocation, item.EvidenceID)
			}
			limits := DefaultLimits()
			limits.MaxEncodedBytes, limits.MaxEvidence = 1<<20, entities+entities/2
			limited, err := mustBuilder(t, limits).Build(input)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("fleet=%d item-cap=%d encoded=%d represented=%d", entities, limits.MaxEvidence, limited.EncodedBytes, len(limited.Evidence))
			assertFleetCoverage(t, limited, entities, entities+entities/2)
			// Leave room for the same blocks plus changed omission metadata.
			// Byte compaction, rather than the item cap, must now thin the fleet.
			limits.MaxEncodedBytes, limits.MaxEvidence = limited.EncodedBytes+256, 256
			compacted, err := mustBuilder(t, limits).Build(input)
			if err != nil {
				t.Fatal(err)
			}
			// Omission detail currently consumes bytes before it is capped (T2).
			// Regardless of that overhead, thinning must preserve every entity.
			if len(compacted.Evidence) < entities || len(compacted.Evidence) >= entities*2 {
				t.Fatalf("unexpected byte-limited fleet size: %d", len(compacted.Evidence))
			}
			assertFleetCoverage(t, compacted, entities, len(compacted.Evidence))
			if compacted.EncodedBytes > limits.MaxEncodedBytes {
				t.Fatalf("encoded ceiling exceeded: %d", compacted.EncodedBytes)
			}
			for index, item := range compacted.Evidence {
				if item.EvidenceID != input.Evidence[index].EvidenceID {
					t.Fatalf("byte trimming did not reverse allocation at item %d", index)
				}
			}
			shuffled := input
			shuffled.Evidence = slices.Clone(input.Evidence)
			slices.Reverse(shuffled.Evidence)
			again, err := mustBuilder(t, limits).Build(shuffled)
			left, _ := json.Marshal(compacted)
			right, _ := json.Marshal(again)
			if err != nil || !slices.Equal(left, right) {
				t.Fatalf("builder did not preserve deterministic retrieval allocation: %v", err)
			}
		})
	}
}

func TestFiftyEntityFleetThinsHonestlyAtComposedProductionAllowance(t *testing.T) {
	if DefaultLimits().MaxEvidence < 50 {
		t.Fatalf("default item cap %d structurally prevents a fitting 50-anchor first round", DefaultLimits().MaxEvidence)
	}
	input, query := fleetEvidence(50, 4)
	for index := range input.Evidence {
		input.Evidence[index].Excerpt = strings.Repeat("x", 512)
	}
	// The composition root uses max(4000, (ContextMaxTokens-MemoryMaxTokens)/2).
	// The deployment record's 48k/1k configuration gives 23,500 tokens.
	query.AllowanceTokens = 23_500
	selection, err := SelectEvidence(input.Evidence, query)
	if err != nil {
		t.Fatal(err)
	}
	if len(selection.AnchorIDs) != 50 {
		t.Fatalf("expected a canonical anchor for every node, got %d", len(selection.AnchorIDs))
	}
	input.SelectionLosses = selectionLosses(selection, input.Evidence)
	input.Evidence = selection.Selected
	input.EvidenceAnchors = selection.AnchorIDs
	for _, item := range selection.Selected {
		input.EvidenceAllocation = append(input.EvidenceAllocation, item.EvidenceID)
	}
	fitLimits := DefaultLimits()
	fitLimits.MaxEvidence, fitLimits.MaxEncodedBytes = 50, 1<<20
	fitting, err := mustBuilder(t, fitLimits).Build(input)
	if err != nil {
		t.Fatal(err)
	}
	assertFleetCoverage(t, fitting, 50, 50)
	t.Logf("50 canonical anchors and exact omissions need %d fixed-point JSON bytes", fitting.EncodedBytes)
	context, err := mustBuilder(t, DefaultLimits()).Build(input)
	if err != nil {
		t.Fatal(err)
	}
	represented := map[string]bool{}
	for _, block := range context.Evidence {
		for _, id := range block.EntityIDs {
			represented[id] = true
		}
	}
	omitted := map[string]bool{}
	for _, omission := range context.Omissions {
		if omission.Kind != OmissionKindEvidence || !OmissionLosesInformation(omission) {
			continue
		}
		for _, id := range omission.EntityIDs {
			if !represented[id] {
				omitted[id] = true
			}
		}
	}
	t.Logf("50x4 at 23500 tokens and 32768 bytes: retrieved=%d retrieval_tokens=%d selected=%d represented=%d omitted=%d encoded=%d", len(selection.Selected), selection.Tokens, len(context.Evidence), len(represented), len(omitted), context.EncodedBytes)
	if len(represented) < 40 || len(represented) >= 50 || len(represented)+len(omitted) != 50 || context.EncodedBytes > DefaultLimits().MaxEncodedBytes {
		t.Fatalf("fleet did not thin honestly: represented=%d omitted=%d encoded=%d omissions=%+v", len(represented), len(omitted), context.EncodedBytes, context.Omissions)
	}
}

func assertFleetCoverage(t *testing.T, value Context, entities, expectedItems int) {
	t.Helper()
	counts := map[string]int{}
	for _, item := range value.Evidence {
		for _, entity := range item.EntityIDs {
			counts[entity]++
		}
	}
	if len(value.Evidence) != expectedItems || len(counts) != entities {
		t.Fatalf("selected %d items across %d entities, want %d across %d", len(value.Evidence), len(counts), expectedItems, entities)
	}
	for entity, count := range counts {
		if count < 1 || count > 2 {
			t.Fatalf("%s received %d items instead of thinner fleet coverage", entity, count)
		}
	}
}

func TestEntityAllocationMandatoryMultiTargetAndClusterRules(t *testing.T) {
	input, query := fleetEvidence(3, 2)
	input.Evidence[0].Protected = true
	input.Evidence[1].Latest, input.Evidence[1].KeepDistinct = true, false
	cluster := input.Evidence[2]
	cluster.EvidenceID, cluster.EntityIDs = "ev-cluster", []string{"cluster-a"}
	input.Evidence = append(input.Evidence, cluster)
	selection, err := SelectEvidence(input.Evidence, query)
	if err != nil {
		t.Fatal(err)
	}
	if !evidenceMandatory(selection.Selected[0]) || !evidenceMandatory(selection.Selected[1]) || selection.Selected[2].EntityIDs[0] != "node-001" || selection.Selected[3].EntityIDs[0] != "node-002" || selection.Selected[4].EvidenceID != "ev-cluster" {
		t.Fatalf("mandatory or cluster allocation order: %v", selectedIDs(selection.Selected))
	}
	// The builder must accept the same cluster evidence as retrieval.
	input.Evidence = selection.Selected
	if _, err := mustBuilder(t, DefaultLimits()).Build(input); err != nil {
		t.Fatal(err)
	}
	query.AllowanceTokens = 1
	if _, err := SelectEvidence(input.Evidence, query); !errors.Is(err, ErrRequiredContextTooLarge) {
		t.Fatalf("mandatory evidence must fail closed: %v", err)
	}
	input, query = fleetEvidence(3, 2)
	input.Evidence[0].EntityIDs = []string{"node-000", "node-001"}
	selection, err = SelectEvidence(input.Evidence, query)
	if err != nil || selection.Selected[1].EntityIDs[0] != "node-002" {
		t.Fatalf("multi-target evidence was not credited to both entities: %v %v", selectedIDs(selection.Selected), err)
	}
}

func TestOptionalRemovalProtectsSingletonsAndMandatoryEvidence(t *testing.T) {
	value := Context{Evidence: []EvidenceBlock{
		{EvidenceID: "a-first", EntityIDs: []string{"a"}, Required: true},
		{EvidenceID: "a-last", EntityIDs: []string{"a"}},
		{EvidenceID: "b-only", EntityIDs: []string{"b"}},
	}}
	if index := value.OptionalEvidenceRemovalIndex(); index != 1 {
		t.Fatalf("removed singleton instead of entity's last item: %d", index)
	}
	value.Evidence[1].Required = true
	if index := value.OptionalEvidenceRemovalIndex(); index != -1 {
		t.Fatalf("required duplicates cannot justify dropping another entity: %d", index)
	}
}

func TestDeduplicationDoesNotEraseDistinctEntityProjections(t *testing.T) {
	input, _ := fleetEvidence(2, 1)
	for index := range input.Evidence {
		input.Evidence[index].KeepDistinct = false
		input.Evidence[index].Coverage = input.Evidence[0].Coverage
	}
	context, err := mustBuilder(t, DefaultLimits()).Build(input)
	if err != nil {
		t.Fatal(err)
	}
	assertFleetCoverage(t, context, 2, 2)
}

func TestRetrievalCanonicalRelevanceMayThinWhenCheaperCoverFits(t *testing.T) {
	input, query := fleetEvidence(10, 1)
	// A cheaper noncanonical cover fits 480 tokens, but the first node's
	// highest-relevance canonical anchor costs 304. The fit promise applies
	// to that canonical set, which needs 736 tokens.
	setCost := func(item *EvidenceInput, tokens int64) {
		t.Helper()
		item.Summary, item.Excerpt = "usable", ""
		encoded, _ := json.Marshal(candidatePromptShape(*item, 0, 0))
		padding := int(tokens)*4 - len(encoded)
		if padding < 0 {
			t.Fatalf("fixture cannot fit %d tokens", tokens)
		}
		item.Excerpt = strings.Repeat("x", padding)
	}
	for index := range input.Evidence {
		setCost(&input.Evidence[index], 48)
	}
	expensive := input.Evidence[0]
	expensive.EvidenceID, expensive.EvidenceClass = "ev-000-hot", "preferred"
	setCost(&expensive, 304)
	input.Evidence = append(input.Evidence, expensive)
	query.EvidenceClasses, query.AllowanceTokens = []string{"preferred"}, 480
	for seed := int64(0); seed < 20; seed++ {
		shuffled := slices.Clone(input.Evidence)
		rand.New(rand.NewSource(seed)).Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
		result, err := SelectEvidence(shuffled, query)
		if err != nil {
			t.Fatal(err)
		}
		if len(result.Selected) != 4 || result.Tokens != 448 || result.Selected[0].EvidenceID != expensive.EvidenceID {
			t.Fatalf("canonical anchors exceeded or ignored the allowance: selected=%v tokens=%d", selectedIDs(result.Selected), result.Tokens)
		}
		if len(result.Exclusions) == 0 {
			t.Fatal("unselected committed anchors must have capacity exclusions")
		}
	}
	// Once the canonical set fits, every node is represented.
	query.AllowanceTokens = 304 + 9*48
	result, err := SelectEvidence(input.Evidence, query)
	if err != nil || len(result.Selected) != 10 || result.Selected[0].EvidenceID != expensive.EvidenceID {
		t.Fatalf("feasible relevance upgrade rejected: %v %v", selectedIDs(result.Selected), err)
	}
}

func TestCanonicalAnchorsCountSharedItemsOnce(t *testing.T) {
	candidates := []EvidenceInput{
		{EvidenceID: "both", EntityIDs: []string{"a", "b"}},
		{EvidenceID: "c", EntityIDs: []string{"c"}},
	}
	if got := canonicalAnchors(candidates, []string{"c", "b", "a"}); !slices.Equal(got, []domain.EvidenceID{"both", "c"}) {
		t.Fatalf("shared canonical anchor double-counted: %v", got)
	}
}

func TestMissingSourceEntityIsNotMisreportedAsCapacityOmission(t *testing.T) {
	input, query := fleetEvidence(3, 1)
	input.Evidence = input.Evidence[:2]
	selection, err := SelectEvidence(input.Evidence, query)
	if err != nil {
		t.Fatal(err)
	}
	if len(selection.AnchorIDs) != 2 || len(selection.Exclusions) != 0 {
		t.Fatalf("missing source was treated as an omitted anchor: anchors=%v exclusions=%v", selection.AnchorIDs, selection.Exclusions)
	}
	input.Evidence = selection.Selected
	input.EvidenceAnchors = selection.AnchorIDs
	context, err := mustBuilder(t, DefaultLimits()).Build(input)
	if err != nil {
		t.Fatal(err)
	}
	for _, omission := range context.Omissions {
		if slices.Contains(omission.EntityIDs, "node-002") {
			t.Fatalf("missing source entity mislabeled as capacity loss: %+v", context.Omissions)
		}
	}
}

func TestStandaloneBuilderRanksMandatoryBeforeOptionalAnchor(t *testing.T) {
	input, _ := fleetEvidence(2, 1)
	mandatoryA := input.Evidence[0]
	mandatoryA.Protected = true
	mandatoryA.KeepDistinct = true
	optionalA := mandatoryA
	optionalA.EvidenceID = "optional-a"
	optionalA.Protected = false
	optionalA.Latest = true // higher relevance score than protected A
	input.Evidence = []EvidenceInput{optionalA, input.Evidence[1], mandatoryA}
	limits := DefaultLimits()
	limits.MaxEvidence = 2
	context, err := mustBuilder(t, limits).Build(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(context.Evidence) != 2 || context.Evidence[0].EvidenceID != mandatoryA.EvidenceID || context.Evidence[1].EntityIDs[0] != "node-001" {
		t.Fatalf("optional A displaced fitting mandatory A + node B anchors: %v", context.Evidence)
	}
}

func TestSharedCanonicalAnchorsNeedNotUseCheaperNoncanonicalPair(t *testing.T) {
	input, query := fleetEvidence(4, 1)
	abc, ab, cd := input.Evidence[0], input.Evidence[1], input.Evidence[2]
	abc.EvidenceID, abc.EntityIDs = "abc", input.Scope.EntityIDs[:3]
	ab.EvidenceID, ab.EntityIDs = "ab", input.Scope.EntityIDs[:2]
	cd.EvidenceID, cd.EntityIDs = "cd", input.Scope.EntityIDs[2:]
	setCost := func(item *EvidenceInput, tokens int64) {
		t.Helper()
		item.Summary, item.Excerpt = "usable", ""
		encoded, _ := json.Marshal(candidatePromptShape(*item, 0, 0))
		padding := int(tokens)*4 - len(encoded)
		if padding < 0 {
			t.Fatalf("fixture cannot fit %d tokens", tokens)
		}
		item.Excerpt = strings.Repeat("x", padding)
	}
	setCost(&abc, 80)
	setCost(&ab, 60)
	setCost(&cd, 60)
	input.Evidence = []EvidenceInput{abc, ab, cd}
	query.AllowanceTokens = 120
	for seed := int64(0); seed < 12; seed++ {
		shuffled := slices.Clone(input.Evidence)
		rand.New(rand.NewSource(seed)).Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
		got, err := SelectEvidence(shuffled, query)
		if err != nil || !slices.Equal(selectedIDs(got.Selected), []domain.EvidenceID{"abc"}) || got.Tokens != 80 || len(got.Exclusions) == 0 {
			t.Fatalf("noncanonical shared cover displaced highest-relevance anchor: selected=%v tokens=%d err=%v", selectedIDs(got.Selected), got.Tokens, err)
		}
	}
}

func TestByteCompactionKeepsFittingProjectedCanonicalFirstRound(t *testing.T) {
	input, query := fleetEvidence(2, 1)
	for index := range input.Evidence {
		input.Evidence[index].Summary = "usable"
		input.Evidence[index].Excerpt = ""
	}
	expensive := input.Evidence[0]
	expensive.EvidenceID = "ev-000-preferred"
	expensive.EvidenceClass = "preferred"
	expensive.Excerpt = strings.Repeat("x", 2048)
	input.Evidence = append(input.Evidence, expensive)
	query.EvidenceClasses = []string{"preferred"}
	selection, err := SelectEvidence(input.Evidence, query)
	if err != nil {
		t.Fatal(err)
	}
	if len(selection.Selected) != 3 || selection.Selected[0].EvidenceID != expensive.EvidenceID {
		t.Fatalf("fixture must admit the preferred large block first: %v", selectedIDs(selection.Selected))
	}
	limits := DefaultLimits()
	limits.MaxEncodedBytes = 3009
	cheap := input
	cheap.Evidence = input.Evidence[:2]
	if baseline, err := mustBuilder(t, limits).Build(cheap); err != nil || len(baseline.Evidence) != 2 {
		t.Fatalf("cheap coverage must fit the encoded bound: bytes=%d error=%v", baseline.EncodedBytes, err)
	}
	input.Evidence = selection.Selected
	for _, item := range selection.Selected {
		input.EvidenceAllocation = append(input.EvidenceAllocation, item.EvidenceID)
	}
	context, err := mustBuilder(t, limits).Build(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(context.Evidence) != 3 || context.Evidence[0].EvidenceID != expensive.EvidenceID || !context.Evidence[0].ExcerptTruncated {
		t.Fatalf("fitting canonical anchor or its truncation was lost: %v", context.Evidence)
	}
	if !slices.Contains(context.Evidence[1].EntityIDs, "node-001") {
		t.Fatalf("second node lost despite fitting canonical anchors: %v", context.Evidence)
	}
	if context.EncodedBytes > limits.MaxEncodedBytes {
		t.Fatalf("compacted context exceeded bound: %d", context.EncodedBytes)
	}
}

func TestByteCompactionIncludesSelectionOmissionOverhead(t *testing.T) {
	input, query := fleetEvidence(2, 1)
	large := input.Evidence[0]
	large.EvidenceID, large.EvidenceClass = "preferred-large", "preferred"
	large.Excerpt = strings.Repeat("x", 2048)
	input.Evidence = append(input.Evidence, large)
	for index := 0; index < 8; index++ {
		input.SelectionLosses = append(input.SelectionLosses, SelectionLoss{
			EvidenceID: domain.EvidenceID(fmt.Sprintf("omitted-%03d", index)),
			EntityIDs:  []string{input.Scope.EntityIDs[index%2]}, Reason: OmissionItemLimit,
		})
	}
	query.EvidenceClasses = []string{"preferred"}
	selection, err := SelectEvidence(input.Evidence, query)
	if err != nil {
		t.Fatal(err)
	}
	cheap := input
	cheap.Evidence = input.Evidence[:2]
	wide := DefaultLimits()
	wide.MaxEncodedBytes = 1 << 20
	baseline, err := mustBuilder(t, wide).Build(cheap)
	if err != nil {
		t.Fatal(err)
	}
	limits := DefaultLimits()
	limits.MaxEncodedBytes = baseline.EncodedBytes + 64
	input.Evidence = selection.Selected
	for _, item := range selection.Selected {
		input.EvidenceAllocation = append(input.EvidenceAllocation, item.EvidenceID)
	}
	context, err := mustBuilder(t, limits).Build(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(context.Evidence) != 2 || context.Evidence[0].EvidenceID != large.EvidenceID || !context.Evidence[0].ExcerptTruncated {
		t.Fatalf("omission overhead displaced a fitting projected canonical set: %v", context.Evidence)
	}
	if context.EncodedBytes > limits.MaxEncodedBytes {
		t.Fatalf("omission rows pushed coverage beyond encoded limit: %d > %d", context.EncodedBytes, limits.MaxEncodedBytes)
	}
}

// T2: evidence depth and omission counts/entities are controller-required
// honesty. Sample IDs are useful detail, but must never spend bytes that would
// otherwise retain an evidence block. The wide measurement uses the complete
// fixed-point JSON, including all omission fields and encoded_bytes itself.
func TestOmissionSamplesYieldBeforeEvidenceDepthAtFleetScale(t *testing.T) {
	for _, entities := range []int{10, 50} {
		t.Run(fmt.Sprintf("entities-%d", entities), func(t *testing.T) {
			input, _ := fleetEvidence(entities, 4)
			for _, item := range input.Evidence {
				input.EvidenceAllocation = append(input.EvidenceAllocation, item.EvidenceID)
			}
			input.EvidenceAnchors = canonicalAnchors(input.Evidence, input.Scope.EntityIDs)

			withSamples := input
			withoutSamples := input
			for entity := 0; entity < entities; entity++ {
				for class := 0; class < 4; class++ {
					loss := SelectionLoss{
						EvidenceID: domain.EvidenceID(fmt.Sprintf("omitted-%03d-%03d", entity, class)),
						EntityIDs:  []string{input.Scope.EntityIDs[entity]},
						Reason:     OmissionItemLimit,
					}
					withSamples.SelectionLosses = append(withSamples.SelectionLosses, loss)
					loss.EvidenceID = "" // Same count and affected entities, no sample detail.
					withoutSamples.SelectionLosses = append(withoutSamples.SelectionLosses, loss)
				}
			}

			wide := DefaultLimits()
			wide.MaxEncodedBytes, wide.MaxEvidence = 1<<20, len(input.Evidence)
			base, err := mustBuilder(t, wide).Build(withoutSamples)
			if err != nil {
				t.Fatal(err)
			}
			detailed, err := mustBuilder(t, wide).Build(withSamples)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("fleet=%d evidence=%d omission-count=%d fixed-point bytes: counts-and-entities=%d with-16-samples=%d (+%d)", entities, len(input.Evidence), entities*4, base.EncodedBytes, detailed.EncodedBytes, detailed.EncodedBytes-base.EncodedBytes)

			limits := wide
			limits.MaxEncodedBytes = base.EncodedBytes + 8
			baseline, err := mustBuilder(t, limits).Build(withoutSamples)
			if err != nil {
				t.Fatal(err)
			}
			if detailed.EncodedBytes <= limits.MaxEncodedBytes {
				t.Fatalf("fixture did not require sample guard: detailed=%d ceiling=%d", detailed.EncodedBytes, limits.MaxEncodedBytes)
			}
			guarded, err := mustBuilder(t, limits).Build(withSamples)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(selectedIDsFromBlocks(guarded.Evidence), selectedIDsFromBlocks(baseline.Evidence)) {
				t.Fatalf("sample detail displaced evidence: with=%v without=%v", selectedIDsFromBlocks(guarded.Evidence), selectedIDsFromBlocks(baseline.Evidence))
			}
			for _, omission := range guarded.Omissions {
				if omission.Kind == OmissionKindEvidence && omission.Reason == OmissionItemLimit {
					if omission.Count != entities*4 || !slices.Equal(omission.EntityIDs, input.Scope.EntityIDs) {
						t.Fatalf("guard lost omission honesty: %+v", omission)
					}
					if len(omission.SampleIDs) != 0 {
						t.Fatalf("binding cap retained sample detail before evidence budget: %+v", omission.SampleIDs)
					}
					return
				}
			}
			t.Fatal("missing evidence omission")
		})
	}
}

func selectedIDsFromBlocks(blocks []EvidenceBlock) []domain.EvidenceID {
	ids := make([]domain.EvidenceID, 0, len(blocks))
	for _, block := range blocks {
		ids = append(ids, block.EvidenceID)
	}
	return ids
}

func TestByteCompactionKeepsFittingProjectedSharedAnchor(t *testing.T) {
	input, query := fleetEvidence(3, 1)
	large := input.Evidence[0]
	large.EvidenceID, large.EvidenceClass = "preferred-ab", "preferred"
	large.EntityIDs = slices.Clone(input.Scope.EntityIDs[:2])
	large.Excerpt = strings.Repeat("x", 2048)
	input.Evidence = append(input.Evidence, large)
	query.EvidenceClasses = []string{"preferred"}
	selection, err := SelectEvidence(input.Evidence, query)
	if err != nil {
		t.Fatal(err)
	}
	if len(selection.Selected) != 4 || selection.Selected[0].EvidenceID != large.EvidenceID {
		t.Fatalf("fixture must admit large shared block first: %v", selectedIDs(selection.Selected))
	}
	limits := DefaultLimits()
	limits.MaxEncodedBytes = 2775
	cheap := input
	cheap.Evidence = input.Evidence[:3]
	if baseline, err := mustBuilder(t, limits).Build(cheap); err != nil || len(baseline.Evidence) != 3 {
		t.Fatalf("cheap A+B+C cover must fit 2775 bytes: bytes=%d err=%v", baseline.EncodedBytes, err)
	}
	input.Evidence = selection.Selected
	for _, item := range selection.Selected {
		input.EvidenceAllocation = append(input.EvidenceAllocation, item.EvidenceID)
	}
	context, err := mustBuilder(t, limits).Build(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(context.Evidence) != 2 || context.Evidence[0].EvidenceID != large.EvidenceID || !context.Evidence[0].ExcerptTruncated || !slices.Contains(context.Evidence[0].EntityIDs, "node-001") || !slices.Contains(context.Evidence[1].EntityIDs, "node-002") {
		t.Fatalf("fitting shared anchor should cover A+B with C and remain explicitly truncated: evidence=%v omissions=%v", context.Evidence, context.Omissions)
	}
}

func TestItemCapKeepsProjectedCanonicalAnchorBeforeAlternatives(t *testing.T) {
	input, query := fleetEvidence(2, 1)
	large := input.Evidence[0]
	large.EvidenceID, large.EvidenceClass = "preferred-large", "preferred"
	large.Excerpt = strings.Repeat("x", 2048)
	input.Evidence = append(input.Evidence, large)
	query.EvidenceClasses = []string{"preferred"}
	selection, err := SelectEvidence(input.Evidence, query)
	if err != nil {
		t.Fatal(err)
	}
	limits := DefaultLimits()
	limits.MaxEvidence, limits.MaxEncodedBytes = 2, 3009
	cheap := input
	cheap.Evidence = input.Evidence[:2]
	baseline, err := mustBuilder(t, limits).Build(cheap)
	if err != nil || len(baseline.Evidence) != 2 {
		t.Fatalf("cheap two-node baseline must fit: bytes=%d err=%v", baseline.EncodedBytes, err)
	}
	input.Evidence = selection.Selected
	for _, item := range selection.Selected {
		input.EvidenceAllocation = append(input.EvidenceAllocation, item.EvidenceID)
	}
	context, err := mustBuilder(t, limits).Build(input)
	if err != nil {
		t.Fatal(err)
	}
	assertFleetCoverage(t, context, 2, 2)
	if context.Evidence[0].EvidenceID != large.EvidenceID || !context.Evidence[0].ExcerptTruncated {
		t.Fatalf("item cap did not preserve compact canonical anchor: %v", context.Evidence)
	}
}

func TestEncodedSizeFixedPointNearDigitBoundary(t *testing.T) {
	input, query := fleetEvidence(3, 1)
	large := input.Evidence[0]
	large.EvidenceID, large.EvidenceClass = "preferred-ab", "preferred"
	large.EntityIDs = slices.Clone(input.Scope.EntityIDs[:2])
	large.Excerpt = strings.Repeat("x", 2048)
	input.Evidence = append(input.Evidence, large)
	query.EvidenceClasses = []string{"preferred"}
	selection, err := SelectEvidence(input.Evidence, query)
	if err != nil {
		t.Fatal(err)
	}
	input.Evidence = selection.Selected
	for _, item := range selection.Selected {
		input.EvidenceAllocation = append(input.EvidenceAllocation, item.EvidenceID)
	}
	for _, ceiling := range []int{2752, 2769, 2770, 2771, 2772, 2775} {
		limits := DefaultLimits()
		limits.MaxEncodedBytes = ceiling
		context, err := mustBuilder(t, limits).Build(input)
		if err != nil {
			t.Fatalf("ceiling %d rejected a context that fits a lower ceiling: %v", ceiling, err)
		}
		encoded, err := json.Marshal(context)
		if err != nil || len(encoded) != context.EncodedBytes || len(encoded) > ceiling {
			t.Fatalf("ceiling %d encoded accounting differs: recorded=%d actual=%d err=%v", ceiling, context.EncodedBytes, len(encoded), err)
		}
	}
}

func TestSharedCanonicalSelectionHasBoundedWork(t *testing.T) {
	input, query := fleetEvidence(32, 5)
	for index := range input.Evidence {
		next := (index/5 + 1) % 32
		input.Evidence[index].EntityIDs = []string{input.Scope.EntityIDs[index/5], input.Scope.EntityIDs[next]}
	}
	query.AllowanceTokens = 3000
	start := time.Now()
	first, err := SelectEvidence(input.Evidence, query)
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("bounded coverage search took %s for 32 entities and 160 shared candidates", elapsed)
	}
	reversed := slices.Clone(input.Evidence)
	slices.Reverse(reversed)
	second, err := SelectEvidence(reversed, query)
	if err != nil || !reflect.DeepEqual(first, second) {
		t.Fatalf("shared-cover fallback changed with candidate order: %v", err)
	}
}
