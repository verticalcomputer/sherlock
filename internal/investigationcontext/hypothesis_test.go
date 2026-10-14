package investigationcontext

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

func TestHypothesisTestsAreBoundedAndPricedInContext(t *testing.T) {
	input := baseInput()
	input.Evidence = nil
	tests := make([]string, 12)
	for i := range tests {
		tests[i] = strings.Repeat("界", 100)
	}
	input.Hypotheses = []HypothesisInput{{ID: "hyp-1", Statement: "Cooling remains unresolved", Status: domain.HypothesisUnresolved, Confidence: .6, UnresolvedTests: tests}}
	result, err := mustBuilder(t, DefaultLimits()).Build(input)
	if err != nil {
		t.Fatal(err)
	}
	block := result.Hypotheses[0]
	if len(block.UnresolvedTests) != 8 || block.UnresolvedTestsOmitted != 4 || !block.UnresolvedTestsTruncated || block.Confidence != .6 {
		t.Fatalf("projection=%+v", block)
	}
	for _, test := range block.UnresolvedTests {
		if len(test) > 256 || !utf8.ValidString(test) {
			t.Fatal("test exceeds UTF-8 bound")
		}
	}
	encoded, err := json.Marshal(result)
	if err != nil || len(encoded) != result.EncodedBytes {
		t.Fatalf("size=%d accounted=%d err=%v", len(encoded), result.EncodedBytes, err)
	}
	again, err := mustBuilder(t, DefaultLimits()).Build(input)
	if err != nil {
		t.Fatal(err)
	}
	other, _ := json.Marshal(again)
	if string(encoded) != string(other) {
		t.Fatal("projection is not deterministic")
	}
	if !slices.Equal(input.Hypotheses[0].UnresolvedTests, tests) || len(tests[0]) != 300 {
		t.Fatal("projection modified input")
	}
	limits := DefaultLimits()
	limits.MaxEncodedBytes = 2048
	reduced, err := mustBuilder(t, limits).Build(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(reduced.Hypotheses) != 0 || reduced.EncodedBytes > limits.MaxEncodedBytes {
		t.Fatalf("tests escaped encoded limit: %+v", reduced)
	}
	for _, omission := range reduced.Omissions {
		if omission.Kind == OmissionKindHypothesis && omission.Count == 1 && omission.Reason == OmissionEncodedSizeLimit {
			return
		}
	}
	t.Fatal("missing explicit hypothesis omission")
}
