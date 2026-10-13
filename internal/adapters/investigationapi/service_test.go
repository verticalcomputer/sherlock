package investigationapi

import (
	"testing"
)

func TestCanonicalEntityKindMatchesReviewedToolIdentifiers(t *testing.T) {
	for input, expected := range map[string]string{"NODE": "node", "Gpu": "gpu", "entity": "entity"} {
		if got := canonicalEntityKind(input); got != expected {
			t.Fatalf("canonicalEntityKind(%q)=%q, want %q", input, got, expected)
		}
	}
}
