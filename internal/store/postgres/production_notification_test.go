package postgres

import (
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestProductionMessageBoundAndEscaping(t *testing.T) {
	o := ProductionOccurrence{ID: strings.Repeat("o", 128), ClusterID: strings.Repeat("c", 128), Asset: strings.Repeat("a", 256), IncidentID: "incident-test", OpenedAt: time.Now(), EvidenceURL: "https://sherlock.example/history"}
	text, err := productionMessage(o, "CATCHUP", time.Now(), strings.Repeat("é<&>", 1000))
	if err != nil {
		t.Fatal(err)
	}
	if len(text) > 3000 || !utf8.ValidString(text) || strings.Contains(text, "<") || !strings.Contains(text, o.ID) || !strings.HasSuffix(text, o.EvidenceURL) {
		t.Fatalf("unsafe message: bytes=%d", len(text))
	}
	for _, v := range []string{"http://example.test/a", "https://user:secret@example.test", "https://example.test/<@everyone>", "https://example.test/a#fragment"} {
		if validEvidenceURL(v) {
			t.Fatalf("accepted %s", v)
		}
	}
}
