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
	for _, v := range []string{" ", "\t", "/admin/history", "http://example.test/a", "https://user:secret@example.test", "https://example.test/<@everyone>", "https://example.test/a#fragment"} {
		if validEvidenceURL(v) {
			t.Fatalf("accepted %s", v)
		}
	}
}

func TestProductionMessageWithoutHistoryURL(t *testing.T) {
	at := time.Date(2026, 11, 19, 13, 55, 0, 0, time.UTC)
	o := ProductionOccurrence{ID: "occurrence-1", ClusterID: "cluster", Asset: "cluster/GPU/node-a/GPU-a/", IncidentID: "incident-1", OpenedAt: at}
	if !validEvidenceURL("") {
		t.Fatal("absent optional history URL rejected")
	}
	for _, kind := range []string{"OPEN", "WORSEN", "RECOVER", "CATCHUP"} {
		text, err := productionMessage(o, kind, at.Add(time.Minute), "Investigation required <@everyone>. "+strings.Repeat("é<&>", 1000))
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{kind, "Node: node-a", "GPU: GPU-a", o.ID, o.IncidentID, "Incident opened: 2026-11-19T13:55:00Z", "Event time: 2026-11-19T13:56:00Z", "Investigation required &lt;@everyone&gt;"} {
			if !strings.Contains(text, want) {
				t.Fatalf("missing retained context %q: %s", want, text)
			}
		}
		if len(text) > 3000 || !utf8.ValidString(text) || strings.Contains(text, "<") || strings.Contains(text, "History:") || strings.Contains(text, "/admin/") {
			t.Fatalf("unsafe or incomplete no-link message: %s", text)
		}
	}
}

func TestProductionEvidenceURL(t *testing.T) {
	if got := productionEvidenceURL("", "cluster", "enrollment", "occurrence"); got != "" {
		t.Fatalf("missing origin manufactured a relative link: %q", got)
	}
	for _, origin := range []string{"https://sherlock.example", "https://sherlock.example/"} {
		if got := productionEvidenceURL(origin, "cluster", "enrollment", "occurrence"); got != "https://sherlock.example/admin/clusters/cluster/assessment/enrollment/occurrence" {
			t.Fatalf("existing link behavior changed: %q", got)
		}
	}
}
