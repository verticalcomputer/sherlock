package cooling

import (
	"encoding/json"
	"testing"
	"time"

	a "github.com/verticalcomputer/sherlock/internal/alertassessment"
)

func TestWarmingInputsReadScopedEvidenceOnce(t *testing.T) {
	at := warmingAnchor
	f := func(kind, id string, body any) a.Fact {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		return a.Fact{Asset: "gpu", Kind: kind, ID: id, AvailableAt: at.Add(time.Minute), Body: b}
	}
	sample := f("SAMPLE", "a", a.Sample{Metric: Temperature, SourceAt: at, Unit: "celsius", Value: 68})
	coverage := f("COVERAGE", "b", a.Coverage{Metric: Power, From: at, Through: at.Add(time.Second)})
	conflict := f("CONFLICT", "c", a.Conflict{Metric: Temperature, SourceAt: at})
	other := sample
	other.Asset = "other"
	other.ID = "d"
	ss, ns, err := WarmingInputsFromFacts([]a.Fact{sample, coverage, conflict, other, sample, coverage}, "gpu")
	if err != nil || len(ss) != 1 || len(ns) != 2 || ns[0].Metric != Power || !ns[0].Through.Equal(at.Add(time.Second)) || ns[1].Metric != Temperature || !ns[1].From.Equal(at) || !ns[1].Through.Equal(at) || !ns[1].AvailableAt.Equal(at.Add(time.Minute)) {
		t.Fatalf("samples=%+v negatives=%+v error=%v", ss, ns, err)
	}
}
