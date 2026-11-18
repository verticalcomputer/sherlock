package alertassessment_test

import (
	"bytes"
	"context"
	"encoding/json"
	"math"
	"os"
	"strings"
	"testing"
	"time"

	a "github.com/verticalcomputer/sherlock/internal/alertassessment"
	"github.com/verticalcomputer/sherlock/internal/alertassessment/cooling"
)

func TestAssessmentCanonical(t *testing.T) {
	v := struct {
		N  int64     `json:"n"`
		F  float64   `json:"f"`
		At time.Time `json:"at"`
		S  string    `json:"s"`
	}{math.MaxInt64, math.Copysign(0, -1), time.Date(2026, 1, 1, 5, 30, 0, 123456789, time.FixedZone("IST", 19800)), "<温>"}
	b, e := a.Canonical(v)
	if e != nil {
		t.Fatal(e)
	}
	want := `{"at":"2026-01-01T00:00:00.123456Z","f":0,"n":9223372036854775807,"s":"\u003c温\u003e"}`
	if string(b) != want {
		t.Fatalf("%s", b)
	}
}
func TestAssessmentStrictDecode(t *testing.T) {
	type body struct {
		N int64    `json:"n"`
		S []string `json:"s"`
		P *string  `json:"p,omitempty"`
	}
	for _, b := range []string{`{"n":1,"s":[],"N":2}`, `{"n":1,"n":2,"s":[]}`, `{"n":1}`, `{"n":1,"s":null}`, `{"n":1,"s":[],"p":null}`, `{"n":9223372036854775808,"s":[]}`, `{"n":-1,"s":[]}`, `{"n":1,"s":[]} {}`, `{"n":1,"s":[],"x":0}`} {
		var x body
		if a.DecodeStrict([]byte(b), &x, 16384) == nil {
			t.Errorf("accepted %s", b)
		}
	}
	var x body
	if e := a.DecodeStrict([]byte(`{"s":[],"n":0}`), &x, 16384); e != nil {
		t.Fatal(e)
	}
	var raw struct {
		Body json.RawMessage `json:"body"`
	}
	if a.DecodeStrict([]byte(`{"body":`+strings.Repeat(`{"x":`, 17)+`0`+strings.Repeat(`}`, 17)+`}`), &raw, 16384) == nil {
		t.Fatal("depth")
	}
}

func TestAssessmentStrictPrimitiveEncoding(t *testing.T) {
	type body struct {
		At    time.Time `json:"at"`
		Text  string    `json:"text"`
		Value float64   `json:"value"`
		Note  *string   `json:"note,omitempty"`
	}
	for _, raw := range []string{
		`{"at":"2026-01-01T00:00:00+00:00","text":"x","value":0}`,
		`{"at":"2026-01-01T00:00:00,1Z","text":"x","value":0}`,
		`{"at":"2026-01-01T00:00:00.0000000001Z","text":"x","value":0}`,
		`{"at":"2026-01-01T00:00:00Z","text":"\uD800","value":0}`,
		`{"at":"2026-01-01T00:00:00Z","text":"\uDC00","value":0}`,
		`{"at":"2026-01-01T00:00:00Z","text":"x","value":1e309}`,
		`{"at":"2026-01-01T00:00:00Z","text":"x","value":"0"}`,
	} {
		var got body
		if a.DecodeStrict([]byte(raw), &got, 1024) == nil {
			t.Errorf("accepted %s", raw)
		}
	}
	note := "old"
	got := body{Note: &note}
	if err := a.DecodeStrict([]byte(`{"at":"2026-01-01T00:00:00.123456789Z","text":"\uD83D\uDE00","value":-0.0}`), &got, 1024); err != nil {
		t.Fatal(err)
	}
	if got.Note != nil || got.Text != "😀" {
		t.Fatalf("optional field or Unicode decoded incorrectly: %+v", got)
	}
	canonical, err := a.Canonical(got)
	if err != nil || string(canonical) != `{"at":"2026-01-01T00:00:00.123456Z","text":"😀","value":0}` {
		t.Fatalf("canonical encoding = %s, %v", canonical, err)
	}
}
func TestAssessmentGoldenConfig(t *testing.T) {
	// Fixtures are copied from the approved contract; tests do not depend on ignored docs.
	b, e := os.ReadFile("../../test/assessment/v1/config.json")
	if e != nil {
		t.Fatal(e)
	}
	r, e := a.NewRegistry(cooling.Category{})
	if e != nil {
		t.Fatal(e)
	}
	c, e := a.ParseConfig(context.Background(), b, r)
	if e != nil {
		t.Fatal(e)
	}
	h, e := c.Hash()
	if e != nil {
		t.Fatal(e)
	}
	if h != "c615bf1d75283522a3a06a70c54ede2d4c036bcf49b12a08e4bf27711d6ef4da" {
		t.Fatal(h)
	}
	if input, err := c.InputConfigHash(); err != nil || input != "8d4f56e2dfa17757141acc106c83034cd3dca512d215486014a24a00f7e8b0ff" {
		t.Fatalf("V1 config input hash %s: %v", input, err)
	}
	p, e := a.NewPayload(c.Category, "policy", 1, cooling.DefaultPolicy())
	if e != nil {
		t.Fatal(e)
	}
	if p.Hash != "1df3c037e3b1799c29b6b366c10d6e0c0c998392c4d103162a70e210d1861920" {
		t.Fatal(p.Hash)
	}
	variant := bytes.Replace(b, []byte(`"stable_watts": 10`), []byte(`"stable_watts": 1e1`), 1)
	if bytes.Equal(b, variant) {
		t.Fatal("equivalent number fixture did not change")
	}
	parsed, err := a.ParseConfig(context.Background(), variant, r)
	if err != nil {
		t.Fatal(err)
	}
	variantHash, err := parsed.Hash()
	if err != nil || variantHash != h {
		t.Fatalf("equivalent config numbers changed identity: %s, %v", variantHash, err)
	}
	var inMemory a.Config
	if err := a.DecodeStrict(variant, &inMemory, 64<<10); err != nil {
		t.Fatal(err)
	}
	normalized, err := a.NormalizeConfig(context.Background(), inMemory, r)
	if err != nil {
		t.Fatal(err)
	}
	inMemory.Policy[0], inMemory.BudgetsMS[0], inMemory.Bindings[0].Metric = '[', 10, "changed"
	normalizedHash, err := normalized.Hash()
	if err != nil || normalizedHash != h {
		t.Fatalf("in-memory normalization did not freeze config identity: %s, %v", normalizedHash, err)
	}
}

func TestAssessmentConfigAdmissionWitness(t *testing.T) {
	ctx := context.Background()
	file, err := os.ReadFile("../../test/assessment/v1/config.json")
	if err != nil {
		t.Fatal(err)
	}
	original := bytes.Replace(file, []byte(`"stable_watts": 10`), []byte(`"stable_watts": 1.00000000000000001e1`), 1)
	if bytes.Equal(file, original) {
		t.Fatal("rounded float fixture did not change")
	}
	registry, err := a.NewRegistry(cooling.Category{})
	if err != nil {
		t.Fatal(err)
	}
	admitted, err := a.ParseConfig(ctx, original, registry)
	if err != nil {
		t.Fatal(err)
	}
	input, err := a.ParseRecoveryConfig(original)
	if err != nil {
		t.Fatal(err)
	}
	witness, err := input.InputConfigHash()
	if err != nil {
		t.Fatal(err)
	}
	normalized, err := a.NormalizeConfig(ctx, admitted, registry)
	if err != nil {
		t.Fatal(err)
	}
	for _, config := range []a.Config{admitted, normalized} {
		if got, err := config.InputConfigHash(); err != nil || got != witness || !bytes.Contains(config.Policy, []byte(`"stable_watts":10`)) {
			t.Fatalf("typed normalization lost the original input witness: %s vs %s (%v)", got, witness, err)
		}
	}
	var reordered map[string]json.RawMessage
	if err := json.Unmarshal(original, &reordered); err != nil {
		t.Fatal(err)
	}
	originalReordered, err := json.Marshal(reordered)
	if err != nil {
		t.Fatal(err)
	}
	inputReordered, err := a.ParseRecoveryConfig(originalReordered)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := inputReordered.InputConfigHash(); err != nil || got != witness {
		t.Fatalf("key order or whitespace changed the input witness: %s vs %s (%v)", got, witness, err)
	}
	for name, mutate := range map[string]func(*a.Config){
		"common fields": func(c *a.Config) { c.RunDurationSeconds++ },
		"typed policy": func(c *a.Config) {
			c.Policy = bytes.Replace(c.Policy, []byte(`"stable_watts":10`), []byte(`"stable_watts":11`), 1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			modified := admitted
			mutate(&modified)
			newWitness, err := modified.InputConfigHash()
			if err != nil || newWitness == witness {
				t.Fatalf("mutated config preserved stale input witness: %s (%v)", newWitness, err)
			}
			retied, err := a.NormalizeConfig(ctx, modified, registry)
			if err != nil {
				t.Fatal(err)
			}
			if rebound, err := retied.InputConfigHash(); err != nil || rebound != newWitness {
				t.Fatalf("normalization retained a witness for different typed data: %s vs %s (%v)", rebound, newWitness, err)
			}
		})
	}
}
