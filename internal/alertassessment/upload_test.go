package alertassessment_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	a "github.com/verticalcomputer/sherlock/internal/alertassessment"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

func uploadFixture(t *testing.T) (a.Suite, *a.Registry) {
	t.Helper()
	s, registry := fixture(t)
	s.Provenance = "OBSERVED_AVAILABILITY"
	s.Facts, s.Faults, s.Expected, s.Legacy, s.Labels = nil, nil, nil, nil, nil
	for i := range s.Config.Bindings {
		b := &s.Config.Bindings[i]
		b.UploadProfileID, b.UploadProfileHash = "cooling-profile", strings.Repeat("1", 64)
		b.UploadCollectorID = "collector"
		b.ScopeNodes = []string{s.Config.Assets[0].NodeID}
		b.ScheduleRevision = 2
	}
	return s, registry
}

func TestAssessmentUploadBindings(t *testing.T) {
	for name, change := range map[string]func([]a.Binding){
		"missing hash":      func(bs []a.Binding) { bs[0].UploadProfileHash = "" },
		"invalid hash":      func(bs []a.Binding) { bs[0].UploadProfileHash = strings.Repeat("A", 64) },
		"missing collector": func(bs []a.Binding) { bs[0].UploadCollectorID = "" },
		"mixed collection modes": func(bs []a.Binding) {
			bs[1].UploadProfileID, bs[1].UploadProfileHash, bs[1].UploadCollectorID = "", "", ""
		},
		"different profiles":      func(bs []a.Binding) { bs[1].UploadProfileID = "another-profile" },
		"different collectors":    func(bs []a.Binding) { bs[1].UploadCollectorID = "another-collector" },
		"different revisions":     func(bs []a.Binding) { bs[1].ScheduleRevision++ },
		"different scopes":        func(bs []a.Binding) { bs[1].ScopeNodes = append(bs[1].ScopeNodes, "other-node") },
		"wrong cooling operation": func(bs []a.Binding) { bs[0].Operation = bs[1].Operation },
	} {
		t.Run(name, func(t *testing.T) {
			s, registry := uploadFixture(t)
			change(s.Config.Bindings)
			if err := s.Config.Validate(t.Context(), registry); !errors.Is(err, a.ErrInvalid) {
				t.Fatalf("invalid upload binding returned %v", err)
			}
		})
	}
	s, registry := fixture(t)
	body, err := a.Canonical(s.Config)
	if err != nil {
		t.Fatal(err)
	}
	emptyUploadFields := bytes.Replace(body, []byte(`"scope_nodes":[]`), []byte(`"scope_nodes":[],"upload_profile_hash":"","upload_profile_id":""`), 1)
	if _, err := a.ParseConfig(t.Context(), emptyUploadFields, registry); !errors.Is(err, a.ErrInvalid) {
		t.Fatalf("explicit empty upload binding returned %v", err)
	}
	prior := s.Facts[0]
	var sample a.Sample
	if err := json.Unmarshal(prior.Body, &sample); err != nil {
		t.Fatal(err)
	}
	actual, err := a.NewFact(s.Config.Category, prior.Run, prior.Asset, prior.Kind, prior.AvailableAt, sample)
	if err != nil || actual.ID != prior.ID || !bytes.Equal(actual.Body, prior.Body) {
		t.Fatalf("V1 sample encoding changed: %v", err)
	}
}

func uploadSample(s a.Suite) a.Sample {
	b := s.Config.Bindings[0]
	p := domain.CoolingUploadProfile{ProfileID: b.UploadProfileID, Revision: b.ScheduleRevision, CollectorID: domain.CollectorID(b.UploadCollectorID),
		ClusterID: domain.ClusterID(s.Config.ClusterID), SourceID: domain.SourceID(s.Config.SourceID)}
	run := p.Task(domain.QueryGPUTemperature, s.StartAt).RunID
	return a.Sample{Metric: b.Metric, Unit: "celsius", SourceAt: s.StartAt, CollectedAt: s.StartAt, CompletedAt: s.StartAt,
		Value: 70, SourceRecord: "receipt-record", Provenance: a.Provenance{Mode: "upload", CollectionRunID: string(run),
			Operation: b.Operation, ScheduleRevision: b.ScheduleRevision, InventoryRevision: s.Config.InventoryRevision, SourceRecord: "receipt-record",
			CollectorID: b.UploadCollectorID, UploadProfileID: b.UploadProfileID, UploadProfileHash: b.UploadProfileHash}}
}

func TestAssessmentUploadRunNamespace(t *testing.T) {
	s, _ := uploadFixture(t)
	sample := uploadSample(s)
	for name, run := range map[string]string{
		"unreserved run": "scheduled-run",
		"short digest":   domain.CoolingUploadRunPrefix + "123",
		"uppercase hash": domain.CoolingUploadRunPrefix + strings.Repeat("A", 64),
	} {
		t.Run(name, func(t *testing.T) {
			bad := sample
			bad.Provenance.CollectionRunID = run
			if _, err := a.NewFact(s.Config.Category, s.Config.RunID, s.Config.Assets[0].EntityKey, "SAMPLE", s.StartAt, bad); !errors.Is(err, a.ErrInvalid) {
				t.Fatalf("invalid upload run namespace returned %v", err)
			}
		})
	}
	for _, mode := range []string{"fixture", "legacy", "durable"} {
		t.Run(mode, func(t *testing.T) {
			bad := sample
			p := &bad.Provenance
			p.Mode, p.CollectorID, p.UploadProfileID, p.UploadProfileHash = mode, "", "", ""
			switch mode {
			case "legacy":
				p.JobID, p.ConfigurationRevision = "job", new(int64)
			case "durable":
				p.WorkID, p.CollectorID = "work", "collector"
			}
			if _, err := a.NewFact(s.Config.Category, s.Config.RunID, s.Config.Assets[0].EntityKey, "SAMPLE", s.StartAt, bad); !errors.Is(err, a.ErrInvalid) {
				t.Fatalf("reserved run namespace in %s mode returned %v", mode, err)
			}
		})
	}
}

func TestAssessmentUploadProvenance(t *testing.T) {
	s, registry := uploadFixture(t)
	b := s.Config.Bindings[0]
	sample := uploadSample(s)
	makeFact := func(at time.Time, sample a.Sample) a.Fact {
		t.Helper()
		f, err := a.NewFact(s.Config.Category, s.Config.RunID, s.Config.Assets[0].EntityKey, "SAMPLE", at, sample)
		if err != nil {
			t.Fatal(err)
		}
		return f
	}
	for name, change := range map[string]func(*a.Provenance){
		"other profile":   func(p *a.Provenance) { p.UploadProfileID = "other-profile" },
		"other hash":      func(p *a.Provenance) { p.UploadProfileHash = strings.Repeat("2", 64) },
		"other revision":  func(p *a.Provenance) { p.ScheduleRevision++ },
		"other inventory": func(p *a.Provenance) { p.InventoryRevision = "other-inventory" },
		"other collector": func(p *a.Provenance) { p.CollectorID = "other-collector" },
		"fixture": func(p *a.Provenance) {
			p.Mode, p.CollectorID, p.UploadProfileID, p.UploadProfileHash = "fixture", "", "", ""
			p.CollectionRunID = "scheduled-run"
		},
		"legacy job": func(p *a.Provenance) {
			p.Mode, p.CollectorID, p.UploadProfileID, p.UploadProfileHash = "legacy", "", "", ""
			p.JobID, p.ConfigurationRevision = "job", new(int64)
			p.CollectionRunID = "scheduled-run"
		},
		"durable work": func(p *a.Provenance) {
			p.Mode, p.WorkID, p.UploadProfileID, p.UploadProfileHash = "durable", "work", "", ""
			p.CollectionRunID = "scheduled-run"
		},
	} {
		t.Run(name, func(t *testing.T) {
			spoof := sample
			change(&spoof.Provenance)
			attempt := s
			attempt.Facts = []a.Fact{makeFact(s.StartAt, spoof)}
			if _, err := a.Replay(t.Context(), attempt, registry); !errors.Is(err, a.ErrInvalid) {
				t.Fatalf("unauthorized source replay returned %v", err)
			}
		})
	}
	first := makeFact(s.StartAt, sample)
	canonical, err := a.Canonical(sample)
	if err != nil || !bytes.Equal(canonical, first.Body) {
		t.Fatalf("upload sample encoding differs from the canonical wire body: %v", err)
	}
	s.Facts = []a.Fact{first}
	synthetic := s
	synthetic.Provenance = "SYNTHETIC"
	if _, err := a.Replay(t.Context(), synthetic, registry); !errors.Is(err, a.ErrInvalid) {
		t.Fatalf("synthetic upload replay returned %v", err)
	}
	scheduled, _ := fixture(t)
	scheduled.Config.Bindings[0].ScheduleRevision = b.ScheduleRevision
	scheduled.Facts = s.Facts
	if _, err := a.Replay(t.Context(), scheduled, registry); !errors.Is(err, a.ErrInvalid) {
		t.Fatalf("upload sample on a scheduled binding returned %v", err)
	}
	spoof := sample.Provenance
	spoof.CollectorID, spoof.SourceRecord = "other-collector", "repeat-record"
	forged, err := a.NewFact(s.Config.Category, first.Run, first.Asset, "PROVENANCE", s.StartAt.Add(time.Second), a.ProvenanceFact{SampleID: first.ID, SourceRecord: spoof.SourceRecord, Provenance: spoof})
	if err != nil {
		t.Fatal(err)
	}
	invalid := s
	invalid.Facts = []a.Fact{first, forged}
	if _, err := a.Replay(t.Context(), invalid, registry); !errors.Is(err, a.ErrInvalid) {
		t.Fatalf("forged source replay returned %v", err)
	}
	sample.SourceRecord, sample.Provenance.SourceRecord = "repeat-record", "repeat-record"
	s.Facts = append(s.Facts, makeFact(s.StartAt.Add(time.Second), sample))
	observed, err := a.Replay(t.Context(), s, registry)
	if err != nil {
		t.Fatal(err)
	}
	source := archiveEngineFixture(t, observed, registry)
	dir := filepath.Join(t.TempDir(), "upload-archive")
	if _, err := a.WriteArchive(t.Context(), dir, source); err != nil {
		t.Fatal(err)
	}
	replayed, err := a.ReplayArchive(t.Context(), dir, registry)
	if err != nil {
		t.Fatal(err)
	}
	if len(observed.Facts) != 2 || len(replayed.Mismatched) != 0 {
		t.Fatalf("wanted one sample and a second receipt's provenance, got %d facts and mismatches %v", len(observed.Facts), replayed.Mismatched)
	}
	var evidence bytes.Buffer
	if err := a.WriteArchiveEvidence(t.Context(), dir, &evidence); err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(&evidence)
	matched := 0
	for {
		var got a.Fact
		err := decoder.Decode(&got)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if got.Kind == "" {
			continue // The evidence stream also contains bundle manifests.
		}
		if want, ok := observed.Facts[got.ID]; !ok || !bytes.Equal(got.Body, want.Body) {
			t.Fatalf("archive changed upload fact %s", got.ID)
		}
		matched++
	}
	if matched != len(observed.Facts) {
		t.Fatalf("archive preserved %d of %d upload facts", matched, len(observed.Facts))
	}
	spoofedSample := uploadSample(s)
	spoofedSample.Provenance.CollectorID = "other-collector"
	for _, tampered := range []a.Fact{makeFact(s.StartAt, spoofedSample), forged} {
		t.Run("archive rejects mismatched collector "+tampered.Kind, func(t *testing.T) {
			original, ok := observed.Facts[tampered.ID]
			if !ok {
				t.Fatal("tampered fact should retain its original ID")
			}
			observed.Facts[tampered.ID] = tampered
			defer func() { observed.Facts[tampered.ID] = original }()
			dir := filepath.Join(t.TempDir(), "tampered-archive")
			if _, err := a.WriteArchive(t.Context(), dir, archiveEngineFixture(t, observed, registry)); err != nil {
				t.Fatal(err)
			}
			if _, err := a.ReplayArchive(t.Context(), dir, registry); !errors.Is(err, a.ErrInvalid) {
				t.Fatalf("unauthorized collector archive replay returned %v", err)
			}
		})
	}
}
