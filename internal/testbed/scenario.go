// Package testbed runs synthetic worlds through production investigation boundaries.
package testbed

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"strings"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

const SchemaVersion = "sherlock.testbed/v1"
const PlannerVersion = "context-driven-simulator-v1"

// World is the only scenario material available to a worker. Oracle labels are
// deliberately absent from this type and from the worker's database record.
type World struct {
	Question string     `json:"question"`
	Start    time.Time  `json:"start"`
	End      time.Time  `json:"end"`
	Evidence []Evidence `json:"evidence"`
}
type Evidence struct {
	ID      string                `json:"id"`
	Role    string                `json:"role"`
	Summary string                `json:"summary"`
	Status  domain.EvidenceStatus `json:"status"`
	// AvailableAfterAction prevents a source from leaking a later result early.
	AvailableAfterAction int `json:"available_after_action"`
}
type Oracle struct {
	RequiredEvidence   []string `json:"required_evidence"`
	ExpectedOutcome    string   `json:"expected_outcome"`
	MinimumHiddenTests int      `json:"minimum_hidden_tests"`
	ExpectDetection    bool     `json:"expect_detection"`
}
type DetectionInput struct {
	Kind        string   `json:"kind"`
	Temperature *float64 `json:"temperature,omitempty"`
}
type Scenario struct {
	ID          string         `json:"id"`
	Description string         `json:"description"`
	World       World          `json:"world"`
	Oracle      Oracle         `json:"oracle"`
	Detection   DetectionInput `json:"detection"`
}
type Suite struct {
	SchemaVersion string     `json:"schema_version"`
	Scenarios     []Scenario `json:"scenarios"`
}

func Load(path string) (Suite, string, error) {
	file, err := os.Open(path)
	if err != nil {
		return Suite{}, "", err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, (2<<20)+1))
	if err != nil {
		return Suite{}, "", err
	}
	if len(raw) > 2<<20 {
		return Suite{}, "", fmt.Errorf("testbed suite exceeds 2 MiB")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var suite Suite
	if err = decoder.Decode(&suite); err != nil {
		return Suite{}, "", err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return Suite{}, "", fmt.Errorf("trailing suite content")
	}
	if err = suite.Validate(); err != nil {
		return Suite{}, "", err
	}
	return suite, domain.ChecksumSHA256(raw).String(), nil
}
func (suite Suite) Validate() error {
	if suite.SchemaVersion != SchemaVersion || len(suite.Scenarios) == 0 || len(suite.Scenarios) > 32 {
		return fmt.Errorf("invalid testbed suite bounds")
	}
	seen := map[string]bool{}
	for _, s := range suite.Scenarios {
		if !token(s.ID) || seen[s.ID] || s.Description == "" || strings.TrimSpace(s.World.Question) == "" || len(s.World.Question) > 4096 || s.World.Start.IsZero() || !s.World.End.After(s.World.Start) || s.World.End.Sub(s.World.Start) > time.Hour || len(s.World.Evidence) < 2 || len(s.World.Evidence) > 128 {
			return fmt.Errorf("invalid scenario %q", s.ID)
		}
		seen[s.ID] = true
		ids := map[string]bool{}
		primary, detail := false, false
		for _, e := range s.World.Evidence {
			if !token(e.ID) || ids[e.ID] || len(e.Summary) == 0 || len(e.Summary) > 1024 || strings.TrimSpace(e.Summary) != e.Summary || e.AvailableAfterAction < 0 || e.AvailableAfterAction > 1 {
				return fmt.Errorf("invalid evidence in %s", s.ID)
			}
			if e.Status != domain.EvidenceComplete && e.Status != domain.EvidencePartial && e.Status != domain.EvidenceUnavailable && e.Status != domain.EvidenceNoData {
				return fmt.Errorf("invalid evidence status")
			}
			if e.Role == "PRIMARY" {
				primary = true
			} else if e.Role == "DETAIL" {
				detail = true
			} else {
				return fmt.Errorf("invalid evidence role")
			}
			ids[e.ID] = true
		}
		if !primary || !detail || len(s.Oracle.RequiredEvidence) == 0 || s.Oracle.ExpectedOutcome != "PARTIAL" || s.Oracle.MinimumHiddenTests < 1 || s.Oracle.MinimumHiddenTests > 32 {
			return fmt.Errorf("invalid oracle in %s", s.ID)
		}
		required := map[string]bool{}
		for _, id := range s.Oracle.RequiredEvidence {
			if !ids[id] || required[id] {
				return fmt.Errorf("invalid required evidence in %s", s.ID)
			}
			required[id] = true
		}
		if s.Detection.Kind == "gpu_thermal" && (s.Detection.Temperature == nil || math.IsNaN(*s.Detection.Temperature) || math.IsInf(*s.Detection.Temperature, 0)) {
			return fmt.Errorf("thermal detection requires an observed numeric temperature")
		}
		switch s.Detection.Kind {
		case "gpu_thermal", "telemetry_loss", "not_exercised":
		default:
			return fmt.Errorf("invalid detection mode")
		}
	}
	return nil
}
func token(s string) bool {
	return len(s) > 0 && len(s) <= 64 && strings.Trim(s, "abcdefghijklmnopqrstuvwxyz0123456789-") == ""
}
