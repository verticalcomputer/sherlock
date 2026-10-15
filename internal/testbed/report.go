package testbed

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/modelprovider"
	"github.com/verticalcomputer/sherlock/internal/platform"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

type Result struct {
	ScenarioID             string          `json:"scenario_id"`
	Passed                 bool            `json:"passed"`
	Outcome                string          `json:"outcome"`
	SelectedEvidence       []string        `json:"selected_evidence"`
	RequiredEvidenceRecall float64         `json:"required_evidence_recall"`
	HiddenTestsRetained    int             `json:"hidden_tests_retained"`
	FullStatementRetained  bool            `json:"full_statement_retained"`
	RestartContextEqual    bool            `json:"restart_context_equal"`
	WorkerProcesses        int             `json:"worker_processes"`
	ExecutedActions        int             `json:"executed_actions"`
	Checkpoints            int             `json:"checkpoints"`
	Manifests              int             `json:"manifests"`
	AuditedCalls           int             `json:"audited_calls"`
	SimulatedTokens        int64           `json:"simulated_tokens"`
	DurationMillis         int64           `json:"duration_millis"`
	Detection              DetectionResult `json:"detection"`
	Violations             []string        `json:"violations"`
}
type Report struct {
	SlurmFailures    *SlurmFailureReport `json:"slurm_failures,omitempty"`
	Pipeline         *PipelineResult     `json:"pipeline,omitempty"`
	SchemaVersion    string              `json:"schema_version"`
	SuiteSHA256      string              `json:"suite_sha256"`
	BinarySHA256     string              `json:"binary_sha256,omitempty"`
	SourceRevision   string              `json:"source_revision,omitempty"`
	SourceDirty      bool                `json:"source_dirty"`
	PlannerVersion   string              `json:"planner_version"`
	Mode             string              `json:"mode"`
	Passed           bool                `json:"passed"`
	Cases            []Result            `json:"cases"`
	UnmeasuredStages []string            `json:"unmeasured_stages"`
}

// A Launcher must start a fresh OS process when process restart qualification is
// desired. Unit/integration tests may explicitly use in-process reconstruction.
type Launcher func(context.Context, domain.InvestigationID, int) error

func Run(ctx context.Context, pool *pgxpool.Pool, suite Suite, digest string, launch Launcher, processes bool) (Report, error) {
	if pool == nil || launch == nil {
		return Report{}, fmt.Errorf("testbed database and worker launcher required")
	}
	if _, err := domain.ParseSHA256(digest); err != nil {
		return Report{}, fmt.Errorf("exact suite digest required")
	}
	if err := suite.Validate(); err != nil {
		return Report{}, err
	}
	if err := Setup(ctx, pool); err != nil {
		return Report{}, err
	}
	report := Report{SchemaVersion: SchemaVersion, SuiteSHA256: digest, PlannerVersion: PlannerVersion, Mode: "SIMULATED_PLANNER", Passed: true, UnmeasuredStages: []string{"source_intake", "automatic_incident_admission", "notification_delivery", "live_model_quality", "native_agent_overhead"}}
	for _, s := range suite.Scenarios {
		start := time.Now()
		suffix, err := (platform.RandomIDGenerator{}).NewID()
		if err != nil {
			return report, err
		}
		prefix := "tb-" + suffix
		id, err := prepare(ctx, pool, s, prefix)
		if err != nil {
			return report, fmt.Errorf("prepare %s: %w", s.ID, err)
		}
		if err = launch(ctx, id, 1); err != nil {
			return report, fmt.Errorf("first worker %s: %w", s.ID, err)
		}
		beforeStore, _ := storepg.NewInvestigationStore(pool)
		beforeSnapshot, found, err := beforeStore.LoadInvestigation(ctx, id)
		if err != nil || !found {
			return report, fmt.Errorf("restart boundary snapshot unavailable")
		}
		var hiddenTests []string
		beforeHypotheses := beforeSnapshot.Hypotheses.Entries()
		if len(beforeHypotheses) == 1 && len(beforeHypotheses[0].UnresolvedTests) > 8 {
			hiddenTests = append([]string{}, beforeHypotheses[0].UnresolvedTests[8:]...)
		}
		before, err := probe(ctx, pool, id)
		if err != nil {
			return report, err
		}
		// A separate pool discards all session-local state before reconstructing
		// context; the next Launcher then runs a fresh worker process.
		fresh, err := pgxpool.NewWithConfig(ctx, pool.Config())
		if err != nil {
			return report, err
		}
		after, err := probe(ctx, fresh, id)
		fresh.Close()
		if err != nil {
			return report, err
		}
		if err = launch(ctx, id, 0); err != nil {
			return report, fmt.Errorf("resumed worker %s: %w", s.ID, err)
		}
		result, err := grade(ctx, pool, s, id, prefix, hiddenTests)
		if err != nil {
			return report, err
		}
		result.RestartContextEqual = bytes.Equal(before, after)
		if processes && result.WorkerProcesses != 2 {
			result.Violations = append(result.Violations, "two distinct worker processes were not observed")
		}
		if !result.RestartContextEqual {
			result.Violations = append(result.Violations, "reconstructed context differs across restart")
		}
		result.DurationMillis = time.Since(start).Milliseconds()
		result.Passed = len(result.Violations) == 0
		report.Passed = report.Passed && result.Passed
		report.Cases = append(report.Cases, result)
	}
	return report, nil
}
func grade(ctx context.Context, pool *pgxpool.Pool, s Scenario, id domain.InvestigationID, prefix string, hiddenTests []string) (Result, error) {
	result := Result{ScenarioID: s.ID, Violations: []string{}}
	store, _ := storepg.NewInvestigationStore(pool)
	snapshot, found, err := store.LoadInvestigation(ctx, id)
	if err != nil || !found {
		return result, fmt.Errorf("missing terminal state: %w", err)
	}
	result.Outcome = string(snapshot.Investigation.Status())
	result.ExecutedActions = len(snapshot.PriorActions)
	if result.Outcome != s.Oracle.ExpectedOutcome {
		result.Violations = append(result.Violations, "unexpected terminal outcome")
	}
	if result.ExecutedActions != 2 {
		result.Violations = append(result.Violations, "expected two distinct source reads")
	}
	if len(snapshot.PriorActions) == 2 && snapshot.PriorActions[0].Digest == snapshot.PriorActions[1].Digest {
		result.Violations = append(result.Violations, "duplicate exact action executed")
	}
	hs := snapshot.Hypotheses.Entries()
	if len(hs) == 1 {
		result.HiddenTestsRetained = retainedQuestions(hiddenTests, hs[0].UnresolvedTests)
		result.FullStatementRetained = hs[0].Statement == longStatement()
	}
	if result.HiddenTestsRetained < s.Oracle.MinimumHiddenTests || !result.FullStatementRetained {
		result.Violations = append(result.Violations, "durable hypothesis lost hidden content")
	}
	if err = pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM investigation_context_checkpoints WHERE investigation_id=$1),(SELECT count(*) FROM investigation_context_manifests WHERE investigation_id=$1),(SELECT count(*) FROM investigation_model_calls WHERE investigation_id=$1),(SELECT count(*) FROM testbed_effects WHERE investigation_id=$1)`, id).Scan(&result.Checkpoints, &result.Manifests, &result.AuditedCalls, &result.ExecutedActions); err != nil {
		return result, err
	}
	if result.Checkpoints < 3 || result.Manifests != 4 || result.AuditedCalls != 4 || result.ExecutedActions != 2 {
		result.Violations = append(result.Violations, "production checkpoint, admission, audit or execution path missing")
	}
	rows, err := pool.Query(ctx, `SELECT kind,turn,payload FROM testbed_requests WHERE investigation_id=$1 ORDER BY kind,turn`, id)
	if err != nil {
		return result, err
	}
	defer rows.Close()
	if err = pool.QueryRow(ctx, `SELECT count(DISTINCT process_id) FROM testbed_workers WHERE investigation_id=$1`, id).Scan(&result.WorkerProcesses); err != nil {
		return result, err
	}
	var synthesis modelprovider.SynthesisRequest
	count := 0
	byID := map[string]Evidence{}
	for _, e := range s.World.Evidence {
		byID[e.ID] = e
	}
	for rows.Next() {
		var kind string
		var turn int
		var raw []byte
		if err = rows.Scan(&kind, &turn, &raw); err != nil {
			return result, err
		}
		count++
		if kind == "synthesis" {
			if err = json.Unmarshal(raw, &synthesis); err != nil {
				return result, err
			}
		} else {
			var request modelprovider.PlanningRequest
			if err = json.Unmarshal(raw, &request); err != nil {
				return result, err
			}
			if request.CheckpointDigest == "" {
				result.Violations = append(result.Violations, "planning omitted checkpoint")
			}
			for _, e := range request.Evidence {
				spec, ok := byID[logicalID(e.EvidenceID, prefix)]
				if !ok || spec.AvailableAfterAction > turn {
					result.Violations = append(result.Violations, "future or foreign evidence reached planner")
				}
			}
			if turn == 1 && (len(request.Hypotheses) != 1 || !request.Hypotheses[0].StatementTruncated || request.Hypotheses[0].UnresolvedTestsOmitted != 4) {
				result.Violations = append(result.Violations, "long hypothesis was not bounded in resumed request")
			}
		}
	}
	if err = rows.Err(); err != nil {
		return result, err
	}
	if count != 4 {
		result.Violations = append(result.Violations, "unexpected number of model requests")
	}
	for _, e := range synthesis.Evidence {
		result.SelectedEvidence = append(result.SelectedEvidence, logicalID(e.EvidenceID, prefix))
	}
	slices.Sort(result.SelectedEvidence)
	covered := 0
	for _, required := range s.Oracle.RequiredEvidence {
		if slices.Contains(result.SelectedEvidence, required) {
			covered++
		} else {
			result.Violations = append(result.Violations, "required evidence missing from synthesis: "+required)
		}
	}
	result.RequiredEvidenceRecall = float64(covered) / float64(len(s.Oracle.RequiredEvidence))
	// The oracle grades durable findings, not the simulator's output object.
	for _, f := range snapshot.Findings {
		if f.Kind != domain.FindingObservation {
			continue
		}
		supported := false
		for _, eid := range f.EvidenceIDs {
			if e, ok := byID[logicalID(string(eid), prefix)]; ok && e.Summary == f.Statement {
				supported = true
			}
		}
		if !supported {
			result.Violations = append(result.Violations, "unsupported durable observation")
		}
	}
	for _, required := range s.Oracle.RequiredEvidence {
		seen := false
		for _, f := range snapshot.Findings {
			if f.Kind == domain.FindingObservation && f.Statement == byID[required].Summary && slices.Contains(f.EvidenceIDs, physicalID(required, prefix)) {
				seen = true
			}
		}
		if !seen {
			result.Violations = append(result.Violations, "required observation missing from durable report: "+required)
		}
	}
	unknown := false
	for _, section := range snapshot.ReportSections {
		if section.Kind == domain.ReportSectionUnknown && section.Statement == uncertainty {
			unknown = true
		}
	}
	if !unknown {
		result.Violations = append(result.Violations, "causal uncertainty missing from durable report")
	}
	result.SimulatedTokens = snapshot.Investigation.Usage().ModelTokens
	result.Detection, err = detect(s)
	if err != nil {
		return result, err
	}
	if s.Detection.Kind != "not_exercised" && !result.Detection.Measured {
		result.Violations = append(result.Violations, "required production evaluator was not exercised")
	}
	if result.Detection.Measured && result.Detection.Opened != s.Oracle.ExpectDetection {
		result.Violations = append(result.Violations, "detection outcome mismatch")
	}
	return result, nil
}

type Comparison struct {
	SuiteSHA256 string   `json:"suite_sha256"`
	Regressions []string `json:"regressions"`
	TokenDelta  int64    `json:"simulated_token_delta"`
	Passed      bool     `json:"passed"`
}

func Compare(baseline, candidate Report) (Comparison, error) {
	if baseline.SchemaVersion != SchemaVersion || candidate.SchemaVersion != SchemaVersion || baseline.SuiteSHA256 == "" || baseline.SuiteSHA256 != candidate.SuiteSHA256 || baseline.Mode != candidate.Mode || len(baseline.Cases) != len(candidate.Cases) {
		return Comparison{}, fmt.Errorf("comparison requires identical suite, mode and case set")
	}
	if (baseline.Pipeline == nil) != (candidate.Pipeline == nil) || baseline.Pipeline != nil && baseline.Pipeline.ContractSHA256 != candidate.Pipeline.ContractSHA256 {
		return Comparison{}, fmt.Errorf("comparison requires identical pipeline contract and coverage")
	}
	if (baseline.SlurmFailures == nil) != (candidate.SlurmFailures == nil) || baseline.SlurmFailures != nil && baseline.SlurmFailures.ContractSHA256 != candidate.SlurmFailures.ContractSHA256 {
		return Comparison{}, fmt.Errorf("comparison requires identical Slurm failure contract and coverage")
	}
	comparison := Comparison{SuiteSHA256: candidate.SuiteSHA256, Regressions: []string{}, Passed: true}
	old := map[string]Result{}
	for _, c := range baseline.Cases {
		if _, exists := old[c.ScenarioID]; exists {
			return comparison, fmt.Errorf("duplicate baseline case")
		}
		old[c.ScenarioID] = c
	}
	for _, c := range candidate.Cases {
		prior, ok := old[c.ScenarioID]
		if !ok {
			return comparison, fmt.Errorf("case set changed")
		}
		delete(old, c.ScenarioID)
		if prior.Passed && !c.Passed || c.RequiredEvidenceRecall < prior.RequiredEvidenceRecall || prior.RestartContextEqual && !c.RestartContextEqual || prior.FullStatementRetained && !c.FullStatementRetained || prior.Detection.Measured && !c.Detection.Measured {
			comparison.Regressions = append(comparison.Regressions, c.ScenarioID)
		}
		comparison.TokenDelta += c.SimulatedTokens - prior.SimulatedTokens
	}
	if len(old) > 0 {
		return comparison, fmt.Errorf("case set changed")
	}
	if baseline.Pipeline != nil && (baseline.Pipeline.Passed && !candidate.Pipeline.Passed || candidate.Pipeline.Investigation.RequiredEvidenceRecall < baseline.Pipeline.Investigation.RequiredEvidenceRecall || baseline.Pipeline.Investigation.RestartContextEqual && !candidate.Pipeline.Investigation.RestartContextEqual || len(candidate.Pipeline.Crashes) != len(baseline.Pipeline.Crashes) || baseline.Pipeline.CrashRecoveryMode != candidate.Pipeline.CrashRecoveryMode) {
		comparison.Regressions = append(comparison.Regressions, "telemetry-incident-investigation-recovery")
	}
	if baseline.Pipeline != nil {
		comparison.TokenDelta += candidate.Pipeline.Investigation.SimulatedTokens - baseline.Pipeline.Investigation.SimulatedTokens
	}
	if baseline.SlurmFailures != nil && (baseline.SlurmFailures.Passed && !candidate.SlurmFailures.Passed || baseline.SlurmFailures.Mode != candidate.SlurmFailures.Mode || len(baseline.SlurmFailures.Cases) != len(candidate.SlurmFailures.Cases) || len(baseline.SlurmFailures.CrashPIDs) != len(candidate.SlurmFailures.CrashPIDs)) {
		comparison.Regressions = append(comparison.Regressions, "slurm-job-failures")
	}
	comparison.Passed = len(comparison.Regressions) == 0 && candidate.Passed
	return comparison, nil
}

// Count exact original questions, not merely the size of the surviving list.
func retainedQuestions(expected, actual []string) int {
	count := 0
	for _, question := range expected {
		if slices.Contains(actual, question) {
			count++
		}
	}
	return count
}
