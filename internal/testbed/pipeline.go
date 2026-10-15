package testbed

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	adapter "github.com/verticalcomputer/sherlock/internal/adapters/prometheus"
	"github.com/verticalcomputer/sherlock/internal/application"
	collector "github.com/verticalcomputer/sherlock/internal/collectorexecution/prometheus"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/platform"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

// This contract is separate from the eight investigation-only fixtures. Changes
// require a new baseline. Expected observations are intentionally in the grader,
// never in the worker's stored input or planner request.
const pipelineContract = `{"version":"sherlock.testbed.pipeline/v1","source":"loopback-prometheus","xid":79,"temperature":87,"expected_incidents":1,"expected_investigations":1,"expected_effects":4,"expected_outcome":"PARTIAL","diagnostics":"four_explicitly_unavailable_simulations","crashes":["telemetry_committed","incident_committed","start_committed","effect_committed","evidence_recording_committed","terminal_committed"]}`

var crashBoundaries = []string{"telemetry_committed", "incident_committed", "start_committed", "effect_committed", "evidence_recording_committed", "terminal_committed"}

// ErrInjectedCrash is used only by integration tests that reconstruct in process.
// The CLI exits immediately with CrashExitCode, without executing deferred cleanup.
var ErrInjectedCrash = errors.New("testbed injected crash")

const CrashExitCode = 86

type CrashEvidence struct {
	Boundary        string `json:"boundary"`
	ProcessID       int    `json:"process_id"`
	CollectionRuns  int    `json:"collection_runs"`
	Observations    int    `json:"observations"`
	Envelopes       int    `json:"envelopes"`
	Incidents       int    `json:"incidents"`
	Investigations  int    `json:"investigations"`
	ReservedStarts  int    `json:"reserved_starts"`
	StartedAttempts int    `json:"started_attempts"`
	Effects         int    `json:"effects"`
	ReplayReceipts  int    `json:"replayed_receipts"`
	LedgerEntries   int    `json:"ledger_entries"`
	PendingEvidence int    `json:"pending_evidence"`
	Actions         int    `json:"actions"`
	State           string `json:"state"`
}
type PipelineResult struct {
	ContractSHA256    string          `json:"contract_sha256"`
	Passed            bool            `json:"passed"`
	CrashRecoveryMode string          `json:"crash_recovery_mode"`
	Crashes           []CrashEvidence `json:"crashes"`
	Investigation     Result          `json:"investigation"`
	Final             CrashEvidence   `json:"final"`
	Violations        []string        `json:"violations"`
	UnmeasuredStages  []string        `json:"unmeasured_stages"`
}

// The launcher must return success only after observing the requested crash (or
// a clean exit for an empty boundary). RunPipeline independently checks durable
// crash markers and the persisted state before launching the replacement.
type PipelineLauncher func(context.Context, string, string) error

type stableIDs struct {
	prefix string
	n      int
}

func (g *stableIDs) NewID() (string, error) {
	g.n++
	return fmt.Sprintf("%s-observation-%d", g.prefix, g.n), nil
}

// collectPipeline exercises the production allowlisted HTTP parser and executor.
// No arbitrary endpoint, metric or command is accepted from workers or fixtures.
func collectPipeline(ctx context.Context, prefix string, at time.Time, query domain.QueryKind, mode string) (domain.CollectionResult, error) {
	expectedQuery, err := adapter.RenderQuery(query, "")
	if err != nil {
		return domain.CollectionResult{}, err
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/query" {
			http.NotFound(w, r)
			return
		}
		if r.URL.Query().Get("query") != expectedQuery {
			http.Error(w, "unexpected query", http.StatusBadRequest)
			return
		}
		if mode == "malformed" {
			_, _ = w.Write([]byte(`{"status":`))
			return
		}
		metric, value := "DCGM_FI_DEV_XID_ERRORS", "79"
		if query == domain.QueryGPUTemperature {
			metric, value = "DCGM_FI_DEV_GPU_TEMP", "87"
		}
		if mode == "healthy" {
			value = "0"
		}
		samples := []any{}
		if mode != "empty" {
			labels := map[string]string{"__name__": metric, "Hostname": "node-1", "UUID": "GPU-a"}
			if mode == "ambiguous" {
				labels["hostname"] = "foreign-node"
			}
			samples = append(samples, map[string]any{"metric": labels, "value": []any{at.Unix(), value}})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": map[string]any{"resultType": "vector", "result": samples}})
	}))
	defer server.Close()
	client, err := adapter.NewClient(adapter.Config{BaseURL: server.URL, Timeout: time.Second, MaxBytes: 1 << 20, MaxSeries: 100})
	if err != nil {
		return domain.CollectionResult{}, err
	}
	run := prefix + "-" + string(query)
	executor, err := collector.New(client, clock{at.Add(time.Second)}, &stableIDs{prefix: run})
	if err != nil {
		return domain.CollectionResult{}, err
	}
	return executor.Execute(ctx, domain.CollectionTask{RunID: domain.RunID(run), ClusterID: domain.ClusterID(prefix), SourceID: domain.SourceID(prefix + "-source"), Query: query, ScheduledFor: at, Deadline: at.Add(time.Hour), MaxSeries: 100, MaxBytes: 1 << 20, IdempotencyKey: run}), nil
}

func pipelinePolicy() application.AutomaticInvestigationPolicy {
	return application.AutomaticInvestigationPolicy{Enabled: true, EnabledRules: map[string]bool{application.XIDNonZeroRuleID: true}, MinimumSeverity: "HIGH", MaximumEvidenceAge: 10 * time.Minute, AllowPartialCoverage: true, Cooldown: time.Hour, MaxConcurrent: 1, DailyTokenBudget: 400000, DailyCostBudget: 2000000, InvestigationBudget: domain.InvestigationBudget{MaxDecisions: 8, MaxToolCalls: 4, MaxDiagnosticCalls: 4, MaxFanOut: 1, MaxModelTokens: 200000, MaxCostMicros: 100000}, InvestigationTTL: time.Hour, ServiceActor: "testbed-auto-investigator"}
}

// PipelineWorker is deliberately stateless. Every replacement replays intake,
// drains the real anomaly bridge and reloads the authoritative investigation.
// All fault wrappers live in the lab; production stores/controllers are unchanged.
func PipelineWorker(ctx context.Context, pool *pgxpool.Pool, prefix, boundary string, crash func() error) error {
	if !strings.HasPrefix(prefix, "tb-pipeline-") || boundary != "" && !slices.Contains(crashBoundaries, boundary) {
		return fmt.Errorf("invalid pipeline worker scope or crash boundary")
	}
	if _, err := pool.Exec(ctx, `INSERT INTO testbed_pipeline_workers(prefix,boundary,process_id) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, prefix, boundary, os.Getpid()); err != nil {
		return err
	}
	var at time.Time
	if err := pool.QueryRow(ctx, `SELECT observed_at FROM testbed_pipeline_inputs WHERE prefix=$1`, prefix).Scan(&at); err != nil {
		return err
	}
	f := &pipelineFault{pool, prefix, boundary, crash}
	collections, _ := storepg.NewCollectionStore(pool)
	if err := collections.EnsureSource(ctx, domain.ClusterID(prefix), "Synthetic pipeline cluster", domain.SourceID(prefix+"-source"), "Loopback Prometheus"); err != nil {
		return err
	}
	inventory, _ := storepg.NewGoodputStore(pool)
	_, err := inventory.RecordExpectedInventoryRevision(ctx, domain.InventoryRevision{SchemaVersion: 1, ID: domain.InventoryRevisionID(prefix + "-inventory"), ClusterID: domain.ClusterID(prefix), SourceID: domain.SourceID(prefix + "-source"), SourceAt: at.Add(-time.Hour), EffectiveAt: at.Add(-time.Hour), ObservedAt: at.Add(-time.Hour), Entities: []domain.EntityIdentity{{ClusterID: domain.ClusterID(prefix), Kind: domain.EntityGPU, NodeID: "node-1", PhysicalGPUUUID: "GPU-a"}}})
	if err != nil {
		return err
	}
	for _, q := range []domain.QueryKind{domain.QueryGPUXID, domain.QueryGPUTemperature} {
		result, err := collectPipeline(ctx, prefix, at, q, "")
		if err != nil {
			return err
		}
		if result.Status != domain.ResultSucceeded || len(result.Observations) != 1 {
			return fmt.Errorf("pipeline collection did not return one valid observation")
		}
		if _, err = collections.RecordResult(ctx, result); err != nil {
			return err
		}
	}
	if err := pipelineMissingDiagnostics(ctx, pool, prefix, at); err != nil {
		return err
	}
	if err := f.fire(ctx, "telemetry_committed"); err != nil {
		return err
	}
	store, _ := storepg.NewInvestigationStore(pool)
	bridgeStore, _ := storepg.NewAnomalyBridgeStore(pool)
	var now time.Time
	if err := pool.QueryRow(ctx, `SELECT clock_timestamp()+interval '1 second'`).Scan(&now); err != nil {
		return err
	}
	starter, err := application.NewInvestigationController(store, application.ScriptedInvestigationPlanner{}, worldAdapter{pool: pool}, clock{now}, platform.RandomIDGenerator{})
	if err != nil {
		return err
	}
	bridge, err := application.NewAnomalyBridge(crashBridgeStore{bridgeStore, f}, crashStarter{starter, f}, clock{now}, "testbed-pipeline-v1", domain.ClusterID(prefix), pipelinePolicy())
	if err != nil {
		return err
	}
	drained := false
	for range 32 {
		progress, err := bridge.RunOnce(ctx)
		if err != nil {
			return err
		}
		if !progress {
			drained = true
			break
		}
	}
	if !drained {
		return fmt.Errorf("pipeline anomaly bridge did not drain")
	}
	var id domain.InvestigationID
	if err := pool.QueryRow(ctx, `SELECT investigation_id FROM investigations WHERE cluster_id=$1`, prefix).Scan(&id); err != nil {
		return err
	}
	if _, err := pipelineWorld(ctx, pool, prefix, id); err != nil {
		return err
	}
	if _, err := pool.Exec(ctx, `INSERT INTO testbed_workers(investigation_id,process_id) VALUES($1,$2) ON CONFLICT DO NOTHING`, id, os.Getpid()); err != nil {
		return err
	}
	controller, _, _, _, err := faultComponents(ctx, pool, id, f)
	if err != nil {
		return err
	}
	for range 64 {
		snapshot, err := controller.Advance(ctx, id)
		if err != nil {
			return err
		}
		if snapshot.Investigation.Status().Terminal() {
			return nil
		}
	}
	return fmt.Errorf("pipeline investigation exceeded transition bound")
}
