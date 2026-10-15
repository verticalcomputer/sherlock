package testbed

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/adapters/investigationapi"
	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/auth"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/investigationtools"
	"github.com/verticalcomputer/sherlock/internal/platform"
	"github.com/verticalcomputer/sherlock/internal/slurmfailures"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

var slurmInvestigationCrashes = []string{"slurm_investigation_reserved", "slurm_start_committed", "slurm_read_completed", "slurm_evidence_recorded", "slurm_terminal_committed"}

type SlurmInvestigationReport struct {
	Passed         bool     `json:"passed"`
	CrashPIDs      []int    `json:"crash_pids"`
	FinalPID       int      `json:"final_pid"`
	Investigations int      `json:"investigations"`
	Correlations   int      `json:"correlations"`
	Actions        int      `json:"actions"`
	Evidence       int      `json:"evidence"`
	ReadReplays    int      `json:"read_replays"`
	SynthesisCalls int      `json:"synthesis_calls"`
	State          string   `json:"state"`
	GPURecords     int      `json:"gpu_records"`
	NetworkPolls   int      `json:"network_polls"`
	Violations     []string `json:"violations"`
}

func slurmInvestigationPolicy() application.AutomaticInvestigationPolicy {
	p := pipelinePolicy()
	p.EnabledRules = map[string]bool{slurmfailures.RuleID: true}
	p.InvestigationBudget.MaxToolCalls = 4
	p.InvestigationBudget.MaxDiagnosticCalls = 0
	return p
}

func slurmCorrelationFixtures(ctx context.Context, pool *pgxpool.Pool, prefix string) error {
	var raw []byte
	if err := pool.QueryRow(ctx, `SELECT document FROM goodput_slurm_lifecycle_facts WHERE cluster_id=$1 LIMIT 1`, prefix).Scan(&raw); err != nil {
		return err
	}
	var l domain.SlurmJobLifecycle
	if err := json.Unmarshal(raw, &l); err != nil {
		return err
	}
	at := l.EndAt.Add(-time.Minute)
	inventory, _ := storepg.NewGoodputStore(pool)
	_, err := inventory.RecordExpectedInventoryRevision(ctx, domain.InventoryRevision{SchemaVersion: 1, ID: domain.InventoryRevisionID(prefix + "-gpu-inventory"), ClusterID: domain.ClusterID(prefix), SourceID: domain.SourceID(prefix + "-source"), SourceAt: at.Add(-time.Hour), EffectiveAt: at.Add(-time.Hour), ObservedAt: at.Add(-time.Hour), Entities: []domain.EntityIdentity{{ClusterID: domain.ClusterID(prefix), Kind: domain.EntityGPU, NodeID: "node-1", PhysicalGPUUUID: "GPU-a"}, {ClusterID: domain.ClusterID(prefix), Kind: domain.EntityGPU, NodeID: "foreign-node", PhysicalGPUUUID: "GPU-foreign"}}})
	if err != nil {
		return err
	}
	collections, _ := storepg.NewCollectionStore(pool)
	for _, q := range []domain.QueryKind{domain.QueryGPUXID, domain.QueryGPUTemperature} {
		result, err := collectPipeline(ctx, prefix, at, q, "")
		if err != nil {
			return err
		}
		foreign := result.Observations[0]
		foreign.ID = domain.ObservationID(string(foreign.ID) + "-foreign")
		foreign.Labels = slices.Clone(foreign.Labels)
		for i := range foreign.Labels {
			if foreign.Labels[i].Name == "Hostname" {
				foreign.Labels[i].Value = "foreign-node"
			}
			if foreign.Labels[i].Name == "UUID" {
				foreign.Labels[i].Value = "GPU-foreign"
			}
		}
		foreign.Value = 999
		result.Observations = append(result.Observations, foreign)
		result.Coverage.SeriesReturned = 2
		expected := 2
		result.Coverage.SeriesExpected = &expected
		if _, err = collections.RecordResult(ctx, result); err != nil {
			return err
		}
	}
	// Committed normalized network-cycle fixture. This intentionally bypasses
	// live enrollment/SSH; production correlation reads the real retained table.
	_, err = pool.Exec(ctx, `INSERT INTO gp09_network_monitors(cluster_id,collector_id,revision,enrollment) VALUES($1,$2,'synthetic-fixture','{}')`, prefix, prefix+"-collector")
	if err != nil {
		return err
	}
	polls := []application.NetworkNodePoll{{Node: "node-1", ObservedAt: at, Outcome: application.NetworkPollComplete, Ports: []application.NetworkPortReading{{Key: application.NetworkPortKey{Node: "node-1", Device: "mlx5_4", Port: 1}, State: "DOWN", PhysicalState: "Polling"}}}, {Node: "foreign-node", ObservedAt: at, Outcome: application.NetworkPollComplete}, {Node: "node-1", ObservedAt: l.EndAt.Add(-time.Hour), Outcome: application.NetworkPollComplete}}
	body, _ := json.Marshal(polls)
	_, err = pool.Exec(ctx, `INSERT INTO gp09_network_cycles(cluster_id,polls,duration_ms) VALUES($1,$2,1)`, prefix, body)
	return err
}

type slurmCrashBridge struct {
	*storepg.AnomalyBridgeStore
	fault *pipelineFault
}

func (s slurmCrashBridge) ReserveSlurmFailureInvestigation(ctx context.Context, c domain.ClusterID, p application.AutomaticInvestigationPolicy, now time.Time) (*application.PendingAutomaticInvestigation, error) {
	pending, err := s.AnomalyBridgeStore.ReserveSlurmFailureInvestigation(ctx, c, p, now)
	if err == nil && pending != nil {
		err = s.fault.fire(ctx, "slurm_investigation_reserved")
	}
	return pending, err
}

type slurmCrashStarter struct {
	application.InvestigationStartCommand
	fault *pipelineFault
}

func (s slurmCrashStarter) Start(ctx context.Context, in application.StartInvestigationInput) (application.InvestigationSnapshot, bool, error) {
	v, created, err := s.InvestigationStartCommand.Start(ctx, in)
	if err == nil {
		err = s.fault.fire(ctx, "slurm_start_committed")
	}
	return v, created, err
}

type slurmReadObserver struct {
	application.InvestigationExecutor
	pool  *pgxpool.Pool
	fault *pipelineFault
}

func (e slurmReadObserver) ExecuteInvestigationAction(ctx context.Context, key string, a domain.InvestigationAction) (application.InvestigationExecutionResult, error) {
	result, err := e.InvestigationExecutor.ExecuteInvestigationAction(ctx, key, a)
	if err != nil {
		return result, err
	}
	raw, _ := json.Marshal(result)
	digest := domain.ChecksumSHA256(raw)
	var prior []byte
	err = e.pool.QueryRow(ctx, `INSERT INTO testbed_slurm_reads(key,digest,replays) VALUES($1,$2,0) ON CONFLICT(key) DO UPDATE SET replays=testbed_slurm_reads.replays+1 RETURNING digest`, key, digest[:]).Scan(&prior)
	if err != nil {
		return result, err
	}
	if !bytes.Equal(prior, digest[:]) {
		return result, fmt.Errorf("slurm read changed during replay")
	}
	return result, e.fault.fire(ctx, "slurm_read_completed")
}

type slurmCrashStore struct {
	application.InvestigationStore
	fault *pipelineFault
}

func (s slurmCrashStore) SaveInvestigation(ctx context.Context, v int, snapshot application.InvestigationSnapshot, event domain.InvestigationEvent) error {
	if err := s.InvestigationStore.SaveInvestigation(ctx, v, snapshot, event); err != nil {
		return err
	}
	if snapshot.Investigation.Status() == domain.InvestigationRecordingEvidence {
		return s.fault.fire(ctx, "slurm_evidence_recorded")
	}
	if snapshot.Investigation.Status().Terminal() {
		return s.fault.fire(ctx, "slurm_terminal_committed")
	}
	return nil
}
func slurmInvestigationWorker(ctx context.Context, pool *pgxpool.Pool, prefix, boundary string, crash func() error) error {
	if err := storepg.NewSlurmFailureStore(pool).Evaluate(ctx, domain.ClusterID(prefix), prefix+"-policy"); err != nil {
		return err
	}
	f := &pipelineFault{pool: pool, prefix: prefix, boundary: boundary, crash: crash}
	store, _ := storepg.NewInvestigationStore(pool)
	bridgeStore, _ := storepg.NewAnomalyBridgeStore(pool)
	var now time.Time
	if err := pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return err
	}
	starter, err := investigationapi.NewFailClosedController(store, clock{now}, platform.RandomIDGenerator{})
	if err != nil {
		return err
	}
	bridge, err := application.NewAnomalyBridge(slurmCrashBridge{bridgeStore, f}, slurmCrashStarter{starter, f}, clock{now}, "testbed-slurm-v2", domain.ClusterID(prefix), slurmInvestigationPolicy())
	if err != nil {
		return err
	}
	for range 32 {
		progress, err := bridge.RunOnce(ctx)
		if err != nil {
			return err
		}
		if !progress {
			break
		}
	}
	var id domain.InvestigationID
	if err := pool.QueryRow(ctx, `SELECT investigation_id FROM investigations WHERE cluster_id=$1`, prefix).Scan(&id); err != nil {
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
	return fmt.Errorf("slurm investigation transition limit")
}
func runSlurmInvestigation(ctx context.Context, pool *pgxpool.Pool, launch PipelineLauncher, processes bool) (SlurmInvestigationReport, error) {
	out := SlurmInvestigationReport{Violations: []string{}}
	if _, err := pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS testbed_slurm_reads(key text PRIMARY KEY,digest bytea NOT NULL,replays int NOT NULL)`); err != nil {
		return out, err
	}
	prefix, err := slurmPrepare(ctx, pool, "investigation")
	if err != nil {
		return out, err
	}
	if err = slurmCorrelationFixtures(ctx, pool, prefix); err != nil {
		return out, err
	}
	pids := map[int]bool{}
	for _, boundary := range slurmInvestigationCrashes {
		if err = launch(ctx, prefix, boundary); err != nil {
			return out, err
		}
		var pid int
		if err = pool.QueryRow(ctx, `SELECT process_id FROM testbed_crashes WHERE prefix=$1 AND boundary=$2`, prefix, boundary).Scan(&pid); err != nil {
			return out, err
		}
		out.CrashPIDs = append(out.CrashPIDs, pid)
		pids[pid] = true
		var investigations, reserved, started, ledger, actions int
		var state string
		if err = pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM investigations WHERE cluster_id=$1),(SELECT count(*) FROM automatic_investigation_attempts WHERE cluster_id=$1 AND status='RESERVED'),(SELECT count(*) FROM automatic_investigation_attempts WHERE cluster_id=$1 AND status='STARTED'),(SELECT count(*) FROM investigation_evidence e JOIN investigations i USING(investigation_id) WHERE i.cluster_id=$1),(SELECT count(*) FROM investigation_actions a JOIN investigations i USING(investigation_id) WHERE i.cluster_id=$1 AND a.status='SUCCEEDED'),coalesce((SELECT status FROM investigations WHERE cluster_id=$1),'')`, prefix).Scan(&investigations, &reserved, &started, &ledger, &actions, &state); err != nil {
			return out, err
		}
		valid := false
		switch boundary {
		case "slurm_investigation_reserved":
			valid = investigations == 0 && reserved == 1
		case "slurm_start_committed":
			valid = investigations == 1 && reserved == 1 && state == "INITIALIZING"
		case "slurm_read_completed":
			valid = investigations == 1 && started == 1 && ledger == 0 && actions == 0 && state == "EXECUTING"
		case "slurm_evidence_recorded":
			valid = investigations == 1 && started == 1 && ledger == 2 && actions == 1 && state == "RECORDING_EVIDENCE"
		case "slurm_terminal_committed":
			valid = investigations == 1 && started == 1 && ledger == 2 && actions == 1 && state == "PARTIAL"
		}
		if !valid {
			out.Violations = append(out.Violations, "unexpected Slurm investigation crash state: "+boundary)
		}
		// Prove the frozen network observations survive deletion of the short ring.
		if boundary == "slurm_investigation_reserved" {
			if _, err = pool.Exec(ctx, `DELETE FROM gp09_network_cycles WHERE cluster_id=$1`, prefix); err != nil {
				return out, err
			}
		}
	}
	if err = launch(ctx, prefix, ""); err != nil {
		return out, err
	}
	if err = pool.QueryRow(ctx, `SELECT process_id FROM testbed_slurm_workers WHERE prefix=$1 AND boundary=''`, prefix).Scan(&out.FinalPID); err != nil {
		return out, err
	}
	var id domain.InvestigationID
	var document []byte
	if err = pool.QueryRow(ctx, `SELECT i.investigation_id,i.status,c.document FROM investigations i JOIN slurm_failure_correlations c USING(incident_id) WHERE i.cluster_id=$1`, prefix).Scan(&id, &out.State, &document); err != nil {
		return out, err
	}
	if err = pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM investigations WHERE cluster_id=$1),(SELECT count(*) FROM slurm_failure_correlations c JOIN incidents i USING(incident_id) WHERE i.cluster_id=$1),(SELECT count(*) FROM investigation_actions WHERE investigation_id=$2 AND status='SUCCEEDED'),(SELECT count(*) FROM investigation_evidence WHERE investigation_id=$2),(SELECT coalesce(sum(replays),0) FROM testbed_slurm_reads WHERE key LIKE 'investigation/'||$2||'/%'),(SELECT count(*) FROM testbed_requests WHERE investigation_id=$2 AND kind='synthesis')`, prefix, id).Scan(&out.Investigations, &out.Correlations, &out.Actions, &out.Evidence, &out.ReadReplays, &out.SynthesisCalls); err != nil {
		return out, err
	}
	var snapshot struct {
		GPU     []json.RawMessage `json:"gpu"`
		Network []json.RawMessage `json:"network"`
		Gaps    []string          `json:"gaps"`
	}
	if err = json.Unmarshal(document, &snapshot); err != nil {
		return out, err
	}
	out.GPURecords, out.NetworkPolls = len(snapshot.GPU), len(snapshot.Network)
	var values struct {
		GPU []struct {
			Value float64 `json:"value"`
		} `json:"gpu"`
	}
	if err = json.Unmarshal(document, &values); err != nil {
		return out, err
	}
	for _, v := range values.GPU {
		if v.Value != 79 && v.Value != 87 {
			out.Violations = append(out.Violations, "foreign GPU value admitted")
		}
	}
	if out.Investigations != 1 || out.Correlations != 1 || out.Actions != 1 || out.Evidence != 2 || out.ReadReplays != 1 || out.SynthesisCalls != 1 || out.State != "PARTIAL" || out.GPURecords != 2 || out.NetworkPolls != 1 || len(snapshot.Gaps) != 0 || strings.Contains(string(document), "foreign-node") {
		out.Violations = append(out.Violations, "Slurm correlation/recovery counts or scope mismatch")
	}
	// Inspect actual model input and durable context, not just terminal status.
	var modelRaw []byte
	if err = pool.QueryRow(ctx, `SELECT payload FROM testbed_requests WHERE investigation_id=$1 AND kind='synthesis'`, id).Scan(&modelRaw); err != nil {
		return out, err
	}
	for _, value := range []string{"GPU_TEMP=87", "XID_ERRORS=79", "mlx5_4", "state=DOWN", "physical=Polling"} {
		if !strings.Contains(string(modelRaw), value) {
			out.Violations = append(out.Violations, "missing committed observation in synthesis: "+value)
		}
	}
	if processes && (len(pids) != len(slurmInvestigationCrashes) || pids[out.FinalPID]) {
		out.Violations = append(out.Violations, "distinct Slurm investigation process recovery missing")
	}
	out.Passed = len(out.Violations) == 0
	return out, nil
}

// Kept beside the process lab to make its real read-only catalog explicit.
func slurmTool(cluster domain.ClusterID) investigationtools.Definition {
	return investigationtools.Definition{SchemaVersion: 1, ID: investigationapi.SlurmFailureToolID, Description: "Read committed Slurm failure correlation", Operation: investigationtools.OperationReadOnly, AllowedClusters: []domain.ClusterID{cluster}, RequiredCapabilities: []auth.Capability{auth.CapabilityInvestigationsRun}, RequiredClusterCapabilities: []investigationtools.ClusterCapability{"testbed.read"}, Scope: investigationtools.ScopePolicy{EntityKinds: []string{"entity"}, MaxTargets: 64, MaxWindow: 24 * time.Hour}, Timeout: time.Second, CostWeight: 1}
}
