package postgres

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/slurmfailures"
)

const slurmCorrelationOperation = "slurm.failure_correlation.v1"

// ReserveSlurmFailureInvestigation consumes a committed episode, never a raw
// scheduler state. Disabled policy leaves detection and delivery untouched.
// source_event_id is the episode occurrence, scoped by its unique incident.
func (s *AnomalyBridgeStore) ReserveSlurmFailureInvestigation(ctx context.Context, cluster domain.ClusterID, policy application.AutomaticInvestigationPolicy, now time.Time) (*application.PendingAutomaticInvestigation, error) {
	if !policy.Enabled || !policy.EnabledRules[slurmfailures.RuleID] {
		return nil, nil
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "automatic-investigation:"+string(cluster)); err != nil {
		return nil, err
	}
	var incident, evidence, source string
	var occurrence int64
	var raw []byte
	var created time.Time
	err = tx.QueryRow(ctx, `SELECT e.incident_id,e.evidence_id,p.source_id,e.occurrence,e.snapshot,e.created_at FROM slurm_failure_episodes e JOIN slurm_failure_policies p USING(policy_id) JOIN incidents i USING(incident_id) JOIN clusters c ON c.cluster_id=p.cluster_id WHERE p.cluster_id=$1 AND c.removed_at IS NULL AND i.status NOT IN ('RESOLVED','CLOSED') AND NOT EXISTS(SELECT 1 FROM automatic_investigation_attempts a WHERE a.incident_id=e.incident_id) ORDER BY e.created_at,e.incident_id LIMIT 1 FOR UPDATE OF i SKIP LOCKED`, cluster).Scan(&incident, &evidence, &source, &occurrence, &raw, &created)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	signal := application.AnomalySignal{RuleID: slurmfailures.RuleID, Severity: "HIGH"}
	decision, err := automaticDecision(ctx, tx, incident, cluster, signal, created, domain.EvidencePartial, policy, now)
	if err != nil {
		return nil, err
	}
	var attached bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM incident_evidence WHERE incident_id=$1 AND evidence_id=$2)`, incident, evidence).Scan(&attached); err != nil {
		return nil, err
	}
	if !attached && decision == "ELIGIBLE" {
		decision = "INCIDENT_EVIDENCE_UNAVAILABLE"
	}
	var attempts []slurmfailures.Attempt
	if len(raw) > 65536 || json.Unmarshal(raw, &attempts) != nil || len(attempts) < 2 || len(attempts) > 32 {
		return nil, fmt.Errorf("invalid Slurm episode snapshot")
	}
	windows := []slurmAttemptWindow{}
	targets := []string{source}
	start, end := now, time.Time{}
	for _, a := range attempts {
		var body []byte
		err = tx.QueryRow(ctx, `SELECT document FROM goodput_slurm_lifecycle_facts WHERE cluster_id=$1 AND source_id=$2 AND record_identity=$3`, cluster, source, a.RecordID).Scan(&body)
		if err == pgx.ErrNoRows {
			if decision == "ELIGIBLE" {
				decision = "ATTEMPT_EVIDENCE_UNAVAILABLE"
			}
			continue
		}
		if err != nil {
			return nil, err
		}
		var l domain.SlurmJobLifecycle
		if json.Unmarshal(body, &l) != nil || slurmfailures.Key(l.Job) != a.Key || !l.EndAt.Equal(a.EndAt) {
			return nil, fmt.Errorf("slurm attempt provenance mismatch")
		}
		from := a.EndAt.Add(-30 * time.Minute)
		if l.StartQuality == domain.SlurmFieldPresent && l.StartAt.After(from) {
			from = l.StartAt
		}
		through := a.EndAt.Add(5 * time.Minute)
		if through.After(now) {
			through = now
		}
		w := slurmAttemptWindow{AttemptKey: a.Key, Start: from, End: through, Nodes: []string{}}
		for _, n := range l.NodeIDs {
			if !slurmfailures.Token(string(n)) {
				return nil, fmt.Errorf("invalid Slurm node identity")
			}
			if !slices.Contains(w.Nodes, string(n)) {
				w.Nodes = append(w.Nodes, string(n))
			}
			if !slices.Contains(targets, string(n)) {
				targets = append(targets, string(n))
			}
		}
		slices.Sort(w.Nodes)
		windows = append(windows, w)
		if len(w.Nodes) == 0 {
			decision = "ATTEMPT_NODES_UNAVAILABLE"
		}
		if from.Before(start) {
			start = from
		}
		if through.After(end) {
			end = through
		}
	}
	if decision == "ELIGIBLE" && (len(targets) > 64 || end.Before(start) || end.Sub(start) > 24*time.Hour) {
		decision = "CORRELATION_SCOPE_LIMIT"
	}
	digest := stableAnomalyDigest(incident, "slurm-investigation-v1")
	key := "auto-slurm-" + hex.EncodeToString(digest[:16])
	attemptID := "auto-attempt-" + hex.EncodeToString(digest[:16])
	id := domain.InvestigationID("investigation-" + hex.EncodeToString(digest[:16]))
	encoded := []byte(`{}`)
	status := "BLOCKED"
	if decision == "ELIGIBLE" {
		budget := policy.InvestigationBudget
		budget.MaxDiagnosticCalls = 0
		budget.MaxPrivilegedCalls = 0
		request := domain.InvestigationRequest{ID: id, IncidentID: domain.IncidentID(incident), ClusterID: cluster, Question: "Why are distinct Slurm job attempts failing? Correlate their recorded nodes and bounded attempt windows with GPU and network observations. Separate coincidence from causality and identify missing coverage.", RequestedBy: policy.ServiceActor, IdempotencyKey: key, Scope: domain.InvestigationScope{EntityKind: "entity", EntityIDs: targets, Start: start.UTC(), End: end.UTC()}, SuccessCriteria: []string{"Cite the failed attempt snapshot and scoped GPU/network correlation", "State unavailable sources, bounded windows and causal uncertainty; do not infer job progress or efficiency"}, Budget: budget, RequestedAt: now.UTC(), Deadline: now.Add(policy.InvestigationTTL).UTC()}
		if err = request.Validate(); err != nil {
			return nil, err
		}
		if err = freezeSlurmCorrelation(ctx, tx, request, source, windows, attempts); err != nil {
			return nil, err
		}
		// The frozen snapshot itself must be committed within the eventual
		// request cutoff; never backdate an evidence envelope.
		if err = tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&request.RequestedAt); err != nil {
			return nil, err
		}
		request.RequestedAt = request.RequestedAt.UTC()
		request.Deadline = request.RequestedAt.Add(policy.InvestigationTTL)
		now = request.RequestedAt
		encoded, err = json.Marshal(request)
		if err != nil {
			return nil, err
		}
		status = "RESERVED"
	}
	_, err = tx.Exec(ctx, `INSERT INTO automatic_investigation_attempts(attempt_id,incident_id,cluster_id,source_event_id,rule_id,service_actor,idempotency_key,status,decision_code,max_model_tokens,max_cost_microunits,request,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$13)`, attemptID, incident, cluster, occurrence, slurmfailures.RuleID, policy.ServiceActor, key, status, decision, policy.InvestigationBudget.MaxModelTokens, policy.InvestigationBudget.MaxCostMicros, encoded, now.UTC())
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	if status != "RESERVED" {
		return nil, nil
	}
	var request domain.InvestigationRequest
	_ = json.Unmarshal(encoded, &request)
	return &application.PendingAutomaticInvestigation{AttemptID: attemptID, Request: request}, nil
}

type slurmAttemptWindow struct {
	AttemptKey string    `json:"attempt_key"`
	Nodes      []string  `json:"nodes"`
	Start      time.Time `json:"start"`
	End        time.Time `json:"end"`
}
type slurmGPUCorrelation struct {
	AttemptKeys   []string  `json:"attempt_keys"`
	EvidenceID    string    `json:"evidence_id"`
	ObservationID string    `json:"observation_id"`
	Node          string    `json:"node"`
	GPU           string    `json:"gpu"`
	Metric        string    `json:"metric"`
	Value         float64   `json:"value"`
	Unit          string    `json:"unit"`
	ObservedAt    time.Time `json:"observed_at"`
}
type slurmNetworkCorrelation struct {
	CycleID     int64                       `json:"cycle_id"`
	AttemptKeys []string                    `json:"attempt_keys"`
	Poll        application.NetworkNodePoll `json:"poll"`
}
type slurmCorrelation struct {
	Attempts       []slurmfailures.Attempt   `json:"attempts"`
	Version        int                       `json:"version"`
	Windows        []slurmAttemptWindow      `json:"attempt_windows"`
	GPU            []slurmGPUCorrelation     `json:"gpu"`
	Network        []slurmNetworkCorrelation `json:"network"`
	GPULimited     bool                      `json:"gpu_input_limited"`
	NetworkLimited bool                      `json:"network_input_limited"`
	Gaps           []string                  `json:"gaps"`
}

func matchingSlurmAttempts(windows []slurmAttemptWindow, node string, at time.Time) []string {
	keys := []string{}
	for _, w := range windows {
		if slices.Contains(w.Nodes, node) && !at.Before(w.Start) && !at.After(w.End) {
			keys = append(keys, w.AttemptKey)
		}
	}
	return keys
}

// Freeze normalized facts before the request cutoff. Neither a later scrape nor
// deletion from the network replay ring can change an admitted correlation.
func freezeSlurmCorrelation(ctx context.Context, tx pgx.Tx, r domain.InvestigationRequest, source string, windows []slurmAttemptWindow, attempts []slurmfailures.Attempt) error {
	out := slurmCorrelation{Version: 1, Attempts: attempts, Windows: windows, GPU: []slurmGPUCorrelation{}, Network: []slurmNetworkCorrelation{}, Gaps: []string{}}
	rows, err := tx.Query(ctx, `SELECT e.evidence_id,o.observation_id,o.metric,o.value,o.unit,o.observed_at,o.labels FROM observations o JOIN evidence_envelopes e ON e.run_id=o.run_id AND e.cluster_id=o.cluster_id AND e.source_id=o.source_id WHERE o.cluster_id=$1 AND o.observed_at BETWEEN $2 AND $3 AND e.created_at<=$4 AND e.operation=ANY($5::text[]) ORDER BY o.observed_at DESC,o.observation_id LIMIT 1025`, r.ClusterID, r.Scope.Start, r.Scope.End, r.RequestedAt, []string{string(domain.QueryGPUXID), string(domain.QueryGPUTemperature), string(domain.QueryGPUPower), string(domain.QueryGPUECC), string(domain.QueryGPUUtilization)})
	if err != nil {
		return err
	}
	count := 0
	for rows.Next() {
		var v slurmGPUCorrelation
		var labelsRaw []byte
		if err = rows.Scan(&v.EvidenceID, &v.ObservationID, &v.Metric, &v.Value, &v.Unit, &v.ObservedAt, &labelsRaw); err != nil {
			rows.Close()
			return err
		}
		count++
		if count > 1024 {
			out.GPULimited = true
			continue
		}
		var labels []domain.Label
		if json.Unmarshal(labelsRaw, &labels) != nil {
			rows.Close()
			return fmt.Errorf("invalid GPU correlation labels")
		}
		node, gpu, ok := domain.DCGMIdentity(labels, domain.CollectionTask{})
		if !ok {
			continue
		}
		v.AttemptKeys = matchingSlurmAttempts(windows, node, v.ObservedAt)
		if len(v.AttemptKeys) == 0 {
			continue
		}
		if len(out.GPU) == 128 {
			out.GPULimited = true
			continue
		}
		v.Node, v.GPU = node, gpu
		out.GPU = append(out.GPU, v)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	rows, err = tx.Query(ctx, `SELECT cycle_id,polls FROM gp09_network_cycles WHERE cluster_id=$1 AND received_at<=$2 ORDER BY cycle_id DESC LIMIT 5`, r.ClusterID, r.RequestedAt)
	if err != nil {
		return err
	}
	cycles := 0
	for rows.Next() {
		var cycle int64
		var raw []byte
		if err = rows.Scan(&cycle, &raw); err != nil {
			rows.Close()
			return err
		}
		cycles++
		if cycles > 4 {
			out.NetworkLimited = true
			continue
		}
		var polls []application.NetworkNodePoll
		if len(raw) > 1048576 || json.Unmarshal(raw, &polls) != nil {
			rows.Close()
			return fmt.Errorf("invalid network correlation input")
		}
		for _, p := range polls {
			keys := matchingSlurmAttempts(windows, p.Node, p.ObservedAt)
			if len(keys) == 0 {
				continue
			}
			if len(out.Network) == 64 {
				out.NetworkLimited = true
				continue
			}
			out.Network = append(out.Network, slurmNetworkCorrelation{CycleID: cycle, AttemptKeys: keys, Poll: p})
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, w := range windows {
		gpu, net := false, false
		for _, v := range out.GPU {
			gpu = gpu || slices.Contains(v.AttemptKeys, w.AttemptKey)
		}
		for _, v := range out.Network {
			net = net || slices.Contains(v.AttemptKeys, w.AttemptKey) && v.Poll.Outcome == application.NetworkPollComplete
		}
		if !gpu {
			out.Gaps = append(out.Gaps, "GPU_NOT_OBSERVED:"+w.AttemptKey)
		}
		if !net {
			out.Gaps = append(out.Gaps, "NETWORK_NOT_OBSERVED:"+w.AttemptKey)
		}
	}
	body, err := json.Marshal(out)
	if err != nil {
		return err
	}
	if len(body) > 240000 {
		return fmt.Errorf("slurm correlation payload limit exceeded")
	}
	eid := domain.EvidenceID("evidence-slurm-correlation-" + string(r.ID))
	target := domain.EvidenceTarget{Kind: domain.EvidenceTargetSource, ID: domain.EvidenceTargetID(source)}
	envelope, err := domain.CreateEvidenceEnvelope(domain.NewEvidenceEnvelope{ID: eid, SchemaVersion: 1, ClusterID: r.ClusterID, Status: domain.EvidencePartial, Source: domain.EvidenceSourceReference{SourceID: domain.SourceID(source), Operation: slurmCorrelationOperation, DefinitionVersion: "1", Reference: domain.EvidenceSourceLocator("slurm-correlation:" + string(r.IncidentID))}, TimeRange: domain.EvidenceTimeRange{Start: r.Scope.Start, End: r.Scope.End}, CollectedAt: r.RequestedAt, Coverage: domain.EvidenceCoverage{Expected: []domain.EvidenceTarget{target}}})
	if err != nil {
		return err
	}
	if _, err = insertEvidenceEnvelope(ctx, tx, envelope); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO slurm_failure_correlations(incident_id,evidence_id,document,created_at) VALUES($1,$2,$3,$4)`, r.IncidentID, eid, body, r.RequestedAt); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO incident_evidence(incident_id,evidence_id,attached_at) VALUES($1,$2,$3)`, r.IncidentID, eid, r.RequestedAt)
	return err
}
