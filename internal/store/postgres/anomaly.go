package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

type AnomalyBridgeStore struct{ pool *pgxpool.Pool }

func NewAnomalyBridgeStore(pool *pgxpool.Pool) (*AnomalyBridgeStore, error) {
	if pool == nil {
		return nil, fmt.Errorf("PostgreSQL pool is required")
	}
	return &AnomalyBridgeStore{pool: pool}, nil
}

func (store *AnomalyBridgeStore) NextCommittedCollection(ctx context.Context, consumer string, cluster domain.ClusterID) (application.CommittedCollection, bool, error) {
	if consumer == "" || cluster == "" {
		return application.CommittedCollection{}, false, fmt.Errorf("anomaly cursor identity is required")
	}
	if _, err := store.pool.Exec(ctx, `INSERT INTO anomaly_reconcile_cursors (consumer_id,cluster_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`, consumer, cluster); err != nil {
		return application.CommittedCollection{}, false, fmt.Errorf("ensure anomaly cursor: %w", err)
	}
	var eventID int64
	var payload []byte
	var eventCreated time.Time
	err := store.pool.QueryRow(ctx, `
		SELECT e.event_id,e.payload,e.created_at
		FROM cluster_events e JOIN anomaly_reconcile_cursors c ON c.cluster_id=e.cluster_id AND c.consumer_id=$1
		WHERE e.cluster_id=$2 AND e.event_id>c.last_event_id
		ORDER BY e.event_id LIMIT 1`, consumer, cluster).Scan(&eventID, &payload, &eventCreated)
	if err == pgx.ErrNoRows {
		return application.CommittedCollection{}, false, nil
	}
	if err != nil {
		return application.CommittedCollection{}, false, fmt.Errorf("load next committed event: %w", err)
	}
	var event struct {
		RunID domain.RunID `json:"run_id"`
	}
	if err := json.Unmarshal(payload, &event); err != nil {
		return application.CommittedCollection{}, false, fmt.Errorf("decode committed event: %w", err)
	}
	// Non-collection events still advance the cursor deterministically.
	if event.RunID == "" {
		return application.CommittedCollection{EventID: eventID, ClusterID: cluster, RunID: domain.RunID(fmt.Sprintf("event-%d", eventID)), Query: "non_collection", CompletedAt: eventCreated.UTC()}, true, nil
	}
	result := application.CommittedCollection{EventID: eventID, ClusterID: cluster, RunID: event.RunID}
	if err := store.pool.QueryRow(ctx, `SELECT query_kind,completed_at FROM collection_runs WHERE run_id=$1 AND cluster_id=$2`, event.RunID, cluster).Scan(&result.Query, &result.CompletedAt); err != nil {
		return application.CommittedCollection{}, false, fmt.Errorf("load committed collection %s: %w", event.RunID, err)
	}
	err = store.pool.QueryRow(ctx, `
		SELECT evidence_id,status,created_at
		FROM evidence_envelopes
		WHERE run_id=$1 AND cluster_id=$2 AND created_at<=$3
		ORDER BY created_at,evidence_id LIMIT 1`, event.RunID, cluster, eventCreated).Scan(&result.EvidenceID, &result.EvidenceStatus, &result.EvidenceCreatedAt)
	if err != nil && err != pgx.ErrNoRows {
		return application.CommittedCollection{}, false, fmt.Errorf("load committed evidence: %w", err)
	}
	rows, err := store.pool.Query(ctx, `SELECT entity_key,metric,labels,value FROM observations WHERE run_id=$1 ORDER BY observation_id`, event.RunID)
	if err != nil {
		return application.CommittedCollection{}, false, fmt.Errorf("load anomaly observations: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var observation application.AnomalyObservation
		var labels []byte
		if err := rows.Scan(&observation.EntityKey, &observation.Metric, &labels, &observation.Value); err != nil {
			return application.CommittedCollection{}, false, err
		}
		var storedLabels []domain.Label
		if err := json.Unmarshal(labels, &storedLabels); err != nil {
			return application.CommittedCollection{}, false, fmt.Errorf("decode observation labels: %w", err)
		}
		observation.Labels = make(map[string]string, len(storedLabels))
		for _, label := range storedLabels {
			observation.Labels[label.Name] = label.Value
		}
		result.Observations = append(result.Observations, observation)
	}
	if err := rows.Err(); err != nil {
		return application.CommittedCollection{}, false, err
	}
	if result.Query == domain.QueryGPUXID {
		result.PreviousXIDValues = make(map[string]float64)
		stateRows, err := store.pool.Query(ctx, `SELECT state_key,last_value FROM anomaly_xid_episode_state WHERE consumer_id=$1 AND cluster_id=$2`, consumer, cluster)
		if err != nil {
			return application.CommittedCollection{}, false, fmt.Errorf("load XID episode state: %w", err)
		}
		defer stateRows.Close()
		for stateRows.Next() {
			var key string
			var value float64
			if err := stateRows.Scan(&key, &value); err != nil {
				return application.CommittedCollection{}, false, fmt.Errorf("scan XID episode state: %w", err)
			}
			result.PreviousXIDValues[key] = value
		}
		if err := stateRows.Err(); err != nil {
			return application.CommittedCollection{}, false, fmt.Errorf("read XID episode state: %w", err)
		}
	}
	return result, true, nil
}

func (store *AnomalyBridgeStore) CommitAnomalyEvaluation(ctx context.Context, consumer string, collection application.CommittedCollection, signal *application.AnomalySignal, policy application.AutomaticInvestigationPolicy, now time.Time) (*application.PendingAutomaticInvestigation, error) {
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, fmt.Errorf("begin anomaly reconciliation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var cursor int64
	if err := tx.QueryRow(ctx, `SELECT last_event_id FROM anomaly_reconcile_cursors WHERE consumer_id=$1 AND cluster_id=$2 FOR UPDATE`, consumer, collection.ClusterID).Scan(&cursor); err != nil {
		return nil, fmt.Errorf("lock anomaly cursor: %w", err)
	}
	if collection.EventID <= cursor {
		return nil, nil
	}
	var next int64
	if err := tx.QueryRow(ctx, `SELECT event_id FROM cluster_events WHERE cluster_id=$1 AND event_id>$2 ORDER BY event_id LIMIT 1`, collection.ClusterID, cursor).Scan(&next); err != nil || next != collection.EventID {
		return nil, fmt.Errorf("anomaly event order conflict")
	}
	var pending *application.PendingAutomaticInvestigation
	if signal != nil {
		pending, err = store.reconcileSignal(ctx, tx, collection, *signal, policy, now.UTC())
		if err != nil {
			return nil, err
		}
	}
	if collection.Query == domain.QueryGPUXID {
		for _, observation := range application.NormalizeXIDObservations(collection.Observations) {
			if _, err := tx.Exec(ctx, `
				INSERT INTO anomaly_xid_episode_state (consumer_id,cluster_id,state_key,last_value,last_observed_at,updated_at)
				VALUES ($1,$2,$3,$4,$5,$6)
				ON CONFLICT (consumer_id,cluster_id,state_key) DO UPDATE
				SET last_value=EXCLUDED.last_value,last_observed_at=EXCLUDED.last_observed_at,updated_at=EXCLUDED.updated_at
				WHERE anomaly_xid_episode_state.last_observed_at<=EXCLUDED.last_observed_at`, consumer, collection.ClusterID, observation.StateKey, observation.Value, collection.CompletedAt.UTC(), now.UTC()); err != nil {
				return nil, fmt.Errorf("record XID episode state: %w", err)
			}
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE anomaly_reconcile_cursors SET last_event_id=$3,updated_at=$4 WHERE consumer_id=$1 AND cluster_id=$2`, consumer, collection.ClusterID, collection.EventID, now.UTC()); err != nil {
		return nil, fmt.Errorf("advance anomaly cursor: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit anomaly reconciliation: %w", err)
	}
	return pending, nil
}

func (store *AnomalyBridgeStore) reconcileSignal(ctx context.Context, tx pgx.Tx, collection application.CommittedCollection, signal application.AnomalySignal, policy application.AutomaticInvestigationPolicy, now time.Time) (*application.PendingAutomaticInvestigation, error) {
	// Revalidate the evidence inside the incident transition transaction.
	var evidenceCreated, observedStart, observedEnd time.Time
	var evidenceStatus domain.EvidenceStatus
	if err := tx.QueryRow(ctx, `SELECT created_at,observed_start,observed_end,status FROM evidence_envelopes WHERE evidence_id=$1 AND cluster_id=$2 AND run_id=$3 AND created_at<=$4`, signal.EvidenceID, collection.ClusterID, collection.RunID, now).Scan(&evidenceCreated, &observedStart, &observedEnd, &evidenceStatus); err != nil {
		return nil, fmt.Errorf("revalidate committed anomaly evidence: %w", err)
	}
	var incidentID string
	var fingerprint []byte
	var version int
	err := tx.QueryRow(ctx, `
		SELECT a.incident_id,a.fingerprint,i.version
		FROM anomaly_incidents a JOIN incidents i ON i.incident_id=a.incident_id
		WHERE a.cluster_id=$1 AND a.rule_id=$2 AND a.entity_key=$3
		  AND a.cooldown_until >= $4 AND i.status NOT IN ('RESOLVED','CLOSED')
		ORDER BY a.last_signal_at DESC LIMIT 1 FOR UPDATE OF a,i`, collection.ClusterID, signal.RuleID, signal.EntityKey, signal.ObservedAt).Scan(&incidentID, &fingerprint, &version)
	if err == pgx.ErrNoRows {
		group := stableAnomalyDigest(string(collection.ClusterID), signal.RuleID, signal.EntityKey)
		bucket := signal.ObservedAt.UTC().Truncate(policy.Cooldown).Format(time.RFC3339Nano)
		episode := stableAnomalyDigest(hex.EncodeToString(group[:]), bucket)
		fingerprint = episode[:]
		incidentID = "incident-auto-" + hex.EncodeToString(episode[:16])
		version = 1
		payload, _ := json.Marshal(map[string]any{"summary": "Deterministic DCGM XID anomaly", "target_ids": signal.EntityIDs, "evidence_ids": []domain.EvidenceID{signal.EvidenceID}, "rule_id": signal.RuleID})
		if _, err := tx.Exec(ctx, `INSERT INTO incidents (incident_id,cluster_id,title,summary,severity,status,created_by,version,next_event_sequence,created_at,updated_at) VALUES ($1,$2,$3,$4,$5,'OPEN',$6,1,2,$7,$7)`, incidentID, collection.ClusterID, "DCGM XID error detected", "A reviewed deterministic rule observed a non-zero DCGM XID counter.", signal.Severity, policy.ServiceActor, now); err != nil {
			return nil, fmt.Errorf("create anomaly incident: %w", err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO incident_events (cluster_id,incident_id,sequence,event_key,event_type,actor_id,incident_version,payload,occurred_at) VALUES ($1,$2,1,$3,'CREATED',$4,1,$5,$6)`, collection.ClusterID, incidentID, "created-"+incidentID, policy.ServiceActor, payload, now); err != nil {
			return nil, fmt.Errorf("record anomaly incident event: %w", err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO anomaly_incidents (fingerprint,cluster_id,rule_id,entity_key,incident_id,first_signal_at,last_signal_at,cooldown_until) VALUES ($1,$2,$3,$4,$5,$6,$6,$7)`, fingerprint, collection.ClusterID, signal.RuleID, signal.EntityKey, incidentID, signal.ObservedAt, signal.ObservedAt.Add(policy.Cooldown)); err != nil {
			return nil, fmt.Errorf("record anomaly fingerprint: %w", err)
		}
	} else if err != nil {
		return nil, fmt.Errorf("find deduplicated incident: %w", err)
	} else {
		version++
		if _, err := tx.Exec(ctx, `UPDATE anomaly_incidents SET last_signal_at=GREATEST(last_signal_at,$2),signal_count=signal_count+1,cooldown_until=GREATEST(cooldown_until,$2+make_interval(secs=>$3)) WHERE fingerprint=$1`, fingerprint, signal.ObservedAt, policy.Cooldown.Seconds()); err != nil {
			return nil, fmt.Errorf("update anomaly occurrence: %w", err)
		}
		if _, err := tx.Exec(ctx, `UPDATE incidents SET version=$2,updated_at=$3 WHERE incident_id=$1`, incidentID, version, now); err != nil {
			return nil, fmt.Errorf("update anomaly incident: %w", err)
		}
	}
	if _, err := tx.Exec(ctx, `INSERT INTO incident_evidence (incident_id,evidence_id,attached_at) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING`, incidentID, signal.EvidenceID, now); err != nil {
		return nil, fmt.Errorf("attach committed incident evidence: %w", err)
	}

	decision, err := automaticDecision(ctx, tx, incidentID, collection.ClusterID, signal, evidenceCreated, evidenceStatus, policy, now)
	if err != nil {
		return nil, err
	}
	attemptDigest := stableAnomalyDigest(incidentID, fmt.Sprint(collection.EventID), decision)
	attemptID := "auto-attempt-" + hex.EncodeToString(attemptDigest[:16])
	if decision != "ELIGIBLE" {
		empty, _ := json.Marshal(map[string]any{})
		_, err := tx.Exec(ctx, `INSERT INTO automatic_investigation_attempts (attempt_id,incident_id,cluster_id,source_event_id,rule_id,service_actor,idempotency_key,status,decision_code,max_model_tokens,max_cost_microunits,request,created_at,updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,'BLOCKED',$8,$9,$10,$11,$12,$12) ON CONFLICT (incident_id,source_event_id) DO NOTHING`, attemptID, incidentID, collection.ClusterID, collection.EventID, signal.RuleID, policy.ServiceActor, "blocked-"+attemptID, decision, policy.InvestigationBudget.MaxModelTokens, policy.InvestigationBudget.MaxCostMicros, empty, now)
		if err != nil {
			return nil, fmt.Errorf("record automatic policy block: %w", err)
		}
		return nil, nil
	}
	idempotency := fmt.Sprintf("auto-%s-v%d", hex.EncodeToString(fingerprint[:16]), version)
	investigationDigest := sha256.Sum256([]byte(string(collection.ClusterID) + "\x00" + idempotency))
	investigationID := domain.InvestigationID("investigation-" + hex.EncodeToString(investigationDigest[:16]))
	request := domain.InvestigationRequest{ID: investigationID, IncidentID: domain.IncidentID(incidentID), ClusterID: collection.ClusterID, Question: "Why did the affected GPU entities report non-zero DCGM XID errors?", RequestedBy: policy.ServiceActor, IdempotencyKey: idempotency, Scope: domain.InvestigationScope{EntityKind: "entity", EntityIDs: signal.EntityIDs, Start: observedStart.UTC(), End: observedEnd.UTC()}, SuccessCriteria: []string{"Explain the XID signal using cited committed evidence", "State coverage gaps and uncertainty"}, Budget: policy.InvestigationBudget, RequestedAt: now, Deadline: now.Add(policy.InvestigationTTL)}
	if err := request.Validate(); err != nil {
		return nil, fmt.Errorf("build automatic investigation request: %w", err)
	}
	encoded, _ := json.Marshal(request)
	_, err = tx.Exec(ctx, `INSERT INTO automatic_investigation_attempts (attempt_id,incident_id,cluster_id,source_event_id,rule_id,service_actor,idempotency_key,status,decision_code,max_model_tokens,max_cost_microunits,request,created_at,updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,'RESERVED','ELIGIBLE',$8,$9,$10,$11,$11) ON CONFLICT (incident_id,source_event_id) DO NOTHING`, attemptID, incidentID, collection.ClusterID, collection.EventID, signal.RuleID, policy.ServiceActor, idempotency, policy.InvestigationBudget.MaxModelTokens, policy.InvestigationBudget.MaxCostMicros, encoded, now)
	if err != nil {
		return nil, fmt.Errorf("reserve automatic investigation: %w", err)
	}
	return &application.PendingAutomaticInvestigation{AttemptID: attemptID, Request: request}, nil
}

func automaticDecision(ctx context.Context, tx pgx.Tx, incidentID string, cluster domain.ClusterID, signal application.AnomalySignal, evidenceCreated time.Time, coverage domain.EvidenceStatus, policy application.AutomaticInvestigationPolicy, now time.Time) (string, error) {
	facts := application.AutomaticInvestigationFacts{EvidenceCreatedAt: evidenceCreated, Coverage: coverage, CooldownElapsed: true}
	var recentStarts int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM automatic_investigation_attempts WHERE incident_id=$1 AND status='STARTED' AND created_at>($2::timestamptz-make_interval(secs=>$3))`, incidentID, now, policy.Cooldown.Seconds()).Scan(&recentStarts); err != nil {
		return "", fmt.Errorf("check automatic investigation cooldown: %w", err)
	}
	facts.CooldownElapsed = recentStarts == 0
	var active int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM investigations WHERE incident_id=$1 AND status NOT IN ('COMPLETED','PARTIAL','BLOCKED','CANCELLED')`, incidentID).Scan(&active); err != nil {
		return "", fmt.Errorf("check incident active investigation: %w", err)
	}
	facts.IncidentActive = active > 0
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM investigations WHERE cluster_id=$1 AND requested_by=$2 AND status NOT IN ('COMPLETED','PARTIAL','BLOCKED','CANCELLED')`, cluster, policy.ServiceActor).Scan(&facts.Concurrent); err != nil {
		return "", fmt.Errorf("check automatic investigation concurrency: %w", err)
	}
	if err := tx.QueryRow(ctx, `SELECT COALESCE(sum(max_model_tokens),0),COALESCE(sum(max_cost_microunits),0) FROM automatic_investigation_attempts WHERE cluster_id=$1 AND status IN ('RESERVED','STARTED') AND created_at>=date_trunc('day',$2 AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'`, cluster, now).Scan(&facts.DailyReservedTokens, &facts.DailyReservedCost); err != nil {
		return "", fmt.Errorf("load automatic daily budgets: %w", err)
	}
	return application.EvaluateAutomaticInvestigationPolicy(signal, policy, facts, now), nil
}

func (store *AnomalyBridgeStore) NextPendingAutomaticInvestigation(ctx context.Context, _ string, cluster domain.ClusterID, _ time.Time) (*application.PendingAutomaticInvestigation, error) {
	var attemptID string
	var encoded []byte
	err := store.pool.QueryRow(ctx, `SELECT attempt_id,request FROM automatic_investigation_attempts WHERE cluster_id=$1 AND status='RESERVED' ORDER BY created_at,attempt_id LIMIT 1`, cluster).Scan(&attemptID, &encoded)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("load reserved automatic investigation: %w", err)
	}
	var request domain.InvestigationRequest
	if err := json.Unmarshal(encoded, &request); err != nil {
		return nil, fmt.Errorf("decode reserved automatic investigation: %w", err)
	}
	if err := request.Validate(); err != nil {
		return nil, fmt.Errorf("validate reserved automatic investigation: %w", err)
	}
	return &application.PendingAutomaticInvestigation{AttemptID: attemptID, Request: request}, nil
}

func (store *AnomalyBridgeStore) CompleteAutomaticInvestigation(ctx context.Context, attemptID string, investigationID domain.InvestigationID, now time.Time) error {
	command, err := store.pool.Exec(ctx, `UPDATE automatic_investigation_attempts SET status='STARTED',investigation_id=$2,updated_at=$3 WHERE attempt_id=$1 AND status='RESERVED'`, attemptID, investigationID, now.UTC())
	if err != nil {
		return fmt.Errorf("complete automatic investigation start: %w", err)
	}
	if command.RowsAffected() != 1 {
		return fmt.Errorf("automatic investigation reservation is unavailable")
	}
	return nil
}

func stableAnomalyDigest(parts ...string) [32]byte {
	hash := sha256.New()
	for _, part := range parts {
		_, _ = hash.Write([]byte(part))
		_, _ = hash.Write([]byte{0})
	}
	var result [32]byte
	copy(result[:], hash.Sum(nil))
	return result
}

var _ application.AnomalyBridgeStore = (*AnomalyBridgeStore)(nil)
