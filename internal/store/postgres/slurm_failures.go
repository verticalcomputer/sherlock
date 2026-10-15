package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/slurmfailures"
)

type SlurmFailureStore struct{ pool *pgxpool.Pool }

func NewSlurmFailureStore(pool *pgxpool.Pool) *SlurmFailureStore { return &SlurmFailureStore{pool} }

type SlurmFailureNotification struct {
	InvestigationID       *string                 `json:"investigation_id"`
	InvestigationDecision string                  `json:"investigation_decision"`
	Snapshot              []slurmfailures.Attempt `json:"attempt_evidence"`
	IncidentID            string                  `json:"incident_id"`
	EvidenceID            string                  `json:"evidence_id"`
	AlertID               string                  `json:"alert_id"`
	Status                string                  `json:"status"`
	LastCode              string                  `json:"last_code"`
	Attempts              int                     `json:"attempts"`
}
type SlurmFailureStatus struct {
	Notifications       []SlurmFailureNotification `json:"notifications"`
	Policy              slurmfailures.Policy       `json:"policy"`
	Enabled             bool                       `json:"enabled"`
	Revision            int64                      `json:"revision"`
	Occurrence          int64                      `json:"occurrence"`
	ActiveIncidentID    *string                    `json:"active_incident_id"`
	LastEvaluatedAt     *time.Time                 `json:"last_evaluated_at"`
	LastCode            string                     `json:"last_code"`
	ObservedFailures    int                        `json:"observed_failures"`
	ConflictingAttempts int                        `json:"conflicting_attempts"`
}

func slurmSourceAuthority(ctx context.Context, tx pgx.Tx, p slurmfailures.Policy) error {
	var kind string
	var removed *time.Time
	err := tx.QueryRow(ctx, `SELECT s.kind,c.removed_at FROM sources s JOIN clusters c USING(cluster_id) WHERE s.cluster_id=$1 AND s.source_id=$2 FOR SHARE OF s,c`, p.ClusterID, p.SourceID).Scan(&kind, &removed)
	if err != nil {
		return err
	}
	if kind != "slurm" || removed != nil {
		return ErrMonitoringAuthority
	}
	return nil
}

// Enroll is local operator administration, with immutable policy content and
// optimistic enable/disable revisions. Actor is audit attribution, not auth.
func (s *SlurmFailureStore) Enroll(ctx context.Context, p slurmfailures.Policy, expected int64, actor string) (SlurmFailureStatus, error) {
	if err := p.Validate(); err != nil {
		return SlurmFailureStatus{}, err
	}
	if !slurmfailures.Token(actor) || expected < 0 {
		return SlurmFailureStatus{}, fmt.Errorf("invalid Slurm monitoring operator command")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return SlurmFailureStatus{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err = slurmSourceAuthority(ctx, tx, p); err != nil {
		return SlurmFailureStatus{}, err
	}
	raw, _ := json.Marshal(p)
	tag, err := tx.Exec(ctx, `INSERT INTO slurm_failure_policies(policy_id,cluster_id,source_id,policy) SELECT $1,$2,$3,$4 WHERE $5=0 ON CONFLICT DO NOTHING`, p.ID, p.ClusterID, p.SourceID, raw, expected)
	if err != nil {
		return SlurmFailureStatus{}, err
	}
	action := "ENROLLED"
	revision := int64(1)
	if tag.RowsAffected() == 0 {
		var prior []byte
		var enabled bool
		if err = tx.QueryRow(ctx, `SELECT policy,enabled,revision FROM slurm_failure_policies WHERE policy_id=$1 AND cluster_id=$2 FOR UPDATE`, p.ID, p.ClusterID).Scan(&prior, &enabled, &revision); err != nil {
			return SlurmFailureStatus{}, err
		}
		var old slurmfailures.Policy
		if err = json.Unmarshal(prior, &old); err != nil {
			return SlurmFailureStatus{}, err
		}
		oldRaw, _ := json.Marshal(old)
		if !bytes.Equal(raw, oldRaw) {
			return SlurmFailureStatus{}, ErrMonitoringPolicyConflict
		}
		if expected != revision {
			return SlurmFailureStatus{}, ErrMonitoringRevision
		}
		if enabled {
			if err = tx.Commit(ctx); err != nil {
				return SlurmFailureStatus{}, err
			}
			return s.Status(ctx, p.ClusterID, p.ID)
		}
		revision++
		action = "ENABLED"
		if _, err = tx.Exec(ctx, `UPDATE slurm_failure_policies SET enabled=true,revision=$2,next_due_at=clock_timestamp() WHERE policy_id=$1`, p.ID, revision); err != nil {
			return SlurmFailureStatus{}, err
		}
	}
	if _, err = tx.Exec(ctx, `INSERT INTO slurm_failure_audit(policy_id,actor,action,revision) VALUES($1,$2,$3,$4)`, p.ID, actor, action, revision); err != nil {
		return SlurmFailureStatus{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return SlurmFailureStatus{}, err
	}
	return s.Status(ctx, p.ClusterID, p.ID)
}
func (s *SlurmFailureStore) Disable(ctx context.Context, cluster domain.ClusterID, id string, expected int64, actor string) error {
	if !slurmfailures.Token(actor) || !slurmfailures.Token(id) || !slurmfailures.Token(string(cluster)) || expected < 1 {
		return ErrMonitoringRevision
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tag, err := tx.Exec(ctx, `UPDATE slurm_failure_policies SET enabled=false,revision=revision+1 WHERE policy_id=$1 AND cluster_id=$2 AND revision=$3`, id, cluster, expected)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrMonitoringRevision
	}
	if _, err = tx.Exec(ctx, `INSERT INTO slurm_failure_audit(policy_id,actor,action,revision) VALUES($1,$2,'DISABLED',$3)`, id, actor, expected+1); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
func (s *SlurmFailureStore) Status(ctx context.Context, cluster domain.ClusterID, id string) (SlurmFailureStatus, error) {
	var status SlurmFailureStatus
	var raw []byte
	err := s.pool.QueryRow(ctx, `SELECT policy,enabled,revision,occurrence,active_incident_id,last_evaluated_at,last_code,observed_failures,conflicting_attempts FROM slurm_failure_policies WHERE cluster_id=$1 AND policy_id=$2`, cluster, id).Scan(&raw, &status.Enabled, &status.Revision, &status.Occurrence, &status.ActiveIncidentID, &status.LastEvaluatedAt, &status.LastCode, &status.ObservedFailures, &status.ConflictingAttempts)
	if err != nil {
		return status, err
	}
	if err = json.Unmarshal(raw, &status.Policy); err != nil {
		return status, err
	}
	status.Notifications = []SlurmFailureNotification{}
	rows, err := s.pool.Query(ctx, `SELECT e.incident_id,e.evidence_id,e.alert_id,o.status,o.last_code,o.attempt_count,e.snapshot,a.investigation_id,coalesce(a.decision_code,'NOT_EVALUATED') FROM slurm_failure_episodes e JOIN slurm_failure_policies p USING(policy_id) JOIN gp09_alert_outbox o USING(alert_id) LEFT JOIN automatic_investigation_attempts a ON a.incident_id=e.incident_id WHERE p.cluster_id=$1 AND p.policy_id=$2 ORDER BY e.occurrence DESC LIMIT 20`, cluster, id)
	if err != nil {
		return status, err
	}
	defer rows.Close()
	for rows.Next() {
		var n SlurmFailureNotification
		var snapshot []byte
		if err = rows.Scan(&n.IncidentID, &n.EvidenceID, &n.AlertID, &n.Status, &n.LastCode, &n.Attempts, &snapshot, &n.InvestigationID, &n.InvestigationDecision); err != nil {
			return status, err
		}
		if err = json.Unmarshal(snapshot, &n.Snapshot); err != nil {
			return status, err
		}
		status.Notifications = append(status.Notifications, n)
	}
	return status, rows.Err()
}

// Refresh is independently supervised by sherlock-control. A bounded batch
// cannot block collection or turn a database error into a workload health claim.
func (s *SlurmFailureStore) Refresh(ctx context.Context) error {
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	rows, err := s.pool.Query(bounded, `SELECT cluster_id,policy_id FROM slurm_failure_policies WHERE enabled AND next_due_at<=clock_timestamp() ORDER BY next_due_at,policy_id LIMIT 32`)
	if err != nil {
		return errors.New("slurm failure monitoring refresh unavailable")
	}
	type due struct {
		cluster domain.ClusterID
		id      string
	}
	items := []due{}
	for rows.Next() {
		var d due
		if err = rows.Scan(&d.cluster, &d.id); err != nil {
			break
		}
		items = append(items, d)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return errors.New("slurm failure monitoring refresh unavailable")
	}
	failed := false
	for _, d := range items {
		per, cancel := context.WithTimeout(bounded, 1500*time.Millisecond)
		err = s.Evaluate(per, d.cluster, d.id)
		cancel()
		if err != nil {
			failed = true
			// A failed incident/outbox transaction remains retryable and visible. Never
			// persist raw PostgreSQL or source payload errors in operator status/logs.
			recovery, stop := context.WithTimeout(ctx, 200*time.Millisecond)
			_, _ = s.pool.Exec(recovery, `UPDATE slurm_failure_policies SET last_code='EVALUATION_FAILED',last_evaluated_at=clock_timestamp(),next_due_at=clock_timestamp()+interval '30 seconds' WHERE cluster_id=$1 AND policy_id=$2`, d.cluster, d.id)
			stop()
		}
	}
	if failed {
		return errors.New("slurm failure monitoring refresh failed")
	}
	return nil
}
func (s *SlurmFailureStore) Evaluate(ctx context.Context, cluster domain.ClusterID, id string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var raw []byte
	var enabled bool
	var occurrence int64
	var active *string
	var eligibleAfter *time.Time
	err = tx.QueryRow(ctx, `SELECT policy,enabled,occurrence,active_incident_id,eligible_after FROM slurm_failure_policies WHERE cluster_id=$1 AND policy_id=$2 FOR UPDATE SKIP LOCKED`, cluster, id).Scan(&raw, &enabled, &occurrence, &active, &eligibleAfter)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if !enabled {
		return nil
	}
	var p slurmfailures.Policy
	if err = json.Unmarshal(raw, &p); err != nil {
		return err
	}
	if err = p.Validate(); err != nil {
		return err
	}
	var now time.Time
	if err = tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return err
	}
	finish := func(code string, count, conflicts int) error {
		if _, err := tx.Exec(ctx, `UPDATE slurm_failure_policies SET last_code=$2,observed_failures=$3,conflicting_attempts=$4,last_evaluated_at=$5,next_due_at=$5::timestamptz+interval '30 seconds' WHERE policy_id=$1`, id, code, count, conflicts, now); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}
	if err = slurmSourceAuthority(ctx, tx, p); err != nil {
		if errors.Is(err, pgx.ErrNoRows) || errors.Is(err, ErrMonitoringAuthority) {
			return finish("AUTHORITY_UNAVAILABLE", 0, 0)
		}
		return err
	}
	// Receipt/replay time is not freshness. Require a recent, supported accounting
	// observation from an authenticated, currently active collector.
	var freshCollector domain.CollectorID
	err = tx.QueryRow(ctx, `WITH recent AS (SELECT * FROM collector_typed_result_ingestions WHERE cluster_id=$1 AND source_id=$2 AND operation='slurm.snapshot.v1' ORDER BY finalized_at DESC LIMIT 128)
 SELECT c.collector_id FROM recent i JOIN goodput_slurm_snapshot_sources ss USING(run_id) JOIN collectors c ON c.collector_id=i.collector_id WHERE i.result_status IN ('SUCCEEDED','PARTIAL') AND c.cluster_id=i.cluster_id AND c.status='ACTIVE' AND ss.source_kind='accounting' AND ss.document->>'schema_support'='SUPPORTED' AND (ss.document->>'reported_errors')::integer=0 AND (ss.document->>'source_at')::timestamptz BETWEEN $3 AND $4 LIMIT 1 FOR SHARE OF c`, p.ClusterID, p.SourceID, now.Add(-time.Duration(p.FreshForSeconds)*time.Second), now).Scan(&freshCollector)
	if errors.Is(err, pgx.ErrNoRows) {
		return finish("ACCOUNTING_STALE_OR_UNAVAILABLE", 0, 0)
	}
	if err != nil {
		return err
	}

	if active != nil {
		var state string
		var closedAt time.Time
		if err = tx.QueryRow(ctx, `SELECT status,coalesce(resolved_at,updated_at) FROM incidents WHERE cluster_id=$1 AND incident_id=$2 FOR SHARE`, cluster, *active).Scan(&state, &closedAt); err != nil {
			return err
		}
		if state == "RESOLVED" || state == "CLOSED" {
			active = nil
			eligibleAfter = &closedAt
			if _, err = tx.Exec(ctx, `UPDATE slurm_failure_policies SET active_incident_id=NULL,eligible_after=$2 WHERE policy_id=$1`, id, closedAt); err != nil {
				return err
			}
		}
	}
	cutoff := now.Add(-time.Duration(p.WindowSeconds) * time.Second)
	if eligibleAfter != nil && eligibleAfter.After(cutoff) {
		cutoff = *eligibleAfter
	}
	// Indexed candidate window, followed by all terminal records for each exact
	// candidate attempt, so cancellations/conflicts cannot be hidden by overlap.
	rows, err := tx.Query(ctx, `WITH candidates AS (
 SELECT DISTINCT scheduler_namespace,job_id,submit_at,attempt FROM slurm_failure_inputs
 WHERE cluster_id=$1 AND source_id=$2 AND scheduler_namespace=$3 AND failed AND ended_at>$4 AND ended_at<=$5
 LIMIT 4097)
 SELECT f.record_identity,f.document,f.first_run_id FROM candidates c JOIN slurm_failure_inputs x ON x.cluster_id=$1 AND x.source_id=$2 AND x.scheduler_namespace=c.scheduler_namespace AND x.job_id=c.job_id AND x.submit_at=c.submit_at AND x.attempt=c.attempt
 JOIN goodput_slurm_lifecycle_facts f ON f.cluster_id=x.cluster_id AND f.source_id=x.source_id AND f.record_identity=x.record_identity
 ORDER BY f.record_identity LIMIT 4097`, cluster, p.SourceID, p.SchedulerNamespace, cutoff, now)
	if err != nil {
		return err
	}
	records := []slurmfailures.Record{}
	for rows.Next() {
		var r slurmfailures.Record
		var body []byte
		if err = rows.Scan(&r.Lifecycle.RecordIdentity, &body, &r.RunID); err != nil {
			break
		}
		recordID := r.Lifecycle.RecordIdentity
		if err = json.Unmarshal(body, &r.Lifecycle); err != nil {
			break
		}
		r.Lifecycle.RecordIdentity = recordID
		records = append(records, r)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return err
	}
	if len(records) > slurmfailures.MaxRecords {
		return finish("INPUT_LIMIT_EXCEEDED", 0, 0)
	}
	evaluation, err := slurmfailures.Evaluate(p, records, now)
	if err != nil {
		return err
	}
	keys := []string{}
	for _, a := range evaluation.Failures {
		keys = append(keys, a.Key)
	}
	seen := map[string]bool{}
	seenRows, err := tx.Query(ctx, `SELECT attempt_key FROM slurm_failure_consumed WHERE policy_id=$1 AND attempt_key=ANY($2)`, id, keys)
	if err != nil {
		return err
	}
	for seenRows.Next() {
		var key string
		if err = seenRows.Scan(&key); err != nil {
			break
		}
		seen[key] = true
	}
	if err == nil {
		err = seenRows.Err()
	}
	seenRows.Close()
	if err != nil {
		return err
	}
	unconsumed := []slurmfailures.Attempt{}
	for _, a := range evaluation.Failures {
		if (eligibleAfter == nil || a.EndAt.After(*eligibleAfter)) && !seen[a.Key] {
			unconsumed = append(unconsumed, a)
		}
	}
	code := "BELOW_THRESHOLD"
	if active == nil && len(unconsumed) >= p.Threshold {
		occurrence++
		if err = publishSlurmFailures(ctx, tx, p, occurrence, unconsumed, now); err != nil {
			return err
		}
		code = "INCIDENT_OPENED"
	} else if active != nil {
		code = "INCIDENT_ACTIVE"
	}
	if code == "INCIDENT_OPENED" || active != nil {
		consumed := []string{}
		for _, a := range unconsumed {
			consumed = append(consumed, a.Key)
		}
		if _, err = tx.Exec(ctx, `INSERT INTO slurm_failure_consumed(policy_id,attempt_key) SELECT $1,unnest($2::text[]) ON CONFLICT DO NOTHING`, id, consumed); err != nil {
			return err
		}
	}
	return finish(code, len(evaluation.Failures), evaluation.ConflictingAttempts)
}

func publishSlurmFailures(ctx context.Context, tx pgx.Tx, p slurmfailures.Policy, occurrence int64, attempts []slurmfailures.Attempt, now time.Time) error {
	digest := monitoringDigest(string(p.ClusterID), p.ID, fmt.Sprint(occurrence))
	incidentID, evidenceID, alertID := "incident-slurm-"+digest[:40], "evidence-slurm-"+digest[:40], "alert-slurm-"+digest[:40]
	sample := attempts[:p.Threshold]
	snapshot, err := json.Marshal(sample)
	if err != nil || len(snapshot) > 65536 {
		return fmt.Errorf("slurm failure evidence exceeds bound")
	}
	target := domain.EvidenceTarget{Kind: domain.EvidenceTargetSource, ID: domain.EvidenceTargetID(p.SourceID)}
	if p.NodeID != "" {
		target = domain.EvidenceTarget{Kind: domain.EvidenceTargetNode, ID: domain.EvidenceTargetID(p.NodeID)}
	}
	envelope, err := domain.CreateEvidenceEnvelope(domain.NewEvidenceEnvelope{ID: domain.EvidenceID(evidenceID), SchemaVersion: 1, ClusterID: p.ClusterID, Status: domain.EvidencePartial, Source: domain.EvidenceSourceReference{SourceID: p.SourceID, Operation: domain.EvidenceOperationID(slurmfailures.RuleID), DefinitionVersion: "1", Reference: domain.EvidenceSourceLocator("slurm-failure-snapshot:" + evidenceID)}, TimeRange: domain.EvidenceTimeRange{Start: sample[0].EndAt, End: sample[len(sample)-1].EndAt}, CollectedAt: now, Coverage: domain.EvidenceCoverage{Expected: []domain.EvidenceTarget{target}}})
	if err != nil {
		return err
	}
	if _, err = insertEvidenceEnvelope(ctx, tx, envelope); err != nil {
		return err
	}
	summary := fmt.Sprintf("Observed %d distinct failed Slurm attempts within %d seconds; physical cause is unconfirmed and accounting coverage may be partial.", len(attempts), p.WindowSeconds)
	payload, _ := json.Marshal(map[string]any{"summary": summary, "target_ids": []string{string(target.ID)}, "evidence_ids": []string{evidenceID}, "rule_id": slurmfailures.RuleID, "policy_id": p.ID, "occurrence": occurrence, "qualifying_attempts": len(attempts), "sampled_attempts": len(sample)})
	if _, err = tx.Exec(ctx, `INSERT INTO incidents(incident_id,cluster_id,title,summary,severity,status,created_by,version,next_event_sequence,created_at,updated_at) VALUES($1,$2,'Repeated Slurm job failures',$3,'HIGH','OPEN','sherlock-monitoring',1,2,$4,$4)`, incidentID, p.ClusterID, summary, now); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO incident_events(cluster_id,incident_id,sequence,event_key,event_type,actor_id,incident_version,payload,occurred_at) VALUES($1,$2,1,$3,'CREATED','sherlock-monitoring',1,$4,$5)`, p.ClusterID, incidentID, evidenceID, payload, now); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO incident_evidence(incident_id,evidence_id,attached_at) VALUES($1,$2,$3)`, incidentID, evidenceID, now); err != nil {
		return err
	}
	message := fmt.Sprintf("Sherlock repeated Slurm failures: cluster=%s source=%s policy=%s distinct_attempts=%d window_seconds=%d incident=%s. Cancellations/preemption excluded; cause unconfirmed.", p.ClusterID, p.SourceID, p.ID, len(attempts), p.WindowSeconds, incidentID)
	if _, err = tx.Exec(ctx, `INSERT INTO gp09_alert_outbox(alert_id,cluster_id,event_key,transition,message,available_at) VALUES($1,$2,$3,'SLURM_FAILURES',$4,$5)`, alertID, p.ClusterID, digest, message, now); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO slurm_failure_episodes(policy_id,occurrence,incident_id,evidence_id,alert_id,snapshot) VALUES($1,$2,$3,$4,$5,$6)`, p.ID, occurrence, incidentID, evidenceID, alertID, snapshot); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE slurm_failure_policies SET occurrence=$2,active_incident_id=$3 WHERE policy_id=$1`, p.ID, occurrence, incidentID)
	return err
}
