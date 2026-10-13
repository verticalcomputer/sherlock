package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/monitoring"
)

const monitoringEpisodeColumns = `policy_id,enrollment_revision,occurrence,version,incident_id,opened_at,closed_at,closed_reason,owner,acknowledged_by,acknowledged_at,maintenance_until,maintenance_by,disposition_id,reason,severity`

func scanMonitoringEpisode(row pgx.Row) (out MonitoringEpisode, err error) {
	err = row.Scan(&out.PolicyID, &out.EnrollmentRevision, &out.Occurrence, &out.Version, &out.IncidentID, &out.OpenedAt, &out.ClosedAt, &out.ClosedReason, &out.Owner, &out.AcknowledgedBy, &out.AcknowledgedAt, &out.MaintenanceUntil, &out.MaintenanceBy, &out.DispositionID, &out.Reason, &out.Severity)
	return
}

// Status is a bounded consistent snapshot. Raw-evidence availability describes
// logical raw IDs at this snapshot; immutable scalar snapshots remain readable.
func (store *MonitoringStore) Status(ctx context.Context, cluster domain.ClusterID, id string) (MonitoringStatus, error) {
	if !monitoringID(string(cluster), 128) || !monitoringID(id, 128) {
		return MonitoringStatus{}, fmt.Errorf("invalid monitoring status scope")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return MonitoringStatus{}, err
	}
	defer rollbackMonitoringTx(tx)
	if _, err = tx.Exec(ctx, `SET LOCAL statement_timeout='1s'; SET LOCAL lock_timeout='250ms'`); err != nil {
		return MonitoringStatus{}, err
	}
	var out MonitoringStatus
	out.Enrollment, err = scanMonitoringEnrollment(tx.QueryRow(ctx, `SELECT `+monitoringEnrollmentColumns+` FROM gp09_monitor_enrollments WHERE cluster_id=$1 AND policy_id=$2`, cluster, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return out, ErrMonitoringNotFound
	}
	if err != nil {
		return out, err
	}
	rows, err := tx.Query(ctx, `SELECT `+monitoringEpisodeColumns+` FROM gp09_monitor_episodes WHERE cluster_id=$1 AND policy_id=$2 ORDER BY occurrence DESC LIMIT 33`, cluster, id)
	if err != nil {
		return out, err
	}
	for rows.Next() {
		episode, e := scanMonitoringEpisode(rows)
		if e != nil {
			rows.Close()
			return out, e
		}
		out.Episodes = append(out.Episodes, episode)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return out, err
	}
	if len(out.Episodes) > 32 {
		out.Episodes = out.Episodes[:32]
		out.EpisodesTruncated = true
	}
	for i := range out.Episodes {
		out.Episodes[i].Evidence, err = loadMonitoringEvidence(ctx, tx, cluster, id, out.Episodes[i].Occurrence)
		if err != nil {
			return out, err
		}
	}
	rows, err = tx.Query(ctx, `SELECT control_revision,occurrence,action,actor,actor_kind,occurred_at,details FROM gp09_monitor_audit WHERE cluster_id=$1 AND policy_id=$2 ORDER BY audit_id DESC LIMIT 65`, cluster, id)
	if err != nil {
		return out, err
	}
	for rows.Next() {
		var a MonitoringAudit
		if err = rows.Scan(&a.Revision, &a.Occurrence, &a.Action, &a.Actor, &a.ActorKind, &a.At, &a.Details); err != nil {
			rows.Close()
			return out, err
		}
		out.Audit = append(out.Audit, a)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return out, err
	}
	if len(out.Audit) > 64 {
		out.Audit = out.Audit[:64]
		out.AuditTruncated = true
	}
	if err = tx.Commit(ctx); err != nil {
		return MonitoringStatus{}, err
	}
	return out, nil
}
func loadMonitoringEvidence(ctx context.Context, tx pgx.Tx, cluster domain.ClusterID, id string, occurrence int64) ([]MonitoringEvidence, error) {
	rows, err := tx.Query(ctx, `SELECT evidence_id,transition,occurred_at,snapshot,qualifying_sample_count,omitted_evidence_count FROM gp09_monitor_transitions WHERE cluster_id=$1 AND policy_id=$2 AND occurrence=$3 ORDER BY occurred_at,transition LIMIT 2`, cluster, id, occurrence)
	if err != nil {
		return nil, err
	}
	out := []MonitoringEvidence{}
	for rows.Next() {
		var e MonitoringEvidence
		var body []byte
		if err = rows.Scan(&e.EvidenceID, &e.Transition, &e.At, &body, &e.QualifyingSampleCount, &e.OmittedEvidenceCount); err != nil {
			rows.Close()
			return nil, err
		}
		if err = json.Unmarshal(body, &e.Snapshot); err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, e)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	for i := range out {
		e := &out[i]
		e.RawEvidenceAvailable = len(e.Snapshot) > 0
		for _, s := range e.Snapshot {
			var exists bool
			err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM collection_runs r JOIN gp09_monitor_enrollments p ON p.cluster_id=r.cluster_id AND p.source_id=r.source_id WHERE p.cluster_id=$1 AND p.policy_id=$2 AND r.run_id=$3) AND ($4='' OR EXISTS(SELECT 1 FROM observations o JOIN gp09_monitor_enrollments p ON p.cluster_id=o.cluster_id AND p.source_id=o.source_id WHERE p.cluster_id=$1 AND p.policy_id=$2 AND o.run_id=$3 AND o.observation_id=$4))`, cluster, id, s.Reference.RunID, s.Reference.ObservationID).Scan(&exists)
			if err != nil {
				return nil, err
			}
			if !exists {
				e.RawEvidenceAvailable = false
			}
		}
	}
	return out, nil
}
func (store *MonitoringStore) Acknowledge(ctx context.Context, cluster domain.ClusterID, id string, occurrence, version int64, actor string) (MonitoringEpisode, error) {
	return store.mutateEpisode(ctx, cluster, id, occurrence, version, actor, "ACKNOWLEDGED", "", 0)
}
func (store *MonitoringStore) AssignOwner(ctx context.Context, cluster domain.ClusterID, id string, occurrence, version int64, actor, owner string) (MonitoringEpisode, error) {
	if owner != "" && !monitoringID(owner, 128) {
		return MonitoringEpisode{}, fmt.Errorf("invalid monitoring owner")
	}
	return store.mutateEpisode(ctx, cluster, id, occurrence, version, actor, "OWNER_ASSIGNED", owner, 0)
}
func (store *MonitoringStore) SetMaintenance(ctx context.Context, cluster domain.ClusterID, id string, occurrence, version int64, actor string, seconds int64) (MonitoringEpisode, error) {
	if seconds < 0 || seconds > 86400 {
		return MonitoringEpisode{}, fmt.Errorf("invalid monitoring maintenance duration")
	}
	return store.mutateEpisode(ctx, cluster, id, occurrence, version, actor, "MAINTENANCE_CHANGED", "", seconds)
}
func (store *MonitoringStore) ReviewRecovery(ctx context.Context, cluster domain.ClusterID, id string, occurrence, version int64, actor, evidenceID string) (MonitoringEpisode, error) {
	if !monitoringID(evidenceID, 128) {
		return MonitoringEpisode{}, fmt.Errorf("invalid monitoring review evidence")
	}
	return store.mutateEpisode(ctx, cluster, id, occurrence, version, actor, "RECOVERY_REVIEWED", evidenceID, 0)
}
func (store *MonitoringStore) mutateEpisode(ctx context.Context, cluster domain.ClusterID, id string, occurrence, version int64, actor, action, value string, seconds int64) (MonitoringEpisode, error) {
	if !monitoringID(string(cluster), 128) || !monitoringID(id, 128) || !monitoringID(actor, 128) || occurrence < 1 || version < 1 {
		return MonitoringEpisode{}, fmt.Errorf("invalid monitoring episode mutation")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tx, err := beginMonitoringTx(ctx, store.pool)
	if err != nil {
		return MonitoringEpisode{}, err
	}
	defer rollbackMonitoringTx(tx)
	enrollment, err := scanMonitoringEnrollment(tx.QueryRow(ctx, `SELECT `+monitoringEnrollmentColumns+` FROM gp09_monitor_enrollments WHERE cluster_id=$1 AND policy_id=$2 FOR UPDATE`, cluster, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return MonitoringEpisode{}, ErrMonitoringNotFound
	}
	if err != nil {
		return MonitoringEpisode{}, err
	}
	episode, err := scanMonitoringEpisode(tx.QueryRow(ctx, `SELECT `+monitoringEpisodeColumns+` FROM gp09_monitor_episodes WHERE cluster_id=$1 AND policy_id=$2 AND occurrence=$3 FOR UPDATE`, cluster, id, occurrence))
	if errors.Is(err, pgx.ErrNoRows) {
		return episode, ErrMonitoringNotFound
	}
	if err != nil {
		return episode, err
	}
	if episode.Version != version || episode.ClosedAt != nil {
		return episode, ErrMonitoringRevision
	}
	var now time.Time
	if err = tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return episode, err
	}
	details := map[string]any{}
	switch action {
	case "ACKNOWLEDGED":
		details["acknowledged"] = true
		episode.AcknowledgedBy = actor
		episode.AcknowledgedAt = &now
		_, err = tx.Exec(ctx, `UPDATE gp09_monitor_episodes SET acknowledged_by=$4,acknowledged_at=$5,version=version+1 WHERE cluster_id=$1 AND policy_id=$2 AND occurrence=$3`, cluster, id, occurrence, actor, now)
	case "OWNER_ASSIGNED":
		details["previous_owner"] = episode.Owner
		details["owner"] = value
		episode.Owner = value
		_, err = tx.Exec(ctx, `UPDATE gp09_monitor_episodes SET owner=$4,version=version+1 WHERE cluster_id=$1 AND policy_id=$2 AND occurrence=$3`, cluster, id, occurrence, value)
	case "MAINTENANCE_CHANGED":
		details["seconds"] = seconds
		var until *time.Time
		by := ""
		if seconds > 0 {
			at := now.Add(time.Duration(seconds) * time.Second)
			until = &at
			by = actor
			details["until"] = at
		}
		episode.MaintenanceUntil = until
		episode.MaintenanceBy = by
		_, err = tx.Exec(ctx, `UPDATE gp09_monitor_episodes SET maintenance_until=$4,maintenance_by=$5,version=version+1 WHERE cluster_id=$1 AND policy_id=$2 AND occurrence=$3`, cluster, id, occurrence, until, by)
		if err == nil {
			_, err = tx.Exec(ctx, `UPDATE gp09_alert_outbox o SET available_at=CASE WHEN $4::timestamptz IS NOT NULL THEN greatest(o.available_at,$4) WHEN o.attempt_count=0 THEN $5 ELSE greatest($5,coalesce((SELECT max(a.attempted_at) FROM gp09_alert_delivery_attempts a WHERE a.alert_id=o.alert_id),$5)+interval '5 minutes') END,updated_at=$5 FROM gp09_monitor_transitions t WHERE t.alert_id=o.alert_id AND t.cluster_id=$1 AND t.policy_id=$2 AND t.occurrence=$3 AND o.status='PENDING'`, cluster, id, occurrence, until, now)
		}
	case "RECOVERY_REVIEWED":
		var valid bool
		err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM evidence_envelopes e JOIN incident_evidence ie USING(evidence_id) WHERE e.cluster_id=$1 AND e.source_id=$2 AND e.evidence_id=$3 AND ie.incident_id=$4)`, cluster, enrollment.Policy.SourceID, value, episode.IncidentID).Scan(&valid)
		if err != nil {
			return episode, err
		}
		if !valid {
			return episode, ErrMonitoringAuthority
		}
		disposition := monitoring.RecoveryDisposition{ID: "monitor-review-" + monitoringDigest(id, fmt.Sprint(occurrence)), PolicyID: id, EnrollmentRevision: enrollment.Policy.Revision, Occurrence: occurrence, Actor: actor, EvidenceID: value, ReviewedAt: now}
		decision, e := monitoring.ApplyReviewedDisposition(enrollment.Policy, enrollment.State, disposition, now)
		if e != nil {
			return episode, e
		}
		if decision.Transition == nil {
			return episode, ErrMonitoringRevision
		}
		_, err = tx.Exec(ctx, `INSERT INTO gp09_monitor_dispositions(disposition_id,cluster_id,policy_id,enrollment_revision,occurrence,actor,evidence_id,reviewed_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, disposition.ID, cluster, id, disposition.EnrollmentRevision, occurrence, actor, value, now)
		if err != nil {
			return episode, err
		}
		var cache []MonitoringEvidenceSnapshot
		var body []byte
		if err = tx.QueryRow(ctx, `SELECT state_evidence FROM gp09_monitor_enrollments WHERE policy_id=$1`, id).Scan(&body); err != nil {
			return episode, err
		}
		if err = json.Unmarshal(body, &cache); err != nil {
			return episode, err
		}
		if err = publishMonitoringTransition(ctx, tx, enrollment.Policy, *decision.Transition, cache); err != nil {
			return episode, err
		}
		body, _ = json.Marshal(decision.State)
		_, err = tx.Exec(ctx, `UPDATE gp09_monitor_enrollments SET evaluator_state=$2,updated_at=$3 WHERE policy_id=$1`, id, body, now)
		episode.ClosedAt = &now
		episode.ClosedReason = decision.Transition.Reason
		episode.DispositionID = disposition.ID
		details["evidence_id"] = value
		details["disposition_id"] = disposition.ID
		details["measured_recovery"] = false
	}
	if err != nil {
		return episode, err
	}
	episode.Version++
	if err = monitoringOperatorAudit(ctx, tx, cluster, id, enrollment.Revision, occurrence, action, actor, details, now); err != nil {
		return episode, err
	}
	episode.Evidence, err = loadMonitoringEvidence(ctx, tx, cluster, id, occurrence)
	if err != nil {
		return episode, err
	}
	if err = tx.Commit(ctx); err != nil {
		return MonitoringEpisode{}, err
	}
	return episode, nil
}
