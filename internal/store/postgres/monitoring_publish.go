package postgres

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/monitoring"
)

// Reference identity uses instants; persistence/restart may change time zones
// and strip monotonic clock metadata without changing immutable evidence.
func monitoringRefsEqual(a, b monitoring.EvidenceRef) bool {
	return a.ObservationID == b.ObservationID && a.RunID == b.RunID && a.ObservedAt.Equal(b.ObservedAt) && a.CollectedAt.Equal(b.CollectedAt) && a.CompletedAt.Equal(b.CompletedAt)
}

func monitoringRefKey(ref monitoring.EvidenceRef) string {
	return string(ref.RunID) + "\x00" + string(ref.ObservationID)
}
func monitoringTransitionSnapshots(transition monitoring.Transition, cache []MonitoringEvidenceSnapshot) ([]MonitoringEvidenceSnapshot, error) {
	index := map[string]MonitoringEvidenceSnapshot{}
	for _, snapshot := range cache {
		index[monitoringRefKey(snapshot.Reference)] = snapshot
	}
	out := []MonitoringEvidenceSnapshot{}
	for _, ref := range transition.Evidence {
		snapshot, ok := index[monitoringRefKey(ref)]
		if !ok || !monitoringRefsEqual(snapshot.Reference, ref) {
			return nil, fmt.Errorf("monitoring immutable evidence unavailable")
		}
		out = append(out, snapshot)
	}
	if len(out) > 32 {
		return nil, fmt.Errorf("monitoring transition evidence exceeds bound")
	}
	return out, nil
}
func publishMonitoringTransition(ctx context.Context, tx pgx.Tx, policy monitoring.Policy, transition monitoring.Transition, cache []MonitoringEvidenceSnapshot) error {
	snapshots, err := monitoringTransitionSnapshots(transition, cache)
	if err != nil {
		return err
	}
	body, err := json.Marshal(snapshots)
	if err != nil || len(body) > 65536 {
		return fmt.Errorf("monitoring transition snapshot exceeds bound")
	}
	digest := monitoringDigest(string(policy.ClusterID), policy.ID, fmt.Sprint(policy.Revision), fmt.Sprint(transition.Occurrence))
	incidentID := "incident-monitor-" + digest[:40]
	evidenceID := "evidence-monitor-" + monitoringDigest(digest, string(transition.Kind))[:40]
	alertID := "monitor-alert-" + monitoringDigest(digest, string(transition.Kind))[:40]
	kind := domain.EvidenceTargetGPU
	if policy.Rule == monitoring.RuleTelemetryLoss {
		kind = domain.EvidenceTargetSource
	}
	target := domain.EvidenceTarget{Kind: kind, ID: domain.EvidenceTargetID(policy.EntityKey)}
	status := domain.EvidenceComplete
	covered := []domain.EvidenceTarget{target}
	if len(snapshots) == 0 {
		status = domain.EvidenceUnavailable
		covered = nil
	}
	envelope, err := domain.CreateEvidenceEnvelope(domain.NewEvidenceEnvelope{ID: domain.EvidenceID(evidenceID), SchemaVersion: domain.EvidenceSchemaVersion, ClusterID: policy.ClusterID, Status: status, Source: domain.EvidenceSourceReference{SourceID: policy.SourceID, Operation: domain.EvidenceOperationID("monitoring." + string(policy.Rule) + ".v1"), DefinitionVersion: fmt.Sprint(policy.RuleVersion), Reference: domain.EvidenceSourceLocator("monitoring-snapshot:" + evidenceID)}, TimeRange: domain.EvidenceTimeRange{Start: transition.At, End: transition.At}, CollectedAt: transition.At, Coverage: domain.EvidenceCoverage{Expected: []domain.EvidenceTarget{target}, Covered: covered}})
	if err != nil {
		return err
	}
	if _, err = insertEvidenceEnvelope(ctx, tx, envelope); err != nil {
		return err
	}
	severity := "HIGH"
	if transition.Severity == domain.HealthSeverityCritical {
		severity = "CRITICAL"
	}
	payload, _ := json.Marshal(map[string]any{"summary": "Reviewed deterministic monitoring transition", "target_ids": []string{policy.EntityKey}, "evidence_ids": []string{evidenceID}, "rule_id": policy.Rule, "rule_version": policy.RuleVersion, "policy_id": policy.ID, "policy_revision": policy.Revision, "occurrence": transition.Occurrence, "reason": transition.Reason, "measured_recovery": transition.Reason == monitoring.ReasonFreshRecovery, "qualifying_sample_count": transition.QualifyingSampleCount, "omitted_evidence_count": transition.OmittedEvidenceCount})
	if transition.Kind != monitoring.TransitionOpen && transition.Kind != monitoring.TransitionRecover {
		return fmt.Errorf("unsupported monitoring transition")
	}
	if transition.Kind == monitoring.TransitionRecover {
		var open bool
		if err = tx.QueryRow(ctx, `SELECT closed_at IS NULL FROM gp09_monitor_episodes WHERE cluster_id=$1 AND policy_id=$2 AND occurrence=$3 FOR UPDATE`, policy.ClusterID, policy.ID, transition.Occurrence).Scan(&open); err != nil {
			return err
		}
		if !open {
			return fmt.Errorf("monitoring occurrence already closed")
		}
	}
	if err = publishIncidentTransition(ctx, tx, string(policy.ClusterID), incidentID, evidenceID, string(transition.Kind), "Monitoring condition detected", "A reviewed deterministic policy confirmed a monitoring condition.", severity, "sherlock-monitoring", transition.At, payload); err != nil {
		return err
	}
	if transition.Kind == monitoring.TransitionOpen {
		_, err = tx.Exec(ctx, `INSERT INTO gp09_monitor_episodes(cluster_id,policy_id,enrollment_revision,occurrence,incident_id,reason,severity,opened_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, policy.ClusterID, policy.ID, policy.Revision, transition.Occurrence, incidentID, transition.Reason, transition.Severity, transition.At)
	} else {
		_, err = tx.Exec(ctx, `UPDATE gp09_monitor_episodes SET closed_at=$4,closed_reason=$5,disposition_id=$6,version=version+1 WHERE cluster_id=$1 AND policy_id=$2 AND occurrence=$3`, policy.ClusterID, policy.ID, transition.Occurrence, transition.At, transition.Reason, transition.DispositionID)
	}
	if err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO incident_evidence(incident_id,evidence_id,attached_at) VALUES($1,$2,$3)`, incidentID, evidenceID, transition.At); err != nil {
		return err
	}
	// Values, labels and receiver credentials never enter notification text.
	message := fmt.Sprintf("Sherlock monitoring %s: cluster=%s policy=%s rule=%s occurrence=%d reason=%s incident=%s", transition.Kind, policy.ClusterID, policy.ID, policy.Rule, transition.Occurrence, transition.Reason, incidentID)
	if _, err = tx.Exec(ctx, `INSERT INTO gp09_alert_outbox(alert_id,cluster_id,event_key,transition,message,available_at) VALUES($1,$2,$3,$4,$5,greatest($6,coalesce((SELECT maintenance_until FROM gp09_monitor_episodes WHERE policy_id=$7 AND occurrence=$8),$6)))`, alertID, policy.ClusterID, digest, "MONITOR_"+string(transition.Kind), message, transition.At, policy.ID, transition.Occurrence); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO gp09_monitor_transitions(cluster_id,policy_id,occurrence,transition,occurred_at,reason,evidence_id,alert_id,snapshot,qualifying_sample_count,omitted_evidence_count) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, policy.ClusterID, policy.ID, transition.Occurrence, transition.Kind, transition.At, transition.Reason, evidenceID, alertID, body, transition.QualifyingSampleCount, transition.OmittedEvidenceCount)
	return err
}
