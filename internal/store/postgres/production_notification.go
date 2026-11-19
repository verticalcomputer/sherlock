package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	a "github.com/verticalcomputer/sherlock/internal/alertassessment"
	"github.com/verticalcomputer/sherlock/internal/alertdelivery"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

// ProductionAssessmentEvent is admitted only by the production host inside its
// state transaction. This function is deliberately not an HTTP ingress API.
type ProductionAssessmentEvent struct {
	EnrollmentID, ClusterID, SourceID, Category, Asset, OccurrenceID string
	EventID, Kind, Summary, EvidenceURL                              string
	At                                                               time.Time
	Evidence                                                         json.RawMessage
	SuppressDelivery                                                 bool
}

type ProductionOccurrence = alertdelivery.ProductionOccurrence

const productionOccurrenceColumns = `occurrence_id,cluster_id,enrollment_id,source_id,category,asset,incident_id,version,next_sequence,opened_at,closed_at,acknowledged_by,acknowledged_at,maintenance_until,maintenance_by,maintenance_reason,evidence_url`

func scanProductionOccurrence(row pgx.Row) (o ProductionOccurrence, err error) {
	err = row.Scan(&o.ID, &o.ClusterID, &o.EnrollmentID, &o.SourceID, &o.Category, &o.Asset, &o.IncidentID, &o.Version, &o.NextSequence, &o.OpenedAt, &o.ClosedAt, &o.AcknowledgedBy, &o.AcknowledgedAt, &o.MaintenanceUntil, &o.MaintenanceBy, &o.MaintenanceReason, &o.EvidenceURL)
	return
}
func productionScope(cluster, enrollment, occurrence string) bool {
	return a.ValidID(cluster, 128) && a.ValidID(enrollment, 128) && a.ValidID(occurrence, 128)
}
func validEvidenceURL(raw string) bool {
	u, e := url.Parse(raw)
	return e == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.Fragment == "" && len(raw) <= 1024 && !strings.ContainsAny(raw, "<>\r\n\t ")
}
func slackText(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}
func boundedNotificationText(s string, n int) string {
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}
func productionMessage(o ProductionOccurrence, kind string, at time.Time, summary string) (string, error) {
	prefix := fmt.Sprintf("Sherlock cooling %s\ncluster=%s asset=%s\noccurrence=%s incident=%s\nconcern_since=%s evidence_at=%s\n", kind, slackText(o.ClusterID), slackText(o.Asset), slackText(o.ID), slackText(o.IncidentID), o.OpenedAt.UTC().Format(time.RFC3339), at.UTC().Format(time.RFC3339))
	suffix := "\nHistory: " + slackText(o.EvidenceURL)
	room := alertdelivery.MaxMessageBytes - len(prefix) - len(suffix)
	if room < 128 {
		return "", errors.New("notification identity exceeds message bound")
	}
	return prefix + boundedNotificationText(slackText(summary), room) + suffix, nil
}

func PublishProductionAssessment(ctx context.Context, tx pgx.Tx, event ProductionAssessmentEvent) error {
	if !productionScope(event.ClusterID, event.EnrollmentID, event.OccurrenceID) || !a.ValidID(event.EventID, 128) || !a.ValidID(event.Category, 128) || !a.ValidID(event.SourceID, 128) || !a.ValidID(event.Asset, 256) || event.At.IsZero() || len(event.Summary) > 2048 || !utf8.ValidString(event.Summary) || !validEvidenceURL(event.EvidenceURL) || len(event.Evidence) > 4<<20 || !json.Valid(event.Evidence) {
		return errors.New("invalid production assessment event")
	}
	if event.Kind != "OPEN" && event.Kind != "WORSEN" && event.Kind != "RECOVER" || event.Kind == "OPEN" && event.SuppressDelivery {
		return errors.New("invalid production transition")
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(event.Evidence, &obj) != nil || obj == nil {
		return errors.New("invalid production evidence")
	}
	body, err := a.Canonical(event)
	if err != nil {
		return err
	}
	hash := domain.ChecksumSHA256(body).String()
	// Serialize duplicate first publication as well as mutations after creation.
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,86))`, event.OccurrenceID); err != nil {
		return err
	}
	var previous string
	err = tx.QueryRow(ctx, `SELECT input_hash FROM production_notification_events WHERE event_id=$1`, event.EventID).Scan(&previous)
	if err == nil {
		if previous != hash {
			return errors.New("production event identity conflict")
		}
		return nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	o, err := scanProductionOccurrence(tx.QueryRow(ctx, `SELECT `+productionOccurrenceColumns+` FROM production_notification_occurrences WHERE occurrence_id=$1 FOR UPDATE`, event.OccurrenceID))
	if errors.Is(err, pgx.ErrNoRows) && event.Kind == "OPEN" {
		o = ProductionOccurrence{ID: event.OccurrenceID, ClusterID: event.ClusterID, EnrollmentID: event.EnrollmentID, SourceID: event.SourceID, Category: event.Category, Asset: event.Asset, IncidentID: "incident-assess-" + monitoringDigest(event.ClusterID, event.EnrollmentID, event.OccurrenceID)[:40], OpenedAt: event.At, NextSequence: 1, EvidenceURL: event.EvidenceURL}
	} else if err != nil {
		return err
	} else if event.Kind == "OPEN" || o.ClosedAt != nil || o.ClusterID != event.ClusterID || o.EnrollmentID != event.EnrollmentID || o.SourceID != event.SourceID || o.Category != event.Category || o.Asset != event.Asset || o.EvidenceURL != event.EvidenceURL || event.At.Before(o.OpenedAt) {
		return errors.New("production occurrence transition conflict")
	}
	evidenceID := "evidence-assess-" + monitoringDigest(event.EventID)[:40]
	target := domain.EvidenceTarget{Kind: domain.EvidenceTargetGPU, ID: domain.EvidenceTargetID(event.Asset)}
	env, err := domain.CreateEvidenceEnvelope(domain.NewEvidenceEnvelope{ID: domain.EvidenceID(evidenceID), SchemaVersion: domain.EvidenceSchemaVersion, ClusterID: domain.ClusterID(event.ClusterID), Status: domain.EvidenceComplete, Source: domain.EvidenceSourceReference{SourceID: domain.SourceID(event.SourceID), Operation: domain.EvidenceOperationID("assessment." + event.Category + ".v1"), DefinitionVersion: "1", Reference: domain.EvidenceSourceLocator("assessment-snapshot:" + evidenceID)}, TimeRange: domain.EvidenceTimeRange{Start: event.At, End: event.At}, CollectedAt: event.At, Coverage: domain.EvidenceCoverage{Expected: []domain.EvidenceTarget{target}, Covered: []domain.EvidenceTarget{target}}})
	if err != nil {
		return err
	}
	if _, err = insertEvidenceEnvelope(ctx, tx, env); err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]any{"summary": event.Summary, "target_ids": []string{event.Asset}, "evidence_ids": []string{evidenceID}, "enrollment_id": event.EnrollmentID, "occurrence_id": event.OccurrenceID, "category": event.Category, "transition": event.Kind, "measured_recovery": event.Kind == "RECOVER"})
	if err = publishIncidentTransition(ctx, tx, event.ClusterID, o.IncidentID, evidenceID, event.Kind, "GPU cooling investigation requested", event.Summary, "HIGH", "sherlock-assessment", event.At, payload); err != nil {
		return err
	}
	if event.Kind == "OPEN" {
		_, err = tx.Exec(ctx, `INSERT INTO production_notification_occurrences(occurrence_id,cluster_id,enrollment_id,source_id,category,asset,incident_id,opened_at,evidence_url) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, o.ID, o.ClusterID, o.EnrollmentID, o.SourceID, o.Category, o.Asset, o.IncidentID, o.OpenedAt, o.EvidenceURL)
		if err != nil {
			return err
		}
	}
	if _, err = tx.Exec(ctx, `INSERT INTO incident_evidence(incident_id,evidence_id,attached_at) VALUES($1,$2,$3)`, o.IncidentID, evidenceID, event.At); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO production_notification_events(event_id,occurrence_id,sequence,kind,occurred_at,summary,evidence_id,evidence,input_hash) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, event.EventID, o.ID, o.NextSequence, event.Kind, event.At, event.Summary, evidenceID, event.Evidence, hash); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE production_notification_occurrences SET next_sequence=next_sequence+1,closed_at=CASE WHEN $2='RECOVER' THEN $3 ELSE closed_at END,version=version+1 WHERE occurrence_id=$1`, o.ID, event.Kind, event.At); err != nil {
		return err
	}
	message, err := productionMessage(o, event.Kind, event.At, event.Summary)
	if err != nil {
		return err
	}
	alertID := "assess-alert-" + monitoringDigest(event.EventID)[:40]
	if _, err = tx.Exec(ctx, `INSERT INTO gp09_alert_outbox(alert_id,cluster_id,event_key,transition,message,assessment_enrollment,assessment_occurrence,status,last_code) VALUES($1,$2,$3,$4,$5,$6,$7,CASE WHEN $8 THEN 'DISABLED' ELSE 'PENDING' END,CASE WHEN $8 THEN 'AUTHORITY_DISABLED' ELSE '' END)`, alertID, o.ClusterID, event.EventID, "ASSESSMENT_"+event.Kind, message, o.EnrollmentID, o.ID, event.SuppressDelivery); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO production_notification_intents(alert_id,occurrence_id,first_sequence,last_sequence,oldest_pending_at) VALUES($1,$2,$3,$3,clock_timestamp())`, alertID, o.ID, o.NextSequence); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO production_notification_coverage(alert_id,event_id) VALUES($1,$2)`, alertID, event.EventID)
	return err
}

type ProductionNotificationStore struct{ pool *pgxpool.Pool }

func NewProductionNotificationStore(pool *pgxpool.Pool) *ProductionNotificationStore {
	return &ProductionNotificationStore{pool: pool}
}
func (s *ProductionNotificationStore) Acknowledge(ctx context.Context, cluster, enrollment, occurrence string, version int64, actor string) (ProductionOccurrence, error) {
	return s.mutate(ctx, cluster, enrollment, occurrence, version, actor, "ACKNOWLEDGED", "", 0)
}
func (s *ProductionNotificationStore) SetMaintenance(ctx context.Context, cluster, enrollment, occurrence string, version int64, actor, reason string, seconds int64) (ProductionOccurrence, error) {
	return s.mutate(ctx, cluster, enrollment, occurrence, version, actor, "MAINTENANCE_CHANGED", reason, seconds)
}
func (s *ProductionNotificationStore) mutate(ctx context.Context, cluster, enrollment, occurrence string, version int64, actor, action, reason string, seconds int64) (ProductionOccurrence, error) {
	if !productionScope(cluster, enrollment, occurrence) || version < 1 || !a.ValidID(actor, 128) || seconds < 0 || seconds > 86400 || len(reason) > 512 || !utf8.ValidString(reason) || action == "MAINTENANCE_CHANGED" && strings.TrimSpace(reason) == "" {
		return ProductionOccurrence{}, errors.New("invalid production operator command")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return ProductionOccurrence{}, err
	}
	defer rollbackMonitoringTx(tx)
	o, err := scanProductionOccurrence(tx.QueryRow(ctx, `SELECT `+productionOccurrenceColumns+` FROM production_notification_occurrences WHERE cluster_id=$1 AND enrollment_id=$2 AND occurrence_id=$3 FOR UPDATE`, cluster, enrollment, occurrence))
	if err != nil {
		return o, err
	}
	if o.Version != version {
		return o, ErrMonitoringRevision
	}
	var now time.Time
	if err = tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return o, err
	}
	details := map[string]any{}
	if action == "ACKNOWLEDGED" {
		o.AcknowledgedBy = actor
		o.AcknowledgedAt = &now
		_, err = tx.Exec(ctx, `UPDATE production_notification_occurrences SET acknowledged_by=$2,acknowledged_at=$3,version=version+1 WHERE occurrence_id=$1`, occurrence, actor, now)
	} else {
		var until *time.Time
		if seconds > 0 {
			v := now.Add(time.Duration(seconds) * time.Second)
			until = &v
		}
		if o.ClosedAt != nil && (until != nil && (o.MaintenanceUntil == nil || until.After(*o.MaintenanceUntil))) {
			return o, errors.New("closed occurrence hold may only be shortened or cleared")
		}
		details = map[string]any{"previous_until": o.MaintenanceUntil, "until": until, "reason": reason}
		o.MaintenanceUntil = until
		o.MaintenanceBy = actor
		o.MaintenanceReason = reason
		_, err = tx.Exec(ctx, `UPDATE production_notification_occurrences SET maintenance_until=$2,maintenance_by=$3,maintenance_reason=$4,version=version+1 WHERE occurrence_id=$1`, occurrence, until, actor, reason)
	}
	if err != nil {
		return o, err
	}
	o.Version++
	body, _ := json.Marshal(details)
	if _, err = tx.Exec(ctx, `INSERT INTO production_notification_audit(occurrence_id,version,actor,action,details) VALUES($1,$2,$3,$4,$5)`, occurrence, o.Version, actor, action, body); err != nil {
		return o, err
	}
	return o, tx.Commit(ctx)
}

type ProductionNotificationEvent = alertdelivery.ProductionNotificationEvent
type ProductionNotificationHistory = alertdelivery.ProductionNotificationHistory

func (s *ProductionNotificationStore) History(ctx context.Context, cluster, enrollment, occurrence string) (ProductionNotificationHistory, error) {
	return s.HistoryPage(ctx, cluster, enrollment, occurrence, 0)
}
func (s *ProductionNotificationStore) HistoryPage(ctx context.Context, cluster, enrollment, occurrence string, after int64) (ProductionNotificationHistory, error) {
	return s.HistoryPageWithAudit(ctx, cluster, enrollment, occurrence, after, 0)
}
func (s *ProductionNotificationStore) HistoryPageWithAudit(ctx context.Context, cluster, enrollment, occurrence string, after, afterAudit int64) (out ProductionNotificationHistory, err error) {
	if !productionScope(cluster, enrollment, occurrence) || after < 0 || afterAudit < 0 {
		return out, errors.New("invalid history scope")
	}
	out.NextAfter, out.NextAuditAfter = after, afterAudit
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return out, err
	}
	defer rollbackMonitoringTx(tx)
	out.Occurrence, err = scanProductionOccurrence(tx.QueryRow(ctx, `SELECT `+productionOccurrenceColumns+` FROM production_notification_occurrences WHERE cluster_id=$1 AND enrollment_id=$2 AND occurrence_id=$3`, cluster, enrollment, occurrence))
	if err != nil {
		return out, err
	}
	rows, err := tx.Query(ctx, `SELECT event_id,sequence,kind,occurred_at,summary,evidence_id,evidence FROM production_notification_events WHERE occurrence_id=$1 AND sequence>$2 ORDER BY sequence LIMIT 65`, occurrence, after)
	if err != nil {
		return out, err
	}
	out.Events = []ProductionNotificationEvent{}
	size := 0
	for rows.Next() {
		var e ProductionNotificationEvent
		if err = rows.Scan(&e.ID, &e.Sequence, &e.Kind, &e.At, &e.Summary, &e.EvidenceID, &e.Evidence); err != nil {
			break
		}
		if len(out.Events) >= 64 || len(out.Events) > 0 && size+len(e.Evidence) > 16<<20 {
			out.More = true
			break
		}
		out.Events = append(out.Events, e)
		size += len(e.Evidence)
		out.NextAfter = e.Sequence
	}
	rows.Close()
	if err != nil {
		return out, err
	}
	if rows.Err() != nil {
		return out, rows.Err()
	}
	// Intent/attempt history is selected only for this event page, never a global dump.
	err = tx.QueryRow(ctx, `SELECT coalesce(jsonb_agg(to_jsonb(x)),'[]'::jsonb) FROM (SELECT o.alert_id,o.status,o.attempt_count,o.available_at,o.accepted_at,o.last_code,i.first_sequence,i.last_sequence,i.oldest_pending_at,i.inherited_attempts,i.superseded_by,i.receipt_uncertain,coalesce((SELECT jsonb_agg(to_jsonb(a)) FROM gp09_alert_delivery_attempts a WHERE a.alert_id=o.alert_id),'[]'::jsonb) AS attempts FROM production_notification_intents i JOIN gp09_alert_outbox o USING(alert_id) WHERE i.occurrence_id=$1 AND i.last_sequence>$2 AND i.first_sequence<=$3 ORDER BY i.first_sequence,o.created_at LIMIT 128) x`, occurrence, after, out.NextAfter).Scan(&out.Delivery)
	if err != nil {
		return out, err
	}
	rows, err = tx.Query(ctx, `SELECT audit_id,to_jsonb(x) FROM (SELECT audit_id,version,actor,action,details,occurred_at FROM production_notification_audit WHERE occurrence_id=$1 AND audit_id>$2 ORDER BY audit_id LIMIT 65) x`, occurrence, afterAudit)
	if err != nil {
		return out, err
	}
	audit := []json.RawMessage{}
	for rows.Next() {
		var id int64
		var body json.RawMessage
		if err = rows.Scan(&id, &body); err != nil {
			break
		}
		if len(audit) == 64 {
			out.MoreAudit = true
			break
		}
		audit = append(audit, body)
		out.NextAuditAfter = id
	}
	rows.Close()
	if err != nil {
		return out, err
	}
	if rows.Err() != nil {
		return out, rows.Err()
	}
	out.Audit, _ = json.Marshal(audit)

	return out, tx.Commit(ctx)
}

// CleanupProductionNotifications retires only closed, dispositioned history.
// Failed or possibly deliverable notices retain evidence until operator action;
// production admission caps bound accumulation rather than deleting that proof.
func CleanupProductionNotifications(ctx context.Context, pool *pgxpool.Pool, cluster, enrollment string) (int, error) {
	if !productionScope(cluster, enrollment, "scope") {
		return 0, errors.New("invalid notification cleanup scope")
	}
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	tx, err := pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer rollbackMonitoringTx(tx)
	rows, err := tx.Query(ctx, `SELECT o.occurrence_id FROM production_notification_occurrences o WHERE o.cluster_id=$1 AND o.enrollment_id=$2 AND o.closed_at<clock_timestamp()-interval '90 days' AND NOT EXISTS(SELECT 1 FROM production_notification_intents i JOIN gp09_alert_outbox q USING(alert_id) WHERE i.occurrence_id=o.occurrence_id AND (q.status NOT IN ('ACCEPTED','SUPERSEDED','DISABLED') OR i.receipt_uncertain)) ORDER BY o.closed_at,o.occurrence_id FOR UPDATE OF o SKIP LOCKED LIMIT 16`, cluster, enrollment)
	if err != nil {
		return 0, err
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			break
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err != nil {
		return 0, err
	}
	if rows.Err() != nil {
		return 0, rows.Err()
	}
	for _, id := range ids {
		// Keep generic incident/evidence metadata; only the explicitly expired
		// assessment history disappears from its scoped read surface.
		queries := []string{
			`DELETE FROM production_notification_coverage WHERE alert_id IN (SELECT alert_id FROM production_notification_intents WHERE occurrence_id=$1)`,
			`DELETE FROM gp09_alert_delivery_attempts WHERE alert_id IN (SELECT alert_id FROM production_notification_intents WHERE occurrence_id=$1)`,
			`DELETE FROM production_notification_intents WHERE occurrence_id=$1`,
			`DELETE FROM gp09_alert_outbox WHERE assessment_occurrence=$1`,
			`DELETE FROM production_notification_events WHERE occurrence_id=$1`,
			`DELETE FROM production_notification_audit WHERE occurrence_id=$1`,
			`DELETE FROM production_notification_occurrences WHERE occurrence_id=$1`,
		}
		for _, q := range queries {
			if _, err = tx.Exec(ctx, q, id); err != nil {
				return 0, err
			}
		}
	}
	return len(ids), tx.Commit(ctx)
}
