package postgres

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// NewAssessmentAlertOutboxStore is an explicit opt-in to one production owner.
// Legacy workers cannot claim these rows, even if configured for the same cluster.
func NewAssessmentAlertOutboxStore(pool *pgxpool.Pool, cluster, enrollment string) (*AlertOutboxStore, error) {
	if pool == nil || !productionScope(cluster, enrollment, "scope") {
		return nil, errors.New("invalid assessment delivery scope")
	}
	return &AlertOutboxStore{pool: pool, assessmentCluster: cluster, assessmentEnrollment: enrollment}, nil
}

type productionIntent struct {
	id, status, message string
	first, last         int64
	attempts, inherited int
	catchup             bool
	available, oldest   time.Time
	lease               *time.Time
}

func (s *AlertOutboxStore) claimAssessment(ctx context.Context) (claim AlertClaim, found bool, err error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return claim, false, err
	}
	defer rollbackMonitoringTx(tx)
	// Lock notification authority before the occurrence, matching the host. A
	// disable that commits first prevents new claims; an earlier lease may finish.
	var enabled bool
	err = tx.QueryRow(ctx, `SELECT notifications_enabled FROM production_assessment_enrollments WHERE enrollment_id=$1 AND cluster_id=$2 FOR SHARE`, s.assessmentEnrollment, s.assessmentCluster).Scan(&enabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return claim, false, nil
	}
	if err == nil && !enabled {
		if err = FenceProductionNotifications(ctx, tx, s.assessmentCluster, s.assessmentEnrollment); err != nil {
			return claim, false, err
		}
		return claim, false, tx.Commit(ctx)
	}
	if err != nil {
		return claim, false, err
	}
	if err = reconcileOldProductionLeases(ctx, tx, s.assessmentCluster, s.assessmentEnrollment); err != nil {
		return claim, false, err
	}
	// Occurrence -> outbox is also the operator/publication/consolidation lock order.
	var occurrence string
	err = tx.QueryRow(ctx, `SELECT o.occurrence_id FROM production_notification_occurrences o JOIN production_assessment_enrollments enrollment ON enrollment.enrollment_id=o.enrollment_id AND enrollment.cluster_id=o.cluster_id AND enrollment.notifications_enabled JOIN LATERAL (
 SELECT q.status,q.available_at,q.lease_until,i.oldest_pending_at FROM production_notification_intents i JOIN gp09_alert_outbox q USING(alert_id)
 WHERE i.occurrence_id=o.occurrence_id AND q.created_at>=enrollment.notifications_enabled_at AND q.status IN ('PENDING','LEASED') ORDER BY i.first_sequence,q.created_at LIMIT 1
 ) p ON true WHERE o.cluster_id=$1 AND o.enrollment_id=$2 AND (o.maintenance_until IS NULL OR o.maintenance_until<=clock_timestamp())
 AND NOT EXISTS(SELECT 1 FROM production_notification_intents failed_intent JOIN gp09_alert_outbox failed_outbox USING(alert_id) WHERE failed_intent.occurrence_id=o.occurrence_id AND failed_outbox.status='FAILED')
 AND ((p.status='PENDING' AND p.available_at<=clock_timestamp()) OR (p.status='LEASED' AND p.lease_until<=clock_timestamp()))
 ORDER BY p.oldest_pending_at,o.occurrence_id FOR UPDATE OF o SKIP LOCKED LIMIT 1`, s.assessmentCluster, s.assessmentEnrollment).Scan(&occurrence)
	if errors.Is(err, pgx.ErrNoRows) {
		return claim, false, tx.Commit(ctx)
	}
	if err != nil {
		return claim, false, err
	}
	o, err := scanProductionOccurrence(tx.QueryRow(ctx, `SELECT `+productionOccurrenceColumns+` FROM production_notification_occurrences WHERE occurrence_id=$1`, occurrence))
	if err != nil {
		return claim, false, err
	}
	var now time.Time
	if err = tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return claim, false, err
	}
	rows, err := tx.Query(ctx, `SELECT q.alert_id,q.status,q.message,i.first_sequence,i.last_sequence,q.attempt_count,i.inherited_attempts,i.catchup,q.available_at,i.oldest_pending_at,q.lease_until FROM production_notification_intents i JOIN gp09_alert_outbox q USING(alert_id) WHERE i.occurrence_id=$1 AND q.created_at >= (SELECT notifications_enabled_at FROM production_assessment_enrollments WHERE enrollment_id=$2 AND notifications_enabled) AND q.status IN ('PENDING','LEASED') ORDER BY i.first_sequence,q.created_at FOR UPDATE OF q LIMIT 64`, occurrence, s.assessmentEnrollment)
	if err != nil {
		return claim, false, err
	}
	intents := []productionIntent{}
	for rows.Next() {
		var i productionIntent
		if err = rows.Scan(&i.id, &i.status, &i.message, &i.first, &i.last, &i.attempts, &i.inherited, &i.catchup, &i.available, &i.oldest, &i.lease); err != nil {
			break
		}
		intents = append(intents, i)
	}
	rows.Close()
	if err != nil {
		return claim, false, err
	}
	if rows.Err() != nil {
		return claim, false, rows.Err()
	}
	if len(intents) == 0 {
		return claim, false, nil
	}
	selected := intents[:1]
	first := intents[0]
	if first.status == "LEASED" && first.lease != nil && first.lease.After(now) {
		return claim, false, nil
	}
	if first.status == "LEASED" {
		if _, err = tx.Exec(ctx, `UPDATE production_notification_intents SET receipt_uncertain=true WHERE alert_id=$1`, first.id); err != nil {
			return claim, false, err
		}
	}
	if first.attempts+first.inherited >= maxAlertAttempts {
		_, err = tx.Exec(ctx, `UPDATE gp09_alert_outbox SET status='FAILED',lease_token=NULL,lease_until=NULL,last_code='RECEIPT_LOST_AFTER_ATTEMPT_LIMIT',updated_at=clock_timestamp() WHERE alert_id=$1`, first.id)
		if err != nil {
			return claim, false, err
		}
		return claim, false, tx.Commit(ctx)
	}
	// Attempted summaries remain immutable retry units. Original attempted intents
	// may enter a summary; their attempt budget and uncertain remote receipt survive.
	if !(first.catchup && first.attempts > 0) && first.status != "LEASED" {
		for _, i := range intents[1:] {
			if i.status == "LEASED" || i.catchup && i.attempts > 0 || i.last-first.first >= 64 || i.available.After(now) {
				break
			}
			selected = append(selected, i)
		}
	}
	current := first
	if len(selected) > 1 {
		current, err = consolidateProduction(ctx, tx, o, selected, now)
		if err != nil {
			return claim, false, err
		}
		if current.inherited >= maxAlertAttempts {
			return claim, false, tx.Commit(ctx)
		}
	}
	var tokenBytes [16]byte
	if _, err = rand.Read(tokenBytes[:]); err != nil {
		return claim, false, err
	}
	claim.Token = hex.EncodeToString(tokenBytes[:])
	err = tx.QueryRow(ctx, `UPDATE gp09_alert_outbox SET status='LEASED',attempt_count=attempt_count+1,lease_token=$2,lease_until=clock_timestamp()+interval '30 seconds',updated_at=clock_timestamp() WHERE alert_id=$1 RETURNING alert_id,cluster_id,message,attempt_count,lease_until`, current.id, claim.Token).Scan(&claim.ID, &claim.ClusterID, &claim.Message, &claim.Attempt, &claim.LeaseUntil)
	if err != nil {
		return claim, false, err
	}
	err = tx.Commit(ctx)
	return claim, err == nil, err
}

func consolidateProduction(ctx context.Context, tx pgx.Tx, o ProductionOccurrence, selected []productionIntent, now time.Time) (productionIntent, error) {
	first, last := selected[0].first, selected[len(selected)-1].last
	ids := []string{}
	inherited := 0
	oldest := selected[0].oldest
	available := selected[0].available
	for _, i := range selected {
		ids = append(ids, i.id)
		inherited += i.attempts + i.inherited
		if i.oldest.Before(oldest) {
			oldest = i.oldest
		}
		if i.available.After(available) {
			available = i.available
		}
	}
	id := "assess-catchup-" + monitoringDigest(append([]string{o.ID, "renderer-v1"}, ids...)...)[:40]
	rows, err := tx.Query(ctx, `SELECT e.kind,e.occurred_at,coalesce(i.display_summary,e.summary) FROM production_notification_events e
LEFT JOIN production_notification_intents i ON i.occurrence_id=e.occurrence_id AND NOT i.catchup AND i.first_sequence=e.sequence AND i.last_sequence=e.sequence
WHERE e.occurrence_id=$1 AND e.sequence BETWEEN $2 AND $3 ORDER BY e.sequence LIMIT 64`, o.ID, first, last)
	if err != nil {
		return productionIntent{}, err
	}
	var from, through time.Time
	var latestKind, latest, worsening, original string
	worseningCount := 0
	count := 0
	for rows.Next() {
		var kind, summary string
		var at time.Time
		if err = rows.Scan(&kind, &at, &summary); err != nil {
			break
		}
		if count == 0 {
			from = at
			original = summary
		}
		count++
		through = at
		latestKind, latest = kind, summary
		if kind == "WORSEN" {
			worsening = summary
			worseningCount++
		}
	}
	rows.Close()
	if err != nil {
		return productionIntent{}, err
	}
	if rows.Err() != nil {
		return productionIntent{}, rows.Err()
	}
	if count == 0 {
		return productionIntent{}, errors.New("missing catch-up history")
	}
	state := "investigation requested; latest retained evidence is not proof of current condition"
	if latestKind == "RECOVER" {
		state = "concern recovered before this delivery"
	}
	summary := fmt.Sprintf("Catch-up: %d retained events, %s to %s; %s. Latest: %s", count, from.UTC().Format(time.RFC3339), through.UTC().Format(time.RFC3339), state, boundedNotificationText(latest, 384))
	if worsening != "" {
		summary += fmt.Sprintf("; %d material worsening events; last worsening: %s", worseningCount, boundedNotificationText(worsening, 256))
	}
	summary += "\nFirst retained concern: " + boundedNotificationText(original, 1024)
	if o.MaintenanceReason != "" {
		summary += "; maintenance: " + boundedNotificationText(o.MaintenanceReason, 128)
	}
	summary += ". Earlier attempts may have reached Slack. Full event and attempt history retained."
	message, err := productionMessage(o, "CATCHUP", through, summary)
	if err != nil {
		return productionIntent{}, err
	}
	status := "PENDING"
	if inherited >= maxAlertAttempts {
		status = "FAILED"
	}
	_, err = tx.Exec(ctx, `INSERT INTO gp09_alert_outbox(alert_id,cluster_id,event_key,transition,message,status,available_at,assessment_enrollment,assessment_occurrence,last_code) VALUES($1,$2,$1,'ASSESSMENT_CATCHUP',$3,$4,$5,$6,$7,$8)`, id, o.ClusterID, message, status, available, o.EnrollmentID, o.ID, map[bool]string{true: "CATCHUP_ATTEMPT_LIMIT", false: ""}[inherited >= maxAlertAttempts])
	if err != nil {
		return productionIntent{}, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO production_notification_intents(alert_id,occurrence_id,first_sequence,last_sequence,inherited_attempts,oldest_pending_at,catchup) VALUES($1,$2,$3,$4,$5,$6,true)`, id, o.ID, first, last, min(inherited, maxAlertAttempts), oldest)
	if err != nil {
		return productionIntent{}, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO production_notification_coverage(alert_id,event_id) SELECT $1,event_id FROM production_notification_events WHERE occurrence_id=$2 AND sequence BETWEEN $3 AND $4`, id, o.ID, first, last)
	if err != nil {
		return productionIntent{}, err
	}
	_, err = tx.Exec(ctx, `UPDATE gp09_alert_outbox SET status='SUPERSEDED',lease_token=NULL,lease_until=NULL,updated_at=clock_timestamp() WHERE alert_id=ANY($1) AND status='PENDING'`, ids)
	if err != nil {
		return productionIntent{}, err
	}
	_, err = tx.Exec(ctx, `UPDATE production_notification_intents SET superseded_by=$2 WHERE alert_id=ANY($1)`, ids, id)
	if err != nil {
		return productionIntent{}, err
	}
	return productionIntent{id: id, status: status, message: message, first: first, last: last, inherited: inherited, oldest: oldest, available: available, catchup: true}, nil
}

// Scope strings are deployment inputs, never inferred from a queued message.
func ValidAssessmentDeliveryScope(cluster, enrollment string) bool {
	return productionScope(cluster, enrollment, "scope") && !strings.ContainsAny(cluster+enrollment, " ")
}

// FenceProductionNotifications is called under the enrollment lock when the
// operator disables or advances notification authority. It never recalls a live
// lease and leaves every event, intent and attempt readable.
func FenceProductionNotifications(ctx context.Context, tx pgx.Tx, cluster, enrollment string) error {
	if !productionScope(cluster, enrollment, "scope") {
		return errors.New("invalid notification fence scope")
	}
	rows, err := tx.Query(ctx, `SELECT occurrence_id FROM production_notification_occurrences WHERE cluster_id=$1 AND enrollment_id=$2 ORDER BY occurrence_id FOR UPDATE`, cluster, enrollment)
	if err != nil {
		return err
	}
	for rows.Next() {
	}
	rows.Close()
	if rows.Err() != nil {
		return rows.Err()
	}
	if _, err = tx.Exec(ctx, `UPDATE production_notification_intents i SET receipt_uncertain=true FROM gp09_alert_outbox q WHERE q.alert_id=i.alert_id AND q.cluster_id=$1 AND q.assessment_enrollment=$2 AND q.status='LEASED' AND q.lease_until<=clock_timestamp()`, cluster, enrollment); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE gp09_alert_outbox SET status=CASE WHEN status='LEASED' THEN 'FAILED' ELSE 'DISABLED' END,lease_token=NULL,lease_until=NULL,last_code=CASE WHEN status='LEASED' THEN 'RECEIPT_LOST_AFTER_DISABLE' ELSE 'AUTHORITY_DISABLED' END,updated_at=clock_timestamp() WHERE cluster_id=$1 AND assessment_enrollment=$2 AND (status='PENDING' OR status='LEASED' AND lease_until<=clock_timestamp())`, cluster, enrollment)
	return err
}

// Reconcile the delivery leases that predate a newly enabled generation. They
// are never eligible for replay, but must not remain LEASED indefinitely.
func reconcileOldProductionLeases(ctx context.Context, tx pgx.Tx, cluster, enrollment string) error {
	rows, err := tx.Query(ctx, `SELECT o.occurrence_id FROM production_notification_occurrences o WHERE o.cluster_id=$1 AND o.enrollment_id=$2 AND EXISTS(SELECT 1 FROM gp09_alert_outbox q JOIN production_assessment_enrollments e ON e.enrollment_id=q.assessment_enrollment WHERE q.assessment_occurrence=o.occurrence_id AND q.status='LEASED' AND q.lease_until<=clock_timestamp() AND q.created_at<e.notifications_enabled_at) ORDER BY o.occurrence_id FOR UPDATE OF o SKIP LOCKED LIMIT 16`, cluster, enrollment)
	if err != nil {
		return err
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
		return err
	}
	if rows.Err() != nil {
		return rows.Err()
	}
	if len(ids) == 0 {
		return nil
	}
	if _, err = tx.Exec(ctx, `UPDATE production_notification_intents i SET receipt_uncertain=true FROM gp09_alert_outbox q,production_assessment_enrollments e WHERE q.alert_id=i.alert_id AND e.enrollment_id=q.assessment_enrollment AND q.assessment_occurrence=ANY($1) AND q.status='LEASED' AND q.lease_until<=clock_timestamp() AND q.created_at<e.notifications_enabled_at`, ids); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE gp09_alert_outbox q SET status='FAILED',lease_token=NULL,lease_until=NULL,last_code='RECEIPT_LOST_AFTER_DISABLE',updated_at=clock_timestamp() FROM production_assessment_enrollments e WHERE e.enrollment_id=q.assessment_enrollment AND q.assessment_occurrence=ANY($1) AND q.status='LEASED' AND q.lease_until<=clock_timestamp() AND q.created_at<e.notifications_enabled_at`, ids)
	return err
}
