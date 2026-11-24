//go:build integration

package postgres_test

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/alertdelivery"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

type notificationFixture struct {
	p           *pgxpool.Pool
	s           *storepg.ProductionNotificationStore
	q           *storepg.AlertOutboxStore
	at          time.Time
	evidenceURL string
}

func notificationTestFixture(t *testing.T) *notificationFixture {
	t.Helper()
	p := durableTestDatabase(t)
	ctx := context.Background()
	c, _ := storepg.NewCollectionStore(p)
	if err := c.EnsureSource(ctx, "notify-cluster", "Notifications", "notify-source", "Fixture"); err != nil {
		t.Fatal(err)
	}
	var at time.Time
	if err := p.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&at); err != nil {
		t.Fatal(err)
	}
	_, err := p.Exec(ctx, `INSERT INTO production_assessment_enrollments(enrollment_id,cluster_id,source_id,category,config,config_hash,revision,notifications_enabled,notifications_enabled_at,evidence_base_url) VALUES('notify-enrollment','notify-cluster','notify-source','gpu_cooling','{}',$1,1,true,clock_timestamp()-interval '1 second','https://sherlock.example')`, strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	q, err := storepg.NewAssessmentAlertOutboxStore(p, "notify-cluster", "notify-enrollment")
	if err != nil {
		t.Fatal(err)
	}
	return &notificationFixture{p: p, s: storepg.NewProductionNotificationStore(p), q: q, at: at, evidenceURL: "https://sherlock.example/admin/clusters/notify-cluster/assessment/notify-enrollment/occurrence-1"}
}
func (f *notificationFixture) publish(t *testing.T, n int, kind string, suppress ...bool) {
	t.Helper()
	ctx := context.Background()
	tx, err := f.p.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	e := storepg.ProductionAssessmentEvent{EnrollmentID: "notify-enrollment", ClusterID: "notify-cluster", SourceID: "notify-source", Category: "gpu_cooling", Asset: "notify-cluster/GPU/node-a/GPU-a/", OccurrenceID: "occurrence-1", EventID: fmt.Sprintf("event-%d", n), Kind: kind, Summary: "Investigation required <@everyone>", EvidenceURL: f.evidenceURL, At: f.at.Add(time.Duration(n) * time.Microsecond), Evidence: json.RawMessage(`{"validated":true}`)}
	e.SuppressDelivery = len(suppress) > 0 && suppress[0]
	if err = storepg.PublishProductionAssessment(ctx, tx, e); err != nil {
		t.Fatal(err)
	}
	if err = storepg.PublishProductionAssessment(ctx, tx, e); err != nil {
		t.Fatalf("idempotent publication: %v", err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}
func (f *notificationFixture) history(t *testing.T) storepg.ProductionNotificationHistory {
	t.Helper()
	h, e := f.s.History(context.Background(), "notify-cluster", "notify-enrollment", "occurrence-1")
	if e != nil {
		t.Fatal(e)
	}
	return h
}
func (f *notificationFixture) claim(t *testing.T) storepg.AlertClaim {
	t.Helper()
	c, ok, e := f.q.Claim(context.Background())
	if e != nil || !ok {
		t.Fatalf("claim found=%v err=%v", ok, e)
	}
	return c
}
func (f *notificationFixture) finish(t *testing.T, c storepg.AlertClaim, outcome alertdelivery.Outcome) {
	t.Helper()
	code := "SLACK_ACCEPTED"
	http := 200
	if outcome != alertdelivery.Accepted {
		code = "RECEIVER_RETRYABLE"
		http = 503
	}
	_, e := f.q.Finish(context.Background(), c, alertdelivery.Result{Outcome: outcome, Code: code, HTTPStatus: http})
	if e != nil {
		t.Fatal(e)
	}
}

func TestProductionNotificationWithoutEvidenceURLLifecycle(t *testing.T) {
	f := notificationTestFixture(t)
	f.evidenceURL = ""
	if _, err := f.p.Exec(t.Context(), `UPDATE production_assessment_enrollments SET evidence_base_url='' WHERE enrollment_id='notify-enrollment'`); err != nil {
		t.Fatal(err)
	}
	f.publish(t, 1, "OPEN")
	initial := f.claim(t)
	if strings.Contains(initial.Message, "History:") || strings.Contains(initial.Message, "/admin/") || !strings.Contains(initial.Message, "occurrence-1") || !strings.Contains(initial.Message, "Investigation required &lt;@everyone&gt;") {
		t.Fatalf("initial notification lost context or manufactured a link: %s", initial.Message)
	}
	f.finish(t, initial, alertdelivery.Accepted)
	f.publish(t, 2, "WORSEN")
	f.publish(t, 3, "RECOVER")
	catchup := f.claim(t)
	if strings.Contains(catchup.Message, "History:") || strings.Contains(catchup.Message, "/admin/") || !strings.Contains(catchup.Message, "Catch-up: 2 retained events") || !strings.Contains(catchup.Message, "concern recovered before this delivery") || !strings.Contains(catchup.Message, "occurrence-1") {
		t.Fatalf("catch-up lost context or manufactured a link: %s", catchup.Message)
	}
	f.finish(t, catchup, alertdelivery.Accepted)
	h := f.history(t)
	if h.Occurrence.EvidenceURL != "" || h.Occurrence.ClosedAt == nil || len(h.Events) != 3 {
		t.Fatalf("history not retained without a URL: %+v", h)
	}
	for _, event := range h.Events {
		if len(event.Evidence) == 0 || event.EvidenceID == "" {
			t.Fatalf("event proof missing: %+v", event)
		}
	}
}
func TestProductionNotificationA1AndScopedClaim(t *testing.T) {
	f := notificationTestFixture(t)
	f.publish(t, 1, "OPEN")
	h := f.history(t)
	ctx := context.Background()
	if _, e := f.s.Acknowledge(ctx, "notify-cluster", "notify-enrollment", "occurrence-1", h.Occurrence.Version, "operator"); e != nil {
		t.Fatal(e)
	}
	legacy, _ := storepg.NewAlertOutboxStore(f.p)
	if _, ok, e := legacy.Claim(ctx); e != nil || ok {
		t.Fatalf("legacy claimed production: %v %v", ok, e)
	}
	if _, ok, e := legacy.ClaimForCluster(ctx, "notify-cluster"); e != nil || ok {
		t.Fatalf("legacy cluster claimed production: %v %v", ok, e)
	}
	other, _ := storepg.NewAssessmentAlertOutboxStore(f.p, "notify-cluster", "other")
	if _, ok, e := other.Claim(ctx); e != nil || ok {
		t.Fatalf("other enrollment claimed production: %v %v", ok, e)
	}
	claim := f.claim(t)
	if strings.Contains(claim.Message, "<@everyone>") {
		t.Fatal("unsafe mention")
	}
	f.finish(t, claim, alertdelivery.Accepted)
	if _, e := f.s.Acknowledge(ctx, "notify-cluster", "notify-enrollment", "occurrence-1", h.Occurrence.Version, "operator"); e == nil {
		t.Fatal("stale version accepted")
	}
}
func TestProductionNotificationD2RetainsFullHistory(t *testing.T) {
	f := notificationTestFixture(t)
	f.publish(t, 1, "OPEN")
	f.publish(t, 2, "WORSEN")
	f.publish(t, 3, "RECOVER")
	claim := f.claim(t)
	if !strings.Contains(claim.Message, "CATCHUP") || !strings.Contains(claim.Message, "recovered before this delivery") || !strings.Contains(claim.Message, "material worsening") {
		t.Fatal(claim.Message)
	}
	f.finish(t, claim, alertdelivery.Accepted)
	h := f.history(t)
	if len(h.Events) != 3 || h.Occurrence.ClosedAt == nil {
		t.Fatalf("history=%+v", h)
	}
	var superseded, coverage int
	if err := f.p.QueryRow(context.Background(), `SELECT count(*) FROM gp09_alert_outbox WHERE status='SUPERSEDED'`).Scan(&superseded); err != nil {
		t.Fatal(err)
	}
	if err := f.p.QueryRow(context.Background(), `SELECT count(*) FROM production_notification_coverage WHERE alert_id=$1`, claim.ID).Scan(&coverage); err != nil {
		t.Fatal(err)
	}
	if superseded != 3 || coverage != 3 {
		t.Fatalf("superseded=%d coverage=%d", superseded, coverage)
	}
}
func TestProductionNotificationMaintenanceClosedCatchup(t *testing.T) {
	f := notificationTestFixture(t)
	f.publish(t, 1, "OPEN")
	ctx := context.Background()
	h := f.history(t)
	if _, err := f.s.SetMaintenance(ctx, "notify-cluster", "notify-enrollment", "occurrence-1", h.Occurrence.Version, "operator", "planned cooling inspection", 60); err != nil {
		t.Fatal(err)
	}
	f.publish(t, 2, "WORSEN")
	f.publish(t, 3, "RECOVER")
	if _, ok, e := f.q.Claim(ctx); e != nil || ok {
		t.Fatalf("held notice claimed=%v err=%v", ok, e)
	}
	h = f.history(t)
	if _, e := f.s.SetMaintenance(ctx, "notify-cluster", "notify-enrollment", "occurrence-1", h.Occurrence.Version, "operator", "extend closed", 120); e == nil {
		t.Fatal("extended closed hold")
	}
	if _, e := f.s.SetMaintenance(ctx, "notify-cluster", "notify-enrollment", "occurrence-1", h.Occurrence.Version, "operator", "inspection complete", 0); e != nil {
		t.Fatal(e)
	}
	c := f.claim(t)
	if !strings.Contains(c.Message, "CATCHUP") {
		t.Fatal(c.Message)
	}
	f.finish(t, c, alertdelivery.Accepted)
}
func TestProductionNotificationCatchupBudgetAndFinalAcceptance(t *testing.T) {
	f := notificationTestFixture(t)
	f.publish(t, 1, "OPEN")
	ctx := context.Background()
	c := f.claim(t)
	f.finish(t, c, alertdelivery.RetryableFailure)
	if _, e := f.p.Exec(ctx, `UPDATE gp09_alert_outbox SET available_at=clock_timestamp()-interval '1 second' WHERE alert_id=$1`, c.ID); e != nil {
		t.Fatal(e)
	}
	f.publish(t, 2, "WORSEN")
	c = f.claim(t)
	if !strings.Contains(c.Message, "CATCHUP") {
		t.Fatal(c.Message)
	}
	// The summary inherited the original attempt; its seventh attempt is total 8.
	if _, e := f.p.Exec(ctx, `UPDATE gp09_alert_outbox SET attempt_count=7 WHERE alert_id=$1`, c.ID); e != nil {
		t.Fatal(e)
	}
	c.Attempt = 7
	status, e := f.q.Finish(ctx, c, alertdelivery.Result{Outcome: alertdelivery.Accepted, Code: "SLACK_ACCEPTED", HTTPStatus: 200})
	if e != nil || status != "ACCEPTED" {
		t.Fatalf("status=%s err=%v", status, e)
	}
}
func TestProductionNotificationDisableAndNoBackfill(t *testing.T) {
	f := notificationTestFixture(t)
	f.publish(t, 1, "OPEN")
	ctx := context.Background()
	tx, e := f.p.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, `UPDATE production_assessment_enrollments SET notifications_enabled=false WHERE enrollment_id='notify-enrollment'`); e != nil {
		t.Fatal(e)
	}
	if e = storepg.FenceProductionNotifications(ctx, tx, "notify-cluster", "notify-enrollment"); e != nil {
		t.Fatal(e)
	}
	if e = tx.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	if _, ok, e := f.q.Claim(ctx); e != nil || ok {
		t.Fatalf("disabled claim=%v err=%v", ok, e)
	}
	if _, e = f.p.Exec(ctx, `UPDATE production_assessment_enrollments SET notifications_enabled=true,notifications_enabled_at=clock_timestamp() WHERE enrollment_id='notify-enrollment'`); e != nil {
		t.Fatal(e)
	}
	if _, ok, e := f.q.Claim(ctx); e != nil || ok {
		t.Fatalf("backfill claim=%v err=%v", ok, e)
	}
	var status string
	if e = f.p.QueryRow(ctx, `SELECT status FROM gp09_alert_outbox LIMIT 1`).Scan(&status); e != nil || status != "DISABLED" {
		t.Fatalf("status=%s err=%v", status, e)
	}
}
func TestProductionNotificationAuditPagination(t *testing.T) {
	f := notificationTestFixture(t)
	f.publish(t, 1, "OPEN")
	ctx := context.Background()
	h := f.history(t)
	v := h.Occurrence.Version
	for i := 0; i < 70; i++ {
		o, e := f.s.Acknowledge(ctx, "notify-cluster", "notify-enrollment", "occurrence-1", v, "operator")
		if e != nil {
			t.Fatal(e)
		}
		v = o.Version
	}
	h, e := f.s.HistoryPageWithAudit(ctx, "notify-cluster", "notify-enrollment", "occurrence-1", 0, 0)
	if e != nil || !h.MoreAudit {
		t.Fatalf("more=%v err=%v", h.MoreAudit, e)
	}
	h2, e := f.s.HistoryPageWithAudit(ctx, "notify-cluster", "notify-enrollment", "occurrence-1", h.NextAfter, h.NextAuditAfter)
	if e != nil || h2.MoreAudit {
		t.Fatalf("more=%v err=%v", h2.MoreAudit, e)
	}
	var rest []any
	if e = json.Unmarshal(h2.Audit, &rest); e != nil || len(rest) != 6 {
		t.Fatalf("rest=%d err=%v", len(rest), e)
	}
}
func TestProductionNotificationLegacyFinalAttemptAccepted(t *testing.T) {
	f := notificationTestFixture(t)
	ctx := context.Background()
	s, _ := storepg.NewAlertOutboxStore(f.p)
	_, e := s.Enqueue(ctx, storepg.AlertOutboxEntry{ID: "test-final-attempt", ClusterID: "notify-cluster", EventKey: "final-attempt", Transition: "TEST", Message: "fixture only"})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.p.Exec(ctx, `UPDATE gp09_alert_outbox SET attempt_count=7 WHERE alert_id='test-final-attempt'`); e != nil {
		t.Fatal(e)
	}
	c, ok, e := s.Claim(ctx)
	if e != nil || !ok {
		t.Fatal(e)
	}
	status, e := s.Finish(ctx, c, alertdelivery.Result{Outcome: alertdelivery.Accepted, Code: "SLACK_ACCEPTED", HTTPStatus: 200})
	if e != nil || status != "ACCEPTED" {
		t.Fatalf("status=%s err=%v", status, e)
	}
}

func TestProductionNotificationRetryCannotEvadeHoldOrBudget(t *testing.T) {
	f := notificationTestFixture(t)
	f.publish(t, 1, "OPEN")
	ctx := context.Background()
	c := f.claim(t)
	h := f.history(t)
	if _, e := f.s.SetMaintenance(ctx, "notify-cluster", "notify-enrollment", "occurrence-1", h.Occurrence.Version, "operator", "inspection", 60); e != nil {
		t.Fatal(e)
	}
	f.finish(t, c, alertdelivery.RetryableFailure)
	if _, e := f.p.Exec(ctx, `UPDATE gp09_alert_outbox SET available_at=clock_timestamp()-interval '1 second' WHERE alert_id=$1`, c.ID); e != nil {
		t.Fatal(e)
	}
	if _, ok, e := f.q.Claim(ctx); e != nil || ok {
		t.Fatalf("retry bypassed hold: %v %v", ok, e)
	}
	h = f.history(t)
	if _, e := f.s.SetMaintenance(ctx, "notify-cluster", "notify-enrollment", "occurrence-1", h.Occurrence.Version, "operator", "clear", 0); e != nil {
		t.Fatal(e)
	}
	f.publish(t, 2, "WORSEN")
	c = f.claim(t)
	if _, e := f.p.Exec(ctx, `UPDATE gp09_alert_outbox SET attempt_count=7 WHERE alert_id=$1`, c.ID); e != nil {
		t.Fatal(e)
	}
	c.Attempt = 7
	state, e := f.q.Finish(ctx, c, alertdelivery.Result{Outcome: alertdelivery.RetryableFailure, Code: "RECEIVER_RETRYABLE", HTTPStatus: 503})
	if e != nil || state != "FAILED" {
		t.Fatalf("state=%s err=%v", state, e)
	}
}
func TestProductionNotificationLeasedSummaryImmutableAndFenced(t *testing.T) {
	f := notificationTestFixture(t)
	ctx := context.Background()
	f.publish(t, 1, "OPEN")
	f.publish(t, 2, "WORSEN")
	c := f.claim(t)
	f.publish(t, 3, "RECOVER")
	if _, ok, e := f.q.Claim(ctx); e != nil || ok {
		t.Fatalf("later notice bypassed lease: %v %v", ok, e)
	}
	if _, e := f.p.Exec(ctx, `UPDATE gp09_alert_outbox SET lease_until=clock_timestamp()-interval '1 second' WHERE alert_id=$1`, c.ID); e != nil {
		t.Fatal(e)
	}
	retry := f.claim(t)
	if retry.ID != c.ID || retry.Message != c.Message {
		t.Fatal("attempted summary rewritten")
	}
	if _, e := f.q.Finish(ctx, c, alertdelivery.Result{Outcome: alertdelivery.Accepted, Code: "SLACK_ACCEPTED", HTTPStatus: 200}); e == nil {
		t.Fatal("expired lease completed")
	}
	f.finish(t, retry, alertdelivery.Accepted)
	recovery := f.claim(t)
	if !strings.Contains(recovery.Message, "RECOVER") || !strings.Contains(recovery.Message, "Incident: ") {
		t.Fatal(recovery.Message)
	}
}
func TestProductionNotificationCommitRollbackAndHumanInvestigation(t *testing.T) {
	f := notificationTestFixture(t)
	f.publish(t, 1, "OPEN")
	ctx := context.Background()
	h := f.history(t)
	if _, e := f.p.Exec(ctx, `UPDATE incidents SET status='INVESTIGATING' WHERE incident_id=$1`, h.Occurrence.IncidentID); e != nil {
		t.Fatal(e)
	}
	f.publish(t, 2, "RECOVER")
	var status string
	if e := f.p.QueryRow(ctx, `SELECT status FROM incidents WHERE incident_id=$1`, h.Occurrence.IncidentID).Scan(&status); e != nil || status != "INVESTIGATING" {
		t.Fatalf("human status=%s err=%v", status, e)
	}
	tx, e := f.p.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	event := storepg.ProductionAssessmentEvent{EnrollmentID: "notify-enrollment", ClusterID: "notify-cluster", SourceID: "notify-source", Category: "gpu_cooling", Asset: "notify-cluster/GPU/node-b/GPU-b/", OccurrenceID: "rollback-occurrence", EventID: "rollback-event", Kind: "OPEN", Summary: "fixture", At: f.at, EvidenceURL: "https://sherlock.example/history", Evidence: json.RawMessage(`{}`)}
	if e = storepg.PublishProductionAssessment(ctx, tx, event); e != nil {
		t.Fatal(e)
	}
	if e = tx.Rollback(ctx); e != nil {
		t.Fatal(e)
	}
	var count int
	if e = f.p.QueryRow(ctx, `SELECT count(*) FROM production_notification_events WHERE event_id='rollback-event'`).Scan(&count); e != nil || count != 0 {
		t.Fatalf("rollback events=%d err=%v", count, e)
	}
}

func TestProductionNotificationRetentionSkipsUndelivered(t *testing.T) {
	f := notificationTestFixture(t)
	f.publish(t, 1, "OPEN")
	f.publish(t, 2, "RECOVER")
	ctx := context.Background()
	if _, e := f.p.Exec(ctx, `UPDATE production_notification_occurrences SET opened_at=clock_timestamp()-interval '92 days',closed_at=clock_timestamp()-interval '91 days' WHERE occurrence_id='occurrence-1'`); e != nil {
		t.Fatal(e)
	}
	n, e := storepg.CleanupProductionNotifications(ctx, f.p, "notify-cluster", "notify-enrollment")
	if e != nil || n != 0 {
		t.Fatalf("pending cleanup=%d err=%v", n, e)
	}
	c := f.claim(t)
	f.finish(t, c, alertdelivery.Accepted)
	n, e = storepg.CleanupProductionNotifications(ctx, f.p, "notify-cluster", "notify-enrollment")
	if e != nil || n != 1 {
		t.Fatalf("accepted cleanup=%d err=%v", n, e)
	}
	var incidents int
	if e = f.p.QueryRow(ctx, `SELECT count(*) FROM incidents`).Scan(&incidents); e != nil || incidents != 1 {
		t.Fatalf("incident deleted count=%d err=%v", incidents, e)
	}
}
func TestProductionNotificationLeaseMayFinishAfterDisable(t *testing.T) {
	f := notificationTestFixture(t)
	f.publish(t, 1, "OPEN")
	ctx := context.Background()
	c := f.claim(t)
	tx, e := f.p.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, `UPDATE production_assessment_enrollments SET notifications_enabled=false WHERE enrollment_id='notify-enrollment'`); e != nil {
		t.Fatal(e)
	}
	if e = storepg.FenceProductionNotifications(ctx, tx, "notify-cluster", "notify-enrollment"); e != nil {
		t.Fatal(e)
	}
	if e = tx.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	status, e := f.q.Finish(ctx, c, alertdelivery.Result{Outcome: alertdelivery.RetryableFailure, Code: "RECEIVER_RETRYABLE", HTTPStatus: 503})
	if e != nil || status != "DISABLED" {
		t.Fatalf("status=%s err=%v", status, e)
	}
}

func TestProductionNotificationMigrationPreservesSlurmProducer(t *testing.T) {
	f := notificationTestFixture(t)
	ctx := context.Background()
	if _, e := f.p.Exec(ctx, `INSERT INTO gp09_alert_outbox(alert_id,cluster_id,event_key,transition,message) VALUES('slurm-regression','notify-cluster','slurm-regression','SLURM_FAILURES','fixture')`); e != nil {
		t.Fatal(e)
	}
	for _, file := range []string{"../../../migrations/000086_production_notifications.down.sql", "../../../migrations/000086_production_notifications.up.sql"} {
		body, e := os.ReadFile(file)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = f.p.Exec(ctx, string(body)); e != nil {
			t.Fatalf("%s: %v", file, e)
		}
	}
	var transition string
	if e := f.p.QueryRow(ctx, `SELECT transition FROM gp09_alert_outbox WHERE alert_id='slurm-regression'`).Scan(&transition); e != nil || transition != "SLURM_FAILURES" {
		t.Fatalf("transition=%s err=%v", transition, e)
	}
}
func TestProductionNotificationLostReceiptSurvivesDisableAndRetention(t *testing.T) {
	f := notificationTestFixture(t)
	f.publish(t, 1, "OPEN")
	ctx := context.Background()
	c := f.claim(t)
	if _, e := f.p.Exec(ctx, `UPDATE gp09_alert_outbox SET lease_until=clock_timestamp()-interval '1 second' WHERE alert_id=$1`, c.ID); e != nil {
		t.Fatal(e)
	}
	tx, e := f.p.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, `UPDATE production_assessment_enrollments SET notifications_enabled=false WHERE enrollment_id='notify-enrollment'`); e != nil {
		t.Fatal(e)
	}
	if e = storepg.FenceProductionNotifications(ctx, tx, "notify-cluster", "notify-enrollment"); e != nil {
		t.Fatal(e)
	}
	if e = tx.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	f.publish(t, 2, "RECOVER", true)
	if _, e = f.p.Exec(ctx, `UPDATE production_notification_occurrences SET opened_at=clock_timestamp()-interval '92 days',closed_at=clock_timestamp()-interval '91 days' WHERE occurrence_id='occurrence-1'`); e != nil {
		t.Fatal(e)
	}
	n, e := storepg.CleanupProductionNotifications(ctx, f.p, "notify-cluster", "notify-enrollment")
	if e != nil || n != 0 {
		t.Fatalf("ambiguous cleanup=%d err=%v", n, e)
	}
	var uncertain bool
	var status, code string
	if e = f.p.QueryRow(ctx, `SELECT i.receipt_uncertain,q.status,q.last_code FROM production_notification_intents i JOIN gp09_alert_outbox q USING(alert_id) WHERE q.alert_id=$1`, c.ID).Scan(&uncertain, &status, &code); e != nil || !uncertain || status != "FAILED" || code != "RECEIPT_LOST_AFTER_DISABLE" {
		t.Fatalf("uncertain=%v status=%s code=%s err=%v", uncertain, status, code, e)
	}
}
func TestProductionNotificationRapidReenableReconcilesOldLease(t *testing.T) {
	f := notificationTestFixture(t)
	f.publish(t, 1, "OPEN")
	ctx := context.Background()
	c := f.claim(t)
	for _, enabled := range []bool{false, true} {
		tx, e := f.p.Begin(ctx)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = tx.Exec(ctx, `UPDATE production_assessment_enrollments SET notifications_enabled=$1,notifications_enabled_at=CASE WHEN $1 THEN clock_timestamp() ELSE notifications_enabled_at END WHERE enrollment_id='notify-enrollment'`, enabled); e != nil {
			t.Fatal(e)
		}
		if e = storepg.FenceProductionNotifications(ctx, tx, "notify-cluster", "notify-enrollment"); e != nil {
			t.Fatal(e)
		}
		if e = tx.Commit(ctx); e != nil {
			t.Fatal(e)
		}
	}
	if _, e := f.p.Exec(ctx, `UPDATE gp09_alert_outbox SET lease_until=clock_timestamp()-interval '1 second' WHERE alert_id=$1`, c.ID); e != nil {
		t.Fatal(e)
	}
	if _, ok, e := f.q.Claim(ctx); e != nil || ok {
		t.Fatalf("old lease replay=%v err=%v", ok, e)
	}
	var status string
	var uncertain bool
	if e := f.p.QueryRow(ctx, `SELECT q.status,i.receipt_uncertain FROM gp09_alert_outbox q JOIN production_notification_intents i USING(alert_id) WHERE q.alert_id=$1`, c.ID).Scan(&status, &uncertain); e != nil || status != "FAILED" || !uncertain {
		t.Fatalf("status=%s uncertain=%v err=%v", status, uncertain, e)
	}
}
func TestProductionNotificationFailedCatchupBlocksRecoveryBudget(t *testing.T) {
	f := notificationTestFixture(t)
	f.publish(t, 1, "OPEN")
	f.publish(t, 2, "WORSEN")
	ctx := context.Background()
	c := f.claim(t)
	f.publish(t, 3, "RECOVER")
	if _, e := f.p.Exec(ctx, `UPDATE gp09_alert_outbox SET attempt_count=8 WHERE alert_id=$1`, c.ID); e != nil {
		t.Fatal(e)
	}
	c.Attempt = 8
	status, e := f.q.Finish(ctx, c, alertdelivery.Result{Outcome: alertdelivery.RetryableFailure, Code: "RECEIVER_RETRYABLE", HTTPStatus: 503})
	if e != nil || status != "FAILED" {
		t.Fatalf("status=%s err=%v", status, e)
	}
	if _, ok, e := f.q.Claim(ctx); e != nil || ok {
		t.Fatalf("recovery bypassed failed dependency=%v err=%v", ok, e)
	}
	var attempts int
	if e = f.p.QueryRow(ctx, `SELECT attempt_count FROM gp09_alert_outbox WHERE transition='ASSESSMENT_RECOVER'`).Scan(&attempts); e != nil || attempts != 0 {
		t.Fatalf("new retry budget=%d err=%v", attempts, e)
	}
}
func TestProductionNotificationSuppressedRecoveryClosesLifecycle(t *testing.T) {
	f := notificationTestFixture(t)
	f.publish(t, 1, "OPEN")
	ctx := context.Background()
	f.finish(t, f.claim(t), alertdelivery.Accepted)
	f.publish(t, 2, "RECOVER", true)
	h := f.history(t)
	if h.Occurrence.ClosedAt == nil || len(h.Events) != 2 {
		t.Fatalf("lifecycle=%+v", h.Occurrence)
	}
	if _, ok, e := f.q.Claim(ctx); e != nil || ok {
		t.Fatalf("suppressed recovery delivered=%v err=%v", ok, e)
	}
	var status string
	if e := f.p.QueryRow(ctx, `SELECT status FROM gp09_alert_outbox WHERE transition='ASSESSMENT_RECOVER'`).Scan(&status); e != nil || status != "DISABLED" {
		t.Fatalf("status=%s err=%v", status, e)
	}
}

// This transport exercises the real sender without performing network I/O.
// Slack may have accepted the body before the client loses its response bytes.
type notificationBodyFailureTransport struct{}

func (notificationBodyFailureTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: notificationFailedResponseBody{}}, nil
}

type notificationFailedResponseBody struct{}

func (notificationFailedResponseBody) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
func (notificationFailedResponseBody) Close() error             { return nil }
func TestProductionNotificationUnexpectedResponseRetainsAmbiguousHistory(t *testing.T) {
	f := notificationTestFixture(t)
	f.publish(t, 1, "OPEN")
	ctx := context.Background()
	claim := f.claim(t)
	sender := alertdelivery.Sender{Client: &http.Client{Transport: notificationBodyFailureTransport{}}}
	result := sender.Send(ctx, "https://hooks.slack.com/services/T123/B456/fixture-never-sent", claim.Message)
	if result.Outcome != alertdelivery.RetryableFailure || result.Code != "UNEXPECTED_RESPONSE" || result.HTTPStatus != http.StatusOK {
		t.Fatalf("sender result=%+v", result)
	}
	status, e := f.q.Finish(ctx, claim, result)
	if e != nil || status != "PENDING" {
		t.Fatalf("finish=%s err=%v", status, e)
	}
	tx, e := f.p.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, `UPDATE production_assessment_enrollments SET notifications_enabled=false WHERE enrollment_id='notify-enrollment'`); e != nil {
		t.Fatal(e)
	}
	if e = storepg.FenceProductionNotifications(ctx, tx, "notify-cluster", "notify-enrollment"); e != nil {
		t.Fatal(e)
	}
	if e = tx.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	f.publish(t, 2, "RECOVER", true)
	if _, e = f.p.Exec(ctx, `UPDATE production_notification_occurrences SET opened_at=clock_timestamp()-interval '92 days',closed_at=clock_timestamp()-interval '91 days' WHERE occurrence_id='occurrence-1'`); e != nil {
		t.Fatal(e)
	}
	n, e := storepg.CleanupProductionNotifications(ctx, f.p, "notify-cluster", "notify-enrollment")
	if e != nil || n != 0 {
		t.Fatalf("ambiguous history cleanup=%d err=%v", n, e)
	}
	var uncertain bool
	var storedStatus, attemptCode string
	if e = f.p.QueryRow(ctx, `SELECT i.receipt_uncertain,q.status,a.code FROM production_notification_intents i JOIN gp09_alert_outbox q USING(alert_id) JOIN gp09_alert_delivery_attempts a USING(alert_id) WHERE q.alert_id=$1`, claim.ID).Scan(&uncertain, &storedStatus, &attemptCode); e != nil || !uncertain || storedStatus != "DISABLED" || attemptCode != "UNEXPECTED_RESPONSE" {
		t.Fatalf("uncertain=%v status=%s code=%s err=%v", uncertain, storedStatus, attemptCode, e)
	}
}

// Maintenance can coalesce an approved OPEN with its recovery before Slack
// makes its first claim. The catch-up should still explain the original risk.
func TestProductionNotificationCatchupKeepsConfirmedWarming(t *testing.T) {
	f := notificationTestFixture(t)
	f.publish(t, 1, "OPEN")
	const summary = "Confirmed warming: 59 → 67 °C\nAssessment: Sustained rise at stable power <@channel>"
	if _, err := f.p.Exec(t.Context(), `UPDATE production_notification_intents SET display_summary=$1 WHERE occurrence_id='occurrence-1' AND first_sequence=1`, summary); err != nil {
		t.Fatal(err)
	}
	f.publish(t, 2, "RECOVER")
	c := f.claim(t)
	for _, part := range []string{"CATCHUP", "recovered before this delivery", "59 → 67 °C", "Sustained rise at stable power &lt;@channel&gt;"} {
		if !strings.Contains(c.Message, part) {
			t.Fatalf("missing %q in catch-up: %s", part, c.Message)
		}
	}
}
