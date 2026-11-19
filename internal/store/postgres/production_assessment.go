package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	a "github.com/verticalcomputer/sherlock/internal/alertassessment"
)

// ProductionAssessmentStore has no collection or workload execution interface.
// It consumes admitted receipts and publishes atomically via the shared outbox.
type ProductionAssessmentStore struct {
	pool     *pgxpool.Pool
	registry *a.Registry
	config   a.ProductionConfig
}

func NewProductionAssessmentStore(ctx context.Context, pool *pgxpool.Pool, r *a.Registry, c a.ProductionConfig) (*ProductionAssessmentStore, error) {
	if pool == nil || r == nil {
		return nil, a.ErrInvalid
	}
	c, err := a.NormalizeProductionConfig(ctx, c, r)
	if err != nil {
		return nil, err
	}
	return &ProductionAssessmentStore{pool: pool, registry: r, config: c}, nil
}
func (s *ProductionAssessmentStore) Start(ctx context.Context) error {
	tx, err := beginProductionAssessmentTx(ctx, s.pool)
	if err != nil {
		return err
	}
	defer rollbackMonitoringTx(tx)
	c := s.config.Assessment
	for _, asset := range c.Assets {
		for _, binding := range c.Bindings {
			if err = validateProductionBaseline(ctx, tx, c, asset, binding); err != nil {
				return err
			}
		}
	}
	hash, err := c.Hash()
	if err != nil {
		return err
	}
	body, err := a.Canonical(c)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO production_assessment_enrollments(enrollment_id,cluster_id,source_id,category,config,config_hash,revision,notifications_enabled,notifications_enabled_at,evidence_base_url)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,CASE WHEN $8 THEN clock_timestamp() END,$9) ON CONFLICT(enrollment_id) DO NOTHING`, c.RunID, c.ClusterID, c.SourceID, c.Category, body, hash, s.config.Revision, s.config.NotificationsEnabled, s.config.EvidenceBaseURL)
	if err != nil {
		return err
	}
	var storedHash, baseURL string
	var revision int64
	var enabled bool
	err = tx.QueryRow(ctx, `SELECT config_hash,revision,notifications_enabled,evidence_base_url FROM production_assessment_enrollments WHERE enrollment_id=$1 FOR UPDATE`, c.RunID).Scan(&storedHash, &revision, &enabled, &baseURL)
	if err != nil {
		return err
	}
	if storedHash != hash || baseURL != s.config.EvidenceBaseURL || revision > s.config.Revision || revision == s.config.Revision && (enabled != s.config.NotificationsEnabled || baseURL != s.config.EvidenceBaseURL) {
		return fmt.Errorf("production enrollment configuration/revision conflict")
	}
	if revision < s.config.Revision {
		if enabled != s.config.NotificationsEnabled {
			if err = FenceProductionNotifications(ctx, tx, c.ClusterID, c.RunID); err != nil {
				return err
			}
		}
		_, err = tx.Exec(ctx, `UPDATE production_assessment_enrollments SET revision=$2,notifications_enabled=$3,notifications_enabled_at=CASE WHEN $3 AND NOT notifications_enabled THEN clock_timestamp() ELSE notifications_enabled_at END,evidence_base_url=$4,updated_at=clock_timestamp() WHERE enrollment_id=$1`, c.RunID, s.config.Revision, s.config.NotificationsEnabled, s.config.EvidenceBaseURL)
		if err != nil {
			return err
		}
	}
	_, err = tx.Exec(ctx, `INSERT INTO production_assessment_controls(enrollment_id,revision,notifications_enabled)VALUES($1,$2,$3)ON CONFLICT DO NOTHING`, c.RunID, s.config.Revision, s.config.NotificationsEnabled)
	if err != nil {
		return err
	}
	for _, asset := range c.Assets {
		_, err = tx.Exec(ctx, `INSERT INTO production_assessment_states(enrollment_id,asset,cluster_id,source_id,category) VALUES($1,$2,$3,$4,$5) ON CONFLICT(enrollment_id,asset) DO NOTHING`, c.RunID, asset.EntityKey, c.ClusterID, c.SourceID, c.Category)
		if err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}
func (s *ProductionAssessmentStore) Refresh(ctx context.Context) error {
	pass, cancel := context.WithTimeout(ctx, a.ShadowRefreshBudget)
	defer cancel()
	// First persist all retained due work. Slow/unavailable acquisition cannot
	// roll back a deadline disposition that does not need new source reads.
	var failures []error
	assets, err := s.refreshOrder(pass)
	if err != nil {
		return err
	}
	for _, dueOnly := range []bool{true, false} {
		for _, asset := range assets {
			gpu, stop := context.WithTimeout(pass, a.ShadowGPUBudget)
			err := s.refreshAsset(gpu, asset, dueOnly)
			stop()
			if err != nil {
				code := assessmentFailureCode(err)
				_, _ = s.pool.Exec(pass, `UPDATE production_assessment_states SET last_failure_code=$3,last_failure_at=clock_timestamp(),last_attempt_at=clock_timestamp(),failure_count=failure_count+1 WHERE enrollment_id=$1 AND asset=$2`, s.config.Assessment.RunID, asset.EntityKey, code)
				failures = append(failures, err)
				if pass.Err() != nil {
					return errors.Join(failures...)
				}
			}
		}
	}
	return errors.Join(failures...)
}
func (s *ProductionAssessmentStore) refreshAsset(ctx context.Context, asset a.Asset, dueOnly bool) (result error) {
	stage, started, outcome := "production.begin", time.Now(), "not_attempted"
	defer func() { result = assessmentTransactionError(stage, started, result, outcome) }()
	tx, err := beginProductionAssessmentTx(ctx, s.pool)
	if err != nil {
		return err
	}
	defer rollbackMonitoringTx(tx)
	stage, started = "production.load", time.Now()
	c := s.config.Assessment
	var start, now time.Time
	var enabledAt *time.Time
	var enabled bool
	var revision int64
	var baseURL string
	var eventCount, retainedBytes int64
	err = tx.QueryRow(ctx, `SELECT created_at,clock_timestamp(),notifications_enabled_at,notifications_enabled,revision,evidence_base_url,retained_events,retained_bytes FROM production_assessment_enrollments WHERE enrollment_id=$1 FOR UPDATE`, c.RunID).Scan(&start, &now, &enabledAt, &enabled, &revision, &baseURL, &eventCount, &retainedBytes)
	if err != nil {
		return err
	}
	if revision < s.config.Revision {
		return fmt.Errorf("production control revision regressed")
	}
	var raw []byte
	var due *time.Time
	err = tx.QueryRow(ctx, `SELECT snapshot,next_due_at FROM production_assessment_states WHERE enrollment_id=$1 AND asset=$2 FOR UPDATE`, c.RunID, asset.EntityKey).Scan(&raw, &due)
	if err != nil {
		return err
	}
	now = now.UTC()
	if dueOnly && (due == nil || due.After(now)) {
		return nil
	}
	e, err := a.NewProductionEngine(ctx, s.config, start.UTC(), s.registry)
	if err != nil {
		return err
	}
	if err = e.RestoreProduction(asset.EntityKey, raw); err != nil {
		return err
	}
	e.CommitClock = assessmentDatabaseClock(now)
	stage, started = "production.input", time.Now()
	facts := []a.Fact{}
	admit := eventCount < 9968 && retainedBytes < 384<<20
	if !dueOnly && (admit || e.Enrollments[asset.EntityKey].Active) {
		facts, err = loadAssessmentInput(ctx, tx, c, asset, now, e.Facts)
		if err != nil {
			return err
		}
	}
	selected := []string{}
	if !dueOnly && (admit || e.Enrollments[asset.EntityKey].Active) {
		selected = []string{asset.EntityKey}
	}
	stage, started = "production.evaluate", time.Now()
	if err = e.AdvanceAssets(ctx, now, now, now, facts, nil, selected); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	stage, started = "production.persist", time.Now()
	for _, d := range e.Decisions {
		evidence, err := e.ProductionEvidenceContext(ctx, d)
		if err != nil {
			return err
		}
		h := a.Hash("production_evidence", c.Category, 1, evidence)
		_, err = tx.Exec(ctx, `INSERT INTO production_assessment_decisions(event_id,enrollment_id,occurrence_id,asset,kind,logical_at,evidence,evidence_hash)VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(event_id) DO NOTHING`, d.ID, c.RunID, d.CandidateID, d.Asset, d.Kind, d.LogicalAt, evidence, h)
		if err != nil {
			return err
		}
		var same bool
		err = tx.QueryRow(ctx, `SELECT evidence_hash=$2 FROM production_assessment_decisions WHERE event_id=$1`, d.ID, h).Scan(&same)
		if err != nil {
			return err
		}
		if !same {
			return fmt.Errorf("production decision idempotency conflict")
		}
		if d.Kind == "RECOVER" {
			_, err = tx.Exec(ctx, `UPDATE production_assessment_decisions SET closed_at=$3 WHERE enrollment_id=$1 AND occurrence_id=$2 AND closed_at IS NULL`, c.RunID, d.CandidateID, d.LogicalAt)
			if err != nil {
				return err
			}
		}
		entered := time.Time{}
		benignWorsening := false
		for _, candidate := range e.Candidates {
			if candidate.ID == d.CandidateID {
				entered = candidate.EnteredAt
				benignWorsening = d.Kind == "UPDATE" && candidate.Terminal != nil && candidate.Terminal.Action == "NONE"
			}
		}

		kind := ""
		if d.Kind == "TERMINAL" && d.Action == "INVESTIGATE" {
			kind = "OPEN"
		}
		if d.Kind == "UPDATE" && d.Action == "INVESTIGATE" {
			kind = "WORSEN"
		}
		if d.Kind == "RECOVER" {
			kind = "RECOVER"
		}
		if kind == "" {
			continue
		}
		var exists bool
		err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM production_notification_occurrences WHERE occurrence_id=$1 AND cluster_id=$2 AND enrollment_id=$3)`, d.CandidateID, c.ClusterID, c.RunID).Scan(&exists)
		if err != nil {
			return err
		}
		eligible := productionNotificationEligible(enabled, enabledAt, entered, d.LogicalAt, exists, benignWorsening)
		if !exists {
			if !eligible || kind == "RECOVER" {
				continue
			}
			// Worsening after a benign terminal is the first actionable event.
			// It opens the same physical occurrence, rather than disappearing.
			kind = "OPEN"
		}

		link := productionEvidenceURL(baseURL, c.ClusterID, c.RunID, d.CandidateID)
		if err = PublishProductionAssessment(ctx, tx, ProductionAssessmentEvent{EnrollmentID: c.RunID, ClusterID: c.ClusterID, SourceID: c.SourceID, Category: c.Category, Asset: asset.EntityKey, OccurrenceID: d.CandidateID, EventID: d.ID, Kind: kind, SuppressDelivery: !eligible, Summary: d.Summary, EvidenceURL: link, At: d.LogicalAt, Evidence: json.RawMessage(evidence)}); err != nil {
			return err
		}
	}
	var nextDue *time.Time
	for _, candidate := range e.Candidates {
		if candidate.Phase == "OBSERVING" && (nextDue == nil || candidate.DueAt.Before(*nextDue)) {
			at := candidate.DueAt
			nextDue = &at
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	snapshot, err := e.SnapshotProductionContext(ctx, asset.EntityKey, now)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	code := ""
	if !admit {
		code = "CAPACITY"
	}
	if len(e.Failures) > 0 {
		code = e.Failures[len(e.Failures)-1].Code
	}
	_, err = tx.Exec(ctx, `UPDATE production_assessment_states SET snapshot=$3,revision=revision+1,next_due_at=$4,last_attempt_at=clock_timestamp(),last_failure_code=$5,last_failure_at=CASE WHEN $5<>'' THEN clock_timestamp() ELSE last_failure_at END,failure_count=failure_count+CASE WHEN $5<>'' THEN 1 ELSE 0 END WHERE enrollment_id=$1 AND asset=$2`, c.RunID, asset.EntityKey, snapshot, nextDue, code)
	if err != nil {
		return err
	}
	stage, started, outcome = "production.commit", time.Now(), "unknown"
	return tx.Commit(ctx)
}

func productionEvidenceURL(baseURL, cluster, enrollment, occurrence string) string {
	if baseURL == "" {
		return ""
	}
	return strings.TrimRight(baseURL, "/") + "/admin/clusters/" + url.PathEscape(cluster) + "/assessment/" + url.PathEscape(enrollment) + "/" + occurrence
}
func (s *ProductionAssessmentStore) Cleanup(ctx context.Context) (count int, resultErr error) {
	started := time.Now()
	defer func() { resultErr = assessmentTransactionError("production.cleanup", started, resultErr, "unknown") }()
	if _, err := CleanupProductionNotifications(ctx, s.pool, s.config.Assessment.ClusterID, s.config.Assessment.RunID); err != nil {
		return 0, err
	}
	tag, err := s.pool.Exec(ctx, `DELETE FROM production_assessment_decisions WHERE event_id IN (SELECT d.event_id FROM production_assessment_decisions d WHERE d.enrollment_id=$1 AND d.closed_at<clock_timestamp()-interval '90 days' AND NOT EXISTS(SELECT 1 FROM production_notification_occurrences o WHERE o.occurrence_id=d.occurrence_id) ORDER BY d.closed_at,d.event_id LIMIT 100)`, s.config.Assessment.RunID)
	return int(tag.RowsAffected()), err
}

// SetProductionAssessmentNotifications changes delivery authority only. It does
// not reset candidates, collect data, or authorize a different scope/policy.
func SetProductionAssessmentNotifications(ctx context.Context, pool *pgxpool.Pool, cluster, enrollment string, expected int64, enabled bool, actor string) (int64, error) {
	if pool == nil || !a.ValidID(cluster, 128) || !a.ValidID(enrollment, 128) || !a.ValidID(actor, 128) || expected < 1 {
		return 0, a.ErrInvalid
	}
	tx, err := beginProductionAssessmentTx(ctx, pool)
	if err != nil {
		return 0, err
	}
	defer rollbackMonitoringTx(tx)
	var revision int64
	err = tx.QueryRow(ctx, `UPDATE production_assessment_enrollments SET revision=revision+1,notifications_enabled=$4,notifications_enabled_at=CASE WHEN $4 AND NOT notifications_enabled THEN clock_timestamp() ELSE notifications_enabled_at END,updated_at=clock_timestamp() WHERE cluster_id=$1 AND enrollment_id=$2 AND revision=$3 RETURNING revision`, cluster, enrollment, expected, enabled).Scan(&revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrMonitoringRevision
	}
	if err != nil {
		return 0, err
	}
	if err = FenceProductionNotifications(ctx, tx, cluster, enrollment); err != nil {
		return 0, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO production_assessment_controls(enrollment_id,revision,notifications_enabled,actor)VALUES($1,$2,$3,$4)`, enrollment, revision, enabled, actor)
	if err != nil {
		return 0, err
	}
	return revision, tx.Commit(ctx)
}

// CheckProductionAssessmentRole keeps the standalone production host out of
// workload execution, collection mutation and the restricted shadow ledger.
func CheckProductionAssessmentRole(ctx context.Context, pool *pgxpool.Pool) error {
	if pool == nil {
		return a.ErrInvalid
	}
	writes := []string{"production_assessment_enrollments", "production_assessment_states", "production_assessment_decisions", "production_assessment_controls", "production_notification_occurrences", "production_notification_events", "production_notification_intents", "production_notification_coverage", "production_notification_audit", "gp09_alert_outbox", "gp09_alert_delivery_attempts", "incidents", "incident_events", "evidence_envelopes", "incident_evidence"}
	var safe bool
	err := pool.QueryRow(ctx, productionAssessmentPrivileges, writes).Scan(&safe)
	if err != nil {
		return err
	}
	if !safe {
		return ErrAssessmentPrivileges
	}
	return nil
}

const productionAssessmentPrivileges = `
WITH session_roles AS(SELECT oid FROM pg_roles WHERE rolname IN(session_user,current_user) UNION SELECT usesysid FROM pg_stat_activity WHERE pid=pg_backend_pid()),
actors AS(SELECT r.oid FROM pg_roles r WHERE EXISTS(SELECT 1 FROM session_roles s WHERE r.oid=s.oid OR pg_has_role(s.oid,r.oid,'SET'))),
schemas AS(SELECT oid,nspowner FROM pg_namespace WHERE left(nspname,3)<>'pg_' AND nspname<>'information_schema'),
relations AS(SELECT c.oid,c.relname,c.relowner,n.oid AS namespace FROM pg_class c JOIN schemas n ON c.relnamespace=n.oid WHERE c.relkind IN('r','p','v','m','f'))
SELECT current_setting('session_replication_role')<>'replica'
AND NOT EXISTS(SELECT 1 FROM actors a JOIN pg_roles r ON pg_has_role(a.oid,r.oid,'USAGE') WHERE r.rolsuper OR r.rolbypassrls OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication OR left(r.rolname,3)='pg_')
AND NOT EXISTS(SELECT 1 FROM actors a CROSS JOIN schemas s WHERE has_schema_privilege(a.oid,s.oid,'CREATE') OR pg_has_role(a.oid,s.nspowner,'USAGE'))
AND NOT EXISTS(SELECT 1 FROM actors a WHERE has_database_privilege(a.oid,current_database(),'CREATE,TEMPORARY') OR has_parameter_privilege(a.oid,'session_replication_role','SET') OR EXISTS(SELECT 1 FROM pg_parameter_acl p WHERE has_parameter_privilege(a.oid,p.parname::text,'ALTER SYSTEM')))
AND NOT EXISTS(SELECT 1 FROM actors a CROSS JOIN relations r WHERE pg_has_role(a.oid,r.relowner,'USAGE') OR has_table_privilege(a.oid,r.oid,'TRUNCATE,REFERENCES,TRIGGER') OR has_any_column_privilege(a.oid,r.oid,'REFERENCES') OR (NOT(r.namespace='public'::regnamespace AND r.relname=ANY($1::text[])) AND (has_table_privilege(a.oid,r.oid,'INSERT,UPDATE,DELETE') OR has_any_column_privilege(a.oid,r.oid,'INSERT,UPDATE'))))
AND NOT EXISTS(SELECT 1 FROM actors a CROSS JOIN pg_proc p JOIN schemas s ON p.pronamespace=s.oid WHERE pg_has_role(a.oid,p.proowner,'USAGE') OR p.prosecdef AND has_function_privilege(a.oid,p.oid,'EXECUTE'))
AND NOT EXISTS(SELECT 1 FROM unnest($1::text[]) n(name) WHERE NOT has_table_privilege(current_user,'public.'||n.name,'SELECT'))
`

func beginProductionAssessmentTx(ctx context.Context, pool *pgxpool.Pool) (pgx.Tx, error) {
	started := time.Now()
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, assessmentTransactionError("begin", started, err, "not_attempted")
	}
	if _, err = tx.Exec(ctx, `SET LOCAL statement_timeout='200ms'; SET LOCAL lock_timeout='50ms'; SET LOCAL search_path=pg_catalog,public,pg_temp`); err != nil {
		rollbackMonitoringTx(tx)
		return nil, assessmentTransactionError("begin", started, err, "not_attempted")
	}
	return tx, nil
}

func productionNotificationEligible(enabled bool, enabledAt *time.Time, entered, eventAt time.Time, previouslyNotified, benignWorsening bool) bool {
	if !enabled || enabledAt == nil {
		return false
	}
	if previouslyNotified || benignWorsening {
		return !eventAt.IsZero() && !eventAt.Before(*enabledAt)
	}
	return !entered.IsZero() && !entered.Before(*enabledAt)
}

func (s *ProductionAssessmentStore) refreshOrder(ctx context.Context) ([]a.Asset, error) {
	rows, err := s.pool.Query(ctx, `SELECT asset FROM production_assessment_states WHERE enrollment_id=$1 ORDER BY CASE WHEN next_due_at<=clock_timestamp() THEN 0 ELSE 1 END,next_due_at NULLS LAST,last_attempt_at NULLS FIRST,asset LIMIT 9`, s.config.Assessment.RunID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []a.Asset{}
	for rows.Next() {
		var key string
		if err = rows.Scan(&key); err != nil {
			return nil, err
		}
		found := false
		for _, asset := range s.config.Assessment.Assets {
			if key == asset.EntityKey {
				out = append(out, asset)
				found = true
				break
			}
		}
		if !found || len(out) > 8 {
			return nil, a.ErrInvalid
		}
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	if len(out) != len(s.config.Assessment.Assets) {
		return nil, a.ErrInvalid
	}
	return out, nil
}
