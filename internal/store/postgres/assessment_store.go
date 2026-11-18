package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	a "github.com/verticalcomputer/sherlock/internal/alertassessment"
)

var ErrAssessmentPrivileges = errors.New("assessment database privileges are not restricted")
var ErrAssessmentRunBusy = errors.New("RUN_BUSY")
var ErrAssessmentCapacity = errors.New("CAPACITY")
var errAssessmentUnsupportedVersion = errors.New("UNSUPPORTED_VERSION")
var errAssessmentRunClosed = errors.New("RUN_CLOSED")

const (
	assessmentNotStarted uint32 = iota
	assessmentStarted
	assessmentRetentionOnly
)

type AssessmentStore struct {
	pool           *pgxpool.Pool
	registry       *a.Registry
	config         a.Config
	buildHash      string
	recoveryOnly   bool
	lifecycle      atomic.Uint32
	observeGPU     func(asset string, elapsed time.Duration)
	failureMu      sync.Mutex
	pendingFailure *assessmentPendingFailure
}

func NewAssessmentStore(ctx context.Context, pool *pgxpool.Pool, registry *a.Registry, c a.Config, buildID string) (*AssessmentStore, error) {
	if pool == nil || registry == nil {
		return nil, a.ErrInvalid
	}
	normalized, err := a.NormalizeConfig(ctx, c, registry)
	sum := sha256.Sum256([]byte(buildID))
	s := &AssessmentStore{pool: pool, registry: registry, config: normalized, buildHash: hex.EncodeToString(sum[:])}
	if preflightErr := s.Preflight(ctx); preflightErr != nil {
		return nil, preflightErr
	}
	if err != nil {
		// Recovery is available only for an already admitted matching run. It
		// never substitutes a codec or admits a replacement config.
		if !a.ValidID(c.RunID, 128) {
			return nil, err
		}
		if recoverErr := s.matchRecoveryConfig(ctx, c); recoverErr != nil {
			return nil, recoverErr
		}
	}
	return s, nil
}

func (s *AssessmentStore) matchRecoveryConfig(ctx context.Context, c a.Config) error {
	var body, descriptor []byte
	var configHash, descriptorHash string
	var inputConfigHash *string
	err := s.pool.QueryRow(ctx, `SELECT config,descriptor,config_hash,descriptor_hash,input_config_hash FROM public.assessment_runs WHERE run_id=$1 AND mode='shadow'`, c.RunID).Scan(&body, &descriptor, &configHash, &descriptorHash, &inputConfigHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return errAssessmentUnsupportedVersion
	}
	if err != nil {
		return err
	}
	var stored a.Config
	if err := a.DecodeStrict(body, &stored, 64<<10); err != nil {
		return err
	}
	pinned, err := matchedAssessmentDescriptor(stored, body, descriptor, configHash, descriptorHash)
	if err != nil {
		return err
	}
	normalized, err := a.NormalizeRecoveryConfig(c, pinned)
	if err != nil {
		return err
	}
	if !assessmentConfigMatches(normalized, body, configHash) {
		submittedHash, err := normalized.InputConfigHash()
		if err != nil || inputConfigHash == nil || submittedHash != *inputConfigHash {
			return ErrAssessmentRunBusy
		}
	}
	// The stored canonical config is authority in either recovery path.
	normalized, err = a.NormalizeRecoveryConfig(stored, pinned)
	if err != nil {
		return err
	}
	s.config, s.recoveryOnly = normalized, true
	return nil
}

func assessmentConfigMatches(c a.Config, body []byte, configHash string) bool {
	canonical, err := a.Canonical(c)
	return err == nil && len(canonical) <= 64<<10 && bytes.Equal(canonical, body) && a.Hash("config", c.Category, 1, body) == configHash
}

func matchedAssessmentDescriptor(c a.Config, body, descriptor []byte, configHash, descriptorHash string) (a.Descriptor, error) {
	if !assessmentConfigMatches(c, body, configHash) {
		return a.Descriptor{}, ErrAssessmentRunBusy
	}
	var pinned a.Descriptor
	if err := a.DecodeStrict(descriptor, &pinned, 16<<10); err != nil {
		return a.Descriptor{}, a.ErrInvalid
	}
	canonical, err := a.Canonical(pinned)
	if err != nil || !bytes.Equal(canonical, descriptor) || a.Hash("descriptor", c.Category, 1, descriptor) != descriptorHash ||
		pinned.Category != c.Category || pinned.Implementation != c.Implementation || pinned.Contract != c.Contract {
		return a.Descriptor{}, a.ErrInvalid
	}
	return pinned, nil
}

var assessmentTables = []string{"assessment_runs", "assessment_enrollments", "assessment_facts", "assessment_bundles", "assessment_candidates", "assessment_decisions", "assessment_failures"}
var assessmentReadTables = []string{"desired_schedules", "collection_jobs", "collection_runs", "collection_run_jobs", "collector_work_items", "durable_schedule_occurrences", "durable_schedule_executions", "collector_result_ingestions", "goodput_inventory_revisions", "goodput_inventory_revision_entities", "observations"}
var assessmentReadColumns = map[string][]string{
	"clusters": {"cluster_id", "removed_at"}, "sources": {"cluster_id", "source_id", "kind"},
	"gp09_monitor_enrollments": {"policy_id", "cluster_id", "source_id", "entity_key", "rule_id", "rule_version", "operation", "scope_key", "enrollment_revision", "policy", "enabled"},
	"gp09_monitor_episodes":    {"cluster_id", "policy_id", "enrollment_revision", "occurrence", "severity", "opened_at", "closed_at"},
	"gp09_monitor_transitions": {"cluster_id", "policy_id", "occurrence", "transition", "occurred_at", "reason", "qualifying_sample_count", "omitted_evidence_count", "snapshot"},
}

var assessmentRoutines = []string{
	"public.assessment_sorted_set(text[],integer)", "public.assessment_guard()", "public.assessment_references()",
	"public.assessment_row_bytes(text,jsonb)", "public.assessment_account()", "public.assessment_sample_source(bytea)",
	"public.assessment_account_fact_insert()",
}

// Preflight checks positive grants for the effective user and negative grants
// also for the login and every role it can select, even without inheritance.
func (s *AssessmentStore) Preflight(ctx context.Context) error {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return err
	}
	defer rollbackMonitoringTx(tx)
	if _, err := tx.Exec(ctx, `SET LOCAL search_path = pg_catalog, public, pg_temp`); err != nil {
		return err
	}
	var tableNames, columnNames []string
	for table, columns := range assessmentReadColumns {
		for _, column := range columns {
			tableNames, columnNames = append(tableNames, table), append(columnNames, column)
		}
	}
	var allowed bool
	if err := tx.QueryRow(ctx, assessmentPreflightSQL, assessmentTables, assessmentReadTables, tableNames, columnNames, assessmentRoutines).Scan(&allowed); err != nil {
		return err
	}
	if !allowed {
		return ErrAssessmentPrivileges
	}
	return tx.Commit(ctx)
}

const assessmentPreflightSQL = `
WITH session_roles AS (
    SELECT oid FROM pg_roles WHERE rolname IN (session_user,current_user)
    UNION SELECT usesysid FROM pg_stat_activity WHERE pid=pg_backend_pid()
), actors AS MATERIALIZED (
    SELECT r.oid FROM pg_roles r
    WHERE EXISTS (SELECT 1 FROM session_roles s WHERE r.oid=s.oid OR
      CASE WHEN current_setting('server_version_num')::int >= 160000
      THEN pg_has_role(s.oid,r.oid,'SET') ELSE pg_has_role(s.oid,r.oid,'MEMBER') END)
), application_schemas AS MATERIALIZED (
    SELECT oid,nspname,nspowner FROM pg_namespace
    WHERE left(nspname,3)<>'pg_' AND nspname<>'information_schema'
), columns_allowed AS MATERIALIZED (
    SELECT * FROM unnest($3::text[],$4::text[]) AS names(relname,attname)
), routines_allowed AS MATERIALIZED (
    SELECT to_regprocedure(signature)::oid AS oid FROM unnest($5::text[]) AS names(signature)
), relations AS MATERIALIZED (
    SELECT c.oid,c.relname,c.relowner,
           n.nspname='public' AND c.relkind IN ('r','p') AND c.relname=ANY($1::text[]) AS stored,
           n.nspname='public' AND (
               c.relkind IN ('r','p') AND c.relname=ANY($2::text[]) OR
               c.relkind='v' AND c.relname='assessment_edges' AND 'security_invoker=true'=ANY(c.reloptions)
           ) IS TRUE AS read_all,
           n.nspname='public' AND c.relkind IN ('r','p') AS public_table
    FROM pg_class c JOIN application_schemas n ON n.oid=c.relnamespace
    WHERE c.relkind IN ('r','p','v','m','f')
)
SELECT has_database_privilege(current_database(),'CONNECT') AND has_schema_privilege('public','USAGE')
AND current_setting('session_replication_role')<>'replica'
-- Effective system capabilities cannot be delegated to the assessment login.
AND NOT EXISTS (
    SELECT 1 FROM actors a JOIN pg_roles r ON pg_has_role(a.oid,r.oid,'USAGE')
    WHERE r.rolsuper OR r.rolbypassrls OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication OR left(r.rolname,3)='pg_'
)
AND NOT EXISTS (
    SELECT 1 FROM actors a CROSS JOIN application_schemas n
    WHERE has_schema_privilege(a.oid,n.oid,'CREATE') OR pg_has_role(a.oid,n.nspowner,'USAGE')
)
AND NOT EXISTS (SELECT 1 FROM actors a WHERE has_database_privilege(a.oid,current_database(),'CREATE,TEMPORARY'))
AND NOT EXISTS (
    SELECT 1 FROM actors a WHERE has_parameter_privilege(a.oid,'session_replication_role','SET')
       OR EXISTS (SELECT 1 FROM pg_parameter_acl p WHERE has_parameter_privilege(a.oid,p.parname::text,'ALTER SYSTEM'))
)
-- Every expected table, invoker view and permitted column must exist and be readable.
AND NOT EXISTS (
    SELECT 1 FROM unnest($1::text[] || $2::text[] || ARRAY['assessment_edges']) AS expected(relname)
    WHERE NOT EXISTS (
        SELECT 1 FROM relations r WHERE r.relname=expected.relname
          AND (r.stored OR r.read_all) AND has_table_privilege(r.oid,'SELECT')
          AND (NOT r.stored OR has_table_privilege(r.oid,'INSERT') AND has_table_privilege(r.oid,'UPDATE') AND has_table_privilege(r.oid,'DELETE'))
    )
)
AND NOT EXISTS (
    SELECT 1 FROM columns_allowed ca WHERE NOT EXISTS (
        SELECT 1 FROM relations r JOIN pg_attribute c ON c.attrelid=r.oid AND c.attnum>0 AND NOT c.attisdropped
        WHERE r.public_table AND r.relname=ca.relname AND c.attname=ca.attname AND has_column_privilege(r.oid,c.attnum,'SELECT')
    )
)
-- Column mutation grants are forbidden even on the table-wide read allow-list.
AND NOT EXISTS (
    SELECT 1 FROM actors a CROSS JOIN relations r
    WHERE pg_has_role(a.oid,r.relowner,'USAGE')
       OR has_table_privilege(a.oid,r.oid,'TRUNCATE,REFERENCES,TRIGGER')
       OR has_any_column_privilege(a.oid,r.oid,'REFERENCES')
       OR CASE WHEN current_setting('server_version_num')::int >= 170000 THEN has_table_privilege(a.oid,r.oid,'MAINTAIN') ELSE false END
       OR NOT r.stored AND (has_table_privilege(a.oid,r.oid,'INSERT,UPDATE,DELETE') OR has_any_column_privilege(a.oid,r.oid,'INSERT,UPDATE'))
       OR NOT (r.stored OR r.read_all) AND has_table_privilege(a.oid,r.oid,'SELECT')
       OR NOT (r.stored OR r.read_all) AND EXISTS (
           SELECT 1 FROM pg_attribute c WHERE c.attrelid=r.oid AND c.attnum>0 AND NOT c.attisdropped AND has_column_privilege(a.oid,r.oid,c.attnum,'SELECT')
             AND NOT (r.public_table AND EXISTS (SELECT 1 FROM columns_allowed ca WHERE ca.relname=r.relname AND ca.attname=c.attname))
       )
)
AND NOT EXISTS (
    SELECT 1 FROM actors a CROSS JOIN pg_class c JOIN application_schemas n ON n.oid=c.relnamespace
    WHERE c.relkind='S' AND (has_sequence_privilege(a.oid,c.oid,'USAGE,SELECT,UPDATE') OR pg_has_role(a.oid,c.relowner,'USAGE'))
)
-- Resolve exact qualified signatures. A missing routine or SECURITY DEFINER
-- replacement cannot satisfy the required validator grants.
AND NOT EXISTS (
    SELECT 1 FROM routines_allowed expected WHERE NOT EXISTS (
        SELECT 1 FROM pg_proc p WHERE p.oid=expected.oid AND p.prokind='f' AND NOT p.prosecdef AND has_function_privilege(p.oid,'EXECUTE')
    )
)
AND NOT EXISTS (
    SELECT 1 FROM actors a CROSS JOIN pg_proc p JOIN application_schemas n ON n.oid=p.pronamespace
    WHERE pg_has_role(a.oid,p.proowner,'USAGE') OR has_function_privilege(a.oid,p.oid,'EXECUTE')
      AND (p.prosecdef OR NOT EXISTS (SELECT 1 FROM routines_allowed expected WHERE expected.oid=p.oid))
)
`

func beginAssessmentTx(ctx context.Context, pool *pgxpool.Pool) (pgx.Tx, error) {
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		return nil, err
	}
	if _, err = tx.Exec(ctx, `SET LOCAL statement_timeout='200ms'; SET LOCAL lock_timeout='50ms'; SET LOCAL search_path = pg_catalog, public, pg_temp`); err != nil {
		rollbackMonitoringTx(tx)
		return nil, err
	}
	return tx, nil
}

// Start opens assessment work once per store. A matching retained CLOSED run
// starts retention only.
func (s *AssessmentStore) Start(ctx context.Context) error {
	if s.lifecycle.Load() != assessmentNotStarted {
		return nil
	}
	wantHash, err := s.config.Hash()
	if err != nil {
		return err
	}
	// No row is available to lock before the first start. Let the unique run
	// constraints choose the winner, then reload under a fresh snapshot.
	const attempts = 3
	for range attempts {
		err = s.start(ctx, wantHash)
		if err == nil {
			s.lifecycle.CompareAndSwap(assessmentNotStarted, assessmentStarted)
			return nil
		}
		if !retryableAssessmentStart(err) || ctx.Err() != nil {
			return err
		}
	}
	return err
}

func retryableAssessmentStart(err error) bool {
	var failure *pgconn.PgError
	if !errors.As(err, &failure) {
		return false
	}
	switch failure.Code {
	case "40001", "55P03": // Serialization failure or bounded row/index lock.
		return true
	case "23505":
		return failure.ConstraintName == "assessment_runs_pkey" || failure.ConstraintName == "assessment_one_open_run"
	default:
		return false
	}
}

func (s *AssessmentStore) start(ctx context.Context, wantHash string) error {
	tx, err := beginAssessmentTx(ctx, s.pool)
	if err != nil {
		return err
	}
	defer rollbackMonitoringTx(tx)
	var id, hash, descriptorHash, mode, state string
	var pinnedConfig, pinnedDescriptor []byte
	err = tx.QueryRow(ctx, `SELECT run_id,config_hash,descriptor_hash,mode,state,config,descriptor FROM assessment_runs WHERE state<>'CLOSED' FOR UPDATE`).Scan(&id, &hash, &descriptorHash, &mode, &state, &pinnedConfig, &pinnedDescriptor)
	if err == nil {
		if id != s.config.RunID || hash != wantHash || mode != "shadow" {
			return ErrAssessmentRunBusy
		}
		pinned, err := matchedAssessmentDescriptor(s.config, pinnedConfig, pinnedDescriptor, hash, descriptorHash)
		if err != nil {
			return err
		}
		_, _, installedHash, lookupErr := s.registry.LookupVersion(s.config.Category, s.config.Implementation)
		if (s.recoveryOnly || lookupErr != nil || installedHash != descriptorHash) && state == "ACTIVE" {
			if _, err := a.NormalizeRecoveryConfig(s.config, pinned); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE assessment_runs SET state='DRAINING',stopped_at=least(admission_end_at,clock_timestamp()),stop_reason='UNSUPPORTED_VERSION' WHERE run_id=$1`, id); err != nil {
				return err
			}
		}
		return tx.Commit(ctx)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	err = tx.QueryRow(ctx, `SELECT config,config_hash,descriptor,descriptor_hash,mode FROM assessment_runs WHERE run_id=$1 AND state='CLOSED'`, s.config.RunID).Scan(&pinnedConfig, &hash, &pinnedDescriptor, &descriptorHash, &mode)
	if err == nil {
		if mode != "shadow" {
			return ErrAssessmentRunBusy
		}
		if _, err := matchedAssessmentDescriptor(s.config, pinnedConfig, pinnedDescriptor, hash, descriptorHash); err != nil {
			return err
		}
		return s.commitAssessmentRetention(ctx, tx)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if s.recoveryOnly {
		return errAssessmentUnsupportedVersion
	}
	var now time.Time
	if err = tx.QueryRow(ctx, `SELECT transaction_timestamp()`).Scan(&now); err != nil {
		return err
	}
	for _, asset := range s.config.Assets {
		for _, binding := range s.config.Bindings {
			if _, err = validateAssessmentAuthority(ctx, tx, s.config, asset, binding, now); err != nil {
				return err
			}
		}
	}
	c, err := a.Canonical(s.config)
	if err != nil {
		return err
	}
	_, desc, dh, err := s.registry.LookupVersion(s.config.Category, s.config.Implementation)
	if err != nil {
		return err
	}
	d, err := a.Canonical(desc)
	if err != nil {
		return err
	}
	inputHash, err := s.config.InputConfigHash()
	if err != nil {
		return err
	}
	end := now.Add(time.Duration(s.config.RunDurationSeconds) * time.Second)
	if _, err = tx.Exec(ctx, `INSERT INTO assessment_runs(run_id,config,config_hash,input_config_hash,descriptor,descriptor_hash,build_hash,mode,state,start_at,admission_end_at) VALUES($1,$2,$3,$4,$5,$6,$7,'shadow','ACTIVE',$8,$9)`, s.config.RunID, c, wantHash, inputHash, d, dh, s.buildHash, now, end); err != nil {
		return err
	}
	bindings, err := a.Canonical(s.config.Bindings)
	if err != nil {
		return err
	}
	for _, asset := range s.config.Assets {
		if _, err = tx.Exec(ctx, `INSERT INTO assessment_enrollments(run_id,category,asset,node_id,gpu_uuid,inventory_revision,bindings,discovery_floor,next_due_at,sequence,revision,rearm_eligible) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$8,0,1,true)`, s.config.RunID, s.config.Category, asset.EntityKey, asset.NodeID, asset.GPUUUID, s.config.InventoryRevision, bindings, now); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (s *AssessmentStore) commitAssessmentRetention(ctx context.Context, tx pgx.Tx) error {
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	// Cleanup can remove the run row. This store stays in retention mode
	// for its remaining lifetime, even when that row no longer exists.
	s.lifecycle.Store(assessmentRetentionOnly)
	return nil
}
