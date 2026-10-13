//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/domain"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

// TestM15RestrictedRemediatorIdentity exercises the complete autonomous path
// with detector/controller/repair request ownership under the restricted role.
// The loopback collector fixture retains its ordinary test pool because result
// finalization is intentionally outside the remediator capability surface.
func TestM15RestrictedRemediatorIdentity(t *testing.T) {
	dsn := os.Getenv("SHERLOCK_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("SHERLOCK_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	m15ApplyRoleArtifact(t, ctx, admin)
	if _, err := admin.Exec(ctx, `GRANT SELECT (public_key_id) ON api_keys TO `+storepg.RestrictedRemediationRole); err != nil {
		t.Fatal(err)
	}
	m15ApplyRoleArtifact(t, ctx, admin)
	var staleColumnGrant bool
	if err := admin.QueryRow(ctx, `SELECT has_column_privilege($1,'api_keys','public_key_id','SELECT')`, storepg.RestrictedRemediationRole).Scan(&staleColumnGrant); err != nil || staleColumnGrant {
		t.Fatalf("role artifact did not clear stale capability column grant granted=%t err=%v", staleColumnGrant, err)
	}
	var installed bool
	if err = admin.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=$1)
		AND to_regprocedure('public.sherlock_m15_lock_live_effect_facts(text)') IS NOT NULL`, storepg.RestrictedRemediationRole).Scan(&installed); err != nil {
		t.Fatal(err)
	}
	if !installed {
		t.Fatal("M15 restricted database role artifact is not applied")
	}

	suffix := fmt.Sprintf("m15priv%d", time.Now().UnixNano())
	runtimeRole := suffix + "runtime"
	readerRole := suffix + "reader"
	escalationRole := suffix + "escalation"
	var runtimeDSN string
	runtimePassword := createRole(t, ctx, admin, runtimeRole)
	readerPassword := createRole(t, ctx, admin, readerRole)
	createRole(t, ctx, admin, escalationRole)
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), "DROP ROLE IF EXISTS "+pgx.Identifier{escalationRole}.Sanitize())
		_, _ = admin.Exec(context.Background(), "DROP ROLE IF EXISTS "+pgx.Identifier{runtimeRole}.Sanitize())
		_, _ = admin.Exec(context.Background(), "DROP ROLE IF EXISTS "+pgx.Identifier{readerRole}.Sanitize())
	})
	if _, err = admin.Exec(ctx, "GRANT "+pgx.Identifier{storepg.RestrictedRemediationRole}.Sanitize()+" TO "+pgx.Identifier{runtimeRole}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	if _, err = admin.Exec(ctx, "GRANT SELECT ON collection_jobs TO "+pgx.Identifier{readerRole}.Sanitize()); err != nil {
		t.Fatal(err)
	}

	var restricted *pgxpool.Pool
	m15RunRecovery(t, m15RecoveryHooks{
		SupervisorPool: func(t *testing.T, ctx context.Context, fixture *pgxpool.Pool, result m15RecoveryResult) (*pgxpool.Pool, error) {
			if _, err := fixture.Exec(ctx, `UPDATE remediation_policies SET max_forward_attempts=1 WHERE cluster_id=$1`, result.ClusterID); err != nil {
				return nil, err
			}
			if _, err := fixture.Exec(ctx, `INSERT INTO remediation_runtime_identity_scopes(login_role,cluster_id) VALUES($1,$2)`, runtimeRole, result.ClusterID); err != nil {
				return nil, err
			}
			if _, err := fixture.Exec(ctx, `INSERT INTO remediation_runtime_identity_jobs(login_role,cluster_id,job_id) VALUES($1,$2,$3)`, runtimeRole, result.ClusterID, result.JobID); err != nil {
				return nil, err
			}
			// A non-owner, non-remediator reader must retain its existing table
			// access; the RLS policy scopes only the fixed capability role.
			readerDSN, err := withDatabaseUser(dsn, readerRole, readerPassword)
			if err != nil {
				return nil, err
			}
			reader, err := pgxpool.New(ctx, readerDSN)
			if err != nil {
				return nil, err
			}
			defer reader.Close()
			var readerSession string
			if err := reader.QueryRow(ctx, `SELECT session_user`).Scan(&readerSession); err != nil || readerSession != readerRole {
				return nil, fmt.Errorf("reader fixture authentication identity=%q err=%v", readerSession, err)
			}
			var visible int
			err = reader.QueryRow(ctx, `SELECT count(*) FROM collection_jobs WHERE cluster_id=$1 AND job_id=$2`, result.ClusterID, result.JobID).Scan(&visible)
			if err != nil || visible != 1 {
				return nil, fmt.Errorf("ordinary reader lost existing access visible=%d err=%v", visible, err)
			}
			runtimeDSN, err = withDatabaseUser(dsn, runtimeRole, runtimePassword)
			if err != nil {
				return nil, err
			}
			restricted, err = storepg.NewRestrictedRemediationPool(ctx, runtimeDSN, result.ClusterID)
			return restricted, err
		},
		AfterVerification: func(t *testing.T, ctx context.Context, fixture *pgxpool.Pool, result m15RecoveryResult) {
			if restricted == nil {
				t.Fatal("restricted pool was not established")
			}
			assertM15PrivilegeDenials(t, ctx, fixture, restricted, result, runtimeDSN, runtimeRole, escalationRole)
		},
	})
	m15ApplyRoleArtifactFile(t, ctx, admin, "database-role-v1.down.sql")
	var roleRetained, stillGranted, jobColumnGranted, workColumnGranted bool
	if err := admin.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=$1),has_table_privilege($1,'remediation_runs','SELECT'),has_column_privilege($1,'collection_jobs','lease_owner','UPDATE'),has_column_privilege($1,'collector_work_items','status','UPDATE')`, storepg.RestrictedRemediationRole).Scan(&roleRetained, &stillGranted, &jobColumnGranted, &workColumnGranted); err != nil || !roleRetained || stillGranted || jobColumnGranted || workColumnGranted {
		t.Fatalf("role artifact rollback retained=%t table_grant=%t job_column=%t work_column=%t err=%v", roleRetained, stillGranted, jobColumnGranted, workColumnGranted, err)
	}
	m15ApplyRoleArtifact(t, ctx, admin)
}

func m15ApplyRoleArtifact(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	m15ApplyRoleArtifactFile(t, ctx, pool, "database-role-v1.up.sql")
}

func m15ApplyRoleArtifactFile(t *testing.T, ctx context.Context, pool *pgxpool.Pool, name string) {
	t.Helper()
	path := filepath.Join("..", "..", "..", "deploy", "m15", name)
	sql, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read M15 restricted role artifact: %v", err)
	}
	if _, err = pool.Exec(ctx, string(sql)); err != nil {
		t.Fatalf("apply M15 restricted role artifact: %v", err)
	}
}

func createRole(t *testing.T, ctx context.Context, pool *pgxpool.Pool, role string) string {
	t.Helper()
	// Each generated login must carry its own credential: production and local
	// PostgreSQL installations commonly require SCRAM over TCP, while an empty
	// password made this fixture depend on a trust-authenticated test server.
	password := "sherlock-test-" + role
	if _, err := pool.Exec(ctx, "CREATE ROLE "+pgx.Identifier{role}.Sanitize()+" LOGIN NOINHERIT PASSWORD '"+password+"' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS"); err != nil {
		t.Fatal(err)
	}
	return password
}

func withDatabaseUser(raw, user, password string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("test database URL is invalid")
	}
	u.User = url.UserPassword(user, password)
	return u.String(), nil
}

func assertM15PrivilegeDenials(t *testing.T, ctx context.Context, fixture, pool *pgxpool.Pool, result m15RecoveryResult, runtimeDSN, runtimeRole, escalationRole string) {
	t.Helper()
	denied := func(name, sql string) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql); err == nil {
			t.Fatalf("restricted remediator unexpectedly allowed %s", name)
		} else {
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
				t.Fatalf("restricted remediator %s error=%v, want PostgreSQL permission denial", name, err)
			}
		}
	}
	denied("API-key read", `SELECT * FROM api_keys LIMIT 1`)
	denied("identity-scope read", `SELECT * FROM remediation_runtime_identity_scopes LIMIT 1`)
	denied("policy mutation", `UPDATE remediation_policies SET enabled=false`)
	denied("collector identity mutation", `INSERT INTO collector_bootstrap_keys(bootstrap_key_id,cluster_id,token_hash,expires_at) VALUES('forbidden','forbidden',decode(repeat('00',32),'hex'),clock_timestamp())`)
	denied("arbitrary schema mutation", `CREATE TABLE public.m15_privilege_escape(x integer)`)
	denied("role escalation", "SET ROLE "+pgx.Identifier{escalationRole}.Sanitize())
	denied("unrelated cluster read", `SELECT * FROM clusters LIMIT 1`)
	otherCluster := "forbidden-" + string(result.ClusterID)
	otherSource := "forbidden-source-" + string(result.ClusterID)
	otherJob := "forbidden-job-" + string(result.ClusterID)
	if _, err := fixture.Exec(ctx, `INSERT INTO clusters(cluster_id,display_name) VALUES($1,'M15 unrelated scope')`, otherCluster); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.Exec(ctx, `INSERT INTO sources(source_id,cluster_id,kind,display_name) VALUES($1,$2,'prometheus','M15 unrelated source')`, otherSource, otherCluster); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.Exec(ctx, `INSERT INTO collection_jobs(job_id,cluster_id,source_id,query_kind,interval_seconds,next_run_at) VALUES($1,$2,$3,'gpu_utilization',60,clock_timestamp())`, otherJob, otherCluster, otherSource); err != nil {
		t.Fatal(err)
	}
	var fixtureRows int
	if err := fixture.QueryRow(ctx, `SELECT count(*) FROM collection_jobs WHERE cluster_id=$1 AND job_id=$2`, otherCluster, otherJob).Scan(&fixtureRows); err != nil || fixtureRows != 1 {
		t.Fatalf("privileged fixture did not create cross-scope job rows=%d err=%v", fixtureRows, err)
	}
	var crossScopeRows int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM collection_jobs WHERE cluster_id=$1 AND job_id=$2`, otherCluster, otherJob).Scan(&crossScopeRows); err != nil || crossScopeRows != 0 {
		t.Fatalf("restricted remediator cross-cluster visibility rows=%d err=%v", crossScopeRows, err)
	}
	changed, err := pool.Exec(ctx, `UPDATE collection_jobs SET lease_owner='forbidden' WHERE cluster_id=$1 AND job_id=$2`, otherCluster, otherJob)
	if err != nil || changed.RowsAffected() != 0 {
		t.Fatalf("restricted remediator cross-cluster write affected=%d err=%v", changed.RowsAffected(), err)
	}

	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	if _, err = conn.Exec(ctx, `RESET ROLE`); err != nil {
		t.Fatal(err)
	}
	if _, err = conn.Exec(ctx, `SELECT * FROM remediation_runs LIMIT 1`); err == nil {
		t.Fatal("RESET ROLE bypassed the restricted capability boundary")
	}
	if _, err = conn.Exec(ctx, "SET ROLE "+storepg.RestrictedRemediationRole); err != nil {
		t.Fatal(err)
	}
	var current, session string
	if err = conn.QueryRow(ctx, `SELECT current_user,session_user`).Scan(&current, &session); err != nil || current != storepg.RestrictedRemediationRole || strings.TrimSpace(session) == "" {
		t.Fatalf("restricted session identity was not restored")
	}

	assertM15RestrictedPoolRefusal(t, ctx, fixture, runtimeDSN, result.ClusterID,
		`GRANT SELECT ON api_keys TO PUBLIC`, `REVOKE SELECT ON api_keys FROM PUBLIC`, true)
	assertM15RestrictedPoolRefusal(t, ctx, fixture, runtimeDSN, result.ClusterID,
		`GRANT SELECT ON api_keys TO `+storepg.RestrictedRemediationRole, `REVOKE SELECT ON api_keys FROM `+storepg.RestrictedRemediationRole, false)
	assertM15RestrictedPoolRefusal(t, ctx, fixture, runtimeDSN, result.ClusterID,
		"GRANT SELECT (public_key_id) ON api_keys TO "+pgx.Identifier{runtimeRole}.Sanitize(),
		"REVOKE SELECT (public_key_id) ON api_keys FROM "+pgx.Identifier{runtimeRole}.Sanitize(), false)
	assertM15RestrictedPoolRefusal(t, ctx, fixture, runtimeDSN, result.ClusterID,
		"GRANT CREATE ON DATABASE "+pgx.Identifier{currentDatabase(t, ctx, fixture)}.Sanitize()+" TO "+pgx.Identifier{runtimeRole}.Sanitize(),
		"REVOKE CREATE ON DATABASE "+pgx.Identifier{currentDatabase(t, ctx, fixture)}.Sanitize()+" FROM "+pgx.Identifier{runtimeRole}.Sanitize(), false)

	extraRole := "m15privextra" + fmt.Sprint(time.Now().UnixNano())
	createRole(t, ctx, fixture, extraRole)
	assertM15RestrictedPoolRefusal(t, ctx, fixture, runtimeDSN, result.ClusterID,
		"GRANT "+pgx.Identifier{extraRole}.Sanitize()+" TO "+pgx.Identifier{runtimeRole}.Sanitize(),
		"REVOKE "+pgx.Identifier{extraRole}.Sanitize()+" FROM "+pgx.Identifier{runtimeRole}.Sanitize(), false)
	if _, err := fixture.Exec(ctx, "DROP ROLE "+pgx.Identifier{extraRole}.Sanitize()); err != nil {
		t.Fatal(err)
	}

	ownedTable := "m15_privilege_owned_" + fmt.Sprint(time.Now().UnixNano())
	if _, err := fixture.Exec(ctx, "CREATE TABLE public."+pgx.Identifier{ownedTable}.Sanitize()+"(value integer)"); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.Exec(ctx, "ALTER TABLE public."+pgx.Identifier{ownedTable}.Sanitize()+" OWNER TO "+pgx.Identifier{storepg.RestrictedRemediationRole}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	assertM15RestrictedPoolRefusal(t, ctx, fixture, runtimeDSN, result.ClusterID, "SELECT 1", "ALTER TABLE public."+pgx.Identifier{ownedTable}.Sanitize()+" OWNER TO CURRENT_USER", false)
	if _, err := fixture.Exec(ctx, "DROP TABLE public."+pgx.Identifier{ownedTable}.Sanitize()); err != nil {
		t.Fatal(err)
	}
}

// assertM15RestrictedPoolRefusal temporarily creates a real SQL escape
// condition, proves a new physical runtime connection fails closed, then
// restores it before the autonomous fixture proceeds to other checks.
func assertM15RestrictedPoolRefusal(t *testing.T, ctx context.Context, fixture *pgxpool.Pool, runtimeDSN string, cluster domain.ClusterID, grant, revoke string, verifyArtifact bool) {
	t.Helper()
	if _, err := fixture.Exec(ctx, grant); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = fixture.Exec(context.Background(), revoke) }()
	if candidate, err := storepg.NewRestrictedRemediationPool(ctx, runtimeDSN, cluster); err == nil {
		candidate.Close()
		t.Fatal("restricted pool accepted an unsafe database identity")
	}
	if verifyArtifact {
		m15RoleArtifactMustFail(t, ctx, fixture, "database-role-v1.up.sql")
	}
	if _, err := fixture.Exec(ctx, revoke); err != nil {
		t.Fatal(err)
	}
}

func currentDatabase(t *testing.T, ctx context.Context, pool *pgxpool.Pool) string {
	t.Helper()
	var database string
	if err := pool.QueryRow(ctx, `SELECT current_database()`).Scan(&database); err != nil {
		t.Fatal(err)
	}
	return database
}

func m15RoleArtifactMustFail(t *testing.T, ctx context.Context, pool *pgxpool.Pool, name string) {
	t.Helper()
	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	path := filepath.Join("..", "..", "..", "deploy", "m15", name)
	sql, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, string(sql)); err == nil {
		t.Fatal("M15 role artifact accepted an unsafe database grant")
	}
	if _, err := conn.Exec(ctx, `ROLLBACK`); err != nil {
		t.Fatal(err)
	}
}
