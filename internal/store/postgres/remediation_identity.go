package postgres

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

// RestrictedRemediationRole is the only capability role accepted by the M15
// remediator. Deployment creates LOGIN NOINHERIT identities separately; this
// package never creates roles, accepts a role name, or logs a database URL.
const RestrictedRemediationRole = "sherlock_m15_remediator_v1"

// NewRestrictedRemediationPool establishes the M15 runtime capability boundary.
// Every physical connection explicitly enters the fixed NOLOGIN role and proves
// that its session_user has an immutable deployment-owned scope mapping. Errors
// are intentionally generic so a failed connection cannot disclose a DSN,
// account name, relation, or policy detail in service logs.
func NewRestrictedRemediationPool(ctx context.Context, databaseURL string, cluster domain.ClusterID) (*pgxpool.Pool, error) {
	if strings.TrimSpace(databaseURL) == "" || cluster == "" {
		return nil, fmt.Errorf("restricted remediation database configuration is required")
	}
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("restricted remediation database configuration is invalid")
	}
	// The remediator must fail closed during startup rather than indefinitely
	// occupying an orchestrator restart slot on an unreachable database.
	if config.ConnConfig.ConnectTimeout == 0 || config.ConnConfig.ConnectTimeout > 5*time.Second {
		config.ConnConfig.ConnectTimeout = 5 * time.Second
	}
	if config.MaxConns < 1 || config.MaxConns > 8 {
		config.MaxConns = 8
	}
	config.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		if _, err := conn.Exec(ctx, "SET ROLE "+RestrictedRemediationRole); err != nil {
			return fmt.Errorf("restricted remediation identity is unavailable")
		}
		if err := validateRestrictedRemediationIdentity(ctx, conn); err != nil {
			return err
		}
		if _, err := conn.Exec(ctx, `SET search_path = pg_catalog, public, pg_temp`); err != nil {
			return fmt.Errorf("restricted remediation identity is unavailable")
		}
		var scoped bool
		if err := conn.QueryRow(ctx, `SELECT public.sherlock_m15_runtime_scope_allows($1, NULL)`, cluster).Scan(&scoped); err != nil || !scoped {
			return fmt.Errorf("restricted remediation identity is not scoped")
		}
		return nil
	}
	connectCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	pool, err := pgxpool.NewWithConfig(connectCtx, config)
	if err != nil {
		return nil, fmt.Errorf("restricted remediation identity is unavailable")
	}
	if err := pool.Ping(connectCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("restricted remediation identity is unavailable")
	}
	return pool, nil
}

func validateRestrictedRemediationIdentity(ctx context.Context, conn *pgx.Conn) error {
	var valid bool
	err := conn.QueryRow(ctx, `
WITH RECURSIVE membership(role_oid) AS (
    SELECT m.roleid FROM pg_auth_members m WHERE m.member=(SELECT oid FROM pg_roles WHERE rolname=session_user)
    UNION
    SELECT m.roleid FROM pg_auth_members m JOIN membership x ON m.member=x.role_oid
), direct_grants AS (
    SELECT 1 FROM pg_class c CROSS JOIN LATERAL aclexplode(c.relacl) a WHERE a.grantee=(SELECT oid FROM pg_roles WHERE rolname=session_user)
    UNION ALL SELECT 1 FROM pg_attribute a CROSS JOIN LATERAL aclexplode(a.attacl) x WHERE a.attnum>0 AND NOT a.attisdropped AND x.grantee=(SELECT oid FROM pg_roles WHERE rolname=session_user)
    UNION ALL SELECT 1 FROM pg_proc p CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee=(SELECT oid FROM pg_roles WHERE rolname=session_user)
    UNION ALL SELECT 1 FROM pg_namespace n CROSS JOIN LATERAL aclexplode(coalesce(n.nspacl,acldefault('n',n.nspowner))) a WHERE a.grantee=(SELECT oid FROM pg_roles WHERE rolname=session_user)
	UNION ALL SELECT 1 FROM pg_database d CROSS JOIN LATERAL aclexplode(coalesce(d.datacl,acldefault('d',d.datdba))) a WHERE a.grantee=(SELECT oid FROM pg_roles WHERE rolname=session_user)
), public_application_grants AS (
    SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace CROSS JOIN LATERAL aclexplode(c.relacl) a WHERE n.nspname='public' AND a.grantee=0 AND c.relkind IN ('r','p','v','m','S')
    UNION ALL SELECT 1 FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace CROSS JOIN LATERAL aclexplode(a.attacl) x WHERE n.nspname='public' AND x.grantee=0 AND a.attnum>0 AND NOT a.attisdropped
), ownership AS (
    SELECT 1 FROM pg_class WHERE relowner=(SELECT oid FROM pg_roles WHERE rolname=session_user)
    UNION ALL SELECT 1 FROM pg_proc WHERE proowner=(SELECT oid FROM pg_roles WHERE rolname=session_user)
    UNION ALL SELECT 1 FROM pg_namespace WHERE nspowner=(SELECT oid FROM pg_roles WHERE rolname=session_user)
), capability_ownership AS (
    SELECT 1 FROM pg_class WHERE relowner=(SELECT oid FROM pg_roles WHERE rolname=$1)
    UNION ALL SELECT 1 FROM pg_proc WHERE proowner=(SELECT oid FROM pg_roles WHERE rolname=$1)
    UNION ALL SELECT 1 FROM pg_namespace WHERE nspowner=(SELECT oid FROM pg_roles WHERE rolname=$1)
), capability_table_grants AS (
    -- Every capability-granted application relation has a restrictive RLS
    -- policy targeted to this fixed role. A direct grant to an unrelated
    -- table (for example api_keys) therefore fails startup even if it was
    -- introduced outside the deployment artifact.
    SELECT 1
    FROM pg_class c
    JOIN pg_namespace n ON n.oid=c.relnamespace
    CROSS JOIN LATERAL aclexplode(c.relacl) x
    WHERE n.nspname='public' AND c.relkind IN ('r','p','v','m','S')
      AND x.grantee=(SELECT oid FROM pg_roles WHERE rolname=$1)
      AND NOT EXISTS (
          SELECT 1 FROM pg_policy p
          WHERE p.polrelid=c.oid AND NOT p.polpermissive
            AND (SELECT oid FROM pg_roles WHERE rolname=$1)=ANY(p.polroles)
      )
), capability_column_grants AS (
    SELECT 1
    FROM pg_attribute a
    JOIN pg_class c ON c.oid=a.attrelid
    JOIN pg_namespace n ON n.oid=c.relnamespace
    CROSS JOIN LATERAL aclexplode(a.attacl) x
    WHERE n.nspname='public' AND a.attnum>0 AND NOT a.attisdropped
      AND x.grantee=(SELECT oid FROM pg_roles WHERE rolname=$1)
      AND NOT (
          (c.relname='collection_jobs' AND a.attname='lease_owner' AND x.privilege_type='UPDATE')
          OR (c.relname='collector_work_items' AND a.attname IN ('status','completed_at') AND x.privilege_type='UPDATE')
      )
), runtime_work_guard AS (
    SELECT to_regprocedure('public.sherlock_m15_mark_runtime_work()') IS NOT NULL
       AND to_regprocedure('public.sherlock_m15_guard_runtime_work()') IS NOT NULL
       AND EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid='public.collector_work_items'::regclass AND attname='remediation_runtime_managed' AND NOT attisdropped)
       AND EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid='public.collector_work_items'::regclass AND tgname='sherlock_m15_mark_runtime_work' AND NOT tgisinternal)
       AND EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid='public.collector_work_items'::regclass AND tgname='sherlock_m15_guard_runtime_work' AND NOT tgisinternal AND tgconstraint<>0 AND tgdeferrable AND tginitdeferred) AS installed
)
SELECT current_user=$1
   AND session_user<>$1
   AND EXISTS (SELECT 1 FROM pg_roles r WHERE r.rolname=session_user AND NOT r.rolsuper AND NOT r.rolcreaterole AND NOT r.rolcreatedb AND NOT r.rolreplication AND NOT r.rolbypassrls AND NOT r.rolinherit)
   AND EXISTS (SELECT 1 FROM pg_roles r WHERE r.rolname=$1 AND NOT r.rolcanlogin AND NOT r.rolsuper AND NOT r.rolcreaterole AND NOT r.rolcreatedb AND NOT r.rolreplication AND NOT r.rolbypassrls AND NOT r.rolinherit)
   AND EXISTS (SELECT 1 FROM membership m JOIN pg_roles r ON r.oid=m.role_oid WHERE r.rolname=$1)
   AND NOT EXISTS (SELECT 1 FROM membership m JOIN pg_roles r ON r.oid=m.role_oid WHERE r.rolname<>$1)
   AND NOT EXISTS (SELECT 1 FROM pg_auth_members m WHERE m.member=(SELECT oid FROM pg_roles WHERE rolname=$1))
   AND NOT EXISTS (SELECT 1 FROM direct_grants)
   AND NOT EXISTS (SELECT 1 FROM public_application_grants)
   AND NOT EXISTS (SELECT 1 FROM ownership)
   AND NOT EXISTS (SELECT 1 FROM capability_ownership)
   AND NOT EXISTS (SELECT 1 FROM capability_table_grants)
   AND NOT EXISTS (SELECT 1 FROM capability_column_grants)
   AND NOT has_database_privilege(session_user, current_database(), 'CREATE')
   AND NOT has_database_privilege($1, current_database(), 'CREATE')
   AND (SELECT installed FROM runtime_work_guard)`, RestrictedRemediationRole).Scan(&valid)
	if err != nil || !valid {
		return fmt.Errorf("restricted remediation identity is invalid")
	}
	return nil
}
