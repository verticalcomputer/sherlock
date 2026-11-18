//go:build integration

package postgres

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestAssessmentIsolationEffectiveRoleAndExactObjects(t *testing.T) {
	f := newAssessmentFixture(t)
	ctx := context.Background()
	pool := f.restrictedPool(t)
	store := &AssessmentStore{pool: pool}
	role := pgx.Identifier{f.role}.Sanitize()
	database := pgx.Identifier{f.admin.Config().ConnConfig.Database}.Sanitize()
	assertAllowed := func(t *testing.T) {
		t.Helper()
		if err := store.Preflight(ctx); err != nil {
			t.Fatalf("approved login failed preflight: %v", err)
		}
	}
	assertDenied := func(t *testing.T, target *AssessmentStore) {
		t.Helper()
		if err := target.Preflight(ctx); !errors.Is(err, ErrAssessmentPrivileges) {
			t.Fatalf("preflight error = %v, want privilege rejection", err)
		}
	}
	assertAllowed(t)

	for _, tc := range []struct{ name, change, restore string }{
		{"column mutation of readable table", "GRANT UPDATE(entity_key) ON public.observations TO " + role, "REVOKE UPDATE(entity_key) ON public.observations FROM " + role},
		{"new table privilege", "GRANT MAINTAIN ON public.observations TO " + role, "REVOKE MAINTAIN ON public.observations FROM " + role},
		{"temporary object creation", "GRANT TEMPORARY ON DATABASE " + database + " TO " + role, "REVOKE TEMPORARY ON DATABASE " + database + " FROM " + role},
		{"setting trigger execution role", "GRANT SET ON PARAMETER session_replication_role TO " + role, "REVOKE SET ON PARAMETER session_replication_role FROM " + role},
		{"server configuration authority", "GRANT ALTER SYSTEM ON PARAMETER work_mem TO " + role, "REVOKE ALTER SYSTEM ON PARAMETER work_mem FROM " + role},
		{"unapproved namespace", "CREATE SCHEMA pgx_assessment; GRANT CREATE ON SCHEMA pgx_assessment TO " + role, "DROP SCHEMA pgx_assessment"},
		{"sequence grant", "CREATE SEQUENCE public.assessment_isolation_seq; GRANT USAGE ON SEQUENCE public.assessment_isolation_seq TO " + role, "DROP SEQUENCE public.assessment_isolation_seq"},
		{"missing column privilege", "REVOKE SELECT(kind) ON public.sources FROM sherlock_assessment", "GRANT SELECT(kind) ON public.sources TO sherlock_assessment"},
		{"missing column", "ALTER TABLE public.sources RENAME COLUMN kind TO isolation_kind", "ALTER TABLE public.sources RENAME COLUMN isolation_kind TO kind"},
		{"missing routine privilege", "REVOKE EXECUTE ON FUNCTION public.assessment_sorted_set(text[],integer) FROM sherlock_assessment", "GRANT EXECUTE ON FUNCTION public.assessment_sorted_set(text[],integer) TO sherlock_assessment"},
		{"missing routine", "ALTER FUNCTION public.assessment_sorted_set(text[],integer) RENAME TO assessment_isolation_set", "ALTER FUNCTION public.assessment_isolation_set(text[],integer) RENAME TO assessment_sorted_set"},
		{"unapproved overload", "CREATE FUNCTION public.assessment_sorted_set(text[],bigint) RETURNS boolean LANGUAGE sql AS 'SELECT true'", "DROP FUNCTION public.assessment_sorted_set(text[],bigint)"},
		{"unapproved schema routine", "CREATE SCHEMA pgx_assessment; CREATE FUNCTION pgx_assessment.assessment_sorted_set(text[],integer) RETURNS boolean LANGUAGE sql AS 'SELECT true'", "DROP SCHEMA pgx_assessment CASCADE"},
		{"security definer routine", "ALTER FUNCTION public.assessment_sorted_set(text[],integer) SECURITY DEFINER", "ALTER FUNCTION public.assessment_sorted_set(text[],integer) SECURITY INVOKER"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f.exec(t, tc.change)
			t.Cleanup(func() { f.exec(t, tc.restore) })
			assertDenied(t, store)
		})
		assertAllowed(t)
	}

	t.Run("settable role without inheritance", func(t *testing.T) {
		settable := pgx.Identifier{f.role + "_set"}.Sanitize()
		f.exec(t, "CREATE ROLE "+settable+" NOLOGIN; GRANT SELECT ON public.gp09_alert_outbox TO "+settable+"; GRANT "+settable+" TO "+role+" WITH INHERIT FALSE, SET TRUE")
		t.Cleanup(func() { f.exec(t, "REVOKE SELECT ON public.gp09_alert_outbox FROM "+settable+"; DROP ROLE "+settable) })
		if _, err := pool.Exec(ctx, `SELECT 1 FROM public.gp09_alert_outbox LIMIT 0`); err == nil {
			t.Fatal("fixture unexpectedly inherited table privilege")
		}
		assertDenied(t, store)
	})
	assertAllowed(t)

	t.Run("settable elevated predefined role", func(t *testing.T) {
		f.exec(t, "GRANT pg_signal_backend TO "+role+" WITH INHERIT FALSE, SET TRUE")
		t.Cleanup(func() { f.exec(t, "REVOKE pg_signal_backend FROM "+role) })
		assertDenied(t, store)
	})
	assertAllowed(t)

	t.Run("session login behind safe effective role", func(t *testing.T) {
		f.exec(t, "GRANT SELECT ON public.gp09_alert_outbox TO "+role)
		t.Cleanup(func() { f.exec(t, "REVOKE SELECT ON public.gp09_alert_outbox FROM "+role) })
		config := pool.Config().Copy()
		config.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
			_, err := conn.Exec(ctx, `SET ROLE sherlock_assessment`)
			return err
		}
		safeEffective, err := pgxpool.NewWithConfig(ctx, config)
		if err != nil {
			t.Fatal(err)
		}
		defer safeEffective.Close()
		if _, err := safeEffective.Exec(ctx, `SELECT 1 FROM public.gp09_alert_outbox LIMIT 0`); err == nil {
			t.Fatal("fixture effective role has the forbidden session privilege")
		}
		assertDenied(t, &AssessmentStore{pool: safeEffective})
	})
}

func TestAssessmentConcurrentStartResumesCanonicalConfig(t *testing.T) {
	f := newAssessmentFixture(t)
	f.seedSource(t, false)
	pool := f.restrictedPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	first, err := NewAssessmentStore(ctx, pool, f.registry, f.config, "fixture-build")
	if err != nil {
		t.Fatal(err)
	}
	variant := f.config
	variant.Policy = bytes.Replace(variant.Policy, []byte(`"stable_watts":10`), []byte(`"stable_watts":1e1`), 1)
	if bytes.Equal(variant.Policy, f.config.Policy) {
		t.Fatal("equivalent numeric fixture did not change")
	}
	second, err := NewAssessmentStore(ctx, pool, f.registry, variant, "fixture-build")
	if err != nil {
		t.Fatal(err)
	}
	// Delay each INSERT briefly to exercise overlapping empty-run snapshots.
	f.exec(t, `CREATE FUNCTION public.assessment_test_start_delay() RETURNS trigger LANGUAGE plpgsql AS $$
	BEGIN PERFORM pg_sleep(0.025); RETURN NEW; END $$;
	REVOKE EXECUTE ON FUNCTION public.assessment_test_start_delay() FROM PUBLIC;
	CREATE TRIGGER assessment_test_start_delay BEFORE INSERT ON public.assessment_runs FOR EACH ROW EXECUTE FUNCTION public.assessment_test_start_delay()`)
	ready := make(chan struct{})
	results := make(chan error, 2)
	for _, store := range []*AssessmentStore{first, second} {
		go func() {
			<-ready
			results <- store.Start(ctx)
		}()
	}
	close(ready)
	for range 2 {
		if err := <-results; err != nil {
			t.Fatalf("matching concurrent start: %v", err)
		}
	}
	var runs, enrollments int
	var persisted string
	if err := f.admin.QueryRow(ctx, `SELECT count(*), min(config_hash), (SELECT count(*) FROM public.assessment_enrollments) FROM public.assessment_runs`).Scan(&runs, &persisted, &enrollments); err != nil {
		t.Fatal(err)
	}
	want, err := f.config.Hash()
	if err != nil || runs != 1 || enrollments != len(f.config.Assets) || persisted != want {
		t.Fatalf("persisted runs=%d enrollments=%d hash=%s, want one run and canonical hash %s", runs, enrollments, persisted, want)
	}
	changed := f.config
	changed.RunDurationSeconds++
	incompatible, err := NewAssessmentStore(ctx, pool, f.registry, changed, "fixture-build")
	if err != nil {
		t.Fatal(err)
	}
	if err := incompatible.Start(ctx); !errors.Is(err, ErrAssessmentRunBusy) {
		t.Fatalf("different config start error = %v, want RUN_BUSY", err)
	}
}
