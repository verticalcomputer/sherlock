//go:build integration

package adminmanage_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/adminmanage"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

const accessTestCanary = "synthetic-store-canary-4b2d"

func insertCollector(t *testing.T, f credentialFixture, id, clusterID string, protocolMax int, capable bool) domain.CollectorID {
	t.Helper()
	mustExec(t, f.pool, `INSERT INTO collectors(collector_id,cluster_id,display_name,status,version,build_commit,protocol_min,protocol_max,operating_system,architecture) VALUES($1,$2,$1,'ACTIVE','test','test',1,$3,'linux','amd64')`, id, clusterID, protocolMax)
	if capable {
		mustExec(t, f.pool, `INSERT INTO collector_capabilities(collector_id,capability,version) VALUES($1,$2,'1')`, id, domain.CredentialAccessTestOperation)
	}
	return domain.CollectorID(id)
}

// bindTarget records the operator approval that lets one collector receive
// credentials for one (cluster, host) target.
func bindTarget(t *testing.T, f credentialFixture, host string, collector domain.CollectorID) {
	t.Helper()
	if err := f.store.BindCredentialTarget(context.Background(), f.clusterID, host, string(collector), f.actor, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
}

func unbindTarget(t *testing.T, f credentialFixture, host string, collector domain.CollectorID) {
	t.Helper()
	if err := f.store.UnbindCredentialTarget(context.Background(), f.clusterID, host, string(collector), f.actor, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
}

func accessTestAudit(kind, actor string) adminmanage.MutationAudit {
	return credentialAudit(fmt.Sprintf("audit-%d", time.Now().UnixNano()), kind, "test", actor, time.Now().UTC())
}

func findTest(tests []adminmanage.CredentialAccessTest, id string) adminmanage.CredentialAccessTest {
	for _, test := range tests {
		if test.ID == id {
			return test
		}
	}
	return adminmanage.CredentialAccessTest{}
}

func leaseToken(seed string) string {
	return strings.Repeat(seed, 40/len(seed)+1)[:40]
}

func assertNoCanaryInDatabase(t *testing.T, f credentialFixture) {
	t.Helper()
	ctx := context.Background()
	rows, err := f.pool.Query(ctx, `SELECT table_name, column_name, data_type FROM information_schema.columns WHERE table_schema='public' AND data_type IN ('text','character varying','bytea','jsonb','json')`)
	if err != nil {
		t.Fatal(err)
	}
	type column struct{ table, name, kind string }
	columns := make([]column, 0)
	for rows.Next() {
		var c column
		if err := rows.Scan(&c.table, &c.name, &c.kind); err != nil {
			t.Fatal(err)
		}
		columns = append(columns, c)
	}
	rows.Close()
	for _, c := range columns {
		expression := fmt.Sprintf(`%q::text`, c.name)
		if c.kind == "bytea" {
			expression = fmt.Sprintf(`encode(%q,'escape')`, c.name)
		}
		var hits int
		if err := f.pool.QueryRow(ctx, fmt.Sprintf(`SELECT count(*) FROM %q WHERE position($1 in %s) > 0`, c.table, expression), accessTestCanary).Scan(&hits); err != nil {
			t.Fatalf("scan %s.%s: %v", c.table, c.name, err)
		}
		if hits > 0 {
			t.Fatalf("synthetic secret found in %s.%s", c.table, c.name)
		}
	}
}

func TestCredentialAccessTestLifecycleBindsCollectorLeaseDigestAndExactVersion(t *testing.T) {
	f := newCredentialFixture(t, 0)
	ctx := context.Background()
	subject := "access-admin-" + fmt.Sprint(time.Now().UnixNano())
	grantCredentialAdmin(t, f, subject)
	credential, err := putCredential(f, ctx, f.clusterID, subject, "fixture1-zone1-headnode", "fixture_user_1", "ssh-"+accessTestCanary, accessTestCanary, 0, "", "create-"+fmt.Sprint(time.Now().UnixNano()))
	if err != nil {
		t.Fatal(err)
	}
	head := insertCollector(t, f, "head-"+fmt.Sprint(time.Now().UnixNano()), f.clusterID, 2, true)
	legacy := insertCollector(t, f, "legacy-"+fmt.Sprint(time.Now().UnixNano()), f.clusterID, 1, false)
	uncapable := insertCollector(t, f, "uncapable-"+fmt.Sprint(time.Now().UnixNano()), f.clusterID, 2, false)
	foreign := insertCollector(t, f, "foreign-"+fmt.Sprint(time.Now().UnixNano()), f.foreignID, 2, true)
	cluster := domain.ClusterID(f.clusterID)
	bindTarget(t, f, "fixture1-zone1-headnode", head)

	if _, err := f.store.RequestCredentialAccessTest(ctx, f.clusterID, "stranger", credential.ID, credential.Version, accessTestAudit(adminmanage.EventAccessTestRequested, "stranger")); !errors.Is(err, adminmanage.ErrCredentialAccessDenied) {
		t.Fatalf("ungranted subject err=%v", err)
	}
	if _, err := f.store.RequestCredentialAccessTest(ctx, f.clusterID, subject, credential.ID, credential.Version+1, accessTestAudit(adminmanage.EventAccessTestRequested, subject)); !errors.Is(err, adminmanage.ErrConflict) {
		t.Fatalf("wrong version err=%v", err)
	}
	if _, err := f.store.RequestCredentialAccessTest(ctx, f.foreignID, subject, credential.ID, credential.Version, accessTestAudit(adminmanage.EventAccessTestRequested, subject)); !errors.Is(err, adminmanage.ErrCredentialAccessDenied) {
		t.Fatalf("foreign cluster request err=%v", err)
	}
	test, err := f.store.RequestCredentialAccessTest(ctx, f.clusterID, subject, credential.ID, credential.Version, accessTestAudit(adminmanage.EventAccessTestRequested, subject))
	if err != nil || test.Status != domain.CredentialAccessTestRequested || !test.CredentialCurrent {
		t.Fatalf("request err=%v test=%+v", err, test)
	}
	if _, err := f.store.RequestCredentialAccessTest(ctx, f.clusterID, subject, credential.ID, credential.Version, accessTestAudit(adminmanage.EventAccessTestRequested, subject)); !errors.Is(err, adminmanage.ErrConflict) {
		t.Fatalf("second live request err=%v", err)
	}

	for name, collector := range map[string]domain.CollectorID{"legacy v1": legacy, "no capability": uncapable, "foreign cluster": foreign} {
		if _, _, err := f.store.ClaimCredentialAccessTest(ctx, cluster, collector, leaseToken("x"), time.Minute); !errors.Is(err, adminmanage.ErrAccessTestCollectorIncompatible) {
			t.Fatalf("%s claim err=%v", name, err)
		}
	}
	if _, found, err := f.store.ClaimCredentialAccessTest(ctx, domain.ClusterID(f.foreignID), foreign, leaseToken("y"), time.Minute); err != nil || found {
		t.Fatalf("foreign cluster must see no work: found=%v err=%v", found, err)
	}
	if _, _, err := f.store.ClaimCredentialAccessTest(ctx, domain.ClusterID(f.foreignID), head, leaseToken("z"), time.Minute); !errors.Is(err, adminmanage.ErrAccessTestCollectorIncompatible) {
		t.Fatalf("collector claiming under another cluster err=%v", err)
	}

	token := leaseToken("a")
	lease, found, err := f.store.ClaimCredentialAccessTest(ctx, cluster, head, token, time.Minute)
	if err != nil || !found || lease.Attempt != 1 || lease.Plan.TestID != test.ID || lease.Plan.CredentialVersion != credential.Version || lease.Plan.Host != "fixture1-zone1-headnode" || lease.Plan.Username != "fixture_user_1" {
		t.Fatalf("claim err=%v found=%v lease=%+v", err, found, lease)
	}
	if _, found, err := f.store.ClaimCredentialAccessTest(ctx, cluster, head, leaseToken("b"), time.Minute); err != nil || found {
		t.Fatalf("leased test was claimable again: found=%v err=%v", found, err)
	}
	ref := adminmanage.CredentialAccessTestLeaseRef{TestID: test.ID, Attempt: 1, LeaseToken: token}
	if _, err := f.store.StartCredentialAccessTest(ctx, cluster, head, ref, time.Minute); err != nil {
		t.Fatal(err)
	}
	digest, err := domain.CredentialAccessTestPlanDigest(lease.Plan)
	if err != nil {
		t.Fatal(err)
	}
	wrongDigest := digest
	wrongDigest[0] ^= 0xff
	for name, attempt := range map[string]func() error{
		"wrong token": func() error {
			_, err := f.store.DeliverCredentialForAccessTest(ctx, cluster, head, adminmanage.CredentialAccessTestLeaseRef{TestID: test.ID, Attempt: 1, LeaseToken: leaseToken("q")}, digest)
			return err
		},
		"wrong attempt": func() error {
			_, err := f.store.DeliverCredentialForAccessTest(ctx, cluster, head, adminmanage.CredentialAccessTestLeaseRef{TestID: test.ID, Attempt: 2, LeaseToken: token}, digest)
			return err
		},
		"wrong digest": func() error {
			_, err := f.store.DeliverCredentialForAccessTest(ctx, cluster, head, ref, wrongDigest)
			return err
		},
		"foreign collector with stolen token": func() error {
			_, err := f.store.DeliverCredentialForAccessTest(ctx, domain.ClusterID(f.foreignID), foreign, ref, digest)
			return err
		},
		"uncapable collector with stolen token": func() error {
			_, err := f.store.DeliverCredentialForAccessTest(ctx, cluster, uncapable, ref, digest)
			return err
		},
	} {
		if err := attempt(); !errors.Is(err, adminmanage.ErrAccessTestLeaseInvalid) && !errors.Is(err, adminmanage.ErrAccessTestCollectorIncompatible) {
			t.Fatalf("%s delivery err=%v", name, err)
		}
	}
	delivery, err := f.store.DeliverCredentialForAccessTest(ctx, cluster, head, ref, digest)
	if err != nil || string(delivery.SudoPassword) != accessTestCanary || delivery.Username != "fixture_user_1" || delivery.CredentialVersion != credential.Version {
		t.Fatalf("delivery err=%v username=%q version=%d", err, delivery.Username, delivery.CredentialVersion)
	}
	if strings.Contains(fmt.Sprintf("%v %+v %s", delivery, delivery, delivery), accessTestCanary) {
		t.Fatal("delivery value formats its secret")
	}
	delivery.Destroy()
	retry, err := f.store.DeliverCredentialForAccessTest(ctx, cluster, head, ref, digest)
	if err != nil || string(retry.SudoPassword) != accessTestCanary {
		t.Fatalf("bounded retry delivery err=%v", err)
	}
	retry.Destroy()
	if _, err := f.store.DeliverCredentialForAccessTest(ctx, cluster, head, ref, digest); !errors.Is(err, adminmanage.ErrAccessTestLeaseInvalid) {
		t.Fatalf("third delivery must hit the bound: err=%v", err)
	}

	now := time.Now().UTC()
	result := domain.CredentialAccessTestResult{SchemaVersion: 1, TestID: test.ID, Attempt: 1, PlanDigest: digest.String(), Outcome: domain.CredentialAccessVerified, Summary: "sudo authenticated and cmsh listed 5 devices read-only on BCM 10.24.", BCMVersion: "10.24", DevicesListed: 5, StartedAt: now, CompletedAt: now.Add(time.Second), Checks: []domain.CredentialAccessCheck{{Name: "sudo_listing", Status: domain.CredentialAccessCheckPassed, Detail: "5 device rows"}}}
	tampered := result
	tampered.PlanDigest = wrongDigest.String()
	if _, err := f.store.CompleteCredentialAccessTest(ctx, cluster, head, ref, tampered); !errors.Is(err, adminmanage.ErrAccessTestLeaseInvalid) {
		t.Fatalf("result with wrong digest err=%v", err)
	}
	completion, err := f.store.CompleteCredentialAccessTest(ctx, cluster, head, ref, result)
	if err != nil || completion.Status != domain.CredentialAccessTestSucceeded || completion.Rejected {
		t.Fatalf("completion err=%v %+v", err, completion)
	}
	replay, err := f.store.CompleteCredentialAccessTest(ctx, cluster, head, ref, result)
	if err != nil || replay.Status != domain.CredentialAccessTestSucceeded || replay.Outcome != domain.CredentialAccessVerified {
		t.Fatalf("replayed completion err=%v %+v", err, replay)
	}
	if _, err := f.store.DeliverCredentialForAccessTest(ctx, cluster, head, ref, digest); !errors.Is(err, adminmanage.ErrAccessTestLeaseInvalid) {
		t.Fatalf("delivery after completion err=%v", err)
	}
	if _, err := f.store.RenewCredentialAccessTestLease(ctx, cluster, head, ref, time.Minute); !errors.Is(err, adminmanage.ErrAccessTestLeaseInvalid) {
		t.Fatalf("renew after completion err=%v", err)
	}

	tests, err := f.store.ListCredentialAccessTests(ctx, f.clusterID, subject, 10)
	if err != nil || len(tests) != 1 || tests[0].Status != domain.CredentialAccessTestSucceeded || !tests[0].CredentialCurrent || tests[0].OutcomeCode != "BCM_ACCESS_VERIFIED" || tests[0].DevicesListed != 5 || tests[0].BCMVersion != "10.24" || tests[0].CollectorID != string(head) || tests[0].Attempt != 1 {
		t.Fatalf("list err=%v tests=%+v", err, tests)
	}
	if _, err := f.store.ListCredentialAccessTests(ctx, f.clusterID, "stranger", 10); !errors.Is(err, adminmanage.ErrCredentialAccessDenied) {
		t.Fatalf("ungranted list err=%v", err)
	}

	// Replacement makes the success stale and blocks delivery for the old version.
	replaced, err := putCredential(f, ctx, f.clusterID, subject, "fixture1-zone1-headnode", "fixture_user_1", "", "replacement-"+accessTestCanary, credential.Version, credential.ID, "replace-"+fmt.Sprint(time.Now().UnixNano()))
	if err != nil {
		t.Fatal(err)
	}
	tests, err = f.store.ListCredentialAccessTests(ctx, f.clusterID, subject, 10)
	if err != nil || len(tests) != 1 || tests[0].CredentialCurrent || tests[0].CredentialStatus != "REVOKED" || tests[0].Status != domain.CredentialAccessTestSucceeded {
		t.Fatalf("stale projection err=%v tests=%+v", err, tests)
	}
	second, err := f.store.RequestCredentialAccessTest(ctx, f.clusterID, subject, replaced.ID, replaced.Version, accessTestAudit(adminmanage.EventAccessTestRequested, subject))
	if err != nil {
		t.Fatal(err)
	}
	// Revocation before claim fails the pending test server-side and no collector ever sees it.
	if err := f.store.RevokeCredential(ctx, f.clusterID, subject, replaced.ID, replaced.Version, credentialAudit("revoke-"+fmt.Sprint(time.Now().UnixNano()), adminmanage.EventCredentialRevoked, "CREDENTIAL_REVOKED", subject, time.Now().UTC())); err != nil {
		t.Fatal(err)
	}
	if _, found, err := f.store.ClaimCredentialAccessTest(ctx, cluster, head, leaseToken("c"), time.Minute); err != nil || found {
		t.Fatalf("revoked credential test was claimable: found=%v err=%v", found, err)
	}
	tests, err = f.store.ListCredentialAccessTests(ctx, f.clusterID, subject, 10)
	if err != nil || len(tests) != 2 || tests[0].ID != second.ID || tests[0].Status != domain.CredentialAccessTestFailed || tests[0].OutcomeCode != "CREDENTIAL_UNAVAILABLE" {
		t.Fatalf("stale request projection err=%v tests=%+v", err, tests)
	}

	var events string
	if err := f.pool.QueryRow(ctx, `SELECT string_agg(event_kind||':'||outcome||':'||reason_code||':'||actor_kind, '|' ORDER BY created_at) FROM credential_access_test_events WHERE test_id=$1`, test.ID).Scan(&events); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"ACCESS_TEST_REQUESTED:SUCCEEDED", "ACCESS_TEST_CLAIMED:SUCCEEDED", "CREDENTIAL_DELIVERY_REFUSED:REJECTED:PLAN_DIGEST_MISMATCH", "CREDENTIAL_DELIVERED:SUCCEEDED", "CREDENTIAL_DELIVERY_REFUSED:REJECTED:DELIVERY_LIMIT", "ACCESS_TEST_RESULT_REJECTED:REJECTED:PLAN_BINDING_MISMATCH", "ACCESS_TEST_COMPLETED:SUCCEEDED:BCM_ACCESS_VERIFIED"} {
		if !strings.Contains(events, want) {
			t.Fatalf("audit trail missing %s: %s", want, events)
		}
	}
	var denied int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM admin_credential_audit_events WHERE cluster_id=$1 AND event_kind='CREDENTIAL_ATTEMPT' AND outcome='REJECTED' AND actor_subject='stranger'`, f.clusterID).Scan(&denied); err != nil || denied < 1 {
		t.Fatalf("denied request audit missing: %d %v", denied, err)
	}
	assertNoCanaryInDatabase(t, f)
}

func TestCredentialAccessTestExpiryRetryCancellationAndRevocationRace(t *testing.T) {
	f := newCredentialFixture(t, 0)
	ctx := context.Background()
	subject := "access-admin-" + fmt.Sprint(time.Now().UnixNano())
	grantCredentialAdmin(t, f, subject)
	credential, err := putCredential(f, ctx, f.clusterID, subject, "fixture1-zone1-headnode", "fixture_user_1", "", accessTestCanary, 0, "", "create-"+fmt.Sprint(time.Now().UnixNano()))
	if err != nil {
		t.Fatal(err)
	}
	head := insertCollector(t, f, "head-"+fmt.Sprint(time.Now().UnixNano()), f.clusterID, 2, true)
	other := insertCollector(t, f, "other-"+fmt.Sprint(time.Now().UnixNano()), f.clusterID, 2, true)
	cluster := domain.ClusterID(f.clusterID)
	bindTarget(t, f, "fixture1-zone1-headnode", head)
	bindTarget(t, f, "fixture1-zone1-headnode", other)
	request := func() adminmanage.CredentialAccessTest {
		t.Helper()
		test, err := f.store.RequestCredentialAccessTest(ctx, f.clusterID, subject, credential.ID, credential.Version, accessTestAudit(adminmanage.EventAccessTestRequested, subject))
		if err != nil {
			t.Fatal(err)
		}
		return test
	}

	// Expired lease: delivery is refused, another compatible collector retries as attempt 2 with fresh validation.
	test := request()
	first, found, err := f.store.ClaimCredentialAccessTest(ctx, cluster, head, leaseToken("a"), time.Minute)
	if err != nil || !found {
		t.Fatalf("claim err=%v found=%v", err, found)
	}
	digest, _ := domain.CredentialAccessTestPlanDigest(first.Plan)
	firstRef := adminmanage.CredentialAccessTestLeaseRef{TestID: test.ID, Attempt: 1, LeaseToken: leaseToken("a")}
	mustExec(t, f.pool, `UPDATE credential_access_test_attempts SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE test_id=$1`, test.ID)
	if _, err := f.store.DeliverCredentialForAccessTest(ctx, cluster, head, firstRef, digest); !errors.Is(err, adminmanage.ErrAccessTestLeaseInvalid) {
		t.Fatalf("expired lease delivery err=%v", err)
	}
	second, found, err := f.store.ClaimCredentialAccessTest(ctx, cluster, other, leaseToken("b"), time.Minute)
	if err != nil || !found || second.Attempt != 2 || second.Plan.TestID != test.ID {
		t.Fatalf("retry claim err=%v found=%v lease=%+v", err, found, second)
	}
	secondRef := adminmanage.CredentialAccessTestLeaseRef{TestID: test.ID, Attempt: 2, LeaseToken: leaseToken("b")}
	if _, err := f.store.DeliverCredentialForAccessTest(ctx, cluster, head, firstRef, digest); !errors.Is(err, adminmanage.ErrAccessTestLeaseInvalid) {
		t.Fatalf("stale attempt-1 token after retry err=%v", err)
	}
	if _, err := f.store.DeliverCredentialForAccessTest(ctx, cluster, head, secondRef, digest); !errors.Is(err, adminmanage.ErrAccessTestLeaseInvalid) {
		t.Fatalf("attempt-2 token from the wrong collector err=%v", err)
	}
	delivered, err := f.store.DeliverCredentialForAccessTest(ctx, cluster, other, secondRef, digest)
	if err != nil || string(delivered.SudoPassword) != accessTestCanary {
		t.Fatalf("retry delivery err=%v", err)
	}
	delivered.Destroy()
	// A late result from the expired attempt is rejected, not recorded.
	late := domain.CredentialAccessTestResult{SchemaVersion: 1, TestID: test.ID, Attempt: 1, PlanDigest: digest.String(), Outcome: domain.CredentialAccessVerified, Summary: "late", DevicesListed: 1, StartedAt: time.Now().UTC(), CompletedAt: time.Now().UTC()}
	if completion, err := f.store.CompleteCredentialAccessTest(ctx, cluster, head, firstRef, late); err != nil || !completion.Rejected {
		t.Fatalf("late result err=%v completion=%+v", err, completion)
	}
	// Cancellation: delivery is refused and the running attempt's result is rejected.
	if err := f.store.CancelCredentialAccessTest(ctx, f.clusterID, subject, test.ID, accessTestAudit(adminmanage.EventAccessTestCancelled, subject)); err != nil {
		t.Fatal(err)
	}
	if err := f.store.CancelCredentialAccessTest(ctx, f.clusterID, subject, test.ID, accessTestAudit(adminmanage.EventAccessTestCancelled, subject)); !errors.Is(err, adminmanage.ErrConflict) {
		t.Fatalf("double cancel err=%v", err)
	}
	if _, err := f.store.DeliverCredentialForAccessTest(ctx, cluster, other, secondRef, digest); !errors.Is(err, adminmanage.ErrAccessTestLeaseInvalid) {
		t.Fatalf("delivery after cancellation err=%v", err)
	}
	after := late
	after.Attempt = 2
	if completion, err := f.store.CompleteCredentialAccessTest(ctx, cluster, other, secondRef, after); err != nil || !completion.Rejected || completion.Status != domain.CredentialAccessTestCancelled {
		t.Fatalf("result after cancellation err=%v completion=%+v", err, completion)
	}
	tests, err := f.store.ListCredentialAccessTests(ctx, f.clusterID, subject, 10)
	if err != nil || len(tests) != 1 || tests[0].Status != domain.CredentialAccessTestCancelled || tests[0].CancelledBy != subject {
		t.Fatalf("cancelled projection err=%v tests=%+v", err, tests)
	}

	// Deadline expiry is applied lazily at claim time.
	overdue := request()
	mustExec(t, f.pool, `UPDATE credential_access_tests SET requested_at=clock_timestamp()-interval '2 seconds', deadline=clock_timestamp()-interval '1 second' WHERE test_id=$1`, overdue.ID)
	if _, found, err := f.store.ClaimCredentialAccessTest(ctx, cluster, head, leaseToken("c"), time.Minute); err != nil || found {
		t.Fatalf("overdue test claimed: found=%v err=%v", found, err)
	}
	tests, err = f.store.ListCredentialAccessTests(ctx, f.clusterID, subject, 10)
	if expired := findTest(tests, overdue.ID); err != nil || expired.Status != domain.CredentialAccessTestExpired {
		t.Fatalf("expired projection err=%v tests=%+v", err, tests)
	}

	// Attempt bound: two expired leases exhaust the test.
	bounded := request()
	if _, found, err := f.store.ClaimCredentialAccessTest(ctx, cluster, head, leaseToken("d"), time.Minute); err != nil || !found {
		t.Fatalf("bounded claim 1 err=%v", err)
	}
	mustExec(t, f.pool, `UPDATE credential_access_test_attempts SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE test_id=$1`, bounded.ID)
	if _, found, err := f.store.ClaimCredentialAccessTest(ctx, cluster, head, leaseToken("e"), time.Minute); err != nil || !found {
		t.Fatalf("bounded claim 2 err=%v", err)
	}
	mustExec(t, f.pool, `UPDATE credential_access_test_attempts SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE test_id=$1`, bounded.ID)
	if _, found, err := f.store.ClaimCredentialAccessTest(ctx, cluster, head, leaseToken("f"), time.Minute); err != nil || found {
		t.Fatalf("third attempt granted: found=%v err=%v", found, err)
	}
	tests, err = f.store.ListCredentialAccessTests(ctx, f.clusterID, subject, 10)
	if exhausted := findTest(tests, bounded.ID); err != nil || exhausted.Status != domain.CredentialAccessTestExpired || exhausted.Attempt != 2 {
		t.Fatalf("exhausted projection err=%v tests=%+v", err, tests)
	}

	// Revocation race: delivery before revocation succeeds, delivery after it is refused,
	// the executing attempt may still report, and the projection marks it stale.
	raced := request()
	lease, found, err := f.store.ClaimCredentialAccessTest(ctx, cluster, head, leaseToken("g"), time.Minute)
	if err != nil || !found {
		t.Fatalf("race claim err=%v", err)
	}
	raceDigest, _ := domain.CredentialAccessTestPlanDigest(lease.Plan)
	raceRef := adminmanage.CredentialAccessTestLeaseRef{TestID: raced.ID, Attempt: 1, LeaseToken: leaseToken("g")}
	before, err := f.store.DeliverCredentialForAccessTest(ctx, cluster, head, raceRef, raceDigest)
	if err != nil {
		t.Fatal(err)
	}
	before.Destroy()
	if err := f.store.RevokeCredential(ctx, f.clusterID, subject, credential.ID, credential.Version, credentialAudit("revoke-"+fmt.Sprint(time.Now().UnixNano()), adminmanage.EventCredentialRevoked, "CREDENTIAL_REVOKED", subject, time.Now().UTC())); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.DeliverCredentialForAccessTest(ctx, cluster, head, raceRef, raceDigest); !errors.Is(err, adminmanage.ErrAccessTestLeaseInvalid) {
		t.Fatalf("delivery after revocation err=%v", err)
	}
	outcome := domain.CredentialAccessTestResult{SchemaVersion: 1, TestID: raced.ID, Attempt: 1, PlanDigest: raceDigest.String(), Outcome: domain.CredentialAccessVerified, Summary: "verified before revocation", DevicesListed: 2, StartedAt: time.Now().UTC(), CompletedAt: time.Now().UTC()}
	if completion, err := f.store.CompleteCredentialAccessTest(ctx, cluster, head, raceRef, outcome); err != nil || completion.Rejected {
		t.Fatalf("result after revocation err=%v completion=%+v", err, completion)
	}
	tests, err = f.store.ListCredentialAccessTests(ctx, f.clusterID, subject, 10)
	if stale := findTest(tests, raced.ID); err != nil || stale.Status != domain.CredentialAccessTestSucceeded || stale.CredentialCurrent || stale.CredentialStatus != "REVOKED" {
		t.Fatalf("post-revocation projection err=%v tests=%+v", err, tests)
	}
	var refusals string
	if err := f.pool.QueryRow(ctx, `SELECT string_agg(reason_code, '|') FROM credential_access_test_events WHERE test_id=$1 AND event_kind='CREDENTIAL_DELIVERY_REFUSED'`, raced.ID).Scan(&refusals); err != nil || !strings.Contains(refusals, "CREDENTIAL_UNAVAILABLE") {
		t.Fatalf("revocation refusal audit missing: %q %v", refusals, err)
	}
	assertNoCanaryInDatabase(t, f)
}

func TestCredentialAccessTestConcurrentClaimsGrantOneLease(t *testing.T) {
	f := newCredentialFixture(t, 0)
	ctx := context.Background()
	subject := "access-admin-" + fmt.Sprint(time.Now().UnixNano())
	grantCredentialAdmin(t, f, subject)
	credential, err := putCredential(f, ctx, f.clusterID, subject, "fixture1-zone1-headnode", "fixture_user_1", "", accessTestCanary, 0, "", "create-"+fmt.Sprint(time.Now().UnixNano()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.RequestCredentialAccessTest(ctx, f.clusterID, subject, credential.ID, credential.Version, accessTestAudit(adminmanage.EventAccessTestRequested, subject)); err != nil {
		t.Fatal(err)
	}
	collectors := make([]domain.CollectorID, 0, 6)
	for i := 0; i < 6; i++ {
		collector := insertCollector(t, f, fmt.Sprintf("head-%d-%d", i, time.Now().UnixNano()), f.clusterID, 2, true)
		bindTarget(t, f, "fixture1-zone1-headnode", collector)
		collectors = append(collectors, collector)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	granted := 0
	for i, collector := range collectors {
		wg.Add(1)
		go func(seed string, collector domain.CollectorID) {
			defer wg.Done()
			_, found, err := f.store.ClaimCredentialAccessTest(ctx, domain.ClusterID(f.clusterID), collector, leaseToken(seed), time.Minute)
			if err != nil {
				t.Errorf("concurrent claim: %v", err)
				return
			}
			if found {
				mu.Lock()
				granted++
				mu.Unlock()
			}
		}(fmt.Sprintf("s%d", i), collector)
	}
	wg.Wait()
	if granted != 1 {
		t.Fatalf("expected exactly one lease, got %d", granted)
	}
}

// accessTestTarget is the shared setup for the binding tests: a granted
// administrator, one active credential on the pilot head and no bindings yet.
func accessTestTarget(t *testing.T) (credentialFixture, string, adminmanage.CredentialMetadata) {
	t.Helper()
	f := newCredentialFixture(t, 0)
	subject := "access-admin-" + fmt.Sprint(time.Now().UnixNano())
	grantCredentialAdmin(t, f, subject)
	credential, err := putCredential(f, context.Background(), f.clusterID, subject, "fixture1-zone1-headnode", "fixture_user_1", "", accessTestCanary, 0, "", "create-"+fmt.Sprint(time.Now().UnixNano()))
	if err != nil {
		t.Fatal(err)
	}
	return f, subject, credential
}

func TestCredentialAccessTestRequiresOperatorApprovedTargetBinding(t *testing.T) {
	f, subject, credential := accessTestTarget(t)
	ctx := context.Background()
	cluster := domain.ClusterID(f.clusterID)
	unbound := insertCollector(t, f, "unbound-"+fmt.Sprint(time.Now().UnixNano()), f.clusterID, 2, true)
	elsewhere := insertCollector(t, f, "elsewhere-"+fmt.Sprint(time.Now().UnixNano()), f.clusterID, 2, true)
	bound := insertCollector(t, f, "bound-"+fmt.Sprint(time.Now().UnixNano()), f.clusterID, 2, true)
	foreign := insertCollector(t, f, "foreign-"+fmt.Sprint(time.Now().UnixNano()), f.foreignID, 2, true)
	// A binding for a different head in the same cluster is not authority here.
	bindTarget(t, f, "fixture1-zone1-login01", elsewhere)

	if err := f.store.BindCredentialTarget(ctx, f.clusterID, "fixture1-zone1-headnode", string(foreign), f.actor, time.Now().UTC()); !errors.Is(err, adminmanage.ErrConflict) {
		t.Fatalf("binding a foreign collector err=%v", err)
	}
	if err := f.store.BindCredentialTarget(ctx, f.clusterID, "fixture1-zone1-headnode", "collector-that-does-not-exist", f.actor, time.Now().UTC()); !errors.Is(err, adminmanage.ErrNotFound) {
		t.Fatalf("binding an unknown collector err=%v", err)
	}

	test, err := f.store.RequestCredentialAccessTest(ctx, f.clusterID, subject, credential.ID, credential.Version, accessTestAudit(adminmanage.EventAccessTestRequested, subject))
	if err != nil {
		t.Fatal(err)
	}
	// A capable, active, in-cluster collector with no binding for this target
	// must not even see the work, so it can never reach the delivery boundary.
	if _, found, err := f.store.ClaimCredentialAccessTest(ctx, cluster, unbound, leaseToken("u"), time.Minute); err != nil || found {
		t.Fatalf("unbound collector claimed: found=%v err=%v", found, err)
	}
	if _, found, err := f.store.ClaimCredentialAccessTest(ctx, cluster, elsewhere, leaseToken("v"), time.Minute); err != nil || found {
		t.Fatalf("collector bound to another host claimed: found=%v err=%v", found, err)
	}

	bindTarget(t, f, "fixture1-zone1-headnode", bound)
	lease, found, err := f.store.ClaimCredentialAccessTest(ctx, cluster, bound, leaseToken("w"), time.Minute)
	if err != nil || !found || lease.Plan.TestID != test.ID {
		t.Fatalf("bound collector claim err=%v found=%v lease=%+v", err, found, lease)
	}
	digest, err := domain.CredentialAccessTestPlanDigest(lease.Plan)
	if err != nil {
		t.Fatal(err)
	}
	ref := adminmanage.CredentialAccessTestLeaseRef{TestID: test.ID, Attempt: 1, LeaseToken: leaseToken("w")}
	delivery, err := f.store.DeliverCredentialForAccessTest(ctx, cluster, bound, ref, digest)
	if err != nil || string(delivery.SudoPassword) != accessTestCanary {
		t.Fatalf("bound delivery err=%v", err)
	}
	delivery.Destroy()

	bindings, err := f.store.ListCredentialTargetBindings(ctx, f.clusterID)
	if err != nil || len(bindings) != 2 {
		t.Fatalf("bindings err=%v bindings=%+v", err, bindings)
	}
	for _, binding := range bindings {
		if binding.RevokedAt != nil || binding.ApprovedBy != f.actor {
			t.Fatalf("unexpected binding %+v", binding)
		}
	}
	var events string
	if err := f.pool.QueryRow(ctx, `SELECT string_agg(event_kind||':'||host||':'||collector_id, '|' ORDER BY created_at) FROM credential_target_binding_audit_events WHERE cluster_id=$1`, f.clusterID).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(events, "CREDENTIAL_TARGET_BOUND:fixture1-zone1-headnode:"+string(bound)) {
		t.Fatalf("binding audit missing: %s", events)
	}
	assertNoCanaryInDatabase(t, f)
}

func TestCredentialAccessTestDeliveryRefusedAfterBindingRevoked(t *testing.T) {
	f, subject, credential := accessTestTarget(t)
	ctx := context.Background()
	cluster := domain.ClusterID(f.clusterID)
	head := insertCollector(t, f, "head-"+fmt.Sprint(time.Now().UnixNano()), f.clusterID, 2, true)
	bindTarget(t, f, "fixture1-zone1-headnode", head)
	test, err := f.store.RequestCredentialAccessTest(ctx, f.clusterID, subject, credential.ID, credential.Version, accessTestAudit(adminmanage.EventAccessTestRequested, subject))
	if err != nil {
		t.Fatal(err)
	}
	lease, found, err := f.store.ClaimCredentialAccessTest(ctx, cluster, head, leaseToken("h"), time.Minute)
	if err != nil || !found {
		t.Fatalf("claim err=%v found=%v", err, found)
	}
	digest, _ := domain.CredentialAccessTestPlanDigest(lease.Plan)
	ref := adminmanage.CredentialAccessTestLeaseRef{TestID: test.ID, Attempt: 1, LeaseToken: leaseToken("h")}

	// Unbinding between claim and delivery must stop the secret even though
	// the lease itself is still live.
	unbindTarget(t, f, "fixture1-zone1-headnode", head)
	if _, err := f.store.DeliverCredentialForAccessTest(ctx, cluster, head, ref, digest); !errors.Is(err, adminmanage.ErrAccessTestLeaseInvalid) {
		t.Fatalf("delivery after unbind err=%v", err)
	}
	var refusals string
	if err := f.pool.QueryRow(ctx, `SELECT string_agg(reason_code, '|') FROM credential_access_test_events WHERE test_id=$1 AND event_kind='CREDENTIAL_DELIVERY_REFUSED'`, test.ID).Scan(&refusals); err != nil || !strings.Contains(refusals, "TARGET_BINDING_MISSING") {
		t.Fatalf("binding refusal audit missing: %q %v", refusals, err)
	}
	var delivered int
	if err := f.pool.QueryRow(ctx, `SELECT delivery_count FROM credential_access_test_attempts WHERE test_id=$1 AND attempt=1`, test.ID).Scan(&delivered); err != nil || delivered != 0 {
		t.Fatalf("refused delivery was counted: %d %v", delivered, err)
	}
	// Re-approving the binding restores delivery for the same live lease.
	bindTarget(t, f, "fixture1-zone1-headnode", head)
	delivery, err := f.store.DeliverCredentialForAccessTest(ctx, cluster, head, ref, digest)
	if err != nil || string(delivery.SudoPassword) != accessTestCanary {
		t.Fatalf("delivery after rebinding err=%v", err)
	}
	delivery.Destroy()
	assertNoCanaryInDatabase(t, f)
}

func TestCredentialAccessTestResultAfterDeadlineIsRejectedAndExpiresTest(t *testing.T) {
	f, subject, credential := accessTestTarget(t)
	ctx := context.Background()
	cluster := domain.ClusterID(f.clusterID)
	head := insertCollector(t, f, "head-"+fmt.Sprint(time.Now().UnixNano()), f.clusterID, 2, true)
	bindTarget(t, f, "fixture1-zone1-headnode", head)
	test, err := f.store.RequestCredentialAccessTest(ctx, f.clusterID, subject, credential.ID, credential.Version, accessTestAudit(adminmanage.EventAccessTestRequested, subject))
	if err != nil {
		t.Fatal(err)
	}
	lease, found, err := f.store.ClaimCredentialAccessTest(ctx, cluster, head, leaseToken("k"), time.Minute)
	if err != nil || !found {
		t.Fatalf("claim err=%v found=%v", err, found)
	}
	digest, _ := domain.CredentialAccessTestPlanDigest(lease.Plan)
	ref := adminmanage.CredentialAccessTestLeaseRef{TestID: test.ID, Attempt: 1, LeaseToken: leaseToken("k")}
	if _, err := f.store.StartCredentialAccessTest(ctx, cluster, head, ref, time.Minute); err != nil {
		t.Fatal(err)
	}
	// The lease is still live; only the test deadline has passed.
	mustExec(t, f.pool, `UPDATE credential_access_tests SET requested_at=clock_timestamp()-interval '2 seconds', deadline=clock_timestamp()-interval '1 second' WHERE test_id=$1`, test.ID)
	now := time.Now().UTC()
	result := domain.CredentialAccessTestResult{SchemaVersion: 1, TestID: test.ID, Attempt: 1, PlanDigest: digest.String(), Outcome: domain.CredentialAccessVerified, Summary: "sudo authenticated and cmsh listed 3 devices read-only on BCM 10.24.", BCMVersion: "10.24", DevicesListed: 3, StartedAt: now, CompletedAt: now.Add(time.Second)}
	completion, err := f.store.CompleteCredentialAccessTest(ctx, cluster, head, ref, result)
	if err != nil || !completion.Rejected || completion.Status != domain.CredentialAccessTestExpired {
		t.Fatalf("overdue result err=%v completion=%+v", err, completion)
	}
	tests, err := f.store.ListCredentialAccessTests(ctx, f.clusterID, subject, 10)
	if expired := findTest(tests, test.ID); err != nil || expired.Status != domain.CredentialAccessTestExpired || expired.OutcomeCode != "EXPIRED" || expired.CompletedAt == nil || expired.DevicesListed != 0 || expired.BCMVersion != "" {
		t.Fatalf("overdue projection err=%v tests=%+v", err, tests)
	}
	var reasons string
	if err := f.pool.QueryRow(ctx, `SELECT string_agg(reason_code, '|') FROM credential_access_test_events WHERE test_id=$1 AND event_kind='ACCESS_TEST_RESULT_REJECTED'`, test.ID).Scan(&reasons); err != nil || !strings.Contains(reasons, "DEADLINE_PASSED") {
		t.Fatalf("deadline rejection audit missing: %q %v", reasons, err)
	}
	var attemptStatus, attemptOutcome string
	if err := f.pool.QueryRow(ctx, `SELECT status, outcome_code FROM credential_access_test_attempts WHERE test_id=$1 AND attempt=1`, test.ID).Scan(&attemptStatus, &attemptOutcome); err != nil || attemptStatus != "REJECTED" {
		t.Fatalf("attempt status=%q outcome=%q err=%v", attemptStatus, attemptOutcome, err)
	}
	assertNoCanaryInDatabase(t, f)
}

func TestCredentialAccessTestOverdueRequestExpiresWithoutAnyCollector(t *testing.T) {
	f, subject, credential := accessTestTarget(t)
	ctx := context.Background()
	backdate := func(id string) {
		t.Helper()
		mustExec(t, f.pool, `UPDATE credential_access_tests SET requested_at=clock_timestamp()-interval '2 seconds', deadline=clock_timestamp()-interval '1 second' WHERE test_id=$1`, id)
	}
	overdue, err := f.store.RequestCredentialAccessTest(ctx, f.clusterID, subject, credential.ID, credential.Version, accessTestAudit(adminmanage.EventAccessTestRequested, subject))
	if err != nil {
		t.Fatal(err)
	}
	backdate(overdue.ID)
	// No collector exists at all: the overdue request must not keep holding the
	// live-test index against a new request.
	fresh, err := f.store.RequestCredentialAccessTest(ctx, f.clusterID, subject, credential.ID, credential.Version, accessTestAudit(adminmanage.EventAccessTestRequested, subject))
	if err != nil {
		t.Fatalf("request after overdue test err=%v", err)
	}
	tests, err := f.store.ListCredentialAccessTests(ctx, f.clusterID, subject, 10)
	if expired := findTest(tests, overdue.ID); err != nil || expired.Status != domain.CredentialAccessTestExpired || expired.OutcomeCode != "EXPIRED" {
		t.Fatalf("expiry on request err=%v tests=%+v", err, tests)
	}
	if live := findTest(tests, fresh.ID); live.Status != domain.CredentialAccessTestRequested {
		t.Fatalf("fresh request status=%+v", live)
	}
	// Listing alone expires overdue work, so the UI never shows a stuck request.
	backdate(fresh.ID)
	tests, err = f.store.ListCredentialAccessTests(ctx, f.clusterID, subject, 10)
	if expired := findTest(tests, fresh.ID); err != nil || expired.Status != domain.CredentialAccessTestExpired {
		t.Fatalf("expiry on list err=%v tests=%+v", err, tests)
	}
	var expiries int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM credential_access_test_events WHERE event_kind='ACCESS_TEST_EXPIRED' AND reason_code='DEADLINE' AND cluster_id=$1`, f.clusterID).Scan(&expiries); err != nil || expiries != 2 {
		t.Fatalf("expiry audit count=%d err=%v", expiries, err)
	}
}

// insertCollectorWithCapabilities is insertCollector with an explicit
// capability set, so a collector that advertises only one of the two reviewed
// operations can be exercised against work that needs the other.
func insertCollectorWithCapabilities(t *testing.T, f credentialFixture, id, clusterID string, capabilities ...string) domain.CollectorID {
	t.Helper()
	mustExec(t, f.pool, `INSERT INTO collectors(collector_id,cluster_id,display_name,status,version,build_commit,protocol_min,protocol_max,operating_system,architecture) VALUES($1,$2,$1,'ACTIVE','test','test',1,2,'linux','amd64')`, id, clusterID)
	for _, capability := range capabilities {
		mustExec(t, f.pool, `INSERT INTO collector_capabilities(collector_id,capability,version) VALUES($1,$2,'1')`, id, capability)
	}
	return domain.CollectorID(id)
}

func discoveryDevices() []domain.CredentialAccessDevice {
	return []domain.CredentialAccessDevice{
		{Type: "HeadNode", Hostname: "fixture1-zone1-headnode", Status: "[ UP ]"},
		{Type: "PhysicalNode", Hostname: "node001", Status: "[ UP ]"},
		{Type: "PhysicalNode", Hostname: "node002", Status: "[ DOWN ]"},
	}
}

func TestCredentialInventoryDiscoveryRetainsBoundedListingUnderTheSameAuthority(t *testing.T) {
	f, subject, credential := accessTestTarget(t)
	ctx := context.Background()
	cluster := domain.ClusterID(f.clusterID)
	stamp := fmt.Sprint(time.Now().UnixNano())
	// One collector advertises only the access test; the other advertises
	// both reviewed operations, as a deployed head does.
	testOnly := insertCollectorWithCapabilities(t, f, "testonly-"+stamp, f.clusterID, domain.CredentialAccessTestOperation)
	head := insertCollectorWithCapabilities(t, f, "head-"+stamp, f.clusterID, domain.CredentialAccessOperations()...)
	bindTarget(t, f, "fixture1-zone1-headnode", testOnly)
	bindTarget(t, f, "fixture1-zone1-headnode", head)

	discovery, err := f.store.RequestCredentialInventoryDiscovery(ctx, f.clusterID, subject, credential.ID, credential.Version, accessTestAudit(adminmanage.EventAccessTestRequested, subject))
	if err != nil || discovery.Operation != domain.CredentialInventoryDiscoveryOperation || discovery.Status != domain.CredentialAccessTestRequested {
		t.Fatalf("request err=%v discovery=%+v", err, discovery)
	}
	if _, err := f.store.RequestCredentialAccessTest(ctx, f.clusterID, subject, credential.ID, credential.Version, accessTestAudit(adminmanage.EventAccessTestRequested, subject)); !errors.Is(err, adminmanage.ErrConflict) {
		t.Fatalf("an access test was scheduled beside a live discovery: %v", err)
	}
	if _, err := f.store.RequestCredentialInventoryDiscovery(ctx, f.clusterID, "stranger", credential.ID, credential.Version, accessTestAudit(adminmanage.EventAccessTestRequested, "stranger")); !errors.Is(err, adminmanage.ErrCredentialAccessDenied) {
		t.Fatalf("ungranted discovery request err=%v", err)
	}
	// Capability for the other operation is not authority for this one: the
	// bound, active, protocol-2 collector must see no work at all.
	if _, found, err := f.store.ClaimCredentialAccessTest(ctx, cluster, testOnly, leaseToken("t"), time.Minute); err != nil || found {
		t.Fatalf("access-test-only collector claimed a discovery: found=%v err=%v", found, err)
	}

	token := leaseToken("i")
	lease, found, err := f.store.ClaimCredentialAccessTest(ctx, cluster, head, token, time.Minute)
	if err != nil || !found || lease.Plan.Operation != domain.CredentialInventoryDiscoveryOperation || lease.Plan.TestID != discovery.ID {
		t.Fatalf("claim err=%v found=%v lease=%+v", err, found, lease)
	}
	digest, err := domain.CredentialAccessTestPlanDigest(lease.Plan)
	if err != nil {
		t.Fatal(err)
	}
	ref := adminmanage.CredentialAccessTestLeaseRef{TestID: discovery.ID, Attempt: 1, LeaseToken: token}
	if _, err := f.store.StartCredentialAccessTest(ctx, cluster, head, ref, time.Minute); err != nil {
		t.Fatal(err)
	}
	// A collector that lacks the discovery capability cannot be delivered for
	// it either, even holding a stolen lease token.
	if _, err := f.store.DeliverCredentialForAccessTest(ctx, cluster, testOnly, ref, digest); !errors.Is(err, adminmanage.ErrAccessTestLeaseInvalid) && !errors.Is(err, adminmanage.ErrAccessTestCollectorIncompatible) {
		t.Fatalf("delivery to an incapable collector err=%v", err)
	}
	delivered, err := f.store.DeliverCredentialForAccessTest(ctx, cluster, head, ref, digest)
	if err != nil || string(delivered.SudoPassword) != accessTestCanary {
		t.Fatalf("delivery err=%v", err)
	}
	delivered.Destroy()

	now := time.Now().UTC()
	devices := discoveryDevices()
	result := domain.CredentialAccessTestResult{
		SchemaVersion: 1, TestID: discovery.ID, Attempt: 1, PlanDigest: digest.String(), Outcome: domain.CredentialAccessVerified,
		Summary: "cmsh listed 3 devices read-only on BCM 10.0 and the inventory rows were retained.", BCMVersion: "10.0",
		DevicesListed: 3, StartedAt: now, CompletedAt: now.Add(time.Second), Devices: devices,
	}
	// A count that disagrees with the retained rows is refused; nothing is
	// written and the test stays claimable for its remaining attempt.
	mismatched := result
	mismatched.DevicesListed = 4
	if _, err := f.store.CompleteCredentialAccessTest(ctx, cluster, head, ref, mismatched); !errors.Is(err, adminmanage.ErrAccessTestLeaseInvalid) && !errors.Is(err, adminmanage.ErrInvalid) {
		t.Fatalf("mismatched device count accepted: %v", err)
	}
	var written int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM credential_access_test_devices WHERE test_id=$1`, discovery.ID).Scan(&written); err != nil || written != 0 {
		t.Fatalf("rejected completion wrote %d rows: %v", written, err)
	}
	completion, err := f.store.CompleteCredentialAccessTest(ctx, cluster, head, ref, result)
	if err != nil || completion.Status != domain.CredentialAccessTestSucceeded || completion.Rejected {
		t.Fatalf("completion err=%v %+v", err, completion)
	}

	// Rows are persisted in the order the head reported them.
	rows, err := f.pool.Query(ctx, `SELECT ordinal, device_type, hostname, status FROM credential_access_test_devices WHERE test_id=$1 ORDER BY ordinal`, discovery.ID)
	if err != nil {
		t.Fatal(err)
	}
	persisted := make([]domain.CredentialAccessDevice, 0)
	for rows.Next() {
		var ordinal int
		var device domain.CredentialAccessDevice
		if err := rows.Scan(&ordinal, &device.Type, &device.Hostname, &device.Status); err != nil {
			t.Fatal(err)
		}
		if ordinal != len(persisted) {
			t.Fatalf("ordinal %d out of order at position %d", ordinal, len(persisted))
		}
		persisted = append(persisted, device)
	}
	rows.Close()
	if len(persisted) != 3 || persisted[0] != devices[0] || persisted[2] != devices[2] {
		t.Fatalf("persisted rows %+v", persisted)
	}

	latest, found, err := f.store.LatestInventoryDiscovery(ctx, f.clusterID, subject)
	if err != nil || !found || latest.TestID != discovery.ID || len(latest.Devices) != 3 || latest.Devices[1] != devices[1] || !latest.CredentialCurrent || latest.BCMVersion != "10.0" || latest.CredentialVersion != credential.Version {
		t.Fatalf("latest err=%v found=%v %+v", err, found, latest)
	}
	if _, _, err := f.store.LatestInventoryDiscovery(ctx, f.clusterID, "stranger"); !errors.Is(err, adminmanage.ErrCredentialAccessDenied) {
		t.Fatalf("ungranted latest err=%v", err)
	}
	if _, found, err := f.store.LatestInventoryDiscovery(ctx, f.foreignID, subject); !errors.Is(err, adminmanage.ErrCredentialAccessDenied) && found {
		t.Fatalf("foreign cluster latest err=%v found=%v", err, found)
	}
	listed, err := f.store.ListCredentialAccessTests(ctx, f.clusterID, subject, 10)
	if err != nil || len(listed) != 1 || listed[0].Operation != domain.CredentialInventoryDiscoveryOperation || len(listed[0].Devices) != 3 || listed[0].DevicesListed != 3 {
		t.Fatalf("list err=%v tests=%+v", err, listed)
	}

	// Replacing the credential makes the retained listing visibly stale.
	replaced, err := putCredential(f, ctx, f.clusterID, subject, "fixture1-zone1-headnode", "fixture_user_1", "", "replacement-"+accessTestCanary, credential.Version, credential.ID, "replace-"+fmt.Sprint(time.Now().UnixNano()))
	if err != nil {
		t.Fatal(err)
	}
	stale, found, err := f.store.LatestInventoryDiscovery(ctx, f.clusterID, subject)
	if err != nil || !found || stale.CredentialCurrent || len(stale.Devices) != 3 {
		t.Fatalf("stale latest err=%v found=%v %+v", err, found, stale)
	}

	// An access test for the replacement must still refuse to carry rows.
	accessTest, err := f.store.RequestCredentialAccessTest(ctx, f.clusterID, subject, replaced.ID, replaced.Version, accessTestAudit(adminmanage.EventAccessTestRequested, subject))
	if err != nil {
		t.Fatal(err)
	}
	accessLease, found, err := f.store.ClaimCredentialAccessTest(ctx, cluster, head, leaseToken("j"), time.Minute)
	if err != nil || !found || accessLease.Plan.Operation != domain.CredentialAccessTestOperation {
		t.Fatalf("access test claim err=%v found=%v lease=%+v", err, found, accessLease)
	}
	accessDigest, err := domain.CredentialAccessTestPlanDigest(accessLease.Plan)
	if err != nil {
		t.Fatal(err)
	}
	accessRef := adminmanage.CredentialAccessTestLeaseRef{TestID: accessTest.ID, Attempt: 1, LeaseToken: leaseToken("j")}
	withDevices := domain.CredentialAccessTestResult{
		SchemaVersion: 1, TestID: accessTest.ID, Attempt: 1, PlanDigest: accessDigest.String(), Outcome: domain.CredentialAccessVerified,
		Summary: "sudo authenticated and cmsh listed 3 devices read-only on BCM 10.0.", BCMVersion: "10.0",
		DevicesListed: 3, StartedAt: now, CompletedAt: now.Add(time.Second), Devices: devices,
	}
	if _, err := f.store.CompleteCredentialAccessTest(ctx, cluster, head, accessRef, withDevices); !errors.Is(err, adminmanage.ErrAccessTestLeaseInvalid) && !errors.Is(err, adminmanage.ErrInvalid) {
		t.Fatalf("access test result carrying device rows accepted: %v", err)
	}
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM credential_access_test_devices WHERE test_id=$1`, accessTest.ID).Scan(&written); err != nil || written != 0 {
		t.Fatalf("access test wrote %d device rows: %v", written, err)
	}
	// The latest discovery is unchanged by the refused access-test result.
	if again, found, err := f.store.LatestInventoryDiscovery(ctx, f.clusterID, subject); err != nil || !found || again.TestID != discovery.ID {
		t.Fatalf("latest changed after a refused access test: err=%v found=%v %+v", err, found, again)
	}
	assertNoCanaryInDatabase(t, f)
}

func TestCredentialInventoryDiscoveryCancelExpiryAndAbsentLatest(t *testing.T) {
	f, subject, credential := accessTestTarget(t)
	ctx := context.Background()
	cluster := domain.ClusterID(f.clusterID)
	head := insertCollectorWithCapabilities(t, f, "head-"+fmt.Sprint(time.Now().UnixNano()), f.clusterID, domain.CredentialAccessOperations()...)
	bindTarget(t, f, "fixture1-zone1-headnode", head)

	// No discovery has ever succeeded: absence is reported as a clean miss.
	if _, found, err := f.store.LatestInventoryDiscovery(ctx, f.clusterID, subject); err != nil || found {
		t.Fatalf("absent latest err=%v found=%v", err, found)
	}

	cancelled, err := f.store.RequestCredentialInventoryDiscovery(ctx, f.clusterID, subject, credential.ID, credential.Version, accessTestAudit(adminmanage.EventAccessTestRequested, subject))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.CancelCredentialAccessTest(ctx, f.clusterID, subject, cancelled.ID, accessTestAudit(adminmanage.EventAccessTestCancelled, subject)); err != nil {
		t.Fatal(err)
	}
	if _, found, err := f.store.ClaimCredentialAccessTest(ctx, cluster, head, leaseToken("c"), time.Minute); err != nil || found {
		t.Fatalf("cancelled discovery claimed: found=%v err=%v", found, err)
	}

	overdue, err := f.store.RequestCredentialInventoryDiscovery(ctx, f.clusterID, subject, credential.ID, credential.Version, accessTestAudit(adminmanage.EventAccessTestRequested, subject))
	if err != nil {
		t.Fatal(err)
	}
	mustExec(t, f.pool, `UPDATE credential_access_tests SET requested_at=clock_timestamp()-interval '2 seconds', deadline=clock_timestamp()-interval '1 second' WHERE test_id=$1`, overdue.ID)
	if _, found, err := f.store.ClaimCredentialAccessTest(ctx, cluster, head, leaseToken("d"), time.Minute); err != nil || found {
		t.Fatalf("overdue discovery claimed: found=%v err=%v", found, err)
	}
	tests, err := f.store.ListCredentialAccessTests(ctx, f.clusterID, subject, 10)
	if expired := findTest(tests, overdue.ID); err != nil || expired.Status != domain.CredentialAccessTestExpired || len(expired.Devices) != 0 {
		t.Fatalf("expired discovery projection err=%v tests=%+v", err, tests)
	}
	if terminated := findTest(tests, cancelled.ID); terminated.Status != domain.CredentialAccessTestCancelled || terminated.Operation != domain.CredentialInventoryDiscoveryOperation {
		t.Fatalf("cancelled discovery projection %+v", terminated)
	}
	// Neither a cancelled nor an expired discovery is ever the latest one.
	if _, found, err := f.store.LatestInventoryDiscovery(ctx, f.clusterID, subject); err != nil || found {
		t.Fatalf("terminal-but-unsuccessful discovery surfaced as latest: found=%v err=%v", found, err)
	}
	assertNoCanaryInDatabase(t, f)
}
