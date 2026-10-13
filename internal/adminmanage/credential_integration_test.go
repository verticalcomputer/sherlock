//go:build integration

package adminmanage_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/adminmanage"
)

type credentialFixture struct {
	pool       *pgxpool.Pool
	store      *adminmanage.PostgresStore
	clusterID  string
	foreignID  string
	actor      string
	credential string
}

func newCredentialFixture(t *testing.T, maxConns int32) credentialFixture {
	t.Helper()
	dsn := os.Getenv("SHERLOCK_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("SHERLOCK_TEST_DATABASE_URL is not set; use an isolated migrated test database")
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("gp20_credentials_%d", time.Now().UnixNano())
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		_ = admin.Close(ctx)
		t.Fatalf("create private credential database: %v", err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec(ctx, "DROP DATABASE "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)"); err != nil {
			t.Errorf("drop private credential database: %v", err)
		}
		_ = admin.Close(ctx)
	})
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.Database = name
	if maxConns > 0 {
		config.MaxConns = maxConns
	}
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	files, err := filepath.Glob("../../migrations/*.up.sql")
	if err != nil || len(files) == 0 {
		t.Fatalf("credential migrations: %v", err)
	}
	sort.Strings(files)
	for _, file := range files {
		body, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		if _, err := pool.Exec(ctx, string(body)); err != nil {
			t.Fatalf("apply %s: %v", file, err)
		}
	}

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	fixture := credentialFixture{
		pool:       pool,
		clusterID:  "gp20-cluster-" + suffix,
		foreignID:  "gp20-foreign-" + suffix,
		actor:      "operator-" + suffix,
		credential: "credential-secret-" + suffix,
	}
	mustExec(t, pool, `INSERT INTO clusters (cluster_id,display_name,created_at) VALUES ($1,$2,$3),($4,$5,$3)`,
		fixture.clusterID, "GP20 test cluster", time.Now().UTC(), fixture.foreignID, "GP20 foreign cluster")
	ring := credentialRing(t, "v1", 0x11)
	fixture.store = credentialStore(t, pool, ring)
	return fixture
}

func credentialRing(t *testing.T, active string, fill byte) *adminmanage.CredentialKeyring {
	t.Helper()
	ring, err := adminmanage.NewCredentialKeyring(active, map[string][]byte{active: bytes.Repeat([]byte{fill}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	return ring
}

func credentialStore(t *testing.T, pool *pgxpool.Pool, ring *adminmanage.CredentialKeyring) *adminmanage.PostgresStore {
	t.Helper()
	store, err := adminmanage.NewPostgresStore(pool, adminmanage.WithCredentialKeyring(ring))
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func credentialAudit(id, kind, reason, actor string, at time.Time) adminmanage.MutationAudit {
	return adminmanage.MutationAudit{
		EventID: id, EventKind: kind, ReasonCode: reason,
		SessionFingerprint: bytes.Repeat([]byte{0x42}, 32), RequestID: id + "-request",
		OccurredAt: at, ActorSubject: actor,
	}
}

func grantCredentialAdmin(t *testing.T, fixture credentialFixture, subject string) {
	t.Helper()
	if err := fixture.store.GrantCredentialAdmin(context.Background(), fixture.clusterID, subject, fixture.actor, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
}

func putCredential(f credentialFixture, ctx context.Context, cluster, subject, host, username, ssh, sudo string, version int64, expectedID, auditID string) (adminmanage.CredentialMetadata, error) {
	return f.store.PutCredential(ctx, cluster, subject, adminmanage.CredentialInput{
		Host: host, Purpose: "BCM_READ_ONLY", Username: username,
		SSHPassword: []byte(ssh), SudoPassword: []byte(sudo),
		ExpectedVersion: version, ExpectedCredentialID: expectedID,
	}, credentialAudit(auditID, adminmanage.EventCredentialCreated, "CREDENTIAL_ENROLLED", subject, time.Now().UTC()))
}

func putCredentialWithAudit(f credentialFixture, ctx context.Context, cluster, subject, host, username, ssh, sudo string, version int64, expectedID, auditID, kind string) (adminmanage.CredentialMetadata, error) {
	return f.store.PutCredential(ctx, cluster, subject, adminmanage.CredentialInput{
		Host: host, Purpose: "BCM_READ_ONLY", Username: username,
		SSHPassword: []byte(ssh), SudoPassword: []byte(sudo),
		ExpectedVersion: version, ExpectedCredentialID: expectedID,
	}, credentialAudit(auditID, kind, "CREDENTIAL_ENROLLED", subject, time.Now().UTC()))
}

func TestCredentialPostgresLifecycleBindsIdentityAndLeavesNoPlaintext(t *testing.T) {
	f := newCredentialFixture(t, 0)
	subject := "credential-admin-" + fmt.Sprintf("%d", time.Now().UnixNano())
	grantCredentialAdmin(t, f, subject)

	first, err := putCredential(f, context.Background(), f.clusterID, subject, "head-a", "operator", "ssh-secret-a", f.credential, 0, "", "gp20-create-"+fmt.Sprint(time.Now().UnixNano()))
	if err != nil {
		t.Fatal(err)
	}
	if first.Version != 1 || first.Status != "ACTIVE" || first.KeyVersion != "v1" || first.ClusterID != f.clusterID || first.Username != "operator" {
		t.Fatalf("unexpected credential metadata: %+v", first)
	}
	if strings.Contains(fmt.Sprintf("%+v", first), "secret") {
		t.Fatal("credential metadata contains a secret marker")
	}

	var ciphertext, nonce []byte
	if err := f.pool.QueryRow(context.Background(), `SELECT ciphertext,nonce FROM cluster_credentials WHERE credential_id=$1`, first.ID).Scan(&ciphertext, &nonce); err != nil {
		t.Fatal(err)
	}
	if len(ciphertext) < 16 || len(nonce) != 12 || bytes.Contains(ciphertext, []byte(f.credential)) || bytes.Contains(ciphertext, []byte("ssh-secret-a")) {
		t.Fatal("persisted credential contains plaintext or invalid authenticated ciphertext")
	}

	resolved, err := f.store.ResolveCredential(context.Background(), adminmanage.CredentialReference{ID: first.ID, ClusterID: f.clusterID})
	if err != nil {
		t.Fatal(err)
	}
	if string(resolved.SSHPassword) != "ssh-secret-a" || string(resolved.SudoPassword) != f.credential {
		resolved.Destroy()
		t.Fatal("resolved credential did not match the enrolled secret")
	}
	resolved.Destroy()

	if _, err := f.store.ResolveCredential(context.Background(), adminmanage.CredentialReference{ID: first.ID, ClusterID: f.foreignID}); !errors.Is(err, adminmanage.ErrNotFound) {
		t.Fatalf("foreign cluster reference err=%v, want ErrNotFound", err)
	}
	if _, err := f.store.ResolveCredential(context.Background(), adminmanage.CredentialReference{ID: "cred_tampered" + first.ID[5:], ClusterID: f.clusterID}); err == nil {
		t.Fatal("unknown credential identity resolved")
	}

	// Changing an authenticated metadata field must make the ciphertext unusable.
	mustExec(t, f.pool, `UPDATE cluster_credentials SET username='tampered-user' WHERE credential_id=$1`, first.ID)
	if _, err := f.store.ResolveCredential(context.Background(), adminmanage.CredentialReference{ID: first.ID, ClusterID: f.clusterID}); err == nil {
		t.Fatal("metadata tampering was accepted")
	}
	mustExec(t, f.pool, `UPDATE cluster_credentials SET username='operator' WHERE credential_id=$1`, first.ID)

	rows, err := f.store.ListCredentialMetadata(context.Background(), f.clusterID, subject)
	if err != nil || len(rows) != 1 || rows[0].ID != first.ID {
		t.Fatalf("metadata listing err=%v rows=%+v", err, rows)
	}

	var auditText string
	if err := f.pool.QueryRow(context.Background(), `SELECT string_agg(event_kind||':'||outcome||':'||reason_code||':'||actor_subject||':'||cluster_id||':'||credential_id||':'||credential_version::text, '|') FROM admin_credential_audit_events WHERE cluster_id=$1`, f.clusterID).Scan(&auditText); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(auditText, f.credential) || strings.Contains(auditText, "ssh-secret-a") || strings.Contains(auditText, "sudo_password") {
		t.Fatal("credential audit contains a secret marker")
	}
	if !strings.Contains(auditText, adminmanage.EventCredentialCreated+":SUCCEEDED") {
		t.Fatalf("successful credential audit missing: %s", auditText)
	}
}

func TestCredentialPostgresReplaceRevokeStaleAndFreshEnrollment(t *testing.T) {
	f := newCredentialFixture(t, 0)
	subject := "lifecycle-admin-" + fmt.Sprint(time.Now().UnixNano())
	grantCredentialAdmin(t, f, subject)
	first, err := putCredential(f, context.Background(), f.clusterID, subject, "head-b", "operator", "ssh-one", "sudo-one", 0, "", "gp20-life-create")
	if err != nil {
		t.Fatal(err)
	}
	replaced, err := putCredentialWithAudit(f, context.Background(), f.clusterID, subject, "head-b", "operator", "ssh-two", "sudo-two", first.Version, first.ID, "gp20-life-replace", adminmanage.EventCredentialReplaced)
	if err != nil {
		t.Fatal(err)
	}
	if replaced.Version != 2 || replaced.ID == first.ID {
		t.Fatalf("replacement metadata: %+v", replaced)
	}

	var oldStatus string
	var oldCiphertext, oldNonce []byte
	var replacedBy string
	if err := f.pool.QueryRow(context.Background(), `SELECT status,ciphertext,nonce,COALESCE(replaced_by,'') FROM cluster_credentials WHERE credential_id=$1`, first.ID).Scan(&oldStatus, &oldCiphertext, &oldNonce, &replacedBy); err != nil {
		t.Fatal(err)
	}
	if oldStatus != "REVOKED" || len(oldCiphertext) != 0 || len(oldNonce) != 0 || replacedBy != replaced.ID {
		t.Fatalf("replaced credential was not cleared: status=%s ciphertext=%d nonce=%d replaced_by=%s", oldStatus, len(oldCiphertext), len(oldNonce), replacedBy)
	}

	if _, err := putCredentialWithAudit(f, context.Background(), f.clusterID, subject, "head-b", "operator", "stale", "stale-sudo", first.Version, first.ID, "gp20-life-stale", adminmanage.EventCredentialReplaced); !errors.Is(err, adminmanage.ErrConflict) {
		t.Fatalf("stale replacement err=%v, want ErrConflict", err)
	}
	if err := f.store.RevokeCredential(context.Background(), f.clusterID, subject, replaced.ID, replaced.Version, credentialAudit("gp20-life-revoke", adminmanage.EventCredentialRevoked, "CREDENTIAL_REVOKED", subject, time.Now().UTC())); err != nil {
		t.Fatal(err)
	}
	var revokedVersion int64
	if err := f.pool.QueryRow(context.Background(), `SELECT credential_version FROM cluster_credentials WHERE credential_id=$1`, replaced.ID).Scan(&revokedVersion); err != nil {
		t.Fatal(err)
	}
	if revokedVersion != 3 {
		t.Fatalf("revoked credential version=%d, want 3", revokedVersion)
	}
	if _, err := f.store.ResolveCredential(context.Background(), adminmanage.CredentialReference{ID: replaced.ID, ClusterID: f.clusterID}); !errors.Is(err, adminmanage.ErrNotFound) {
		t.Fatalf("revoked credential resolved with err=%v", err)
	}
	if _, err := putCredentialWithAudit(f, context.Background(), f.clusterID, subject, "head-b", "operator", "stale-after-revoke", "stale-sudo", replaced.Version, replaced.ID, "gp20-life-stale-revoke", adminmanage.EventCredentialReplaced); !errors.Is(err, adminmanage.ErrConflict) {
		t.Fatalf("stale post-revoke enrollment err=%v, want ErrConflict", err)
	}
	fresh, err := putCredentialWithAudit(f, context.Background(), f.clusterID, subject, "head-b", "operator", "ssh-three", "sudo-three", revokedVersion, replaced.ID, "gp20-life-fresh", adminmanage.EventCredentialReplaced)
	if err != nil || fresh.Version != 4 {
		t.Fatalf("fresh enrollment metadata=%+v err=%v", fresh, err)
	}
	var active, revoked int
	if err := f.pool.QueryRow(context.Background(), `SELECT count(*) FILTER (WHERE status='ACTIVE'),count(*) FILTER (WHERE status='REVOKED') FROM cluster_credentials WHERE cluster_id=$1 AND host='head-b'`, f.clusterID).Scan(&active, &revoked); err != nil {
		t.Fatal(err)
	}
	if active != 1 || revoked != 2 {
		t.Fatalf("credential lifecycle counts active=%d revoked=%d", active, revoked)
	}
	var rejected, succeeded int
	if err := f.pool.QueryRow(context.Background(), `SELECT count(*) FILTER (WHERE outcome='REJECTED'),count(*) FILTER (WHERE outcome='SUCCEEDED') FROM admin_credential_audit_events WHERE cluster_id=$1`, f.clusterID).Scan(&rejected, &succeeded); err != nil {
		t.Fatal(err)
	}
	if rejected != 2 || succeeded != 4 {
		t.Fatalf("audit lifecycle counts rejected=%d succeeded=%d", rejected, succeeded)
	}
}

func TestCredentialPostgresDefaultDenyForeignClusterRevokedGrantAndRemovedCluster(t *testing.T) {
	f := newCredentialFixture(t, 0)
	subject := "scope-admin-" + fmt.Sprint(time.Now().UnixNano())
	allowed, err := f.store.CredentialAdminAllowed(context.Background(), f.clusterID, subject)
	if err != nil || allowed {
		t.Fatalf("default grant allowed=%t err=%v", allowed, err)
	}
	if _, err := putCredential(f, context.Background(), f.clusterID, subject, "head-c", "operator", "ssh", "sudo", 0, "", "gp20-scope-denied"); !errors.Is(err, adminmanage.ErrCredentialAccessDenied) {
		t.Fatalf("default-deny put err=%v", err)
	}
	grantCredentialAdmin(t, f, subject)
	first, err := putCredential(f, context.Background(), f.clusterID, subject, "head-c", "operator", "ssh", "sudo", 0, "", "gp20-scope-create")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := putCredential(f, context.Background(), f.foreignID, subject, "head-c", "operator", "foreign-ssh", "foreign-sudo", 0, "", "gp20-scope-foreign"); !errors.Is(err, adminmanage.ErrCredentialAccessDenied) {
		t.Fatalf("foreign cluster put err=%v", err)
	}
	if err := f.store.RevokeCredentialAdmin(context.Background(), f.clusterID, subject, f.actor, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.ListCredentialMetadata(context.Background(), f.clusterID, subject); !errors.Is(err, adminmanage.ErrCredentialAccessDenied) {
		t.Fatalf("revoked grant list err=%v", err)
	}
	if _, err := putCredential(f, context.Background(), f.clusterID, subject, "head-c", "operator", "new-ssh", "new-sudo", first.Version, first.ID, "gp20-scope-revoked"); !errors.Is(err, adminmanage.ErrCredentialAccessDenied) {
		t.Fatalf("revoked grant put err=%v", err)
	}
	removedAt := time.Now().UTC()
	mustExec(t, f.pool, `UPDATE clusters SET removed_at=$2 WHERE cluster_id=$1`, f.clusterID, removedAt)
	if err := f.store.GrantCredentialAdmin(context.Background(), f.clusterID, "other-subject", f.actor, removedAt.Add(time.Second)); !errors.Is(err, adminmanage.ErrNotFound) {
		t.Fatalf("removed cluster grant err=%v, want ErrNotFound", err)
	}
	if _, err := f.store.ResolveCredential(context.Background(), adminmanage.CredentialReference{ID: first.ID, ClusterID: f.clusterID}); !errors.Is(err, adminmanage.ErrNotFound) {
		t.Fatalf("removed cluster resolve err=%v, want ErrNotFound", err)
	}
}

func TestCredentialPostgresConcurrentCreateReplaceAndRevokeSerialize(t *testing.T) {
	f := newCredentialFixture(t, 0)
	subject := "concurrent-admin-" + fmt.Sprint(time.Now().UnixNano())
	grantCredentialAdmin(t, f, subject)
	put := func(host, ssh, sudo string, version int64, expectedID, id, kind string) (adminmanage.CredentialMetadata, error) {
		return putCredentialWithAudit(f, context.Background(), f.clusterID, subject, host, "operator", ssh, sudo, version, expectedID, id, kind)
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	metadata := make(chan adminmanage.CredentialMetadata, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			item, err := put("head-concurrent", fmt.Sprintf("ssh-%d", i), fmt.Sprintf("sudo-%d", i), 0, "", fmt.Sprintf("gp20-concurrent-create-%d", i), adminmanage.EventCredentialCreated)
			metadata <- item
			results <- err
		}(i)
	}
	wg.Wait()
	close(results)
	close(metadata)
	var winner adminmanage.CredentialMetadata
	successes, conflicts := 0, 0
	for err := range results {
		if err == nil {
			successes++
		} else if errors.Is(err, adminmanage.ErrConflict) {
			conflicts++
		} else {
			t.Fatalf("concurrent create err=%v", err)
		}
	}
	for item := range metadata {
		if item.ID != "" {
			winner = item
		}
	}
	if successes != 1 || conflicts != 1 || winner.ID == "" || winner.Version != 1 {
		t.Fatalf("concurrent create successes=%d conflicts=%d winner=%+v", successes, conflicts, winner)
	}

	results = make(chan error, 2)
	metadata = make(chan adminmanage.CredentialMetadata, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			item, err := put("head-concurrent", fmt.Sprintf("replace-ssh-%d", i), fmt.Sprintf("replace-sudo-%d", i), winner.Version, winner.ID, fmt.Sprintf("gp20-concurrent-replace-%d", i), adminmanage.EventCredentialReplaced)
			metadata <- item
			results <- err
		}(i)
	}
	wg.Wait()
	close(results)
	close(metadata)
	successes, conflicts = 0, 0
	for err := range results {
		if err == nil {
			successes++
		} else if errors.Is(err, adminmanage.ErrConflict) {
			conflicts++
		} else {
			t.Fatalf("concurrent replacement err=%v", err)
		}
	}
	for item := range metadata {
		if item.ID != "" {
			winner = item
		}
	}
	if successes != 1 || conflicts != 1 || winner.ID == "" || winner.Version != 2 {
		t.Fatalf("concurrent replacement successes=%d conflicts=%d winner=%+v", successes, conflicts, winner)
	}

	results = make(chan error, 2)
	go func() {
		results <- f.store.RevokeCredential(context.Background(), f.clusterID, subject, winner.ID, winner.Version, credentialAudit("gp20-concurrent-revoke", adminmanage.EventCredentialRevoked, "CREDENTIAL_REVOKED", subject, time.Now().UTC()))
	}()
	go func() {
		_, err := put("head-concurrent", "last-ssh", "last-sudo", winner.Version, winner.ID, "gp20-concurrent-final-replace", adminmanage.EventCredentialReplaced)
		results <- err
	}()
	successes, conflicts = 0, 0
	for i := 0; i < 2; i++ {
		err := <-results
		if err == nil {
			successes++
		} else if errors.Is(err, adminmanage.ErrConflict) {
			conflicts++
		} else {
			t.Fatalf("concurrent revoke/replace err=%v", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("concurrent revoke/replace successes=%d conflicts=%d", successes, conflicts)
	}
	var active int
	if err := f.pool.QueryRow(context.Background(), `SELECT count(*) FROM cluster_credentials WHERE cluster_id=$1 AND host='head-concurrent' AND status='ACTIVE'`, f.clusterID).Scan(&active); err != nil {
		t.Fatal(err)
	}
	if active > 1 {
		t.Fatalf("concurrent operations left %d active credentials", active)
	}
}

func TestCredentialPostgresRotationSuccessAndTamperRollback(t *testing.T) {
	f := newCredentialFixture(t, 0)
	subject := "rotation-admin-" + fmt.Sprint(time.Now().UnixNano())
	grantCredentialAdmin(t, f, subject)
	first, err := putCredential(f, context.Background(), f.clusterID, subject, "head-rotate-a", "operator", "rotate-ssh-a", "rotate-sudo-a", 0, "", "gp20-rotate-create-a")
	if err != nil {
		t.Fatal(err)
	}
	second, err := putCredential(f, context.Background(), f.clusterID, subject, "head-rotate-b", "operator", "rotate-ssh-b", "rotate-sudo-b", 0, "", "gp20-rotate-create-b")
	if err != nil {
		t.Fatal(err)
	}
	next, err := adminmanage.NewCredentialKeyring("v2", map[string][]byte{"v1": bytes.Repeat([]byte{0x11}, 32), "v2": bytes.Repeat([]byte{0x22}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.RotateCredentials(context.Background(), next, credentialAudit("gp20-rotate-success", adminmanage.EventCredentialKeyRotated, "CREDENTIAL_KEY_ROTATED", subject, time.Now().UTC())); err != nil {
		t.Fatal(err)
	}
	secretByID := map[string][2]string{
		first.ID:  {"rotate-ssh-a", "rotate-sudo-a"},
		second.ID: {"rotate-ssh-b", "rotate-sudo-b"},
	}
	ciphertextByID := make(map[string][]byte, 2)
	for _, item := range []adminmanage.CredentialMetadata{first, second} {
		var keyVersion string
		var ciphertext []byte
		if err := f.pool.QueryRow(context.Background(), `SELECT key_version,ciphertext FROM cluster_credentials WHERE credential_id=$1`, item.ID).Scan(&keyVersion, &ciphertext); err != nil {
			t.Fatal(err)
		}
		if keyVersion != "v2" {
			t.Fatalf("credential %s key version=%s, want v2", item.ID, keyVersion)
		}
		ciphertextByID[item.ID] = append([]byte(nil), ciphertext...)
	}

	// A fresh backend process with only the new key must recover the exact
	// secrets after rotation; this proves the durable key version is sufficient.
	restarted := credentialStore(t, f.pool, credentialRing(t, "v2", 0x22))
	for _, item := range []adminmanage.CredentialMetadata{first, second} {
		resolved, err := restarted.ResolveCredential(context.Background(), adminmanage.CredentialReference{ID: item.ID, ClusterID: f.clusterID})
		if err != nil {
			t.Fatal(err)
		}
		want := secretByID[item.ID]
		if string(resolved.SSHPassword) != want[0] || string(resolved.SudoPassword) != want[1] {
			resolved.Destroy()
			t.Fatalf("fresh store resolved unexpected secret for credential %s", item.ID)
		}
		resolved.Destroy()
	}

	secondCiphertext := append([]byte(nil), ciphertextByID[second.ID]...)
	secondCiphertext[len(secondCiphertext)-1] ^= 1
	mustExec(t, f.pool, `UPDATE cluster_credentials SET ciphertext=$2 WHERE credential_id=$1`, second.ID, secondCiphertext)
	third, err := adminmanage.NewCredentialKeyring("v3", map[string][]byte{"v2": bytes.Repeat([]byte{0x22}, 32), "v3": bytes.Repeat([]byte{0x33}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.RotateCredentials(context.Background(), third, credentialAudit("gp20-rotate-tampered", adminmanage.EventCredentialKeyRotated, "CREDENTIAL_KEY_ROTATED", subject, time.Now().UTC())); err == nil {
		t.Fatal("tampered credential rotation unexpectedly succeeded")
	}
	var versions int
	if err := f.pool.QueryRow(context.Background(), `SELECT count(*) FILTER (WHERE key_version='v2') FROM cluster_credentials WHERE credential_id IN ($1,$2)`, first.ID, second.ID).Scan(&versions); err != nil {
		t.Fatal(err)
	}
	if versions != 2 {
		t.Fatalf("tampered rotation partially committed %d v2 records", 2-versions)
	}
	// Restore the tamper so a database trigger can force a failure after the
	// rotation UPDATE has run and the audit INSERT is attempted.
	mustExec(t, f.pool, `UPDATE cluster_credentials SET ciphertext=$2 WHERE credential_id=$1`, second.ID, ciphertextByID[second.ID])
	mustExec(t, f.pool, `CREATE FUNCTION gp20_rotation_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.event_kind = 'CREDENTIAL_KEY_ROTATED' THEN RAISE EXCEPTION 'gp20 rotation rollback'; END IF; RETURN NEW; END $$`)
	mustExec(t, f.pool, `CREATE TRIGGER gp20_rotation_failure_trigger BEFORE INSERT ON admin_credential_audit_events FOR EACH ROW EXECUTE FUNCTION gp20_rotation_failure()`)
	if err := f.store.RotateCredentials(context.Background(), third, credentialAudit("gp20-rotate-trigger", adminmanage.EventCredentialKeyRotated, "CREDENTIAL_KEY_ROTATED", subject, time.Now().UTC())); err == nil {
		t.Fatal("audit-triggered rotation unexpectedly succeeded")
	}
	for _, item := range []adminmanage.CredentialMetadata{first, second} {
		var keyVersion string
		var ciphertext []byte
		if err := f.pool.QueryRow(context.Background(), `SELECT key_version,ciphertext FROM cluster_credentials WHERE credential_id=$1`, item.ID).Scan(&keyVersion, &ciphertext); err != nil {
			t.Fatal(err)
		}
		if keyVersion != "v2" || !bytes.Equal(ciphertext, ciphertextByID[item.ID]) {
			t.Fatalf("audit-triggered rotation committed credential %s: key=%s ciphertext_changed=%t", item.ID, keyVersion, !bytes.Equal(ciphertext, ciphertextByID[item.ID]))
		}
	}
	var rotationAudits int
	rows, err := f.pool.Query(context.Background(), `SELECT event_kind,outcome,reason_code,actor_subject,cluster_id,credential_id,credential_version,request_id FROM admin_credential_audit_events WHERE event_kind=$1 AND cluster_id=$2 ORDER BY credential_id`, adminmanage.EventCredentialKeyRotated, f.clusterID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var eventKind, outcome, reason, actor, cluster, credentialID, requestID string
		var version int64
		if err := rows.Scan(&eventKind, &outcome, &reason, &actor, &cluster, &credentialID, &version, &requestID); err != nil {
			t.Fatal(err)
		}
		if eventKind != adminmanage.EventCredentialKeyRotated || outcome != "SUCCEEDED" || reason != "CREDENTIAL_KEY_ROTATED" || actor != subject || cluster != f.clusterID || !strings.HasPrefix(credentialID, "cred_") || version < 1 || requestID != "gp20-rotate-success-request" {
			t.Fatalf("unexpected rotation audit facts: kind=%s outcome=%s reason=%s actor=%s cluster=%s credential=%s version=%d request=%s", eventKind, outcome, reason, actor, cluster, credentialID, version, requestID)
		}
		if strings.Contains(strings.Join([]string{eventKind, outcome, reason, actor, cluster, credentialID, requestID}, "|"), "rotate-sudo") || strings.Contains(strings.Join([]string{eventKind, outcome, reason, actor, cluster, credentialID, requestID}, "|"), "rotate-ssh") {
			t.Fatal("rotation audit contains a secret marker")
		}
		rotationAudits++
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if rotationAudits != 2 {
		t.Fatalf("rotation audit count=%d, want 2", rotationAudits)
	}
}

func TestCredentialPostgresMissingAndWrongKeyAndSingleConnectionRejectionAudit(t *testing.T) {
	f := newCredentialFixture(t, 0)
	subject := "key-admin-" + fmt.Sprint(time.Now().UnixNano())
	grantCredentialAdmin(t, f, subject)
	first, err := putCredential(f, context.Background(), f.clusterID, subject, "head-key", "operator", "key-ssh", "key-sudo", 0, "", "gp20-key-create")
	if err != nil {
		t.Fatal(err)
	}
	disabled, err := adminmanage.NewPostgresStore(f.pool)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := disabled.ListCredentialMetadata(context.Background(), f.clusterID, subject); !errors.Is(err, adminmanage.ErrCredentialKeyUnavailable) {
		t.Fatalf("missing key list err=%v", err)
	}
	wrong := credentialStore(t, f.pool, credentialRing(t, "v1", 0x99))
	if _, err := wrong.ResolveCredential(context.Background(), adminmanage.CredentialReference{ID: first.ID, ClusterID: f.clusterID}); err == nil {
		t.Fatal("wrong key resolved credential")
	}

	config := f.pool.Config()
	config.MaxConns = 1
	lowPool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer lowPool.Close()
	lowStore := credentialStore(t, lowPool, credentialRing(t, "v1", 0x11))
	deniedSubject := "single-connection-denied-" + fmt.Sprint(time.Now().UnixNano())
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	_, err = putCredentialWithAudit(credentialFixture{store: lowStore}, ctx, f.clusterID, deniedSubject, "head-denied", "operator", "denied-ssh", "denied-sudo", 0, "", "gp20-single-denied", adminmanage.EventCredentialCreated)
	cancel()
	if !errors.Is(err, adminmanage.ErrCredentialAccessDenied) {
		t.Fatalf("single-connection denied put err=%v", err)
	}
	var rejected int
	if err := f.pool.QueryRow(context.Background(), `SELECT count(*) FROM admin_credential_audit_events WHERE cluster_id=$1 AND actor_subject=$2 AND outcome='REJECTED' AND reason_code=$3`, f.clusterID, deniedSubject, adminmanage.CredentialRejectAccessDenied).Scan(&rejected); err != nil {
		t.Fatal(err)
	}
	if rejected != 1 {
		t.Fatalf("single-connection rejected audit count=%d, want 1", rejected)
	}
	var eventKind, outcome, reason, actor, credentialID, requestID string
	var version int64
	if err := f.pool.QueryRow(context.Background(), `SELECT event_kind,outcome,reason_code,actor_subject,credential_id,credential_version,request_id FROM admin_credential_audit_events WHERE cluster_id=$1 AND actor_subject=$2 AND outcome='REJECTED'`, f.clusterID, deniedSubject).Scan(&eventKind, &outcome, &reason, &actor, &credentialID, &version, &requestID); err != nil {
		t.Fatal(err)
	}
	if eventKind != adminmanage.EventCredentialAttempt || outcome != "REJECTED" || reason != adminmanage.CredentialRejectAccessDenied || actor != deniedSubject || credentialID != "cred_rejected" || version != 0 || requestID != "gp20-single-denied-request" {
		t.Fatalf("unexpected rejected audit facts: kind=%s outcome=%s reason=%s actor=%s credential=%s version=%d request=%s", eventKind, outcome, reason, actor, credentialID, version, requestID)
	}
	if strings.Contains(strings.Join([]string{eventKind, outcome, reason, actor, credentialID, requestID}, "|"), "denied-ssh") || strings.Contains(strings.Join([]string{eventKind, outcome, reason, actor, credentialID, requestID}, "|"), "denied-sudo") {
		t.Fatal("rejected audit contains a secret marker")
	}
}
