package adminmanage

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

// Access-test event kinds recorded in credential_access_test_events.
const (
	EventAccessTestRequested        = "ACCESS_TEST_REQUESTED"
	EventAccessTestClaimed          = "ACCESS_TEST_CLAIMED"
	EventCredentialDelivered        = "CREDENTIAL_DELIVERED"
	EventCredentialDeliveryRefused  = "CREDENTIAL_DELIVERY_REFUSED"
	EventAccessTestCompleted        = "ACCESS_TEST_COMPLETED"
	EventAccessTestResultRejected   = "ACCESS_TEST_RESULT_REJECTED"
	EventAccessTestCancelled        = "ACCESS_TEST_CANCELLED"
	EventAccessTestExpired          = "ACCESS_TEST_EXPIRED"
	CredentialRejectAccessTestState = "CREDENTIAL_ACCESS_TEST_CONFLICT"

	// Operator-approved collector-to-target binding audit kinds.
	EventCredentialTargetBound   = "CREDENTIAL_TARGET_BOUND"
	EventCredentialTargetUnbound = "CREDENTIAL_TARGET_UNBOUND"

	accessTestMaxDeliveries = 2
	accessTestLeaseMinimum  = 5 * time.Second
	accessTestLeaseMaximum  = 5 * time.Minute
)

var (
	// ErrAccessTestLeaseInvalid means the collector, attempt, token, lease
	// expiry, plan digest or test state no longer authorizes the operation.
	ErrAccessTestLeaseInvalid = errors.New("credential access test lease is invalid or expired")
	// ErrAccessTestCollectorIncompatible means the authenticated collector is
	// not active in the cluster or does not advertise the reviewed capability.
	ErrAccessTestCollectorIncompatible = errors.New("collector is not eligible for credential access tests")
)

// CredentialAccessTest is the redacted projection of one durable test. It
// carries codes, counts and timing only. CredentialCurrent reports whether the
// credential row is still ACTIVE at exactly the tested version; replacement
// or revocation makes an older success visibly stale.
type CredentialAccessTest struct {
	ID                string
	ClusterID         string
	CredentialID      string
	CredentialVersion int64
	Host              string
	Purpose           string
	Username          string
	Operation         string
	Status            domain.CredentialAccessTestStatus
	RequestedBy       string
	RequestedAt       time.Time
	Deadline          time.Time
	Attempt           int
	CollectorID       string
	LeaseExpiresAt    *time.Time
	OutcomeCode       string
	OutcomeSummary    string
	BCMVersion        string
	DevicesListed     int
	CompletedAt       *time.Time
	CancelledBy       string
	CredentialCurrent bool
	CredentialStatus  string
	// Devices is populated only for a SUCCEEDED inventory discovery. The
	// access-test operation never retains rows, so it is always empty there.
	Devices []domain.CredentialAccessDevice
}

// CredentialInventoryDiscovery is the newest successful retained listing for
// one cluster. CredentialCurrent reports whether the credential row is still
// ACTIVE at exactly the version the listing was produced with, so an operator
// can see that an older inventory predates a replacement or revocation.
type CredentialInventoryDiscovery struct {
	TestID            string
	ClusterID         string
	CredentialID      string
	CredentialVersion int64
	Host              string
	BCMVersion        string
	CompletedAt       time.Time
	CredentialCurrent bool
	Devices           []domain.CredentialAccessDevice
}

// CredentialAccessTestLease is what a compatible collector receives when it
// claims a test: the secret-free plan plus attempt and lease authority.
type CredentialAccessTestLease struct {
	Plan         domain.CredentialAccessTestPlan
	Attempt      int
	CollectorID  domain.CollectorID
	LeaseToken   string
	LeaseExpires time.Time
}

// CredentialAccessTestLeaseRef identifies an attempt from the collector's
// perspective. The token is compared by hash against the durable attempt.
type CredentialAccessTestLeaseRef struct {
	TestID     string
	Attempt    int
	LeaseToken string
}

// CredentialAccessDelivery is the only value that ever carries a decrypted
// secret across a boundary. It contains the sudo password only: a head-local
// sudo check has no use for the SSH password, so it is never delivered.
type CredentialAccessDelivery struct {
	Host              string
	Username          string
	CredentialVersion int64
	SudoPassword      []byte
}

func (delivery CredentialAccessDelivery) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "[REDACTED]")
}
func (delivery CredentialAccessDelivery) MarshalJSON() ([]byte, error) {
	return nil, errors.New("credential delivery cannot be JSON encoded")
}
func (delivery CredentialAccessDelivery) MarshalText() ([]byte, error) {
	return nil, errors.New("credential delivery cannot be text encoded")
}
func (delivery *CredentialAccessDelivery) Destroy() {
	if delivery == nil {
		return
	}
	clearBytes(delivery.SudoPassword)
	delivery.SudoPassword = nil
}

// CredentialAccessTestCompletion is the redacted outcome recorded for an
// attempt. Rejected reports whether the store refused the result.
type CredentialAccessTestCompletion struct {
	Status   domain.CredentialAccessTestStatus
	Outcome  domain.CredentialAccessOutcome
	Rejected bool
}

// CredentialTargetBinding is one operator-approved authorization for a single
// collector to run credential-bearing work against a single (cluster, host)
// target. RevokedAt non-nil means the binding no longer authorizes anything.
type CredentialTargetBinding struct {
	ClusterID   string
	Host        string
	CollectorID string
	ApprovedBy  string
	ApprovedAt  time.Time
	RevokedAt   *time.Time
}

// BindCredentialTarget records an operator's approval for one collector to
// receive credentials for one (cluster, host) target. Like GrantCredentialAdmin
// this is a protected operator maintenance operation: it is intentionally
// absent from the browser and private API surfaces. Capability advertisement
// alone never entitles a collector to a secret; only this binding does.
func (store *PostgresStore) BindCredentialTarget(ctx context.Context, clusterID, host, collectorID, actorSubject string, now time.Time) error {
	return store.changeCredentialTargetBinding(ctx, clusterID, host, collectorID, actorSubject, now, false)
}

// UnbindCredentialTarget revokes an existing binding. A head that is already
// executing cannot be recalled, but every later claim and delivery is refused.
func (store *PostgresStore) UnbindCredentialTarget(ctx context.Context, clusterID, host, collectorID, actorSubject string, now time.Time) error {
	return store.changeCredentialTargetBinding(ctx, clusterID, host, collectorID, actorSubject, now, true)
}

// ListCredentialTargetBindings returns every binding recorded for a cluster,
// revoked ones included, so an operator can audit the current authority set.
func (store *PostgresStore) ListCredentialTargetBindings(ctx context.Context, clusterID string) ([]CredentialTargetBinding, error) {
	if validateClusterID(clusterID) != nil {
		return nil, fmt.Errorf("%w: cluster ID is invalid", ErrInvalid)
	}
	rows, err := store.pool.Query(ctx, `SELECT cluster_id,host,collector_id,approved_by,approved_at,revoked_at FROM credential_target_bindings WHERE cluster_id=$1 ORDER BY host, collector_id`, clusterID)
	if err != nil {
		return nil, fmt.Errorf("list credential target bindings: %w", err)
	}
	defer rows.Close()
	bindings := make([]CredentialTargetBinding, 0)
	for rows.Next() {
		var binding CredentialTargetBinding
		if err := rows.Scan(&binding.ClusterID, &binding.Host, &binding.CollectorID, &binding.ApprovedBy, &binding.ApprovedAt, &binding.RevokedAt); err != nil {
			return nil, fmt.Errorf("scan credential target binding: %w", err)
		}
		bindings = append(bindings, binding)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate credential target bindings: %w", err)
	}
	return bindings, nil
}

func (store *PostgresStore) changeCredentialTargetBinding(ctx context.Context, clusterID, host, collectorID, actorSubject string, now time.Time, unbind bool) error {
	if validateClusterID(clusterID) != nil || !validCredentialHost(host) || !validCollectorIdentifier(collectorID) || !validAccessSubject(actorSubject) || now.IsZero() {
		return fmt.Errorf("%w: credential target binding is invalid", ErrInvalid)
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin credential target binding: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var locked string
	if err := tx.QueryRow(ctx, `SELECT cluster_id FROM clusters WHERE cluster_id=$1 AND removed_at IS NULL FOR UPDATE`, clusterID).Scan(&locked); errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return fmt.Errorf("lock cluster for credential target binding: %w", err)
	}
	kind := EventCredentialTargetBound
	if unbind {
		kind = EventCredentialTargetUnbound
	}
	if unbind {
		if _, err := tx.Exec(ctx, `UPDATE credential_target_bindings SET revoked_at=$4 WHERE cluster_id=$1 AND host=$2 AND collector_id=$3 AND revoked_at IS NULL`, clusterID, host, collectorID, now.UTC()); err != nil {
			return fmt.Errorf("revoke credential target binding: %w", err)
		}
	} else {
		// A binding only means anything for a collector that exists in this
		// cluster: an unknown or foreign collector is never approvable.
		var collectorCluster string
		if err := tx.QueryRow(ctx, `SELECT cluster_id FROM collectors WHERE collector_id=$1 FOR SHARE`, collectorID).Scan(&collectorCluster); errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		} else if err != nil {
			return fmt.Errorf("lock collector for credential target binding: %w", err)
		}
		if collectorCluster != clusterID {
			return fmt.Errorf("%w: collector belongs to another cluster", ErrConflict)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO credential_target_bindings(cluster_id,host,collector_id,approved_by,approved_at,revoked_at) VALUES($1,$2,$3,$4,$5,NULL)
			ON CONFLICT (cluster_id,host,collector_id) DO UPDATE SET approved_by=EXCLUDED.approved_by, approved_at=EXCLUDED.approved_at, revoked_at=NULL`, clusterID, host, collectorID, actorSubject, now.UTC()); err != nil {
			return classifyMutationError("bind credential target", err)
		}
	}
	eventID, err := newCredentialAuditID()
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO credential_target_binding_audit_events(event_id,event_kind,actor_subject,cluster_id,host,collector_id,occurred_at) VALUES($1,$2,$3,$4,$5,$6,$7)`,
		eventID, kind, actorSubject, clusterID, host, collectorID, now.UTC()); err != nil {
		return classifyMutationError("record credential target binding event", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return classifyMutationError("commit credential target binding", err)
	}
	return nil
}

func validCredentialHost(host string) bool {
	return len(host) > 0 && len(host) <= 256 && !strings.ContainsAny(host, "\x00\r\n")
}

func validCollectorIdentifier(id string) bool {
	return len(id) > 0 && len(id) <= 128 && !strings.ContainsAny(id, "\x00\r\n")
}

// RequestCredentialAccessTest creates a durable test for the exact active
// credential version. It requires the caller's cluster grant, refuses a
// second live test for the same credential, and records the request audit in
// the same transaction. The plan it stores never contains a secret.
func (store *PostgresStore) RequestCredentialAccessTest(ctx context.Context, clusterID, subject, credentialID string, expectedVersion int64, audit MutationAudit) (CredentialAccessTest, error) {
	return store.requestCredentialAccessOperation(ctx, clusterID, subject, credentialID, expectedVersion, domain.CredentialAccessTestOperation, audit)
}

// RequestCredentialInventoryDiscovery creates a durable request for the
// second reviewed operation. It shares every authorization, binding, digest
// and deadline rule with the access test; only the plan's operation differs,
// and with it whether the head is authorized to retain the listing rows.
func (store *PostgresStore) RequestCredentialInventoryDiscovery(ctx context.Context, clusterID, subject, credentialID string, expectedVersion int64, audit MutationAudit) (CredentialAccessTest, error) {
	return store.requestCredentialAccessOperation(ctx, clusterID, subject, credentialID, expectedVersion, domain.CredentialInventoryDiscoveryOperation, audit)
}

func (store *PostgresStore) requestCredentialAccessOperation(ctx context.Context, clusterID, subject, credentialID string, expectedVersion int64, operation string, audit MutationAudit) (CredentialAccessTest, error) {
	if !store.credentialsEnabled() {
		return CredentialAccessTest{}, ErrCredentialKeyUnavailable
	}
	if validateClusterID(clusterID) != nil || !validCredentialID(credentialID) || expectedVersion < 1 || !validAccessSubject(subject) {
		return CredentialAccessTest{}, fmt.Errorf("%w: credential access test request is invalid", ErrInvalid)
	}
	if !domain.IsCredentialAccessOperation(operation) {
		return CredentialAccessTest{}, fmt.Errorf("%w: credential access operation is not reviewed", ErrInvalid)
	}
	if err := validateMutationAudit(audit, EventAccessTestRequested); err != nil {
		return CredentialAccessTest{}, err
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return CredentialAccessTest{}, fmt.Errorf("begin credential access test request: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT cluster_id FROM clusters WHERE cluster_id=$1 AND removed_at IS NULL FOR UPDATE`, clusterID); err != nil {
		return CredentialAccessTest{}, fmt.Errorf("lock cluster for credential access test: %w", err)
	}
	allowed, err := credentialAdminAllowedTx(ctx, tx, clusterID, subject)
	if err != nil {
		return CredentialAccessTest{}, err
	}
	if !allowed {
		return CredentialAccessTest{}, finishRejectedCredentialTx(ctx, tx, clusterID, subject, CredentialRejectAccessDenied, audit, ErrCredentialAccessDenied)
	}
	var host, purpose, username string
	err = tx.QueryRow(ctx, `SELECT host,purpose,username FROM cluster_credentials WHERE credential_id=$1 AND cluster_id=$2 AND status='ACTIVE' AND credential_version=$3 FOR SHARE`, credentialID, clusterID, expectedVersion).Scan(&host, &purpose, &username)
	if errors.Is(err, pgx.ErrNoRows) {
		return CredentialAccessTest{}, finishRejectedCredentialTx(ctx, tx, clusterID, subject, CredentialRejectConflict, audit, fmt.Errorf("%w: active credential version does not exist", ErrConflict))
	}
	if err != nil {
		return CredentialAccessTest{}, fmt.Errorf("lock credential for access test: %w", err)
	}
	// Overdue work must not block new requests: without this pass a REQUESTED
	// test for a cluster that has no compatible collector would hold the live
	// unique index until someone cancelled it by hand.
	if err := expireAccessTestsTx(ctx, tx, domain.ClusterID(clusterID)); err != nil {
		return CredentialAccessTest{}, err
	}
	var live bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM credential_access_tests WHERE credential_id=$1 AND status IN ('REQUESTED','CLAIMED','RUNNING'))`, credentialID).Scan(&live); err != nil {
		return CredentialAccessTest{}, fmt.Errorf("check live credential access test: %w", err)
	}
	if live {
		// One live operation per credential, whichever it is: an access test
		// and an inventory discovery share the same credential, head and
		// delivery bound, so they are never run concurrently.
		return CredentialAccessTest{}, finishRejectedCredentialTx(ctx, tx, clusterID, subject, CredentialRejectAccessTestState, audit, fmt.Errorf("%w: a credential access test or inventory discovery is already in progress for this credential", ErrConflict))
	}
	testID, err := newCredentialAccessTestID()
	if err != nil {
		return CredentialAccessTest{}, err
	}
	requestedAt := audit.OccurredAt.UTC()
	plan := domain.CredentialAccessTestPlan{
		SchemaVersion: domain.CredentialAccessTestSchemaVersion, TestID: testID, ClusterID: domain.ClusterID(clusterID),
		Operation: operation, Host: host, Purpose: purpose, Username: username,
		CredentialID: credentialID, CredentialVersion: expectedVersion, RequestedAt: requestedAt,
		Deadline: requestedAt.Add(15 * time.Minute),
		Limits:   domain.CredentialAccessTestLimits{TimeoutSeconds: int(domain.CredentialAccessTestDefaultTimeout / time.Second), MaxOutputBytes: domain.CredentialAccessTestMaxOutputBytes},
	}
	digest, err := domain.CredentialAccessTestPlanDigest(plan)
	if err != nil {
		return CredentialAccessTest{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	encodedPlan, err := json.Marshal(plan)
	if err != nil {
		return CredentialAccessTest{}, err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO credential_access_tests (test_id,cluster_id,credential_id,credential_version,host,purpose,username,operation,plan,plan_digest,requested_by,requested_at,deadline,status,max_attempts)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'REQUESTED',$14)`,
		testID, clusterID, credentialID, expectedVersion, host, purpose, username, operation, encodedPlan, digest[:], subject, requestedAt, plan.Deadline, domain.CredentialAccessTestMaxAttempts); err != nil {
		return CredentialAccessTest{}, classifyMutationError("store credential access test", err)
	}
	if err := insertAccessTestEvent(ctx, tx, accessTestEvent{Kind: EventAccessTestRequested, Outcome: "SUCCEEDED", Reason: audit.ReasonCode, ActorKind: "ACCESS_SUBJECT", Actor: subject, ClusterID: clusterID, TestID: testID, CredentialID: credentialID, CredentialVersion: expectedVersion, RequestID: audit.RequestID, OccurredAt: requestedAt}); err != nil {
		return CredentialAccessTest{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return CredentialAccessTest{}, classifyMutationError("commit credential access test request", err)
	}
	return CredentialAccessTest{ID: testID, ClusterID: clusterID, CredentialID: credentialID, CredentialVersion: expectedVersion, Host: host, Purpose: purpose, Username: username, Operation: operation, Status: domain.CredentialAccessTestRequested, RequestedBy: subject, RequestedAt: requestedAt, Deadline: plan.Deadline, CredentialCurrent: true, CredentialStatus: "ACTIVE"}, nil
}

// ListCredentialAccessTests returns the cluster's tests, newest first, with
// exact-version freshness against the current credential row.
func (store *PostgresStore) ListCredentialAccessTests(ctx context.Context, clusterID, subject string, limit int) ([]CredentialAccessTest, error) {
	if !store.credentialsEnabled() {
		return nil, ErrCredentialKeyUnavailable
	}
	if err := validateLimit(limit); err != nil {
		return nil, err
	}
	allowed, err := store.CredentialAdminAllowed(ctx, clusterID, subject)
	if err != nil {
		return nil, err
	}
	if !allowed {
		return nil, ErrCredentialAccessDenied
	}
	// A short transaction of its own, so the projection the operator reads
	// already shows overdue work as EXPIRED even when no collector ever claims.
	if err := store.expireAccessTests(ctx, domain.ClusterID(clusterID)); err != nil {
		return nil, err
	}
	rows, err := store.pool.Query(ctx, accessTestProjectionSQL+` WHERE t.cluster_id=$1 ORDER BY t.requested_at DESC, t.test_id DESC LIMIT $2`, clusterID, limit)
	if err != nil {
		return nil, fmt.Errorf("list credential access tests: %w", err)
	}
	defer rows.Close()
	tests := make([]CredentialAccessTest, 0)
	for rows.Next() {
		test, err := scanAccessTest(rows)
		if err != nil {
			return nil, err
		}
		tests = append(tests, test)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate credential access tests: %w", err)
	}
	// Retained rows exist only for a succeeded inventory discovery, so only
	// those tests pay for the bounded per-test load.
	for i := range tests {
		if tests[i].Operation != domain.CredentialInventoryDiscoveryOperation || tests[i].Status != domain.CredentialAccessTestSucceeded {
			continue
		}
		devices, err := store.loadAccessTestDevices(ctx, tests[i].ID)
		if err != nil {
			return nil, err
		}
		tests[i].Devices = devices
	}
	return tests, nil
}

// loadAccessTestDevices reads one test's retained listing in ordinal order.
// The query is bounded by the same reviewed constant the head and the schema
// enforce, so a row set that somehow grew past it cannot be read back whole.
func (store *PostgresStore) loadAccessTestDevices(ctx context.Context, testID string) ([]domain.CredentialAccessDevice, error) {
	rows, err := store.pool.Query(ctx, `SELECT device_type, hostname, category, status FROM credential_access_test_devices WHERE test_id=$1 ORDER BY ordinal LIMIT $2`, testID, domain.CredentialAccessTestMaxDevices)
	if err != nil {
		return nil, fmt.Errorf("load credential inventory devices: %w", err)
	}
	defer rows.Close()
	devices := make([]domain.CredentialAccessDevice, 0)
	for rows.Next() {
		var device domain.CredentialAccessDevice
		if err := rows.Scan(&device.Type, &device.Hostname, &device.Category, &device.Status); err != nil {
			return nil, fmt.Errorf("scan credential inventory device: %w", err)
		}
		devices = append(devices, device)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate credential inventory devices: %w", err)
	}
	return devices, nil
}

// LatestInventoryDiscovery returns the newest SUCCEEDED inventory discovery
// for a cluster with its retained rows. It is grant-checked exactly like the
// listing: an ungranted subject gets ErrCredentialAccessDenied, never rows.
func (store *PostgresStore) LatestInventoryDiscovery(ctx context.Context, clusterID, subject string) (CredentialInventoryDiscovery, bool, error) {
	if !store.credentialsEnabled() {
		return CredentialInventoryDiscovery{}, false, ErrCredentialKeyUnavailable
	}
	allowed, err := store.CredentialAdminAllowed(ctx, clusterID, subject)
	if err != nil {
		return CredentialInventoryDiscovery{}, false, err
	}
	if !allowed {
		return CredentialInventoryDiscovery{}, false, ErrCredentialAccessDenied
	}
	return store.loadLatestInventoryDiscovery(ctx, clusterID)
}

// loadLatestInventoryDiscovery is the grant-free loader shared with the
// expected-inventory preview. Every caller must have already proved the
// cluster grant: this function does not re-check it.
func (store *PostgresStore) loadLatestInventoryDiscovery(ctx context.Context, clusterID string) (CredentialInventoryDiscovery, bool, error) {
	var discovery CredentialInventoryDiscovery
	err := store.pool.QueryRow(ctx, `SELECT t.test_id, t.cluster_id, t.credential_id, t.credential_version, t.host, t.bcm_version, t.completed_at,
		(cc.status='ACTIVE' AND cc.credential_version=t.credential_version)
		FROM credential_access_tests t JOIN cluster_credentials cc ON cc.credential_id=t.credential_id
		WHERE t.cluster_id=$1 AND t.operation=$2 AND t.status='SUCCEEDED' AND t.completed_at IS NOT NULL
		ORDER BY t.completed_at DESC, t.test_id DESC LIMIT 1`, clusterID, domain.CredentialInventoryDiscoveryOperation).Scan(
		&discovery.TestID, &discovery.ClusterID, &discovery.CredentialID, &discovery.CredentialVersion, &discovery.Host, &discovery.BCMVersion, &discovery.CompletedAt, &discovery.CredentialCurrent)
	if errors.Is(err, pgx.ErrNoRows) {
		return CredentialInventoryDiscovery{}, false, nil
	}
	if err != nil {
		return CredentialInventoryDiscovery{}, false, fmt.Errorf("load latest credential inventory discovery: %w", err)
	}
	devices, err := store.loadAccessTestDevices(ctx, discovery.TestID)
	if err != nil {
		return CredentialInventoryDiscovery{}, false, err
	}
	discovery.Devices = devices
	discovery.CompletedAt = discovery.CompletedAt.UTC()
	return discovery, true, nil
}

// CancelCredentialAccessTest marks a non-terminal test cancelled. A running
// head attempt cannot be recalled, but its later delivery and result are
// refused and the recorded outcome stays CANCELLED.
func (store *PostgresStore) CancelCredentialAccessTest(ctx context.Context, clusterID, subject, testID string, audit MutationAudit) error {
	if !store.credentialsEnabled() {
		return ErrCredentialKeyUnavailable
	}
	if validateClusterID(clusterID) != nil || !domain.ValidCredentialAccessTestID(testID) || !validAccessSubject(subject) {
		return fmt.Errorf("%w: credential access test reference is invalid", ErrInvalid)
	}
	if err := validateMutationAudit(audit, EventAccessTestCancelled); err != nil {
		return err
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin credential access test cancellation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT cluster_id FROM clusters WHERE cluster_id=$1 AND removed_at IS NULL FOR UPDATE`, clusterID); err != nil {
		return fmt.Errorf("lock cluster for credential access test cancellation: %w", err)
	}
	allowed, err := credentialAdminAllowedTx(ctx, tx, clusterID, subject)
	if err != nil {
		return err
	}
	if !allowed {
		return finishRejectedCredentialTx(ctx, tx, clusterID, subject, CredentialRejectAccessDenied, audit, ErrCredentialAccessDenied)
	}
	now := audit.OccurredAt.UTC()
	var credentialID string
	var credentialVersion int64
	err = tx.QueryRow(ctx, `UPDATE credential_access_tests SET status='CANCELLED', cancelled_by=$3, completed_at=$4, outcome_code='CANCELLED', outcome_summary='Cancelled by an administrator before completion.'
		WHERE test_id=$1 AND cluster_id=$2 AND status IN ('REQUESTED','CLAIMED','RUNNING') RETURNING credential_id, credential_version`, testID, clusterID, subject, now).Scan(&credentialID, &credentialVersion)
	if errors.Is(err, pgx.ErrNoRows) {
		return finishRejectedCredentialTx(ctx, tx, clusterID, subject, CredentialRejectAccessTestState, audit, fmt.Errorf("%w: credential access test is not pending", ErrConflict))
	}
	if err != nil {
		return fmt.Errorf("cancel credential access test: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE credential_access_test_attempts SET status='REJECTED', completed_at=$2, outcome_code='CANCELLED' WHERE test_id=$1 AND status IN ('CLAIMED','STARTED')`, testID, now); err != nil {
		return fmt.Errorf("reject cancelled access test attempts: %w", err)
	}
	if err := insertAccessTestEvent(ctx, tx, accessTestEvent{Kind: EventAccessTestCancelled, Outcome: "SUCCEEDED", Reason: audit.ReasonCode, ActorKind: "ACCESS_SUBJECT", Actor: subject, ClusterID: clusterID, TestID: testID, CredentialID: credentialID, CredentialVersion: credentialVersion, RequestID: audit.RequestID, OccurredAt: now}); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return classifyMutationError("commit credential access test cancellation", err)
	}
	return nil
}

// ClaimCredentialAccessTest hands the oldest claimable test in the collector's
// cluster to a compatible collector that an operator has bound to the test's
// exact (cluster, host) target. Capability advertisement alone is never
// enough: an unbound collector sees no work at all, so it never reaches the
// delivery boundary. It lazily expires lost leases and
// overdue tests and fails tests whose credential no longer matches, so a head
// never claims work that delivery would refuse anyway.
func (store *PostgresStore) ClaimCredentialAccessTest(ctx context.Context, clusterID domain.ClusterID, collectorID domain.CollectorID, token string, leaseFor time.Duration) (CredentialAccessTestLease, bool, error) {
	if !store.credentialsEnabled() {
		return CredentialAccessTestLease{}, false, ErrCredentialKeyUnavailable
	}
	if validateClusterID(string(clusterID)) != nil || collectorID == "" || len(token) < 32 || len(token) > 256 || leaseFor < accessTestLeaseMinimum || leaseFor > accessTestLeaseMaximum {
		return CredentialAccessTestLease{}, false, fmt.Errorf("%w: claim identity or lease bounds are invalid", ErrInvalid)
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return CredentialAccessTestLease{}, false, fmt.Errorf("begin credential access test claim: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := lockAccessTestCollector(ctx, tx, clusterID, collectorID); err != nil {
		return CredentialAccessTestLease{}, false, err
	}
	if err := expireAccessTestsTx(ctx, tx, clusterID); err != nil {
		return CredentialAccessTestLease{}, false, err
	}
	var testID string
	var attempt int
	var encodedPlan []byte
	err = tx.QueryRow(ctx, `SELECT t.test_id, t.next_attempt, t.plan FROM credential_access_tests t
		JOIN clusters c ON c.cluster_id=t.cluster_id AND c.removed_at IS NULL
		WHERE t.cluster_id=$1 AND t.status IN ('REQUESTED','CLAIMED','RUNNING')
		  AND t.deadline>clock_timestamp() AND t.next_attempt<=t.max_attempts
		  AND EXISTS (SELECT 1 FROM collector_capabilities cap WHERE cap.collector_id=$2 AND cap.capability=t.operation AND cap.version='1')
		  AND EXISTS (SELECT 1 FROM credential_target_bindings b WHERE b.cluster_id=t.cluster_id AND b.host=t.host AND b.collector_id=$2 AND b.revoked_at IS NULL)
		  AND NOT EXISTS (SELECT 1 FROM credential_access_test_attempts a WHERE a.test_id=t.test_id AND a.status IN ('CLAIMED','STARTED') AND a.lease_expires_at>clock_timestamp())
		ORDER BY t.requested_at, t.test_id FOR UPDATE OF t SKIP LOCKED LIMIT 1`, string(clusterID), string(collectorID)).Scan(&testID, &attempt, &encodedPlan)
	if errors.Is(err, pgx.ErrNoRows) {
		if err := tx.Commit(ctx); err != nil {
			return CredentialAccessTestLease{}, false, err
		}
		return CredentialAccessTestLease{}, false, nil
	}
	if err != nil {
		return CredentialAccessTestLease{}, false, fmt.Errorf("select credential access test: %w", err)
	}
	var plan domain.CredentialAccessTestPlan
	if err := json.Unmarshal(encodedPlan, &plan); err != nil || domain.ValidateCredentialAccessTestPlan(plan) != nil || plan.TestID != testID || plan.ClusterID != clusterID {
		return CredentialAccessTestLease{}, false, fmt.Errorf("%w: stored credential access test plan is invalid", ErrConflict)
	}
	// Re-prove the capability for this test's exact operation now that it is
	// known, so the eligibility check is never weaker than the work granted.
	if err := lockAccessTestCollector(ctx, tx, clusterID, collectorID, plan.Operation); err != nil {
		return CredentialAccessTestLease{}, false, err
	}
	if _, err := tx.Exec(ctx, `UPDATE credential_access_test_attempts SET status='EXPIRED', completed_at=clock_timestamp(), outcome_code='LEASE_EXPIRED' WHERE test_id=$1 AND status IN ('CLAIMED','STARTED')`, testID); err != nil {
		return CredentialAccessTestLease{}, false, fmt.Errorf("expire credential access test attempts: %w", err)
	}
	tokenHash := sha256.Sum256([]byte(token))
	var leaseExpires time.Time
	if err := tx.QueryRow(ctx, `INSERT INTO credential_access_test_attempts (test_id,attempt,collector_id,lease_token_hash,status,lease_expires_at)
		VALUES ($1,$2,$3,$4,'CLAIMED',clock_timestamp()+($5*interval '1 millisecond')) RETURNING lease_expires_at`, testID, attempt, string(collectorID), tokenHash[:], leaseFor.Milliseconds()).Scan(&leaseExpires); err != nil {
		return CredentialAccessTestLease{}, false, classifyMutationError("insert credential access test attempt", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE credential_access_tests SET status='CLAIMED', next_attempt=next_attempt+1 WHERE test_id=$1`, testID); err != nil {
		return CredentialAccessTestLease{}, false, fmt.Errorf("claim credential access test: %w", err)
	}
	if err := insertAccessTestEvent(ctx, tx, accessTestEvent{Kind: EventAccessTestClaimed, Outcome: "SUCCEEDED", Reason: "CLAIMED", ActorKind: "COLLECTOR", Actor: string(collectorID), ClusterID: string(clusterID), TestID: testID, Attempt: attempt, CredentialID: plan.CredentialID, CredentialVersion: plan.CredentialVersion, OccurredAt: time.Now().UTC()}); err != nil {
		return CredentialAccessTestLease{}, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return CredentialAccessTestLease{}, false, fmt.Errorf("commit credential access test claim: %w", err)
	}
	return CredentialAccessTestLease{Plan: plan, Attempt: attempt, CollectorID: collectorID, LeaseToken: token, LeaseExpires: leaseExpires.UTC()}, true, nil
}

// StartCredentialAccessTest acknowledges execution start and renews the lease.
func (store *PostgresStore) StartCredentialAccessTest(ctx context.Context, clusterID domain.ClusterID, collectorID domain.CollectorID, ref CredentialAccessTestLeaseRef, leaseFor time.Duration) (time.Time, error) {
	return store.updateAccessTestLease(ctx, clusterID, collectorID, ref, leaseFor, true)
}

// RenewCredentialAccessTestLease extends a live lease without changing state.
func (store *PostgresStore) RenewCredentialAccessTestLease(ctx context.Context, clusterID domain.ClusterID, collectorID domain.CollectorID, ref CredentialAccessTestLeaseRef, leaseFor time.Duration) (time.Time, error) {
	return store.updateAccessTestLease(ctx, clusterID, collectorID, ref, leaseFor, false)
}

func (store *PostgresStore) updateAccessTestLease(ctx context.Context, clusterID domain.ClusterID, collectorID domain.CollectorID, ref CredentialAccessTestLeaseRef, leaseFor time.Duration, start bool) (time.Time, error) {
	if !store.credentialsEnabled() {
		return time.Time{}, ErrCredentialKeyUnavailable
	}
	if err := validateAccessTestLeaseRef(clusterID, collectorID, ref); err != nil || leaseFor < accessTestLeaseMinimum || leaseFor > accessTestLeaseMaximum {
		return time.Time{}, fmt.Errorf("%w: lease reference or duration is invalid", ErrInvalid)
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return time.Time{}, fmt.Errorf("begin credential access test lease update: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := lockAccessTestCollector(ctx, tx, clusterID, collectorID); err != nil {
		return time.Time{}, err
	}
	if _, err := lockAccessTestAttempt(ctx, tx, clusterID, collectorID, ref); err != nil {
		return time.Time{}, err
	}
	var expires time.Time
	statement := `UPDATE credential_access_test_attempts SET lease_expires_at=clock_timestamp()+($3*interval '1 millisecond') WHERE test_id=$1 AND attempt=$2 RETURNING lease_expires_at`
	if start {
		statement = `UPDATE credential_access_test_attempts SET status='STARTED', started_at=COALESCE(started_at,clock_timestamp()), lease_expires_at=clock_timestamp()+($3*interval '1 millisecond') WHERE test_id=$1 AND attempt=$2 RETURNING lease_expires_at`
	}
	if err := tx.QueryRow(ctx, statement, ref.TestID, ref.Attempt, leaseFor.Milliseconds()).Scan(&expires); err != nil {
		return time.Time{}, fmt.Errorf("update credential access test lease: %w", err)
	}
	if start {
		if _, err := tx.Exec(ctx, `UPDATE credential_access_tests SET status='RUNNING' WHERE test_id=$1 AND status='CLAIMED'`, ref.TestID); err != nil {
			return time.Time{}, fmt.Errorf("mark credential access test running: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return time.Time{}, fmt.Errorf("commit credential access test lease update: %w", err)
	}
	return expires.UTC(), nil
}

// DeliverCredentialForAccessTest is the single authorization and decryption
// boundary for head delivery. Every fact is re-proved from durable rows inside
// one short transaction: collector eligibility, the operator-approved binding
// of this collector to the test's target, attempt ownership and lease
// token, lease expiry, test state and deadline, plan digest, exact credential
// identity and version, cluster liveness and the delivery bound. The
// transaction commits before decryption; no lock is held during any network
// or process activity. Revocation committed earlier wins; bytes delivered
// earlier cannot be recalled.
func (store *PostgresStore) DeliverCredentialForAccessTest(ctx context.Context, clusterID domain.ClusterID, collectorID domain.CollectorID, ref CredentialAccessTestLeaseRef, planDigest domain.SHA256) (CredentialAccessDelivery, error) {
	if !store.credentialsEnabled() {
		return CredentialAccessDelivery{}, ErrCredentialKeyUnavailable
	}
	if err := validateAccessTestLeaseRef(clusterID, collectorID, ref); err != nil || planDigest == (domain.SHA256{}) {
		return CredentialAccessDelivery{}, fmt.Errorf("%w: delivery reference is invalid", ErrInvalid)
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return CredentialAccessDelivery{}, fmt.Errorf("begin credential delivery: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := lockAccessTestCollector(ctx, tx, clusterID, collectorID); err != nil {
		return CredentialAccessDelivery{}, err
	}
	state, err := lockAccessTestAttempt(ctx, tx, clusterID, collectorID, ref)
	if err != nil {
		return CredentialAccessDelivery{}, err
	}
	refuse := func(reason string) error {
		_ = insertAccessTestEvent(ctx, tx, accessTestEvent{Kind: EventCredentialDeliveryRefused, Outcome: "REJECTED", Reason: reason, ActorKind: "COLLECTOR", Actor: string(collectorID), ClusterID: string(clusterID), TestID: ref.TestID, Attempt: ref.Attempt, CredentialID: state.credentialID, CredentialVersion: state.credentialVersion, OccurredAt: time.Now().UTC()})
		_ = tx.Commit(ctx)
		return ErrAccessTestLeaseInvalid
	}
	// The operator-approved binding is re-proved here, under a share lock, so
	// an unbind that commits before this transaction stops delivery even for a
	// collector that holds a live lease claimed while it was still bound.
	var boundAt time.Time
	err = tx.QueryRow(ctx, `SELECT approved_at FROM credential_target_bindings
		WHERE cluster_id=$1 AND host=$2 AND collector_id=$3 AND revoked_at IS NULL FOR SHARE`,
		string(clusterID), state.host, string(collectorID)).Scan(&boundAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return CredentialAccessDelivery{}, refuse("TARGET_BINDING_MISSING")
	}
	if err != nil {
		return CredentialAccessDelivery{}, fmt.Errorf("lock credential target binding: %w", err)
	}
	if state.planDigest != planDigest {
		return CredentialAccessDelivery{}, refuse("PLAN_DIGEST_MISMATCH")
	}
	if state.deliveryCount >= accessTestMaxDeliveries {
		return CredentialAccessDelivery{}, refuse("DELIVERY_LIMIT")
	}
	var host, purpose, username, keyVersion string
	var nonce, ciphertext []byte
	err = tx.QueryRow(ctx, `SELECT cc.host, cc.purpose, cc.username, cc.key_version, cc.nonce, cc.ciphertext
		FROM cluster_credentials cc JOIN clusters c ON c.cluster_id=cc.cluster_id AND c.removed_at IS NULL
		WHERE cc.credential_id=$1 AND cc.cluster_id=$2 AND cc.credential_version=$3 AND cc.status='ACTIVE'
		  AND cc.host=$4 AND cc.purpose=$5 AND cc.username=$6 FOR SHARE OF cc`,
		state.credentialID, string(clusterID), state.credentialVersion, state.host, state.purpose, state.username).Scan(&host, &purpose, &username, &keyVersion, &nonce, &ciphertext)
	if errors.Is(err, pgx.ErrNoRows) {
		return CredentialAccessDelivery{}, refuse("CREDENTIAL_UNAVAILABLE")
	}
	if err != nil {
		return CredentialAccessDelivery{}, fmt.Errorf("load credential for delivery: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE credential_access_test_attempts SET delivery_count=delivery_count+1, delivered_at=clock_timestamp() WHERE test_id=$1 AND attempt=$2`, ref.TestID, ref.Attempt); err != nil {
		clearBytes(nonce)
		clearBytes(ciphertext)
		return CredentialAccessDelivery{}, fmt.Errorf("record credential delivery: %w", err)
	}
	if err := insertAccessTestEvent(ctx, tx, accessTestEvent{Kind: EventCredentialDelivered, Outcome: "SUCCEEDED", Reason: "DELIVERED", ActorKind: "COLLECTOR", Actor: string(collectorID), ClusterID: string(clusterID), TestID: ref.TestID, Attempt: ref.Attempt, CredentialID: state.credentialID, CredentialVersion: state.credentialVersion, OccurredAt: time.Now().UTC()}); err != nil {
		clearBytes(nonce)
		clearBytes(ciphertext)
		return CredentialAccessDelivery{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		clearBytes(nonce)
		clearBytes(ciphertext)
		return CredentialAccessDelivery{}, fmt.Errorf("commit credential delivery: %w", err)
	}
	secrets, err := store.credentialCipher.open(string(clusterID), host, purpose, username, state.credentialID, state.credentialVersion, keyVersion, nonce, ciphertext)
	clearBytes(nonce)
	clearBytes(ciphertext)
	if err != nil {
		return CredentialAccessDelivery{}, err
	}
	clearBytes(secrets.SSHPassword)
	secrets.SSHPassword = nil
	return CredentialAccessDelivery{Host: host, Username: username, CredentialVersion: state.credentialVersion, SudoPassword: secrets.SudoPassword}, nil
}

// CompleteCredentialAccessTest records the head's redacted result. It rechecks
// the lease, the test deadline and the plan binding, refuses results for
// overdue, cancelled or replaced work and marks the test terminal. A second submission for a finished attempt is
// reported as previously completed without changing durable state.
func (store *PostgresStore) CompleteCredentialAccessTest(ctx context.Context, clusterID domain.ClusterID, collectorID domain.CollectorID, ref CredentialAccessTestLeaseRef, result domain.CredentialAccessTestResult) (CredentialAccessTestCompletion, error) {
	if !store.credentialsEnabled() {
		return CredentialAccessTestCompletion{}, ErrCredentialKeyUnavailable
	}
	if err := validateAccessTestLeaseRef(clusterID, collectorID, ref); err != nil {
		return CredentialAccessTestCompletion{}, fmt.Errorf("%w: completion reference is invalid", ErrInvalid)
	}
	if err := domain.ValidateCredentialAccessTestResult(result); err != nil || result.TestID != ref.TestID || result.Attempt != ref.Attempt {
		return CredentialAccessTestCompletion{}, fmt.Errorf("%w: credential access test result is invalid", ErrInvalid)
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return CredentialAccessTestCompletion{}, fmt.Errorf("begin credential access test completion: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := lockAccessTestCollector(ctx, tx, clusterID, collectorID); err != nil {
		return CredentialAccessTestCompletion{}, err
	}
	state, err := lockAccessTestAttemptForCompletion(ctx, tx, clusterID, collectorID, ref)
	if err != nil {
		return CredentialAccessTestCompletion{}, err
	}
	now := time.Now().UTC()
	if state.attemptStatus == "SUCCEEDED" || state.attemptStatus == "FAILED" {
		if err := tx.Commit(ctx); err != nil {
			return CredentialAccessTestCompletion{}, err
		}
		return CredentialAccessTestCompletion{Status: state.testStatus, Outcome: domain.CredentialAccessOutcome(state.attemptOutcome)}, nil
	}
	if err := domain.ValidateCredentialAccessTestResultForPlan(result, state.plan, ref.Attempt); err != nil {
		_ = insertAccessTestEvent(ctx, tx, accessTestEvent{Kind: EventAccessTestResultRejected, Outcome: "REJECTED", Reason: "PLAN_BINDING_MISMATCH", ActorKind: "COLLECTOR", Actor: string(collectorID), ClusterID: string(clusterID), TestID: ref.TestID, Attempt: ref.Attempt, CredentialID: state.credentialID, CredentialVersion: state.credentialVersion, OccurredAt: now})
		_ = tx.Commit(ctx)
		return CredentialAccessTestCompletion{}, ErrAccessTestLeaseInvalid
	}
	// A result produced after the test deadline is as unauthorized as one
	// produced under an invalid lease: the head may have started long after
	// the window the administrator approved. Reject it and expire the test.
	if !state.testStatus.Terminal() && !state.deadline.After(now) {
		if _, err := tx.Exec(ctx, `UPDATE credential_access_test_attempts SET status=CASE WHEN status IN ('CLAIMED','STARTED') THEN 'REJECTED' ELSE status END, completed_at=COALESCE(completed_at,$3), outcome_code=CASE WHEN outcome_code='' THEN 'EXPIRED' ELSE outcome_code END WHERE test_id=$1 AND attempt=$2`, ref.TestID, ref.Attempt, now); err != nil {
			return CredentialAccessTestCompletion{}, fmt.Errorf("reject overdue credential access test result: %w", err)
		}
		if _, err := tx.Exec(ctx, `UPDATE credential_access_tests SET status='EXPIRED', completed_at=COALESCE(completed_at,$2), outcome_code='EXPIRED', outcome_summary='The head reported after the test deadline had passed.'
			WHERE test_id=$1 AND status IN ('REQUESTED','CLAIMED','RUNNING')`, ref.TestID, now); err != nil {
			return CredentialAccessTestCompletion{}, fmt.Errorf("expire credential access test on late result: %w", err)
		}
		if err := insertAccessTestEvent(ctx, tx, accessTestEvent{Kind: EventAccessTestResultRejected, Outcome: "REJECTED", Reason: "DEADLINE_PASSED", ActorKind: "COLLECTOR", Actor: string(collectorID), ClusterID: string(clusterID), TestID: ref.TestID, Attempt: ref.Attempt, CredentialID: state.credentialID, CredentialVersion: state.credentialVersion, OccurredAt: now}); err != nil {
			return CredentialAccessTestCompletion{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return CredentialAccessTestCompletion{}, err
		}
		return CredentialAccessTestCompletion{Status: domain.CredentialAccessTestExpired, Outcome: result.Outcome, Rejected: true}, nil
	}
	if state.attemptStatus != "CLAIMED" && state.attemptStatus != "STARTED" || state.testStatus.Terminal() || !state.leaseExpires.After(now) {
		if _, err := tx.Exec(ctx, `UPDATE credential_access_test_attempts SET status=CASE WHEN status IN ('CLAIMED','STARTED') THEN 'REJECTED' ELSE status END, completed_at=COALESCE(completed_at,$3), outcome_code=CASE WHEN outcome_code='' THEN $4 ELSE outcome_code END WHERE test_id=$1 AND attempt=$2`, ref.TestID, ref.Attempt, now, string(result.Outcome)); err != nil {
			return CredentialAccessTestCompletion{}, fmt.Errorf("reject late credential access test result: %w", err)
		}
		if err := insertAccessTestEvent(ctx, tx, accessTestEvent{Kind: EventAccessTestResultRejected, Outcome: "REJECTED", Reason: "LEASE_OR_STATE_INVALID", ActorKind: "COLLECTOR", Actor: string(collectorID), ClusterID: string(clusterID), TestID: ref.TestID, Attempt: ref.Attempt, CredentialID: state.credentialID, CredentialVersion: state.credentialVersion, OccurredAt: now}); err != nil {
			return CredentialAccessTestCompletion{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return CredentialAccessTestCompletion{}, err
		}
		return CredentialAccessTestCompletion{Status: state.testStatus, Outcome: result.Outcome, Rejected: true}, nil
	}
	attemptStatus, testStatus := "FAILED", domain.CredentialAccessTestFailed
	if result.Outcome.Success() {
		attemptStatus, testStatus = "SUCCEEDED", domain.CredentialAccessTestSucceeded
	}
	if _, err := tx.Exec(ctx, `UPDATE credential_access_test_attempts SET status=$3, completed_at=$4, outcome_code=$5 WHERE test_id=$1 AND attempt=$2`, ref.TestID, ref.Attempt, attemptStatus, now, string(result.Outcome)); err != nil {
		return CredentialAccessTestCompletion{}, fmt.Errorf("complete credential access test attempt: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE credential_access_tests SET status=$2, outcome_code=$3, outcome_summary=$4, bcm_version=$5, devices_listed=$6, completed_by_collector=$7, completed_at=$8 WHERE test_id=$1`,
		ref.TestID, string(testStatus), string(result.Outcome), result.Summary, result.BCMVersion, result.DevicesListed, string(collectorID), now); err != nil {
		return CredentialAccessTestCompletion{}, fmt.Errorf("complete credential access test: %w", err)
	}
	// Device rows are retained in the same transaction that marks the test
	// terminal, and only for a verified inventory discovery. Every other
	// operation and outcome stores nothing; ValidateCredentialAccessTestResultForPlan
	// above already refused a result that carried rows it was not authorized
	// to retain, and the count equality is re-proved here against the row
	// count actually written.
	if state.plan.Operation == domain.CredentialInventoryDiscoveryOperation && result.Outcome.Success() {
		if len(result.Devices) != result.DevicesListed || len(result.Devices) < 1 || len(result.Devices) > domain.CredentialAccessTestMaxDevices {
			return CredentialAccessTestCompletion{}, fmt.Errorf("%w: retained device rows do not match the reported count", ErrInvalid)
		}
		for ordinal, device := range result.Devices {
			if _, err := tx.Exec(ctx, `INSERT INTO credential_access_test_devices(test_id,ordinal,device_type,hostname,category,status) VALUES($1,$2,$3,$4,$5,$6)`,
				ref.TestID, ordinal, device.Type, device.Hostname, device.Category, device.Status); err != nil {
				return CredentialAccessTestCompletion{}, classifyMutationError("store credential inventory device", err)
			}
		}
	}
	if err := insertAccessTestEvent(ctx, tx, accessTestEvent{Kind: EventAccessTestCompleted, Outcome: "SUCCEEDED", Reason: string(result.Outcome), ActorKind: "COLLECTOR", Actor: string(collectorID), ClusterID: string(clusterID), TestID: ref.TestID, Attempt: ref.Attempt, CredentialID: state.credentialID, CredentialVersion: state.credentialVersion, OccurredAt: now}); err != nil {
		return CredentialAccessTestCompletion{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return CredentialAccessTestCompletion{}, fmt.Errorf("commit credential access test completion: %w", err)
	}
	return CredentialAccessTestCompletion{Status: testStatus, Outcome: result.Outcome}, nil
}

type accessTestAttemptState struct {
	testStatus        domain.CredentialAccessTestStatus
	attemptStatus     string
	attemptOutcome    string
	leaseExpires      time.Time
	deadline          time.Time
	deliveryCount     int
	planDigest        domain.SHA256
	plan              domain.CredentialAccessTestPlan
	credentialID      string
	credentialVersion int64
	host, purpose     string
	username          string
}

// lockAccessTestCollector proves the collector is active in this cluster,
// speaks protocol 2 and advertises the capability for the named operations.
// Callers that do not yet know which operation a test carries pass the whole
// reviewed family; every caller that does know re-checks the exact one, so a
// collector advertising only bcm.access_test.v1 can never claim, be delivered
// for, or complete an inventory discovery.
func lockAccessTestCollector(ctx context.Context, tx pgx.Tx, clusterID domain.ClusterID, collectorID domain.CollectorID, operations ...string) error {
	if len(operations) == 0 {
		operations = domain.CredentialAccessOperations()
	}
	for _, operation := range operations {
		if !domain.IsCredentialAccessOperation(operation) {
			return ErrAccessTestCollectorIncompatible
		}
	}
	var eligible bool
	err := tx.QueryRow(ctx, `SELECT c.cluster_id=$2 AND c.status='ACTIVE' AND c.protocol_min<=2 AND c.protocol_max>=2
		AND EXISTS (SELECT 1 FROM collector_capabilities cap WHERE cap.collector_id=c.collector_id AND cap.capability=ANY($3) AND cap.version='1')
		FROM collectors c WHERE c.collector_id=$1 FOR SHARE OF c`, string(collectorID), string(clusterID), operations).Scan(&eligible)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && !eligible) {
		return ErrAccessTestCollectorIncompatible
	}
	if err != nil {
		return fmt.Errorf("lock collector for credential access test: %w", err)
	}
	return nil
}

func loadAccessTestAttempt(ctx context.Context, tx pgx.Tx, clusterID domain.ClusterID, collectorID domain.CollectorID, ref CredentialAccessTestLeaseRef) (accessTestAttemptState, bool, error) {
	tokenHash := sha256.Sum256([]byte(ref.LeaseToken))
	var state accessTestAttemptState
	var digest []byte
	var encodedPlan []byte
	var leaseExpires time.Time
	err := tx.QueryRow(ctx, `SELECT t.status, a.status, a.outcome_code, a.lease_expires_at, t.deadline, a.delivery_count, t.plan_digest, t.plan, t.credential_id, t.credential_version, t.host, t.purpose, t.username
		FROM credential_access_tests t JOIN credential_access_test_attempts a ON a.test_id=t.test_id
		WHERE t.test_id=$1 AND a.attempt=$2 AND t.cluster_id=$3 AND a.collector_id=$4 AND a.lease_token_hash=$5
		FOR UPDATE OF t, a`, ref.TestID, ref.Attempt, string(clusterID), string(collectorID), tokenHash[:]).Scan(
		&state.testStatus, &state.attemptStatus, &state.attemptOutcome, &leaseExpires, &state.deadline, &state.deliveryCount, &digest, &encodedPlan, &state.credentialID, &state.credentialVersion, &state.host, &state.purpose, &state.username)
	if errors.Is(err, pgx.ErrNoRows) {
		return accessTestAttemptState{}, false, nil
	}
	if err != nil {
		return accessTestAttemptState{}, false, fmt.Errorf("lock credential access test attempt: %w", err)
	}
	state.leaseExpires = leaseExpires.UTC()
	copy(state.planDigest[:], digest)
	if err := json.Unmarshal(encodedPlan, &state.plan); err != nil {
		return accessTestAttemptState{}, false, fmt.Errorf("%w: stored credential access test plan is invalid", ErrConflict)
	}
	return state, true, nil
}

// lockAccessTestAttempt requires a live, unexpired lease on a non-terminal
// test; anything else is a lease failure, never a partial authorization.
func lockAccessTestAttempt(ctx context.Context, tx pgx.Tx, clusterID domain.ClusterID, collectorID domain.CollectorID, ref CredentialAccessTestLeaseRef) (accessTestAttemptState, error) {
	state, found, err := loadAccessTestAttempt(ctx, tx, clusterID, collectorID, ref)
	if err != nil {
		return accessTestAttemptState{}, err
	}
	now := time.Now().UTC()
	if !found || (state.attemptStatus != "CLAIMED" && state.attemptStatus != "STARTED") || state.testStatus.Terminal() || (state.testStatus != domain.CredentialAccessTestClaimed && state.testStatus != domain.CredentialAccessTestRunning) || !state.leaseExpires.After(now) || !state.deadline.After(now) {
		return accessTestAttemptState{}, ErrAccessTestLeaseInvalid
	}
	if err := lockAccessTestCollector(ctx, tx, clusterID, collectorID, state.plan.Operation); err != nil {
		return accessTestAttemptState{}, err
	}
	return state, nil
}

func lockAccessTestAttemptForCompletion(ctx context.Context, tx pgx.Tx, clusterID domain.ClusterID, collectorID domain.CollectorID, ref CredentialAccessTestLeaseRef) (accessTestAttemptState, error) {
	state, found, err := loadAccessTestAttempt(ctx, tx, clusterID, collectorID, ref)
	if err != nil {
		return accessTestAttemptState{}, err
	}
	if !found {
		return accessTestAttemptState{}, ErrAccessTestLeaseInvalid
	}
	if err := lockAccessTestCollector(ctx, tx, clusterID, collectorID, state.plan.Operation); err != nil {
		return accessTestAttemptState{}, err
	}
	return state, nil
}

// expireAccessTests runs the lazy expiry pass for one cluster in a short
// transaction of its own. Callers that already hold a transaction use
// expireAccessTestsTx directly.
func (store *PostgresStore) expireAccessTests(ctx context.Context, clusterID domain.ClusterID) error {
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin credential access test expiry: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := expireAccessTestsTx(ctx, tx, clusterID); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit credential access test expiry: %w", err)
	}
	return nil
}

func expireAccessTestsTx(ctx context.Context, tx pgx.Tx, clusterID domain.ClusterID) error {
	rows, err := tx.Query(ctx, `UPDATE credential_access_tests SET status='EXPIRED', completed_at=clock_timestamp(), outcome_code='EXPIRED', outcome_summary='No compatible head collector completed the test before its deadline.'
		WHERE cluster_id=$1 AND status IN ('REQUESTED','CLAIMED','RUNNING') AND (deadline<=clock_timestamp() OR (next_attempt>max_attempts AND NOT EXISTS (SELECT 1 FROM credential_access_test_attempts a WHERE a.test_id=credential_access_tests.test_id AND a.status IN ('CLAIMED','STARTED') AND a.lease_expires_at>clock_timestamp())))
		RETURNING test_id, credential_id, credential_version`, string(clusterID))
	if err != nil {
		return fmt.Errorf("expire credential access tests: %w", err)
	}
	expired := make([]accessTestEvent, 0)
	for rows.Next() {
		event := accessTestEvent{Kind: EventAccessTestExpired, Outcome: "SUCCEEDED", Reason: "DEADLINE", ActorKind: "SYSTEM", Actor: "control", ClusterID: string(clusterID), OccurredAt: time.Now().UTC()}
		if err := rows.Scan(&event.TestID, &event.CredentialID, &event.CredentialVersion); err != nil {
			rows.Close()
			return err
		}
		expired = append(expired, event)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, event := range expired {
		if _, err := tx.Exec(ctx, `UPDATE credential_access_test_attempts SET status='EXPIRED', completed_at=clock_timestamp(), outcome_code='EXPIRED' WHERE test_id=$1 AND status IN ('CLAIMED','STARTED')`, event.TestID); err != nil {
			return err
		}
		if err := insertAccessTestEvent(ctx, tx, event); err != nil {
			return err
		}
	}
	rows, err = tx.Query(ctx, `UPDATE credential_access_tests t SET status='FAILED', completed_at=clock_timestamp(), outcome_code='CREDENTIAL_UNAVAILABLE', outcome_summary='The tested credential version was replaced or revoked before the head could use it.'
		WHERE t.cluster_id=$1 AND t.status='REQUESTED'
		  AND NOT EXISTS (SELECT 1 FROM cluster_credentials cc WHERE cc.credential_id=t.credential_id AND cc.cluster_id=t.cluster_id AND cc.credential_version=t.credential_version AND cc.status='ACTIVE')
		RETURNING t.test_id, t.credential_id, t.credential_version`, string(clusterID))
	if err != nil {
		return fmt.Errorf("fail stale credential access tests: %w", err)
	}
	stale := make([]accessTestEvent, 0)
	for rows.Next() {
		event := accessTestEvent{Kind: EventAccessTestExpired, Outcome: "SUCCEEDED", Reason: "CREDENTIAL_UNAVAILABLE", ActorKind: "SYSTEM", Actor: "control", ClusterID: string(clusterID), OccurredAt: time.Now().UTC()}
		if err := rows.Scan(&event.TestID, &event.CredentialID, &event.CredentialVersion); err != nil {
			rows.Close()
			return err
		}
		stale = append(stale, event)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, event := range stale {
		if err := insertAccessTestEvent(ctx, tx, event); err != nil {
			return err
		}
	}
	return nil
}

func validateAccessTestLeaseRef(clusterID domain.ClusterID, collectorID domain.CollectorID, ref CredentialAccessTestLeaseRef) error {
	if validateClusterID(string(clusterID)) != nil || collectorID == "" || !domain.ValidCredentialAccessTestID(ref.TestID) || ref.Attempt < 1 || ref.Attempt > domain.CredentialAccessTestMaxAttempts || len(ref.LeaseToken) < 32 || len(ref.LeaseToken) > 256 {
		return ErrInvalid
	}
	return nil
}

type accessTestEvent struct {
	Kind, Outcome, Reason, ActorKind, Actor, ClusterID, TestID, CredentialID, RequestID string
	Attempt                                                                             int
	CredentialVersion                                                                   int64
	OccurredAt                                                                          time.Time
}

func insertAccessTestEvent(ctx context.Context, tx pgx.Tx, event accessTestEvent) error {
	eventID, err := newAccessTestEventID()
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO credential_access_test_events (event_id,event_kind,outcome,reason_code,actor_kind,actor,cluster_id,test_id,attempt,credential_id,credential_version,request_id,occurred_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, eventID, event.Kind, event.Outcome, event.Reason, event.ActorKind, event.Actor, event.ClusterID, event.TestID, event.Attempt, event.CredentialID, event.CredentialVersion, event.RequestID, event.OccurredAt.UTC()); err != nil {
		return classifyMutationError("record credential access test event", err)
	}
	return nil
}

const accessTestProjectionSQL = `SELECT t.test_id, t.cluster_id, t.credential_id, t.credential_version, t.host, t.purpose, t.username, t.operation, t.status, t.requested_by, t.requested_at, t.deadline,
	COALESCE(a.attempt,0), COALESCE(a.collector_id,''), a.lease_expires_at, t.outcome_code, t.outcome_summary, t.bcm_version, t.devices_listed, t.completed_at, COALESCE(t.cancelled_by,''),
	(cc.status='ACTIVE' AND cc.credential_version=t.credential_version), cc.status
	FROM credential_access_tests t
	JOIN cluster_credentials cc ON cc.credential_id=t.credential_id
	LEFT JOIN LATERAL (SELECT attempt, collector_id, lease_expires_at FROM credential_access_test_attempts WHERE test_id=t.test_id ORDER BY attempt DESC LIMIT 1) a ON TRUE`

func scanAccessTest(rows pgx.Rows) (CredentialAccessTest, error) {
	var test CredentialAccessTest
	var status string
	if err := rows.Scan(&test.ID, &test.ClusterID, &test.CredentialID, &test.CredentialVersion, &test.Host, &test.Purpose, &test.Username, &test.Operation, &status, &test.RequestedBy, &test.RequestedAt, &test.Deadline,
		&test.Attempt, &test.CollectorID, &test.LeaseExpiresAt, &test.OutcomeCode, &test.OutcomeSummary, &test.BCMVersion, &test.DevicesListed, &test.CompletedAt, &test.CancelledBy, &test.CredentialCurrent, &test.CredentialStatus); err != nil {
		return CredentialAccessTest{}, fmt.Errorf("scan credential access test: %w", err)
	}
	test.Status = domain.CredentialAccessTestStatus(status)
	return test, nil
}

func newCredentialAccessTestID() (string, error) {
	raw := make([]byte, 18)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return "", err
	}
	return "ctest_" + base64.RawURLEncoding.EncodeToString(raw), nil
}

func newAccessTestEventID() (string, error) {
	raw := make([]byte, 18)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return "", err
	}
	return "ctest_event_" + base64.RawURLEncoding.EncodeToString(raw), nil
}
