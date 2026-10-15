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
	"github.com/verticalcomputer/sherlock/internal/alertdelivery"
)

const maxAlertAttempts = 8

type AlertOutboxStore struct{ pool *pgxpool.Pool }

func NewAlertOutboxStore(pool *pgxpool.Pool) (*AlertOutboxStore, error) {
	if pool == nil {
		return nil, errors.New("PostgreSQL pool is required")
	}
	return &AlertOutboxStore{pool: pool}, nil
}

type AlertOutboxEntry struct {
	ID         string
	ClusterID  string
	EventKey   string
	Transition string
	Message    string
}

func NewAlertID() (string, error) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	return "gp09-alert-" + hex.EncodeToString(random[:]), nil
}

// Enqueue is idempotent for one reviewed event transition. A repeated key
// with different content is a conflict, not an implicit edit to a queued alert.
// Incident producers must call an equivalent insert inside their own incident
// transition transaction; this standalone method currently serves TEST only.
func (store *AlertOutboxStore) Enqueue(ctx context.Context, entry AlertOutboxEntry) (string, error) {
	if !validAlertEntry(entry) || entry.Transition != "TEST" {
		return "", errors.New("invalid GP-09 test alert")
	}
	_, err := store.pool.Exec(ctx, `INSERT INTO gp09_alert_outbox(alert_id,cluster_id,event_key,transition,message)
		VALUES($1,$2,$3,$4,$5) ON CONFLICT (cluster_id,event_key,transition) DO NOTHING`,
		entry.ID, entry.ClusterID, entry.EventKey, entry.Transition, entry.Message)
	if err != nil {
		return "", fmt.Errorf("enqueue GP-09 test alert: %w", err)
	}
	var id, message string
	if err := store.pool.QueryRow(ctx, `SELECT alert_id,message FROM gp09_alert_outbox
		WHERE cluster_id=$1 AND event_key=$2 AND transition=$3`, entry.ClusterID, entry.EventKey, entry.Transition).Scan(&id, &message); err != nil {
		return "", fmt.Errorf("read queued GP-09 test alert: %w", err)
	}
	if message != entry.Message {
		return "", errors.New("GP-09 alert idempotency conflict")
	}
	return id, nil
}

func validAlertEntry(entry AlertOutboxEntry) bool {
	for _, value := range []string{entry.ID, entry.ClusterID, entry.EventKey, entry.Transition} {
		if value == "" || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\r\n\x00") {
			return false
		}
	}
	return len(entry.ID) >= 8 && len(entry.ID) <= 128 && len(entry.ClusterID) <= 128 &&
		len(entry.EventKey) <= 256 && len(entry.Message) > 0 && len(entry.Message) <= alertdelivery.MaxMessageBytes
}

type AlertClaim struct {
	ID         string
	ClusterID  string
	Message    string
	Token      string
	Attempt    int
	LeaseUntil time.Time
}

// Claim selects one due row with SKIP LOCKED. Expired leases are retryable:
// a previous HTTP acceptance can therefore be delivered twice if its result
// was lost before Finish committed.
func (store *AlertOutboxStore) Claim(ctx context.Context) (AlertClaim, bool, error) {
	return store.claim(ctx, "")
}

// ClaimForCluster bounds lab/tenant-specific delivery without consuming another
// cluster's alerts. Ordinary alert-worker delivery retains its existing scope.
func (store *AlertOutboxStore) ClaimForCluster(ctx context.Context, cluster string) (AlertClaim, bool, error) {
	if cluster == "" || len(cluster) > 128 || strings.ContainsAny(cluster, "\r\n\x00") {
		return AlertClaim{}, false, errors.New("invalid alert cluster scope")
	}
	return store.claim(ctx, cluster)
}
func (store *AlertOutboxStore) claim(ctx context.Context, cluster string) (AlertClaim, bool, error) {
	if _, err := store.pool.Exec(ctx, `UPDATE gp09_alert_outbox SET status='FAILED',lease_token=NULL,
		lease_until=NULL,last_code='RECEIPT_LOST_AFTER_ATTEMPT_LIMIT',updated_at=clock_timestamp()
		WHERE status='LEASED' AND attempt_count>=8 AND lease_until<=clock_timestamp() AND ($1='' OR cluster_id=$1)`, cluster); err != nil {
		return AlertClaim{}, false, fmt.Errorf("expire exhausted GP-09 delivery leases: %w", err)
	}
	var tokenBytes [16]byte
	if _, err := rand.Read(tokenBytes[:]); err != nil {
		return AlertClaim{}, false, err
	}
	token := hex.EncodeToString(tokenBytes[:])
	var claim AlertClaim
	err := store.pool.QueryRow(ctx, `WITH candidate AS (
		SELECT alert_id FROM gp09_alert_outbox
		WHERE ($2='' OR cluster_id=$2) AND attempt_count < 8 AND
			((status='PENDING' AND available_at<=clock_timestamp()) OR
			 (status='LEASED' AND lease_until<=clock_timestamp()))
		ORDER BY available_at,alert_id FOR UPDATE SKIP LOCKED LIMIT 1
	)
	UPDATE gp09_alert_outbox o SET status='LEASED',attempt_count=o.attempt_count+1,
		lease_token=$1,lease_until=clock_timestamp()+interval '30 seconds',updated_at=clock_timestamp()
	FROM candidate c WHERE o.alert_id=c.alert_id
	RETURNING o.alert_id,o.cluster_id,o.message,o.attempt_count,o.lease_until`, token, cluster).
		Scan(&claim.ID, &claim.ClusterID, &claim.Message, &claim.Attempt, &claim.LeaseUntil)
	if errors.Is(err, pgx.ErrNoRows) {
		return AlertClaim{}, false, nil
	}
	if err != nil {
		return AlertClaim{}, false, fmt.Errorf("claim GP-09 alert: %w", err)
	}
	claim.Token = token
	return claim, true, nil
}

// Finish records an attempt and the resulting outbox state in one transaction.
// A late owner cannot overwrite a newer lease or an accepted delivery.
func (store *AlertOutboxStore) Finish(ctx context.Context, claim AlertClaim, result alertdelivery.Result) (string, error) {
	if claim.ID == "" || claim.Token == "" || claim.Attempt < 1 || claim.Attempt > maxAlertAttempts ||
		!validDeliveryCode(result.Code) || result.HTTPStatus < 0 || result.HTTPStatus > 599 {
		return "", errors.New("invalid GP-09 delivery result")
	}
	if result.Outcome != alertdelivery.Accepted && result.Outcome != alertdelivery.RetryableFailure && result.Outcome != alertdelivery.PermanentFailure {
		return "", errors.New("invalid GP-09 delivery outcome")
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return "", fmt.Errorf("begin GP-09 delivery receipt: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var attempt int
	err = tx.QueryRow(ctx, `SELECT attempt_count FROM gp09_alert_outbox
		WHERE alert_id=$1 AND lease_token=$2 AND status='LEASED' AND lease_until>clock_timestamp()
		FOR UPDATE`, claim.ID, claim.Token).Scan(&attempt)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", errors.New("GP-09 delivery lease is no longer current")
	}
	if err != nil {
		return "", fmt.Errorf("lock GP-09 delivery lease: %w", err)
	}
	if attempt != claim.Attempt {
		return "", errors.New("GP-09 delivery attempt changed")
	}
	status := "PENDING"
	if result.Outcome == alertdelivery.Accepted {
		status = "ACCEPTED"
	}
	if result.Outcome == alertdelivery.PermanentFailure || attempt >= maxAlertAttempts {
		status = "FAILED"
	}
	delay := time.Duration(1<<min(attempt, 8)) * time.Second
	if result.RetryAfter > delay {
		delay = result.RetryAfter
	}
	if delay > 5*time.Minute {
		delay = 5 * time.Minute
	}
	if _, err := tx.Exec(ctx, `INSERT INTO gp09_alert_delivery_attempts(alert_id,attempt_no,outcome,code,http_status)
		VALUES($1,$2,$3,$4,$5)`, claim.ID, attempt, string(result.Outcome), result.Code, result.HTTPStatus); err != nil {
		return "", fmt.Errorf("record GP-09 delivery attempt: %w", err)
	}
	_, err = tx.Exec(ctx, `UPDATE gp09_alert_outbox SET status=$3,lease_token=NULL,lease_until=NULL,
		available_at=clock_timestamp()+make_interval(secs=>$4),
		accepted_at=CASE WHEN $3='ACCEPTED' THEN clock_timestamp() ELSE accepted_at END,
		last_code=$5,updated_at=clock_timestamp()
		WHERE alert_id=$1 AND lease_token=$2`, claim.ID, claim.Token, status, delay.Seconds(), result.Code)
	if err != nil {
		return "", fmt.Errorf("update GP-09 delivery state: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return "", fmt.Errorf("commit GP-09 delivery receipt: %w", err)
	}
	return status, nil
}

func validDeliveryCode(code string) bool {
	switch code {
	case "SLACK_ACCEPTED", "TRANSPORT_FAILURE", "RECEIVER_RETRYABLE", "RECEIVER_REJECTED", "UNEXPECTED_RESPONSE", "INVALID_INPUT":
		return true
	default:
		return false
	}
}
