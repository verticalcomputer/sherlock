//go:build integration

package postgres_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/alertdelivery"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

func TestGP09AlertOutboxLeaseAndReceipts(t *testing.T) {
	pool := durableTestDatabase(t)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `INSERT INTO clusters(cluster_id,display_name) VALUES('pilot-cluster','Pilot')`); err != nil {
		t.Fatal(err)
	}
	store, err := storepg.NewAlertOutboxStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	id, err := storepg.NewAlertID()
	if err != nil {
		t.Fatal(err)
	}
	entry := storepg.AlertOutboxEntry{ID: id, ClusterID: "pilot-cluster", EventKey: "test-1", Transition: "TEST", Message: "[TEST] no real rail fault"}
	first, err := store.Enqueue(ctx, entry)
	if err != nil || first != id {
		t.Fatalf("enqueue=%s err=%v", first, err)
	}
	second, err := store.Enqueue(ctx, entry)
	if err != nil || second != id {
		t.Fatalf("idempotent enqueue=%s err=%v", second, err)
	}
	changed := entry
	changed.Message = "different payload"
	if _, err := store.Enqueue(ctx, changed); err == nil {
		t.Fatal("changed event payload accepted")
	}
	var mu sync.Mutex
	claims := []storepg.AlertClaim{}
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			claim, found, err := store.Claim(ctx)
			if err != nil {
				t.Error(err)
				return
			}
			if found {
				mu.Lock()
				claims = append(claims, claim)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if len(claims) != 1 || claims[0].ID != id || claims[0].Attempt != 1 {
		t.Fatalf("concurrent claims=%+v", claims)
	}
	claim := claims[0]
	if _, err := store.Finish(ctx, storepg.AlertClaim{ID: claim.ID, Token: "wrong", Attempt: 1}, alertdelivery.Result{Outcome: alertdelivery.Accepted, Code: "SLACK_ACCEPTED", HTTPStatus: 200}); err == nil {
		t.Fatal("wrong lease token accepted")
	}
	state, err := store.Finish(ctx, claim, alertdelivery.Result{Outcome: alertdelivery.RetryableFailure, Code: "RECEIVER_RETRYABLE", HTTPStatus: 429, RetryAfter: time.Second})
	if err != nil || state != "PENDING" {
		t.Fatalf("retry state=%s err=%v", state, err)
	}
	var attempts int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM gp09_alert_delivery_attempts WHERE alert_id=$1`, id).Scan(&attempts); err != nil || attempts != 1 {
		t.Fatalf("attempt count=%d err=%v", attempts, err)
	}
	// Advance only this private fixture's queue clock to avoid a wall-time sleep.
	if _, err := pool.Exec(ctx, `UPDATE gp09_alert_outbox SET available_at=clock_timestamp()-interval '1 second' WHERE alert_id=$1`, id); err != nil {
		t.Fatal(err)
	}
	claim2, found, err := store.Claim(ctx)
	if err != nil || !found || claim2.Attempt != 2 || claim2.Token == claim.Token {
		t.Fatalf("retry claim=%+v found=%v err=%v", claim2, found, err)
	}
	if _, err := store.Finish(ctx, claim, alertdelivery.Result{Outcome: alertdelivery.Accepted, Code: "SLACK_ACCEPTED", HTTPStatus: 200}); err == nil {
		t.Fatal("stale owner finished newer lease")
	}
	state, err = store.Finish(ctx, claim2, alertdelivery.Result{Outcome: alertdelivery.Accepted, Code: "SLACK_ACCEPTED", HTTPStatus: 200})
	if err != nil || state != "ACCEPTED" {
		t.Fatalf("accepted state=%s err=%v", state, err)
	}
	if _, found, err := store.Claim(ctx); err != nil || found {
		t.Fatalf("accepted alert reclaimed: found=%v err=%v", found, err)
	}
	var acceptedAt *time.Time
	if err := pool.QueryRow(ctx, `SELECT accepted_at FROM gp09_alert_outbox WHERE alert_id=$1`, id).Scan(&acceptedAt); err != nil || acceptedAt == nil {
		t.Fatalf("acceptance missing: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM gp09_alert_delivery_attempts WHERE alert_id=$1`, id).Scan(&attempts); err != nil || attempts != 2 {
		t.Fatalf("attempt count=%d err=%v", attempts, err)
	}
	var leaked int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM gp09_alert_outbox WHERE message LIKE '%hooks.slack.com%' OR last_code LIKE '%hooks.slack.com%'`).Scan(&leaked); err != nil || leaked != 0 {
		t.Fatalf("secret-shaped value persisted: %d %v", leaked, err)
	}
}

func TestGP09AlertOutboxPermanentAndExhaustedLease(t *testing.T) {
	pool := durableTestDatabase(t)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `INSERT INTO clusters(cluster_id,display_name) VALUES('pilot-cluster','Pilot')`); err != nil {
		t.Fatal(err)
	}
	store, _ := storepg.NewAlertOutboxStore(pool)
	for i := 0; i < 2; i++ {
		id, _ := storepg.NewAlertID()
		entry := storepg.AlertOutboxEntry{ID: id, ClusterID: "pilot-cluster", EventKey: fmt.Sprintf("event-%d", i), Transition: "TEST", Message: "test only"}
		if _, err := store.Enqueue(ctx, entry); err != nil {
			t.Fatal(err)
		}
		claim, found, err := store.Claim(ctx)
		if err != nil || !found || claim.ID != id {
			t.Fatalf("claim=%+v found=%v err=%v", claim, found, err)
		}
		if i == 0 {
			state, err := store.Finish(ctx, claim, alertdelivery.Result{Outcome: alertdelivery.PermanentFailure, Code: "RECEIVER_REJECTED", HTTPStatus: 403})
			if err != nil || state != "FAILED" {
				t.Fatalf("permanent=%s err=%v", state, err)
			}
		} else {
			if _, err := pool.Exec(ctx, `UPDATE gp09_alert_outbox SET attempt_count=8,lease_until=clock_timestamp()-interval '1 second' WHERE alert_id=$1`, id); err != nil {
				t.Fatal(err)
			}
			if _, found, err := store.Claim(ctx); err != nil || found {
				t.Fatalf("exhausted lease reclaimed: found=%v err=%v", found, err)
			}
			var status, code string
			if err := pool.QueryRow(ctx, `SELECT status,last_code FROM gp09_alert_outbox WHERE alert_id=$1`, id).Scan(&status, &code); err != nil || status != "FAILED" || code != "RECEIPT_LOST_AFTER_ATTEMPT_LIMIT" {
				t.Fatalf("exhausted status=%s code=%s err=%v", status, code, err)
			}
		}
	}
}
