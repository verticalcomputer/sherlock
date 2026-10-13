package main

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/alertdelivery"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

type fakeOutbox struct {
	mu       sync.Mutex
	queue    []storepg.AlertClaim
	claimed  int
	finished int
}

func (f *fakeOutbox) Claim(context.Context) (storepg.AlertClaim, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.queue) == 0 {
		return storepg.AlertClaim{}, false, nil
	}
	claim := f.queue[0]
	f.queue = f.queue[1:]
	f.claimed++
	return claim, true, nil
}
func (f *fakeOutbox) Finish(_ context.Context, _ storepg.AlertClaim, result alertdelivery.Result) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.finished++
	if result.Outcome == alertdelivery.Accepted {
		return "ACCEPTED", nil
	}
	return "PENDING", nil
}

type fakeSender func(context.Context, string, string) alertdelivery.Result

func (f fakeSender) Send(ctx context.Context, webhook, message string) alertdelivery.Result {
	return f(ctx, webhook, message)
}

func TestDeliverBatchLeavesRowsUntouchedWithoutReceiver(t *testing.T) {
	outbox := &fakeOutbox{queue: []storepg.AlertClaim{{ID: "one", Message: "test"}}}
	err := deliverBatch(context.Background(), outbox, fakeSender(func(context.Context, string, string) alertdelivery.Result {
		t.Fatal("sent without receiver")
		return alertdelivery.Result{}
	}), func() (string, error) { return "", errors.New("secret-canary") })
	if err == nil || err.Error() != "receiver unavailable" || outbox.claimed != 0 {
		t.Fatalf("err=%v claimed=%d", err, outbox.claimed)
	}
}

func TestDeliverBatchRecordsOneReceiptPerClaim(t *testing.T) {
	outbox := &fakeOutbox{queue: []storepg.AlertClaim{{ID: "one", Message: "first"}, {ID: "two", Message: "second"}}}
	sent := []string{}
	err := deliverBatch(context.Background(), outbox, fakeSender(func(_ context.Context, hook, message string) alertdelivery.Result {
		if hook != "hook" {
			t.Fatal("wrong hook")
		}
		sent = append(sent, message)
		return alertdelivery.Result{Outcome: alertdelivery.Accepted, Code: "SLACK_ACCEPTED", HTTPStatus: 200}
	}), func() (string, error) { return "hook", nil })
	if err != nil || outbox.claimed != 2 || outbox.finished != 2 || len(sent) != 2 || sent[0] != "first" || sent[1] != "second" {
		t.Fatalf("err=%v claimed=%d finished=%d sent=%v", err, outbox.claimed, outbox.finished, sent)
	}
}

func TestRunSerializesCyclesAndStopsOnCancel(t *testing.T) {
	outbox := &fakeOutbox{queue: []storepg.AlertClaim{{ID: "one", Message: "first"}, {ID: "two", Message: "second"}}}
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	var mu sync.Mutex
	inFlight, maxInFlight := 0, 0
	sender := fakeSender(func(ctx context.Context, _, _ string) alertdelivery.Result {
		mu.Lock()
		inFlight++
		if inFlight > maxInFlight {
			maxInFlight = inFlight
		}
		mu.Unlock()
		select {
		case entered <- struct{}{}:
		default:
		}
		select {
		case <-release:
		case <-ctx.Done():
		}
		mu.Lock()
		inFlight--
		mu.Unlock()
		return alertdelivery.Result{Outcome: alertdelivery.Accepted, Code: "SLACK_ACCEPTED", HTTPStatus: 200}
	})
	ctx, cancel := context.WithCancel(context.Background())
	ticks := make(chan time.Time, 2)
	done := make(chan struct{})
	go func() {
		defer close(done)
		run(ctx, outbox, sender, func() (string, error) { return "hook", nil }, ticks, func(error) {})
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("immediate cycle did not start")
	}
	ticks <- time.Now()
	cancel()
	close(release)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("worker failed to join")
	}
	mu.Lock()
	got := maxInFlight
	mu.Unlock()
	if got != 1 {
		t.Fatalf("overlapping sends: %d", got)
	}
}
