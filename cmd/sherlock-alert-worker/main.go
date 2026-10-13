// sherlock-alert-worker drains committed GP-09 outbox rows. It does not
// observe nodes, create incidents, or decide whether an alert is warranted.
package main

import (
	"context"
	"errors"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/alertdelivery"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

const webhookFile = "/etc/sherlock/alert-secrets/slack-webhook.url"
const pollInterval = 5 * time.Second
const maxBatch = 16

type outbox interface {
	Claim(context.Context) (storepg.AlertClaim, bool, error)
	Finish(context.Context, storepg.AlertClaim, alertdelivery.Result) (string, error)
}

type slackSender interface {
	Send(context.Context, string, string) alertdelivery.Result
}

func deliverBatch(ctx context.Context, store outbox, sender slackSender, load func() (string, error)) error {
	// Read the receiver before claiming. A missing or invalid secret leaves all
	// committed messages pending instead of consuming their attempt budget.
	webhook, err := load()
	if err != nil {
		return errors.New("receiver unavailable")
	}
	for i := 0; i < maxBatch; i++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		claim, found, err := store.Claim(ctx)
		if err != nil {
			return errors.New("outbox claim failed")
		}
		if !found {
			return nil
		}
		result := sender.Send(ctx, webhook, claim.Message)
		if _, err := store.Finish(ctx, claim, result); err != nil {
			// The lease expires and can be reclaimed. A lost HTTP response can
			// produce a duplicate; the outbox does not claim exactly-once Slack.
			return errors.New("delivery receipt failed")
		}
	}
	return nil
}

func run(ctx context.Context, store outbox, sender slackSender, load func() (string, error), tick <-chan time.Time, report func(error)) {
	lastError := ""
	cycle := func() {
		err := deliverBatch(ctx, store, sender, load)
		if ctx.Err() != nil {
			return
		}
		if err == nil {
			lastError = ""
			return
		}
		if err.Error() != lastError {
			report(err)
			lastError = err.Error()
		}
	}
	cycle()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick:
			cycle()
		}
	}
}

func main() {
	databaseURL := os.Getenv("SHERLOCK_DATABASE_URL")
	if databaseURL == "" {
		log.Fatal("GP-09 database configuration is unavailable")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		log.Fatal("GP-09 database configuration is invalid")
	}
	config.MaxConns = 2
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		log.Fatal("GP-09 database connection failed")
	}
	defer pool.Close()
	store, err := storepg.NewAlertOutboxStore(pool)
	if err != nil {
		log.Fatal("GP-09 outbox is unavailable")
	}
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	run(ctx, store, alertdelivery.Sender{}, func() (string, error) {
		return alertdelivery.LoadWebhookFile(webhookFile)
	}, ticker.C, func(err error) { log.Print("GP-09 delivery cycle: ", err) })
}
