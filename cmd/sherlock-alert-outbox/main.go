// sherlock-alert-outbox is an operator-run GP-09 delivery checkpoint. No
// automatic source, schedule or alert policy is enabled by this command.
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/verticalcomputer/sherlock/internal/alertdelivery"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

const webhookFile = "/etc/sherlock/alert-secrets/slack-webhook.url"

func main() {
	if len(os.Args) != 2 || (os.Args[1] != "enqueue-test" && os.Args[1] != "deliver-once") {
		fmt.Fprintln(os.Stderr, "use enqueue-test or deliver-once")
		os.Exit(2)
	}
	databaseURL := os.Getenv("SHERLOCK_DATABASE_URL")
	if databaseURL == "" {
		fmt.Fprintln(os.Stderr, "GP-09 database configuration is unavailable")
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		fmt.Fprintln(os.Stderr, "GP-09 database connection failed")
		os.Exit(1)
	}
	defer pool.Close()
	store, err := storepg.NewAlertOutboxStore(pool)
	if err != nil {
		fmt.Fprintln(os.Stderr, "GP-09 outbox is unavailable")
		os.Exit(1)
	}
	if os.Args[1] == "enqueue-test" {
		id, err := storepg.NewAlertID()
		if err != nil {
			fmt.Fprintln(os.Stderr, "GP-09 test identity failed")
			os.Exit(1)
		}
		message := fmt.Sprintf("[SHERLOCK GP-09 OUTBOX TEST] Durable delivery check at %s UTC. This is a test only; no node or network fault is being reported.", time.Now().UTC().Format("2006-01-02 15:04:05"))
		queued, err := store.Enqueue(ctx, storepg.AlertOutboxEntry{ID: id, ClusterID: "pilot-cluster", EventKey: id, Transition: "TEST", Message: message})
		if err != nil {
			fmt.Fprintln(os.Stderr, "GP-09 test could not be queued")
			os.Exit(1)
		}
		fmt.Println("queued", queued)
		return
	}
	webhook, err := alertdelivery.LoadWebhookFile(webhookFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "GP-09 Slack webhook configuration is unavailable")
		os.Exit(2)
	}
	claim, found, err := store.Claim(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "GP-09 alert claim failed")
		os.Exit(1)
	}
	if !found {
		fmt.Println("no due GP-09 alerts")
		return
	}
	result := (alertdelivery.Sender{}).Send(ctx, webhook, claim.Message)
	state, err := store.Finish(ctx, claim, result)
	if err != nil {
		fmt.Fprintln(os.Stderr, "GP-09 delivery receipt failed; lease will expire for retry")
		os.Exit(1)
	}
	fmt.Printf("%s state=%s %s\n", claim.ID, state, result.Describe())
	if state != "ACCEPTED" {
		os.Exit(1)
	}
}
