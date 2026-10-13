// sherlock-alert-test is an operator-run, one-shot GP-09 receiver smoke test.
// It does not claim or generate a node/rail incident.
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/verticalcomputer/sherlock/internal/alertdelivery"
)

const webhookFile = "/etc/sherlock/alert-secrets/slack-webhook.url"

func main() {
	webhook, err := alertdelivery.LoadWebhookFile(webhookFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "GP-09 Slack webhook configuration is unavailable")
		os.Exit(2)
	}
	message := fmt.Sprintf("[SHERLOCK GP-09 TEST] Delivery check at %s UTC. This is a test only; no node or network fault is being reported.",
		time.Now().UTC().Format("2006-01-02 15:04:05"))
	result := (alertdelivery.Sender{}).Send(context.Background(), webhook, message)
	fmt.Println(result.Describe())
	if result.Outcome != alertdelivery.Accepted {
		os.Exit(1)
	}
}
