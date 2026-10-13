// sherlock-network-probe is an operator-run, one-shot discovery tool. It does
// not enroll ports, run periodically, persist readings, or send notifications.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/networkprobe"
)

type result struct {
	Node       string                           `json:"node"`
	ObservedAt time.Time                        `json:"observed_at"`
	Outcome    string                           `json:"outcome"`
	ReadError  string                           `json:"read_error,omitempty"`
	BootID     string                           `json:"boot_id,omitempty"`
	Ports      []application.NetworkPortReading `json:"ports,omitempty"`
}

func main() {
	// The outer bound includes all ten sequential node deadlines plus startup.
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	encoder := json.NewEncoder(os.Stdout)
	runner := networkprobe.SSHRunner{}
	failed := false
	for _, node := range networkprobe.PilotNodes {
		poll, err := networkprobe.Probe(ctx, runner, node, time.Now)
		if err != nil {
			fmt.Fprintln(os.Stderr, "network probe setup failed")
			os.Exit(2)
		}
		if poll.Outcome != application.NetworkPollComplete {
			failed = true
		}
		if err := encoder.Encode(result{Node: poll.Node, ObservedAt: poll.ObservedAt, Outcome: poll.Outcome,
			ReadError: poll.ReadError, BootID: poll.BootID, Ports: poll.Ports}); err != nil {
			fmt.Fprintln(os.Stderr, "network probe output failed")
			os.Exit(2)
		}
	}
	if failed {
		os.Exit(1)
	}
}
