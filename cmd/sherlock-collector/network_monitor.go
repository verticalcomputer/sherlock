package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/collectorruntime"
	"github.com/verticalcomputer/sherlock/internal/config"
	"github.com/verticalcomputer/sherlock/internal/gpussh"
	"github.com/verticalcomputer/sherlock/internal/networkmonitor"
	"github.com/verticalcomputer/sherlock/internal/networkprobe"
	"github.com/verticalcomputer/sherlock/internal/servicefailure"
)

// Independent of the collection journal and its work-claim loop. A complete
// fleet cycle fits in the interval even when every two-way read times out.
func collectNetworkCycle(ctx context.Context, runner networkprobe.Runner, revision string) networkmonitor.Cycle {
	started := time.Now()
	polls := make([]application.NetworkNodePoll, len(networkprobe.FixtureNetworkNodes))
	var wg sync.WaitGroup
	slots := make(chan struct{}, 2)
	for i, node := range networkprobe.FixtureNetworkNodes {
		wg.Add(1)
		go func(i int, node string) {
			defer wg.Done()
			select {
			case slots <- struct{}{}:
				defer func() { <-slots }()
			case <-ctx.Done():
				return
			}
			p, err := networkprobe.Probe(ctx, runner, node, time.Now)
			if err != nil {
				return
			}
			p.InventoryRevision = revision
			p.ManagementRevision = os.Getenv("SHERLOCK_NETWORK_MANAGEMENT_REVISION")
			polls[i] = p
		}(i, node)
	}
	wg.Wait()
	return networkmonitor.Cycle{Revision: revision, Polls: polls, DurationMS: time.Since(started).Milliseconds()}
}
func runNetworkMonitor(ctx context.Context, logger *slog.Logger) error {
	host, err := os.Hostname()
	if err != nil {
		return configurationFailure(errors.New("network head identity unavailable"))
	}
	return runNetworkMonitorOnHost(ctx, logger, host, networkprobe.SSHRunner{ClusterID: "fixture2-zone2", Role: "network-monitor"})
}

// The runner/hostname parameters are local fixture seams, never control input.
func runNetworkMonitorOnHost(ctx context.Context, logger *slog.Logger, host string, runner networkprobe.Runner) error {
	if os.Getenv("SHERLOCK_NETWORK_MONITOR_ENABLED") != "true" || os.Getenv("SHERLOCK_NETWORK_MONITOR_REVISION") == "" {
		return configurationFailure(errors.New("network monitoring is not explicitly enabled"))
	}
	if host != "fixture2-zone1-headnode" {
		return configurationFailure(errors.New("network monitoring requires the approved FixtureNetwork 2 head"))
	}
	revision := os.Getenv("SHERLOCK_NETWORK_MONITOR_REVISION")
	ticker := time.NewTicker(networkmonitor.Interval)
	defer ticker.Stop()
	for {
		bounded, cancel := context.WithTimeout(ctx, 65*time.Second)
		// Validate current identity and independent operator authority before
		// any node probe, including the first cycle after boot or renewal.
		cfg, err := config.LoadCollectorRenewal()
		if err != nil {
			err = configurationFailure(err)
		}
		if err == nil && os.Getenv("SHERLOCK_CLUSTER_ID") != "fixture2-zone2" {
			err = configurationFailure(fmt.Errorf("wrong network cluster"))
		}
		var cycle networkmonitor.Cycle
		if err == nil {
			err = gpussh.Require("network-monitor", "fixture2-zone2")
		}
		if err == nil {
			client, clientErr := controlHTTPClient(cfg)
			err = configurationFailure(clientErr)
			if err == nil {
				control, clientErr := collectorruntime.NewHTTPClient(cfg.ControlURL, client, time.Minute)
				err = clientErr
				if err == nil {
					cycle = collectNetworkCycle(bounded, runner, revision)
					err = control.SubmitNetworkCycle(bounded, cycle)
				}
				client.CloseIdleConnections()
			}
		}
		cancel()
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if servicefailure.Permanent(err) || errors.Is(err, gpussh.ErrBlocked) {
			return err
		}
		if err != nil {
			logger.Warn("collector.network_cycle_failed", "reason", "poll delivery unavailable")
		} else {
			logger.Info("collector.network_cycle_committed", "nodes", len(cycle.Polls), "revision", revision)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// qualifyNetworkMonitor is a one-shot source-only check in the final service
// sandbox. It publishes no data and opens no collection journal.
func qualifyNetworkMonitor(ctx context.Context, out io.Writer) error {
	if err := gpussh.Require("network-readiness", "fixture2-zone2"); err != nil {
		return err
	}
	cfg, err := config.LoadCollectorRenewal()
	if err != nil {
		return err
	}
	client, err := controlHTTPClient(cfg)
	if err != nil {
		return err
	}
	client.CloseIdleConnections()
	host, err := os.Hostname()
	if err != nil || host != "fixture2-zone1-headnode" {
		return errors.New("unapproved network head")
	}
	bounded, cancel := context.WithTimeout(ctx, 65*time.Second)
	defer cancel()
	cycle := collectNetworkCycle(bounded, networkprobe.SSHRunner{ClusterID: "fixture2-zone2", Role: "network-readiness"}, "qualification-only")
	if err := json.NewEncoder(out).Encode(cycle); err != nil {
		return err
	}
	for _, p := range cycle.Polls {
		if p.Outcome != application.NetworkPollComplete {
			return errors.New("source qualification incomplete")
		}
	}
	return nil
}
