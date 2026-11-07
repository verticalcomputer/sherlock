package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/config"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/gpussh"
	"github.com/verticalcomputer/sherlock/internal/networkprobe"
	"github.com/verticalcomputer/sherlock/internal/servicefailure"
)

type networkFake struct {
	active, max atomic.Int32
	calls       atomic.Int32
}

func (f *networkFake) Read(ctx context.Context, node string) ([]byte, []byte, error) {
	current := f.active.Add(1)
	defer f.active.Add(-1)
	for {
		m := f.max.Load()
		if current <= m || f.max.CompareAndSwap(m, current) {
			break
		}
	}
	f.calls.Add(1)
	select {
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	case <-time.After(time.Millisecond):
	}
	return []byte(`{"boot_id":"12345678","ports":[]}`), nil, nil
}
func TestNetworkCycleReadsExactlyApprovedNodesWithBoundedFanout(t *testing.T) {
	f := &networkFake{}
	cycle := collectNetworkCycle(context.Background(), f, "revision-v1")
	if f.calls.Load() != 14 || f.max.Load() > 2 {
		t.Fatalf("calls=%d max=%d", f.calls.Load(), f.max.Load())
	}
	for i, p := range cycle.Polls {
		if p.Node != networkprobe.FixtureNetworkNodes[i] || p.InventoryRevision != "revision-v1" || p.Outcome != "COMPLETE" {
			t.Fatal(fmt.Sprint(p))
		}
	}
}
func TestNetworkCycleCancelJoinsReaders(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f := &networkFake{}
	done := make(chan struct{})
	go func() { collectNetworkCycle(ctx, f, "revision-v1"); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("cancellation leaked readers")
	}
	if f.active.Load() != 0 {
		t.Fatal("reader still active")
	}
}

func TestNetworkMonitorValidatesIdentityBeforeAnyNodeRead(t *testing.T) {
	t.Setenv("SHERLOCK_NETWORK_MONITOR_ENABLED", "true")
	t.Setenv("SHERLOCK_NETWORK_MONITOR_REVISION", "fixture")
	t.Setenv("SHERLOCK_CLUSTER_ID", "fixture2-zone2")
	t.Setenv("SHERLOCK_COLLECTOR_IDENTITY_DIR", "")
	f := &networkFake{}
	err := runNetworkMonitorOnHost(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)), "fixture2-zone1-headnode", f)
	if !errors.Is(err, servicefailure.ErrConfiguration) || f.calls.Load() != 0 {
		t.Fatalf("identity failure called nodes=%d err=%v", f.calls.Load(), err)
	}
}

func TestReadinessAndGPUStartupRequireIndependentApproval(t *testing.T) {
	t.Setenv(gpussh.Environment, "")
	cfg := config.Collector{ClusterID: "cluster", Operations: []domain.CollectionOperationID{domain.OperationGPUProcessObservations}}
	if err := writeCollectionReadiness(io.Discard, cfg, nil); !errors.Is(err, gpussh.ErrBlocked) {
		t.Fatalf("GPU readiness escaped operator policy: %v", err)
	}
	if _, _, err := buildCollectionExecutors(cfg, nil); !errors.Is(err, gpussh.ErrBlocked) {
		t.Fatalf("ordinary GPU startup escaped policy: %v", err)
	}
	if err := qualifyNetworkMonitor(context.Background(), io.Discard); !errors.Is(err, gpussh.ErrBlocked) {
		t.Fatalf("network readiness escaped policy: %v", err)
	}
	// Even an explicit readiness approval cannot bypass missing identity.
	path := filepath.Join(t.TempDir(), "approval.json")
	a := gpussh.Approval{Schema: "sherlock.gpu-ssh-approval.v1", ClusterID: "fixture2-zone2", Roles: []string{"network-readiness"}, ApprovedBy: "fixture", ApprovalID: "test-only", ExpiresAt: time.Now().Add(time.Hour)}
	b, _ := json.Marshal(a)
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(gpussh.Environment, path)
	t.Setenv("SHERLOCK_COLLECTOR_IDENTITY_DIR", "")
	if err := qualifyNetworkMonitor(context.Background(), io.Discard); err == nil {
		t.Fatal("network readiness ignored identity")
	}
}
