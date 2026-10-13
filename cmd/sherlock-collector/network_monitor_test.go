package main

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/networkprobe"
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
