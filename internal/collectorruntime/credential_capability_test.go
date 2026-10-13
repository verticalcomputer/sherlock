package collectorruntime

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

func TestRuntimeAdvertisesAdditionalCapabilityWithProtocolRange(t *testing.T) {
	var mu sync.Mutex
	var seen Heartbeat
	client := &fakeControl{heartbeat: func(_ context.Context, heartbeat Heartbeat, _ int) error {
		mu.Lock()
		seen = heartbeat
		mu.Unlock()
		return nil
	}}
	journal := openTestJournal(t, filepath.Join(t.TempDir(), "journal.db"), fakeRuntimeClock{})
	runtime, err := NewRuntime(RuntimeConfig{CollectorID: "collector-1", SourceID: "source-1", Version: "v", Capabilities: []string{string(domain.QueryGPUUtilization)}, HeartbeatInterval: time.Hour, ClaimWait: 10 * time.Millisecond, RenewInterval: time.Second, BackoffMinimum: time.Millisecond, BackoffMaximum: time.Millisecond, AdditionalCapabilities: []string{domain.CredentialAccessTestOperation}}, client, executorFunc(func(context.Context, domain.CollectionTask) domain.CollectionResult { return domain.CollectionResult{} }), journal, fakeRuntimeClock{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_ = runtime.Run(ctx)
	mu.Lock()
	defer mu.Unlock()
	if seen.ProtocolMin != 1 || seen.ProtocolMax != domain.CollectionProtocolVersion {
		t.Fatalf("protocol range not advertised: %+v", seen)
	}
	found := false
	for _, capability := range seen.Capabilities {
		if capability.Name == domain.CredentialAccessTestOperation && capability.Version == "1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("capability not advertised: %+v", seen.Capabilities)
	}
}
