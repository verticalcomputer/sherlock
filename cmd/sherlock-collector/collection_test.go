package main

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/config"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

type slurmFixtureRunner struct {
	calls    int
	body     string
	bodies   map[string]string
	command  string
	args     []string
	maxBytes int
}

func (r *slurmFixtureRunner) Run(_ context.Context, maximum int, command string, args ...string) ([]byte, error) {
	r.calls++
	r.command = command
	r.args = append([]string(nil), args...)
	r.maxBytes = maximum
	if body, ok := r.bodies[command+" "+strings.Join(args, " ")]; ok {
		return []byte(body), nil
	}
	if body, ok := r.bodies[command]; ok {
		return []byte(body), nil
	}
	return []byte(r.body), nil
}

func slurmFixtureConfig() config.Collector {
	return config.Collector{Operations: []domain.CollectionOperationID{domain.OperationSlurmInventory}, SlurmClusterID: "cluster-1", SlurmSourceID: "slurm-1", SlurmNodes: map[domain.StableNodeID]string{"node-1": "comp007"}}
}

func TestCollectionReadinessOnlyAdvertisesInstalledOperations(t *testing.T) {
	cfg := slurmFixtureConfig()
	cfg.ControlURL = "https://endpoint.invalid"
	cfg.PrometheusURL = "https://source.invalid"
	cfg.PrometheusBearer = "secret-token"
	cfg.PrivateKeyFile = "/secret/key"
	cfg.AccessServiceTokenFile = "/secret/access"
	runner := &slurmFixtureRunner{}
	var output bytes.Buffer
	if err := writeCollectionReadiness(&output, cfg, runner); err != nil {
		t.Fatal(err)
	}
	var ready struct {
		Ready      bool                           `json:"ready"`
		Min        int                            `json:"protocol_min"`
		Max        int                            `json:"protocol_max"`
		Operations []domain.CollectionOperationID `json:"operations"`
	}
	if err := json.Unmarshal(output.Bytes(), &ready); err != nil {
		t.Fatal(err)
	}
	if !ready.Ready || ready.Min != 1 || ready.Max != 2 || !reflect.DeepEqual(ready.Operations, cfg.Operations) || runner.calls != 0 {
		t.Fatalf("readiness=%s calls=%d", output.String(), runner.calls)
	}
	for _, value := range []string{"secret", "endpoint", "source.invalid", "comp007", "cluster-1", "slurm-1"} {
		if strings.Contains(output.String(), value) {
			t.Fatalf("readiness leaked configuration: %s", value)
		}
	}
	for _, id := range []domain.CollectionOperationID{domain.OperationSlurmAllocation, domain.OperationSlurmEvents, "diagnostics:execute", "repair.execute.v1", "unknown"} {
		cfg.Operations = []domain.CollectionOperationID{id}
		output.Reset()
		if err := writeCollectionReadiness(&output, cfg, runner); err == nil || output.Len() != 0 {
			t.Fatalf("advertised unsupported operation %s", id)
		}
	}
	cfg = slurmFixtureConfig()
	t.Setenv("PATH", t.TempDir())
	if _, _, err := buildCollectionExecutors(cfg, nil); err == nil {
		t.Fatal("missing scontrol was advertised")
	}
}

func TestCollectionLegacyConfigurationKeepsV1Capabilities(t *testing.T) {
	cfg := config.Collector{Operations: []domain.CollectionOperationID{domain.OperationPrometheusGPUXID}, Capabilities: []string{string(domain.QueryGPUXID)}, PrometheusURL: "http://prometheus.invalid"}
	legacy, typed, err := buildCollectionExecutors(cfg, nil)
	if err != nil || legacy == nil || typed != nil {
		t.Fatalf("legacy=%v typed=%v err=%v", legacy, typed, err)
	}
	var output bytes.Buffer
	if err := writeCollectionReadiness(&output, cfg, nil); err != nil || !strings.Contains(output.String(), `"protocol_max":1`) {
		t.Fatalf("readiness=%s err=%v", output.String(), err)
	}
	cfg.Capabilities = append(cfg.Capabilities, "diagnostics:execute")
	if _, _, err := buildCollectionExecutors(cfg, nil); err == nil {
		t.Fatal("unconfigured capability accepted")
	}
}

func TestCollectionSlurmFixtureHasBoundedArgvAndStableIdentity(t *testing.T) {
	runner := &slurmFixtureRunner{body: `{"nodes":[{"name":"comp007","state":"ALLOCATED","last_busy":123}]}`}
	_, registry, err := buildCollectionExecutors(slurmFixtureConfig(), runner)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	p := domain.CollectionPlan{SchemaVersion: 2, RunID: "run-1", ClusterID: "cluster-1", SourceID: "slurm-1", SourceKind: domain.CollectionSourceSlurm, Operation: domain.OperationSlurmInventory, PayloadSchema: domain.CollectionInventorySchema,
		Scope: domain.CollectionScope{Nodes: []domain.StableNodeID{"node-1"}}, Interval: &domain.CollectionInterval{Start: now.Add(-time.Minute), End: now}, ScheduledFor: now, Deadline: now.Add(time.Minute), Limits: domain.CollectionLimits{MaxRecords: 10, MaxBytes: 100000}, IdempotencyKey: "key-1"}
	l := domain.TypedWorkLease{Plan: p, Lease: domain.WorkLease{CollectorID: "collector-1", Attempt: 1, LeaseToken: strings.Repeat("a", 32), LeaseExpires: p.Deadline, Work: domain.CollectorWork{WorkID: "work-1", WorkExpiresAt: p.Deadline, Task: domain.CollectionTask{RunID: p.RunID, ClusterID: p.ClusterID, SourceID: p.SourceID, IdempotencyKey: p.IdempotencyKey}}}}
	result := registry.ExecuteTyped(context.Background(), l)
	if err := domain.ValidateTypedResultForLease(result, l); err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.ResultSucceeded || runner.command != "scontrol" || !reflect.DeepEqual(runner.args, []string{"show", "nodes", "--json", "comp007"}) || runner.maxBytes > 8<<20 {
		t.Fatalf("result=%+v runner=%+v", result, runner)
	}
	if result.Payload.Inventory.Revisions[0].Entities[0].NodeID != "node-1" || result.Coverage.SourceAt.Before(now) {
		t.Fatal("invented stable identity or source timestamp")
	}
	for _, body := range []string{`{`, `{"nodes":[{"name":"outside"}]}`, `{"nodes":[]}`, `{"nodes":[{"name":"comp007"},{"name":"comp007"}]}`, `{"warnings":[{"description":"partial"}],"nodes":[{"name":"comp007"}]}`} {
		runner.body = body
		result = registry.ExecuteTyped(context.Background(), l)
		if err := domain.ValidateTypedResultForLease(result, l); err != nil || result.Status != domain.ResultFailed {
			t.Fatalf("malformed fixture result=%+v err=%v", result, err)
		}
	}
	before := runner.calls
	for _, mutate := range []func(*domain.TypedWorkLease){func(l *domain.TypedWorkLease) { l.Plan.ClusterID = "foreign" }, func(l *domain.TypedWorkLease) { l.Plan.SourceID = "foreign" }, func(l *domain.TypedWorkLease) { l.Plan.Scope.Nodes = []domain.StableNodeID{"unconfigured"} }, func(l *domain.TypedWorkLease) { l.Plan.Operation = domain.OperationSlurmEvents }, func(l *domain.TypedWorkLease) { l.Plan.SchemaVersion = 99 }} {
		copy := l
		mutate(&copy)
		if registry.ExecuteTyped(context.Background(), copy).Status != domain.ResultFailed {
			t.Fatal("forged plan executed")
		}
	}
	if runner.calls != before {
		t.Fatal("forged plan reached Slurm")
	}
	cfg := slurmFixtureConfig()
	cfg.SlurmNodes["node-2"] = "comp008"
	_, expanded, err := buildCollectionExecutors(cfg, runner)
	if err != nil {
		t.Fatal(err)
	}
	if result := expanded.ExecuteTyped(context.Background(), l); result.Status != domain.ResultFailed || runner.calls != before {
		t.Fatal("partial inventory scope replaced source snapshot")
	}
}
