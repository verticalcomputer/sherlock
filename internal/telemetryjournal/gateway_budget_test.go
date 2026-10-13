package telemetryjournal

import (
	"bytes"
	"encoding/json"
	"errors"
	"path/filepath"
	"sync"
	"testing"

	"github.com/verticalcomputer/sherlock/internal/telemetry"
)

func TestGatewayAggregateLeaseSerializesAdmissionAndPreservesUnackedBytes(t *testing.T) {
	root := filepath.Join(t.TempDir(), "gateway")
	limits := AggregateLimits{Total: 16 << 20, Payload: (1 << 20) - 4096, Metadata: 8 << 20, LossContact: 4 << 20, Staging: 3 << 20}
	budget, e := OpenGatewayBudget(root, limits)
	if e != nil {
		t.Fatal(e)
	}
	defer budget.Close()
	_, e = OpenGatewayBudget(root, limits)
	assertError(t, e, ErrInUse)
	queues := make([]*Queue, 2)
	bodies := make([][]byte, 2)
	for i, node := range []string{"node-a", "node-b"} {
		o := testOptions(Gateway)
		o.GatewayBudget = budget
		o.Scope.NodeID = node
		queues[i] = mustOpen(t, filepath.Join(root, node), o)
		var envelope Envelope
		json.Unmarshal(testBody(1, Data, "one"), &envelope)
		envelope.Key.NodeID = node
		body, _ := json.Marshal(envelope)
		bodies[i] = append(body, bytes.Repeat([]byte(" "), 512<<10-len(body))...)
	}
	var wg sync.WaitGroup
	receipts := make([]telemetry.Receipt, 2)
	failures := make([]error, 2)
	for i := range queues {
		wg.Add(1)
		go func(i int) { defer wg.Done(); receipts[i], failures[i] = queues[i].Put(ctx, bodies[i]) }(i)
	}
	wg.Wait()
	winner, loser := -1, -1
	for i, e := range failures {
		if e == nil {
			winner = i
		} else if errors.Is(e, ErrCapacity) {
			loser = i
		} else {
			t.Fatal("unexpected aggregate mutation failure", e)
		}
	}
	if winner < 0 || loser < 0 {
		t.Fatal("aggregate preflight raced", failures)
	}
	if _, e = queues[winner].Read(ctx, receipts[winner].Key); e != nil {
		t.Fatal("backpressure lost owned bytes", e)
	}
	stats, e := budget.Stats()
	if e != nil || stats.Total > limits.Total || stats.Payload > limits.Payload || stats.Metadata > limits.Metadata || stats.Staging > limits.Staging {
		t.Fatal("aggregate budget exceeded", stats, e)
	}
	cloud := receipts[winner]
	cloud.ID = "cloud-a"
	cloud.Durability = "CLOUD"
	if e = queues[winner].Acknowledge(ctx, cloud, receipts[winner].ID); e != nil {
		t.Fatal(e)
	}
	mustPut(t, queues[loser], bodies[loser])
	assertError(t, budget.Close(), ErrInUse)
	for _, q := range queues {
		q.Close()
	}
	if e = budget.Close(); e != nil {
		t.Fatal(e)
	}
}

func TestGatewayAggregateRejectsForeignRootAndNodeOwnership(t *testing.T) {
	root := filepath.Join(t.TempDir(), "gateway")
	budget, e := OpenGatewayBudget(root, DefaultGatewayAggregateLimits())
	if e != nil {
		t.Fatal(e)
	}
	defer budget.Close()
	o := testOptions(Gateway)
	o.GatewayBudget = budget
	_, e = Open(filepath.Join(t.TempDir(), "outside"), o)
	assertError(t, e, ErrRole)
	o.Role = Node
	o.Limits = NodeLimits()
	o.Limits.MinimumFree = 0
	_, e = Open(filepath.Join(root, "node"), o)
	assertError(t, e, ErrRole)
}

func TestGatewayAggregateClassifiesControlAndStagingIndependently(t *testing.T) {
	root := filepath.Join(t.TempDir(), "gateway")
	budget, e := OpenGatewayBudget(root, DefaultGatewayAggregateLimits())
	if e != nil {
		t.Fatal(e)
	}
	defer budget.Close()
	o := testOptions(Gateway)
	o.GatewayBudget = budget
	q := mustOpen(t, filepath.Join(root, "node"), o)
	mustPut(t, q, testBody(1, Contact, "contact"))
	stats, e := budget.Stats()
	if e != nil || stats.LossContact == 0 || stats.Payload != 0 {
		t.Fatal("control ownership charged as data", stats, e)
	}
	q.opts.fault = func(stage string) error {
		if stage == "payload_synced" {
			return ErrCapacity
		}
		return nil
	}
	_, e = q.Put(ctx, testBody(2, Data, "data"))
	assertError(t, e, ErrCapacity)
	stats, e = budget.Stats()
	if e != nil || stats.Staging == 0 || stats.Total > budget.limits.Total {
		t.Fatal("staging bytes not accounted", stats, e)
	}
	q.Close()
	q = mustOpen(t, filepath.Join(root, "node"), o)
	stats, e = budget.Stats()
	if e != nil || stats.Staging != 0 || stats.Payload == 0 {
		t.Fatal("recovered staging ownership not accounted", stats, e)
	}
	q.Close()
}
