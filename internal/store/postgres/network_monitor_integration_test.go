//go:build integration

package postgres_test

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/networkmonitor"
	storepg "github.com/verticalcomputer/sherlock/internal/store/postgres"
)

func TestNetworkMonitorEpisodesReplayRecoveryAndStaleness(t *testing.T) {
	pool := durableTestDatabase(t)
	ctx := context.Background()
	data, err := os.ReadFile("../../../test/fixtures/network-enrollment.synthetic.json")
	if err != nil {
		t.Fatal(err)
	}
	var e networkmonitor.Enrollment
	if err := json.Unmarshal(data, &e); err != nil {
		t.Fatal(err)
	}
	_, err = pool.Exec(ctx, `INSERT INTO clusters(cluster_id,display_name) VALUES('fixture2-zone2','FixtureNetwork 2'); INSERT INTO collectors(collector_id,cluster_id,display_name,status,version,build_commit,protocol_min,protocol_max,operating_system,architecture) VALUES('fixture-network-collector','fixture2-zone2','head','ACTIVE','test','test',1,2,'linux','amd64')`)
	if err != nil {
		t.Fatal(err)
	}
	s := storepg.NewNetworkMonitorStore(pool)
	if err := s.Enroll(ctx, e); err != nil {
		t.Fatal(err)
	}
	if err := s.Enroll(ctx, e); err != nil {
		t.Fatal("idempotent enrollment", err)
	}
	now := fixtureDatabaseTime(t, ctx, pool).Add(-2 * time.Minute)
	nodes := []application.NetworkNodePoll{}
	byNode := map[string]int{}
	for _, port := range e.Ports {
		idx, ok := byNode[port.Key.Node]
		if !ok {
			idx = len(nodes)
			byNode[port.Key.Node] = idx
			nodes = append(nodes, application.NetworkNodePoll{InventoryRevision: e.Revision, Node: port.Key.Node, BootID: "12345678-0000-0000-0000-000000000000", Outcome: application.NetworkPollComplete})
		}
		nodes[idx].Ports = append(nodes[idx].Ports, application.NetworkPortReading{Key: port.Key, NodeGUID: port.NodeGUID, LinkLayer: "InfiniBand", State: "4: ACTIVE", PhysicalState: "5: LinkUp"})
	}
	record := func(at time.Time) {
		t.Helper()
		for i := range nodes {
			nodes[i].ObservedAt = at
		}
		if err := s.RecordNetworkCycle(ctx, e.ClusterID, e.CollectorID, networkmonitor.Cycle{Revision: e.Revision, Polls: nodes}); err != nil {
			t.Fatal(err)
		}
	}
	count := func(transition string, want int) {
		t.Helper()
		var n int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM gp09_alert_outbox WHERE transition=$1`, transition).Scan(&n); err != nil || n != want {
			t.Fatalf("%s count=%d want=%d err=%v", transition, n, want, err)
		}
	}
	record(now)
	record(now.Add(10 * time.Second))
	count("PORT_DOWN", 0)
	count("SOURCE_GAP", 0)
	if err := s.RecordNetworkCycle(ctx, e.ClusterID, "wrong-collector", networkmonitor.Cycle{}); err == nil {
		t.Fatal("wrong collector accepted")
	}
	if err := s.RecordNetworkCycle(ctx, e.ClusterID, e.CollectorID, networkmonitor.Cycle{Revision: e.Revision, Polls: nodes}); err == nil {
		t.Fatal("replay accepted")
	}
	nodes[0].Ports[0].State = "1: DOWN"
	nodes[0].Ports[0].PhysicalState = "3: Disabled"
	record(now.Add(20 * time.Second))
	count("PORT_DOWN", 0)
	record(now.Add(30 * time.Second))
	count("PORT_DOWN", 1)
	if err := s.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	count("PORT_DOWN", 1)
	nodes[0].Ports[0].State = "4: ACTIVE"
	nodes[0].Ports[0].PhysicalState = "5: LinkUp"
	record(now.Add(40 * time.Second))
	count("RECOVERED", 0)
	record(now.Add(50 * time.Second))
	count("RECOVERED", 1)
	saved := nodes[0].Ports
	nodes[0].Ports = nil
	nodes[0].Outcome = application.NetworkPollAuthUnavailable
	nodes[0].ReadError = application.NetworkReadSSHAuthDenied
	record(now.Add(60 * time.Second))
	count("SOURCE_GAP", 1)
	if err := s.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	count("SOURCE_GAP", 1)
	nodes[0].Ports = saved
	nodes[0].Outcome = application.NetworkPollComplete
	nodes[0].ReadError = ""
	record(now.Add(70 * time.Second))
	record(now.Add(80 * time.Second))
	count("RECOVERED", 2)
	// A cumulative historic count alone creates no event; only a comparable
	// increase does, and it has a distinct transition from a current port down.
	oldCount, newCount := uint64(12), uint64(13)
	nodes[0].Ports[0].LinkDowned = &oldCount
	record(now.Add(90 * time.Second))
	record(now.Add(100 * time.Second))
	count("LINK_EVENT", 0)
	nodes[0].Ports[0].LinkDowned = &newCount
	record(now.Add(110 * time.Second))
	count("LINK_EVENT", 1)
	if err := s.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	count("LINK_EVENT", 1)
	// Evaluator detects loss of publisher even with no new request. A synthetic
	// retained-record time shift tests that boundary without waiting minutes.
	// Make every stored observation old using JSON transformation.
	_, err = pool.Exec(ctx, `UPDATE gp09_network_cycles SET polls=(SELECT jsonb_agg(jsonb_set(p,'{ObservedAt}',to_jsonb((p->>'ObservedAt')::timestamptz-interval '10 minutes'))) FROM jsonb_array_elements(polls) p)`)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	count("SOURCE_GAP", 15)
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM gp09_network_cycles`).Scan(&n); err != nil || n != 4 {
		t.Fatalf("window %d %v", n, err)
	}
}
