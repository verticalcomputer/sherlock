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

func TestManagementEnrollmentAndMemberEpisodeIsolation(t *testing.T) {
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
	nodes := []application.NetworkNodePoll{}
	byNode := map[string]int{}
	for _, port := range e.Ports {
		idx, ok := byNode[port.Key.Node]
		if !ok {
			idx = len(nodes)
			byNode[port.Key.Node] = idx
			nodes = append(nodes, application.NetworkNodePoll{Node: port.Key.Node, InventoryRevision: e.Revision, BootID: "12345678-0000-0000-0000-000000000000", Outcome: application.NetworkPollComplete})
		}
		nodes[idx].Ports = append(nodes[idx].Ports, application.NetworkPortReading{Key: port.Key, NodeGUID: port.NodeGUID, LinkLayer: "InfiniBand", State: "4: ACTIVE", PhysicalState: "5: LinkUp"})
	}
	now := fixtureDatabaseTime(t, ctx, pool).Add(-2 * time.Minute)
	record := func(offset int) {
		t.Helper()
		for i := range nodes {
			nodes[i].ObservedAt = now.Add(time.Duration(offset) * time.Second)
		}
		if err := s.RecordNetworkCycle(ctx, e.ClusterID, e.CollectorID, networkmonitor.Cycle{Revision: e.Revision, Polls: nodes}); err != nil {
			t.Fatal(err)
		}
	}
	count := func(transition string, want int) {
		t.Helper()
		var n int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM gp09_alert_outbox WHERE transition=$1`, transition).Scan(&n); err != nil || n != want {
			t.Fatalf("%s=%d want %d %v", transition, n, want, err)
		}
	}
	record(0)
	record(10)
	e.ManagementEnabled = true
	e.ManagementRevision = "fixture2-zone4-20260930-v1"
	for _, n := range nodes {
		e.Bonds = append(e.Bonds, networkmonitor.ExpectedBond{Node: n.Node, Name: "bond0", Mode: "802.3ad 4", Members: []string{"enp55s0f0np0", "enp55s0f1np1"}})
	}
	if err := s.EnableManagement(ctx, e); err != nil {
		t.Fatal(err)
	}
	if err := s.EnableManagement(ctx, e); err != nil {
		t.Fatal("idempotency", err)
	}
	if err := s.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	count("SOURCE_GAP", 0)
	// The replay uses synthetic historical timestamps; move only this private
	// fixture enrollment epoch to the same timeline after proving startup grace.
	if _, err := pool.Exec(ctx, `UPDATE gp09_network_monitors SET enrollment=jsonb_set(enrollment,'{ManagementEnrolledAt}',to_jsonb($1::timestamptz))`, now); err != nil {
		t.Fatal(err)
	}
	wrong := e
	wrong.Revision = "new-IB-revision"
	if s.EnableManagement(ctx, wrong) == nil {
		t.Fatal("IB inventory change accepted")
	}
	for i := range nodes {
		nodes[i].ManagementRevision = e.ManagementRevision
		nodes[i].Bonds = []application.NetworkBondReading{{Name: "bond0", Present: true, Mode: "802.3ad 4", Carrier: "1", OperState: "up", Members: []application.NetworkInterfaceReading{{Name: "enp55s0f0np0", Present: true, Carrier: "1", OperState: "up"}, {Name: "enp55s0f1np1", Present: true, Carrier: "1", OperState: "up"}}}}
	}
	record(20)
	record(30)
	summary := func() networkmonitor.Summary {
		t.Helper()
		var doc []byte
		if err := pool.QueryRow(ctx, `SELECT summary FROM gp09_network_monitors`).Scan(&doc); err != nil {
			t.Fatal(err)
		}
		var out networkmonitor.Summary
		if err := json.Unmarshal(doc, &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	if v := summary(); v.Management.HealthyLinks != 42 || v.HealthyPorts != 112 {
		t.Fatalf("%+v", v)
	}
	nodes[0].Bonds[0].Members[0].Carrier = "0"
	nodes[0].Bonds[0].Members[0].OperState = "down"
	record(40)
	count("PORT_DOWN", 0)
	record(50)
	count("PORT_DOWN", 1)
	if v := summary(); v.Management.DownLinks != 1 || v.HealthyPorts != 112 || v.InfiniBandState != "HEALTHY" || v.State != "DEGRADED" {
		t.Fatalf("%+v", v)
	}
	if err := s.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	count("PORT_DOWN", 1)
	nodes[0].Bonds[0].ReadError = application.NetworkReadSourceFailed
	record(60)
	count("SOURCE_GAP", 1)
	count("RECOVERED", 0)
	nodes[0].Bonds[0].ReadError = ""
	nodes[0].Bonds[0].Members[0].Carrier = "1"
	nodes[0].Bonds[0].Members[0].OperState = "up"
	record(70)
	count("RECOVERED", 0)
	record(80)
	count("RECOVERED", 2)
	// SSH loss gets one node-source episode rather than an additional management
	// source gap or fabricated down-member messages.
	ports, bonds := nodes[0].Ports, nodes[0].Bonds
	nodes[0].Outcome = application.NetworkPollAuthUnavailable
	nodes[0].ReadError = application.NetworkReadSSHAuthDenied
	nodes[0].Ports = nil
	nodes[0].Bonds = nil
	record(90)
	count("SOURCE_GAP", 2)
	count("PORT_DOWN", 1)
	nodes[0].Outcome = application.NetworkPollComplete
	nodes[0].ReadError = ""
	nodes[0].Ports = ports
	nodes[0].Bonds = bonds
	record(100)
	record(110)
	count("RECOVERED", 3)
	if err := s.DisableManagement(ctx, e.ClusterID); err != nil {
		t.Fatal(err)
	}
	for i := range nodes {
		nodes[i].ManagementRevision = ""
	}
	record(115)
	if v := summary(); v.Management.Enrolled || v.HealthyPorts != 112 {
		t.Fatalf("disable tainted IB %+v", v)
	}
	// A removed cluster cannot create alert work during background refresh.
	if _, err := pool.Exec(ctx, `UPDATE clusters SET removed_at=clock_timestamp()`); err != nil {
		t.Fatal(err)
	}
	if err := s.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	count("SOURCE_GAP", 2)
}
