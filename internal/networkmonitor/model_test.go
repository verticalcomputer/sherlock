package networkmonitor

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/application"
)

func testEnrollment(t *testing.T) Enrollment {
	t.Helper()
	data, err := os.ReadFile("../../test/fixtures/network-enrollment.synthetic.json")
	if err != nil {
		t.Fatal(err)
	}
	var e Enrollment
	if err := json.Unmarshal(data, &e); err != nil {
		t.Fatal(err)
	}
	return e
}
func testPolls(e Enrollment, now time.Time) []application.NetworkNodePoll {
	var polls []application.NetworkNodePoll
	byNode := map[string]int{}
	for _, p := range e.Ports {
		idx, ok := byNode[p.Key.Node]
		if !ok {
			idx = len(polls)
			byNode[p.Key.Node] = idx
			polls = append(polls, application.NetworkNodePoll{InventoryRevision: e.Revision, Node: p.Key.Node, BootID: "12345678-0000-0000-0000-000000000000", ObservedAt: now, Outcome: application.NetworkPollComplete})
		}
		polls[idx].Ports = append(polls[idx].Ports, application.NetworkPortReading{Key: p.Key, NodeGUID: p.NodeGUID, LinkLayer: "InfiniBand", State: "4: ACTIVE", PhysicalState: "5: LinkUp"})
	}
	return polls
}
func TestEnrollmentAndIdentityCannotDrift(t *testing.T) {
	e := testEnrollment(t)
	if err := Validate(e); err != nil {
		t.Fatal(err)
	}
	copy := e
	copy.Ports = append([]ExpectedPort(nil), e.Ports...)
	copy.Ports[1] = copy.Ports[0]
	if Validate(copy) == nil {
		t.Fatal("duplicate accepted")
	}
	copy = e
	copy.Ports = copy.Ports[:111]
	if Validate(copy) == nil {
		t.Fatal("missing expected port accepted")
	}
	copy = e
	copy.ClusterID = "pilot-cluster"
	if Validate(copy) == nil {
		t.Fatal("wrong cluster accepted")
	}
}
func TestCycleFreshnessAndGUIDReplacement(t *testing.T) {
	e := testEnrollment(t)
	now := time.Now().UTC()
	p := testPolls(e, now.Add(-time.Second))
	if err := ValidateCycle(e, Cycle{Revision: e.Revision, Polls: p}, now); err != nil {
		t.Fatal(err)
	}
	previous := testPolls(e, now.Add(-time.Minute))
	p[0].Ports[0].NodeGUID = "0000:0000:0000:0000"
	result, err := Assess(e, append(previous, p...), now)
	if err != nil {
		t.Fatal(err)
	}
	if result[0].Condition != "UNKNOWN" || result[0].Reason != "PORT_IDENTITY_CHANGED" {
		t.Fatalf("replacement: %+v", result[0])
	}
	p[0].ObservedAt = now.Add(time.Minute)
	if ValidateCycle(e, Cycle{Revision: e.Revision, Polls: p}, now) == nil {
		t.Fatal("future accepted")
	}
	p = testPolls(e, now.Add(-4*time.Minute))
	if ValidateCycle(e, Cycle{Revision: e.Revision, Polls: p}, now) == nil {
		t.Fatal("stale accepted")
	}
}

func TestRestoredGUIDNeedsTwoNewConfirmations(t *testing.T) {
	e := testEnrollment(t)
	now := time.Now().UTC()
	wrong := testPolls(e, now.Add(-time.Minute))
	wrong[0].Ports[0].NodeGUID = "0000:0000:0000:0000"
	current := testPolls(e, now.Add(-time.Second))
	a, err := Assess(e, append(wrong, current...), now)
	if err != nil {
		t.Fatal(err)
	}
	if a[0].Condition == "HEALTHY" {
		t.Fatal("old GUID counted for recovery")
	}
}

func TestHistoricCounterIsNotNewAndIncreaseIsDistinctFromDown(t *testing.T) {
	e := testEnrollment(t)
	now := time.Now().UTC()
	before := testPolls(e, now.Add(-time.Minute))
	current := testPolls(e, now.Add(-time.Second))
	old, newCount := uint64(12), uint64(13)
	before[0].Ports[0].LinkDowned = &old
	current[0].Ports[0].LinkDowned = &old
	a, err := Assess(e, append(before, current...), now)
	if err != nil || a[0].Condition != "HEALTHY" {
		t.Fatalf("baseline %+v %v", a[0], err)
	}
	current[0].Ports[0].LinkDowned = &newCount
	a, err = Assess(e, append(before, current...), now)
	if err != nil || a[0].Reason != "LINK_DOWNED_INCREASE" || a[0].Condition == "DOWN" {
		t.Fatalf("increase %+v %v", a[0], err)
	}
}
