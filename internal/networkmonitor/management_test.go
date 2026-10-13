package networkmonitor

import (
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/networkprobe"
)

func managementEnrollment(t *testing.T) Enrollment {
	e := testEnrollment(t)
	e.ManagementEnabled = true
	e.ManagementRevision = "fixture2-zone4-20260930-v1"
	for _, n := range networkprobe.FixtureNetworkNodes {
		e.Bonds = append(e.Bonds, ExpectedBond{Node: n, Name: "bond0", Mode: "802.3ad 4", Members: []string{"enp55s0f0np0", "enp55s0f1np1"}})
	}
	return e
}
func managementPolls(e Enrollment, at time.Time) []application.NetworkNodePoll {
	p := testPolls(e, at)
	for i := range p {
		p[i].ManagementRevision = e.ManagementRevision
		p[i].Bonds = []application.NetworkBondReading{{Name: "bond0", Present: true, Mode: "802.3ad 4", Carrier: "1", OperState: "up", Members: []application.NetworkInterfaceReading{{Name: "enp55s0f0np0", Present: true, Carrier: "1", OperState: "up"}, {Name: "enp55s0f1np1", Present: true, Carrier: "1", OperState: "up"}}}}
	}
	return p
}
func TestManagementMemberDownWhileBondUpAndConfirmedRecovery(t *testing.T) {
	e := managementEnrollment(t)
	now := time.Now().UTC()
	before := managementPolls(e, now.Add(-2*time.Minute))
	bad1 := managementPolls(e, now.Add(-time.Minute))
	bad2 := managementPolls(e, now.Add(-time.Second))
	for _, p := range [][]application.NetworkNodePoll{bad1, bad2} {
		p[0].Bonds[0].Members[0].Carrier = "0"
		p[0].Bonds[0].Members[0].OperState = "down"
	}
	s, err := AssessManagement(e, append(before, bad1...), now)
	if err != nil || s.DownLinks != 0 || s.PendingLinks != 1 {
		t.Fatalf("first failure %+v %v", s, err)
	}
	s, err = AssessManagement(e, append(bad1, bad2...), now)
	if err != nil || s.DownLinks != 1 || s.HealthyLinks != 41 || s.Details[0].Condition != "HEALTHY" {
		t.Fatalf("member while bond healthy %+v %v", s, err)
	}
	recovery := managementPolls(e, now)
	s, err = AssessManagement(e, append(bad2, recovery...), now)
	if err != nil || s.PendingLinks != 1 {
		t.Fatalf("early recovery %+v %v", s, err)
	}
	s, err = AssessManagement(e, append(recovery, managementPolls(e, now.Add(time.Minute))...), now.Add(time.Minute))
	if err != nil || s.HealthyLinks != 42 {
		t.Fatalf("recovery %+v %v", s, err)
	}
}
func TestManagementMissingAndUnknownAreDistinct(t *testing.T) {
	cases := []struct {
		name          string
		modify        func(*application.NetworkNodePoll)
		down, unknown int
	}{
		{"missing member", func(p *application.NetworkNodePoll) { p.Bonds[0].Members = p.Bonds[0].Members[1:] }, 1, 0},
		{"missing bond", func(p *application.NetworkNodePoll) { p.Bonds[0].Present = false }, 3, 0},
		{"bond read failed", func(p *application.NetworkNodePoll) { p.Bonds[0].ReadError = application.NetworkReadSourceFailed }, 0, 3},
		{"unsupported old publisher", func(p *application.NetworkNodePoll) { p.ManagementRevision = ""; p.Bonds = nil }, 0, 3},
		{"mode changed", func(p *application.NetworkNodePoll) { p.Bonds[0].Mode = "active-backup 1" }, 0, 3},
		{"extra member", func(p *application.NetworkNodePoll) {
			p.Bonds[0].Members = append(p.Bonds[0].Members, application.NetworkInterfaceReading{Name: "eno2", Present: true, Carrier: "0", OperState: "down"})
		}, 0, 3},
		{"authentication failure", func(p *application.NetworkNodePoll) {
			p.Outcome = application.NetworkPollAuthUnavailable
			p.ReadError = application.NetworkReadSSHAuthDenied
			p.Ports = nil
			p.Bonds = nil
		}, 0, 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := managementEnrollment(t)
			now := time.Now().UTC()
			a := managementPolls(e, now.Add(-time.Minute))
			b := managementPolls(e, now.Add(-time.Second))
			tc.modify(&a[0])
			tc.modify(&b[0])
			s, err := AssessManagement(e, append(a, b...), now)
			if err != nil || s.DownLinks != tc.down || s.UnknownLinks != tc.unknown {
				t.Fatalf("%+v %v", s, err)
			}
			if tc.name == "bond read failed" {
				ib, err := Assess(e, append(a, b...), now)
				if err != nil || ib[0].Condition != "HEALTHY" {
					t.Fatalf("management error tainted IB: %+v %v", ib, err)
				}
			}
		})
	}
}
func TestManagementGapsBootChangesAndCounters(t *testing.T) {
	e := managementEnrollment(t)
	now := time.Now().UTC()
	for _, tc := range []string{"boot change", "poll gap", "read gap", "stale", "counter baseline"} {
		t.Run(tc, func(t *testing.T) {
			a := managementPolls(e, now.Add(-time.Minute))
			b := managementPolls(e, now.Add(-time.Second))
			want := 3
			switch tc {
			case "boot change":
				b[0].BootID = "different-boot"
			case "poll gap":
				a[0].ObservedAt = now.Add(-2 * time.Minute)
			case "read gap":
				a[0].Bonds[0].ReadError = application.NetworkReadSourceFailed
			case "stale":
				a[0].ObservedAt = now.Add(-5 * time.Minute)
				b[0].ObservedAt = now.Add(-4 * time.Minute)
			case "counter baseline":
				v := uint64(21377)
				a[0].Bonds[0].Members[0].RXErrors = &v
				b[0].Bonds[0].Members[0].RXErrors = &v
				want = 0
			}
			s, err := AssessManagement(e, append(a, b...), now)
			if err != nil || s.DownLinks != 0 || s.UnknownLinks+s.PendingLinks != want {
				t.Fatalf("%+v %v", s, err)
			}
		})
	}
}
func TestManagementEnrollmentAndCycleFailClosed(t *testing.T) {
	e := managementEnrollment(t)
	if Validate(e) != nil {
		t.Fatal("valid enrollment refused")
	}
	e.Bonds[0].Members[0] = "eno2"
	if Validate(e) == nil {
		t.Fatal("unapproved member accepted")
	}
	e = managementEnrollment(t)
	now := time.Now().UTC()
	p := managementPolls(e, now.Add(-time.Second))
	p[0].Bonds[0].Members[0].Carrier = "bogus"
	if ValidateCycle(e, Cycle{Revision: e.Revision, Polls: p}, now) == nil {
		t.Fatal("invalid state accepted")
	}
	p = managementPolls(e, now.Add(-time.Second))
	p[0].ManagementRevision = "other-revision"
	if ValidateCycle(e, Cycle{Revision: e.Revision, Polls: p}, now) == nil {
		t.Fatal("foreign revision accepted")
	}
}

func TestManagementReenableDoesNotReuseOldConfirmations(t *testing.T) {
	e := managementEnrollment(t)
	now := time.Now().UTC()
	e.ManagementEnrolledAt = now.Add(-30 * time.Second)
	old := managementPolls(e, now.Add(-time.Minute))
	fresh := managementPolls(e, now.Add(-time.Second))
	s, err := AssessManagement(e, append(old, fresh...), now)
	if err != nil || s.PendingLinks != 42 || s.HealthyLinks != 0 {
		t.Fatalf("old epoch used for recovery: %+v %v", s, err)
	}
}
