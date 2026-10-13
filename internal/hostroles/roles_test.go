package hostroles

import (
	"strings"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/commandpack"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

func observedAt() time.Time { return time.Date(2026, 8, 22, 10, 0, 0, 0, time.UTC) }

// A derived role must carry why it holds and when that was confirmed, because
// a host-role map decides which machines are reached and what runs on them.
func TestRolesAreDerivedWithProvenanceFromEachSource(t *testing.T) {
	now := observedAt()
	entries, conflicts, err := Derive(Observations{
		ClusterID: "cluster-a",
		SlurmNodes: []SlurmNode{
			{Name: "comp001", State: "IDLE", Partition: "gpu", ObservedAt: now},
			{Name: "head01", Controller: true, State: "UP", ObservedAt: now},
		},
		Coverage: []CoverageTarget{{Node: "comp001", ObservedAt: now.Add(time.Minute)}},
		Redfish:  []RedfishEndpoint{{Host: "bmc001", ObservedAt: now}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(conflicts) != 0 {
		t.Fatalf("unexpected conflicts: %+v", conflicts)
	}
	byTarget := map[domain.DiagnosticTarget]Entry{}
	for _, entry := range entries {
		byTarget[entry.Target] = entry
	}
	if len(byTarget) != 3 {
		t.Fatalf("entries = %+v", entries)
	}
	compute := byTarget["comp001"]
	if compute.Role != commandpack.TargetCompute {
		t.Fatalf("comp001 role = %s", compute.Role)
	}
	// Two sources agreeing reinforce the entry, and the later confirmation wins.
	if len(compute.Sources) != 2 {
		t.Fatalf("comp001 sources = %v, want both Slurm and coverage", compute.Sources)
	}
	if !compute.ConfirmedAt.Equal(now.Add(time.Minute)) {
		t.Fatalf("comp001 confirmed at %s, want the most recent observation", compute.ConfirmedAt)
	}
	for _, want := range []string{"Slurm reports node comp001", "collector coverage observed node comp001"} {
		if !strings.Contains(compute.Reason, want) {
			t.Fatalf("comp001 reason does not record %q: %s", want, compute.Reason)
		}
	}
	if byTarget["head01"].Role != commandpack.TargetHead {
		t.Fatalf("head01 role = %s, want HEAD", byTarget["head01"].Role)
	}
	if !strings.Contains(byTarget["head01"].Reason, "controller host") {
		t.Fatalf("head01 reason = %s", byTarget["head01"].Reason)
	}
	if byTarget["bmc001"].Role != commandpack.TargetBMCGateway {
		t.Fatalf("bmc001 role = %s, want BMC_GATEWAY", byTarget["bmc001"].Role)
	}
}

// A host two sources disagree about must become ineligible rather than have one
// answer silently chosen: that is how a controller ends up running a compute
// diagnostic.
func TestDisagreeingSourcesRemoveTheTargetAndRecordWhy(t *testing.T) {
	now := observedAt()
	entries, conflicts, err := Derive(Observations{
		ClusterID:  "cluster-a",
		SlurmNodes: []SlurmNode{{Name: "head01", Controller: true, State: "UP", ObservedAt: now}},
		Coverage:   []CoverageTarget{{Node: "head01", ObservedAt: now}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Target == "head01" {
			t.Fatalf("a disputed host stayed eligible as %s", entry.Role)
		}
	}
	if len(conflicts) != 1 || conflicts[0].Target != "head01" {
		t.Fatalf("conflicts = %+v", conflicts)
	}
	if !strings.Contains(conflicts[0].Reason, "controller host") || !strings.Contains(conflicts[0].Reason, "collector coverage") {
		t.Fatalf("the conflict does not record both claims: %s", conflicts[0].Reason)
	}
}

// A confirmation that has aged out makes a host ineligible. A stale entry is
// not a weaker form of known; it is not known.
func TestUnconfirmedEntryIsIneligible(t *testing.T) {
	now := observedAt()
	resolver, err := NewResolver(10 * time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	entries, _, err := Derive(Observations{ClusterID: "cluster-a", SlurmNodes: []SlurmNode{{Name: "comp001", State: "IDLE", Partition: "gpu", ObservedAt: now}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := resolver.Replace("cluster-a", entries); err != nil {
		t.Fatal(err)
	}
	if _, eligible := resolver.Role("cluster-a", "comp001", now.Add(9*time.Minute)); !eligible {
		t.Fatal("a recently confirmed host must be eligible")
	}
	if _, eligible := resolver.Role("cluster-a", "comp001", now.Add(11*time.Minute)); eligible {
		t.Fatal("a host not confirmed within the lifetime stayed eligible")
	}
	if _, eligible := resolver.Role("cluster-a", "comp999", now); eligible {
		t.Fatal("an unknown host was eligible")
	}
	if _, eligible := resolver.Role("cluster-b", "comp001", now); eligible {
		t.Fatal("a host was eligible in the wrong cluster")
	}
	// A confirmation stamped in the future is not evidence of anything current.
	if _, eligible := resolver.Role("cluster-a", "comp001", now.Add(-time.Minute)); eligible {
		t.Fatal("a host was eligible before it was confirmed")
	}
}

// Removing a node from Slurm must remove its eligibility with no operator
// action, which is the whole reason derivation replaces a maintained file.
func TestRemovingANodeFromSlurmRemovesEligibility(t *testing.T) {
	now := observedAt()
	resolver, err := NewResolver(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	full, _, err := Derive(Observations{ClusterID: "cluster-a", SlurmNodes: []SlurmNode{
		{Name: "comp001", State: "IDLE", Partition: "gpu", ObservedAt: now},
		{Name: "comp002", State: "IDLE", Partition: "gpu", ObservedAt: now},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := resolver.Replace("cluster-a", full); err != nil {
		t.Fatal(err)
	}
	if _, eligible := resolver.Role("cluster-a", "comp002", now); !eligible {
		t.Fatal("comp002 should start eligible")
	}

	// The next scheduled derivation simply does not mention comp002.
	reduced, _, err := Derive(Observations{ClusterID: "cluster-a", SlurmNodes: []SlurmNode{
		{Name: "comp001", State: "IDLE", Partition: "gpu", ObservedAt: now.Add(time.Minute)},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := resolver.Replace("cluster-a", reduced); err != nil {
		t.Fatal(err)
	}
	if _, eligible := resolver.Role("cluster-a", "comp002", now.Add(time.Minute)); eligible {
		t.Fatal("a node Slurm no longer reports stayed eligible")
	}
	if _, eligible := resolver.Role("cluster-a", "comp001", now.Add(time.Minute)); !eligible {
		t.Fatal("a node Slurm still reports lost eligibility")
	}
}

func TestDerivationAndResolverRefuseIncompleteInput(t *testing.T) {
	now := observedAt()
	if _, _, err := Derive(Observations{SlurmNodes: []SlurmNode{{Name: "comp001", ObservedAt: now}}}); err == nil {
		t.Fatal("derivation without a cluster was accepted")
	}
	if _, _, err := Derive(Observations{ClusterID: "cluster-a", SlurmNodes: []SlurmNode{{Name: "comp001"}}}); err == nil {
		t.Fatal("an observation with no observation time was accepted")
	}
	if _, _, err := Derive(Observations{ClusterID: "cluster-a", Coverage: []CoverageTarget{{Node: "", ObservedAt: now}}}); err == nil {
		t.Fatal("an unnamed host was accepted")
	}
	if _, err := NewResolver(0); err == nil {
		t.Fatal("a resolver with no confirmation lifetime was accepted")
	}
	if _, err := NewResolver(48 * time.Hour); err == nil {
		t.Fatal("a resolver with an unreviewable confirmation lifetime was accepted")
	}
	resolver, _ := NewResolver(time.Hour)
	if err := resolver.Replace("cluster-a", []Entry{{ClusterID: "cluster-b", Target: "comp001", Role: commandpack.TargetCompute, Sources: []Source{SourceSlurm}, Reason: "r", ConfirmedAt: now}}); err == nil {
		t.Fatal("an entry belonging to another cluster was installed")
	}
	if err := resolver.Replace("cluster-a", []Entry{{ClusterID: "cluster-a", Target: "comp001", Role: "GATEWAY", Sources: []Source{SourceSlurm}, Reason: "r", ConfirmedAt: now}}); err == nil {
		t.Fatal("an unknown role was installed")
	}
	if err := resolver.Replace("cluster-a", []Entry{{ClusterID: "cluster-a", Target: "comp001", Role: commandpack.TargetCompute, Sources: []Source{"GUESS"}, Reason: "r", ConfirmedAt: now}}); err == nil {
		t.Fatal("an unknown provenance source was installed")
	}
	if err := resolver.Replace("cluster-a", []Entry{{ClusterID: "cluster-a", Target: "comp001", Role: commandpack.TargetCompute, Sources: []Source{SourceSlurm}, ConfirmedAt: now}}); err == nil {
		t.Fatal("an entry with no recorded reason was installed")
	}
}
