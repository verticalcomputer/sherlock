package application

import (
	"testing"
	"time"
)

func networkFixture() (NetworkDetectorPolicy, []NetworkNodePoll, time.Time) {
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	key := NetworkPortKey{Node: "comp001", Device: "mlx5_0", Port: 1}
	policy := NetworkDetectorPolicy{Version: 1, InventoryRevision: "reviewed-1", ExpectedPorts: []NetworkPortKey{key}, MaxSampleAge: 2 * time.Minute, MaxPollInterval: 75 * time.Second, FailureConfirmations: 2, RecoveryConfirmations: 2}
	zero := uint64(0)
	healthy := NetworkPortReading{Key: key, LinkLayer: "InfiniBand", State: "4: ACTIVE", PhysicalState: "5: LinkUp", LinkDowned: &zero}
	polls := []NetworkNodePoll{
		{InventoryRevision: "reviewed-1", Node: key.Node, BootID: "boot-1", ObservedAt: now.Add(-time.Minute), Outcome: NetworkPollComplete, Ports: []NetworkPortReading{healthy}},
		{InventoryRevision: "reviewed-1", Node: key.Node, BootID: "boot-1", ObservedAt: now, Outcome: NetworkPollComplete, Ports: []NetworkPortReading{healthy}},
	}
	return policy, polls, now
}

func TestNetworkDetectorRequiresCompleteFreshPortEvidence(t *testing.T) {
	policy, _, now := networkFixture()
	tests := []struct {
		name, wantCondition, wantReason string
		change                          func([]NetworkNodePoll) []NetworkNodePoll
	}{
		{"healthy", NetworkHealthy, "ACTIVE_LINK_UP", func(p []NetworkNodePoll) []NetworkNodePoll { return p }},
		{"one down", NetworkDegraded, "PORT_NOT_ACTIVE", func(p []NetworkNodePoll) []NetworkNodePoll { p[1].Ports[0].State = "1: DOWN"; return p }},
		{"two down", NetworkDown, "PORT_NOT_ACTIVE", func(p []NetworkNodePoll) []NetworkNodePoll {
			for i := range p {
				p[i].Ports[0].State = "1: DOWN"
			}
			return p
		}},
		{"two down across reboot are not one episode", NetworkDegraded, "PORT_NOT_ACTIVE", func(p []NetworkNodePoll) []NetworkNodePoll {
			for i := range p {
				p[i].Ports[0].State = "1: DOWN"
			}
			p[1].BootID = "boot-2"
			return p
		}},
		{"two down across poll gap are not consecutive", NetworkDegraded, "PORT_NOT_ACTIVE", func(p []NetworkNodePoll) []NetworkNodePoll {
			for i := range p {
				p[i].Ports[0].State = "1: DOWN"
			}
			p[0].ObservedAt = now.Add(-90 * time.Second)
			return p
		}},
		{"missing expected", NetworkDown, "PORT_MISSING", func(p []NetworkNodePoll) []NetworkNodePoll {
			for i := range p {
				p[i].Ports = nil
			}
			return p
		}},
		{"auth gap", NetworkUnknown, NetworkPollAuthUnavailable, func(p []NetworkNodePoll) []NetworkNodePoll {
			p[1].Outcome = NetworkPollAuthUnavailable
			p[1].ReadError = NetworkReadSSHAuthDenied
			p[1].Ports = nil
			return p
		}},
		{"node unreachable", NetworkUnknown, NetworkPollNodeUnreachable, func(p []NetworkNodePoll) []NetworkNodePoll {
			p[1].Outcome = NetworkPollNodeUnreachable
			p[1].Ports = nil
			return p
		}},
		{"ethernet link", NetworkUnknown, "LINK_LAYER_MISMATCH", func(p []NetworkNodePoll) []NetworkNodePoll { p[1].Ports[0].LinkLayer = "Ethernet"; return p }},
		{"reboot", NetworkUnknown, "BOOT_ID_CHANGED", func(p []NetworkNodePoll) []NetworkNodePoll { p[1].BootID = "boot-2"; return p }},
		{"stale", NetworkUnknown, "SOURCE_STALE", func(p []NetworkNodePoll) []NetworkNodePoll {
			p[0].ObservedAt = now.Add(-4 * time.Minute)
			p[1].ObservedAt = now.Add(-3 * time.Minute)
			return p
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, samples, _ := networkFixture()
			// Each test owns its own port slice; copy the readings before mutation.
			for i := range samples {
				samples[i].Ports = append([]NetworkPortReading(nil), samples[i].Ports...)
			}
			result, err := EvaluateNetworkPorts(policy, test.change(samples), now)
			if err != nil || len(result) != 1 || result[0].Condition != test.wantCondition || result[0].Reason != test.wantReason {
				t.Fatalf("result=%+v err=%v", result, err)
			}
			if test.name == "auth gap" && result[0].ReadError != NetworkReadSSHAuthDenied {
				t.Fatalf("read error was lost: %+v", result[0])
			}
		})
	}
}

func TestNetworkDetectorPassiveLinkDownAndReset(t *testing.T) {
	policy, polls, now := networkFixture()
	for i := range polls {
		polls[i].Ports = append([]NetworkPortReading(nil), polls[i].Ports...)
	}
	one := uint64(1)
	polls[1].Ports[0].LinkDowned = &one
	result, err := EvaluateNetworkPorts(policy, polls, now)
	if err != nil || result[0].Condition != NetworkDegraded || result[0].Reason != "LINK_DOWNED_INCREASE" || result[0].LinkDownDelta != 1 {
		t.Fatalf("increment=%+v err=%v", result, err)
	}
	two := uint64(2)
	polls[0].Ports[0].LinkDowned = &two
	result, err = EvaluateNetworkPorts(policy, polls, now)
	if err != nil || result[0].Condition != NetworkUnknown || result[0].Reason != "COUNTER_RESET" {
		t.Fatalf("reset=%+v err=%v", result, err)
	}
	polls[1].Ports[0].LinkDowned = nil
	result, err = EvaluateNetworkPorts(policy, polls, now)
	if err != nil || result[0].Condition != NetworkHealthy || result[0].CounterGap != "COUNTER_UNAVAILABLE" {
		t.Fatalf("counter gap=%+v err=%v", result, err)
	}
}

func TestNetworkDetectorKeepsPerNodeSourceGapsSeparate(t *testing.T) {
	policy, polls, now := networkFixture()
	other := NetworkPortKey{Node: "comp002", Device: "mlx5_7", Port: 1}
	policy.ExpectedPorts = append(policy.ExpectedPorts, other)
	polls[0].Ports = append(polls[0].Ports, NetworkPortReading{Key: NetworkPortKey{Node: "comp001", Device: "mlx5_bond_0", Port: 1}, LinkLayer: "Ethernet"})
	polls = append(polls, NetworkNodePoll{InventoryRevision: "reviewed-1", Node: "comp002", ObservedAt: now.Add(-time.Minute), Outcome: NetworkPollAuthUnavailable})
	result, err := EvaluateNetworkPorts(policy, polls, now)
	if err != nil || len(result) != 2 || result[0].Key.Node != "comp001" || result[0].Condition != NetworkHealthy ||
		result[1].Key.Node != "comp002" || result[1].Condition != NetworkUnknown || result[1].Reason != NetworkPollAuthUnavailable {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestNetworkDetectorRejectsUnreviewedOrAmbiguousInputs(t *testing.T) {
	_, _, now := networkFixture()
	tests := []struct {
		name   string
		change func(*NetworkDetectorPolicy, *[]NetworkNodePoll)
	}{
		{"policy version", func(p *NetworkDetectorPolicy, _ *[]NetworkNodePoll) { p.Version = 2 }},
		{"duplicate expected", func(p *NetworkDetectorPolicy, _ *[]NetworkNodePoll) {
			p.ExpectedPorts = append(p.ExpectedPorts, p.ExpectedPorts[0])
		}},
		{"foreign node", func(_ *NetworkDetectorPolicy, s *[]NetworkNodePoll) { (*s)[1].Node = "foreign" }},
		{"duplicate time", func(_ *NetworkDetectorPolicy, s *[]NetworkNodePoll) { (*s)[1].ObservedAt = (*s)[0].ObservedAt }},
		{"inventory mismatch", func(_ *NetworkDetectorPolicy, s *[]NetworkNodePoll) { (*s)[1].InventoryRevision = "other" }},
		{"partial data on auth failure", func(_ *NetworkDetectorPolicy, s *[]NetworkNodePoll) { (*s)[1].Outcome = NetworkPollAuthUnavailable }},
		{"missing boot", func(_ *NetworkDetectorPolicy, s *[]NetworkNodePoll) { (*s)[1].BootID = "" }},
		{"unreviewed read error", func(_ *NetworkDetectorPolicy, s *[]NetworkNodePoll) {
			(*s)[1].Outcome = NetworkPollReadFailed
			(*s)[1].Ports = nil
			(*s)[1].ReadError = "Permission denied; password=secret"
		}},
		{"error on complete poll", func(_ *NetworkDetectorPolicy, s *[]NetworkNodePoll) { (*s)[1].ReadError = "SSH_AUTH_DENIED" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			p, s, _ := networkFixture()
			test.change(&p, &s)
			if _, err := EvaluateNetworkPorts(p, s, now); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
}
