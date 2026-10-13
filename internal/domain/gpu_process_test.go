package domain

import "testing"

func TestGPUProcessIdentityIncarnations(t *testing.T) {
	base := GPUProcessIdentity{Node: EntityIdentity{ClusterID: "cluster-a", Kind: EntityNode, NodeID: "node-a"}, BootID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", PIDNamespace: "pid:[4026531836]", PID: 42, StartTicks: 100}
	key, err := base.Key()
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*GPUProcessIdentity){
		func(p *GPUProcessIdentity) { p.StartTicks++ },
		func(p *GPUProcessIdentity) { p.BootID = "bbbbbbbb-bbbb-cccc-dddd-eeeeeeeeeeee" },
		func(p *GPUProcessIdentity) { p.PIDNamespace = "pid:[4026531837]" },
		func(p *GPUProcessIdentity) { p.Node.NodeID = "node-b" },
		func(p *GPUProcessIdentity) { p.Node.ClusterID = "cluster-b" },
	} {
		other := base
		mutate(&other)
		otherKey, err := other.Key()
		if err != nil || otherKey == key {
			t.Fatalf("process incarnations merged: %v", err)
		}
	}
	for _, mutate := range []func(*GPUProcessIdentity){
		func(p *GPUProcessIdentity) { p.StartTicks = 0 },
		func(p *GPUProcessIdentity) { p.BootID = "unknown" },
		func(p *GPUProcessIdentity) { p.PIDNamespace = "" },
		func(p *GPUProcessIdentity) { p.Node.Kind = EntityGPU },
		func(p *GPUProcessIdentity) { p.PID = 0 },
	} {
		other := base
		mutate(&other)
		if _, err := other.Key(); err == nil {
			t.Fatal("incomplete identity received stable key")
		}
	}
}
