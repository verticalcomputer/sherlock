package domain

import "testing"

func TestResolveGPUObservationIdentity(t *testing.T) {
	canonical := (EntityIdentity{ClusterID: "cluster-a", Kind: EntityGPU, NodeID: "node-a", PhysicalGPUUUID: "GPU-a"}).Key()
	for _, tt := range []struct {
		name, key, cluster, source string
		labels                     []Label
		wantKey, wantUUID          string
		wantCanonical, valid       bool
	}{
		{name: "canonical", key: canonical, wantKey: canonical, wantUUID: "GPU-a", wantCanonical: true, valid: true},
		{name: "empty canonical UUID cannot be repaired", key: "cluster-a/GPU/node-a//", labels: []Label{{"UUID", "GPU-a"}}},
		{name: "legacy MIG token", key: "node/node-a/gpu/MIG-a"},
		{name: "legacy MIG GPU token", key: "node/node-a/gpu/MIG-GPU-a"},
		{name: "canonical consistent labels", key: canonical, labels: []Label{{"Hostname", "node-a"}, {"UUID", "GPU-a"}}, wantKey: canonical, wantUUID: "GPU-a", wantCanonical: true, valid: true},
		{name: "legacy UUID key", key: "node/node-a/gpu/GPU-a", wantKey: canonical, wantUUID: "GPU-a", wantCanonical: true, valid: true},
		{name: "legacy UUID label", key: "node/node-a/gpu/0", labels: []Label{{"Hostname", "node-a"}, {"UUID", "GPU-a"}}, wantKey: canonical, wantUUID: "GPU-a", wantCanonical: true, valid: true},
		{name: "legacy unproven index", key: "node/node-a/gpu/0", wantKey: "node/node-a/gpu/0", valid: true},
		{name: "instance and device cannot map index", key: "node/node-a/gpu/0", labels: []Label{{"instance", "other:9400"}, {"device", "GPU-a"}}, wantKey: "node/node-a/gpu/0", valid: true},
		{name: "deployment metadata cannot change scope", key: canonical, labels: []Label{{"cluster", "foreign"}}, wantKey: canonical, wantUUID: "GPU-a", wantCanonical: true, valid: true},
		{name: "foreign observation cluster", key: canonical, cluster: "foreign"},
		{name: "foreign observation source", key: canonical, source: "foreign"},
		{name: "foreign canonical key", key: "foreign/GPU/node-a/GPU-a/"},
		{name: "canonical node label conflict", key: canonical, labels: []Label{{"hostname", "node-b"}}},
		{name: "canonical UUID label conflict", key: canonical, labels: []Label{{"UUID", "GPU-b"}}},
		{name: "legacy UUID key label conflict", key: "node/node-a/gpu/GPU-a", labels: []Label{{"UUID", "GPU-b"}}},
		{name: "conflicting hostname aliases", key: "node/node-a/gpu/0", labels: []Label{{"Hostname", "node-a"}, {"hostname", "node-b"}}},
		{name: "conflicting UUID aliases", key: "node/node-a/gpu/0", labels: []Label{{"UUID", "GPU-a"}, {"uuid", "GPU-b"}}},
		{name: "MIG label", key: canonical, labels: []Label{{"MIG_UUID", "MIG-a"}}},
		{name: "MIG key", key: "cluster-a/MIG/node-a/GPU-a/MIG-a"},
		{name: "malformed trailing segment", key: canonical + "extra"},
		{name: "malformed legacy suffix", key: "node/node-a/gpu/0/extra"},
		{name: "invalid UUID label", key: "node/node-a/gpu/0", labels: []Label{{"UUID", "0"}}},
		{name: "non GPU key", key: "source/source-a"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cluster, source := ClusterID("cluster-a"), SourceID("source-a")
			if tt.cluster != "" {
				cluster = ClusterID(tt.cluster)
			}
			if tt.source != "" {
				source = SourceID(tt.source)
			}
			observation := Observation{ClusterID: cluster, SourceID: source, EntityKey: tt.key, Labels: tt.labels}
			identity, valid := ResolveGPUObservationIdentity("cluster-a", "source-a", observation)
			if valid != tt.valid || identity.EntityKey != tt.wantKey || string(identity.PhysicalGPUUUID) != tt.wantUUID || identity.Canonical != tt.wantCanonical {
				t.Fatalf("identity=%+v valid=%t want key=%s UUID=%s canonical=%t valid=%t", identity, valid, tt.wantKey, tt.wantUUID, tt.wantCanonical, tt.valid)
			}
			if valid && identity.NodeID != "node-a" {
				t.Fatalf("node identity was inferred or aliased: %+v", identity)
			}
			if observation.EntityKey != tt.key {
				t.Fatal("resolver rewrote stored evidence")
			}
		})
	}
}
