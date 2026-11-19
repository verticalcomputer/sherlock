package domain

import (
	"encoding/json"
	"fmt"
	"slices"
	"testing"
	"time"
)

func fleetCoolingProfile() CoolingUploadProfile {
	p := coolingTestProfile()
	p.Version = 3
	p.EndsAt = time.Time{}
	p.State = "ENABLED"
	p.Assets = nil
	for i := range 128 {
		p.Assets = append(p.Assets, CoolingUploadAsset{StableNodeID(fmt.Sprintf("node-%02d", i/8)), PhysicalGPUUUID(fmt.Sprintf("GPU-%03d", i))})
	}
	return p
}
func TestFleetCoolingProfileVersionedBounds(t *testing.T) {
	p := fleetCoolingProfile()
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*CoolingUploadProfile){
		"129 GPUs":                  func(p *CoolingUploadProfile) { p.Assets = append(p.Assets, CoolingUploadAsset{"node-15", "GPU-128"}) },
		"17 nodes":                  func(p *CoolingUploadProfile) { p.Assets[127].NodeID = "node-16" },
		"cross-node duplicate GPU":  func(p *CoolingUploadProfile) { p.Assets[127].GPUUUID = p.Assets[0].GPUUUID },
		"V2 cannot use fleet scope": func(p *CoolingUploadProfile) { p.Version = 2; p.State = ""; p.EndsAt = p.StartsAt.Add(time.Hour) },
	} {
		t.Run(name, func(t *testing.T) {
			p := p
			p.Assets = slices.Clone(p.Assets)
			change(&p)
			if p.Validate() == nil {
				t.Fatal("invalid authority accepted")
			}
		})
	}
	p.Version = 2
	p.State = ""
	p.EndsAt = p.StartsAt.Add(time.Hour)
	p.Assets = p.Assets[:8]
	if err := p.Validate(); err != nil {
		t.Fatal("original V2 scope rejected", err)
	}
}
func TestFleetCoolingFullReportAndForeignPair(t *testing.T) {
	p := fleetCoolingProfile()
	slot := p.StartsAt.Add(time.Minute)
	hash := ChecksumSHA256([]byte("fleet")).String()
	r := CoolingUploadReport{Version: 3, ProfileID: p.ProfileID, ProfileRevision: p.Revision, ProfileHash: hash, Result: CollectionResult{Task: p.Task(QueryGPUPower, slot), Status: ResultSucceeded, StartedAt: slot, CompletedAt: slot.Add(time.Second), Coverage: Coverage{SeriesReturned: 128, Complete: true}}}
	for _, asset := range p.Assets {
		identity := EntityIdentity{ClusterID: p.ClusterID, Kind: EntityGPU, NodeID: asset.NodeID, PhysicalGPUUUID: asset.GPUUUID}
		r.Result.Observations = append(r.Result.Observations, Observation{ID: ObservationID(asset.GPUUUID), SchemaVersion: 1, ClusterID: p.ClusterID, SourceID: p.SourceID, Kind: "gpu_power", EntityKey: identity.Key(), Metric: "DCGM_FI_DEV_POWER_USAGE", Unit: "watts", Labels: []Label{{"Hostname", string(asset.NodeID)}, {"UUID", string(asset.GPUUUID)}}, Value: 150, ObservedAt: slot, CollectedAt: slot.Add(time.Second), SourceReference: DCGMSourceReference(QueryGPUPower)})
	}
	if err := r.Validate(p, hash, slot.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(r)
	if err != nil || len(b) > CoolingUploadMaxBytes {
		t.Fatalf("full report bytes=%d err=%v", len(b), err)
	}
	t.Logf("128-GPU complete report: %d bytes within unchanged 1MiB limit", len(b))
	r.Result.Observations[0].Labels[0].Value = "node-01"
	if r.Validate(p, hash, slot.Add(time.Second)) == nil {
		t.Fatal("cross-product node/GPU pair accepted")
	}
}
