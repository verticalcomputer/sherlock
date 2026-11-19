package domain

import (
	"slices"
	"testing"
	"time"
)

func coolingTestProfile() CoolingUploadProfile {
	start := time.Date(2026, 11, 18, 8, 0, 0, 0, time.UTC)
	return CoolingUploadProfile{
		Version: CoolingUploadVersion, ProfileID: "trial", Revision: 2, CollectorID: "collector",
		ClusterID: "cluster", SourceID: "dcgm", InventoryRevision: "inventory",
		StartsAt: start, EndsAt: start.Add(time.Hour),
		Assets: []CoolingUploadAsset{{NodeID: "node-a", GPUUUID: "GPU-1"}, {NodeID: "node-b", GPUUUID: "GPU-2"}},
	}
}

func TestCoolingUploadProfileBounds(t *testing.T) {
	for name, mutate := range map[string]func(*CoolingUploadProfile){
		"version":       func(p *CoolingUploadProfile) { p.Version = 1 },
		"revision":      func(p *CoolingUploadProfile) { p.Revision = 0 },
		"collector":     func(p *CoolingUploadProfile) { p.CollectorID = "" },
		"unordered":     func(p *CoolingUploadProfile) { slices.Reverse(p.Assets) },
		"duplicate":     func(p *CoolingUploadProfile) { p.Assets[1].GPUUUID = p.Assets[0].GPUUUID },
		"MIG":           func(p *CoolingUploadProfile) { p.Assets[1].GPUUUID = "MIG-2" },
		"extra node":    func(p *CoolingUploadProfile) { p.Assets = append(p.Assets, CoolingUploadAsset{"node-c", "GPU-3"}) },
		"too many GPUs": func(p *CoolingUploadProfile) { p.Assets = make([]CoolingUploadAsset, CoolingUploadMaxAssets+1) },
		"empty scope":   func(p *CoolingUploadProfile) { p.Assets = nil },
		"unbounded window": func(p *CoolingUploadProfile) {
			p.EndsAt = p.StartsAt.Add(CoolingUploadMaxWindow + CoolingUploadInterval)
		},
		"unaligned window": func(p *CoolingUploadProfile) { p.StartsAt = p.StartsAt.Add(time.Second) },
	} {
		t.Run(name, func(t *testing.T) {
			p := coolingTestProfile()
			mutate(&p)
			if err := p.Validate(); err == nil {
				t.Fatal("invalid profile accepted")
			}
		})
	}
	p := coolingTestProfile()
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	slot := p.StartsAt.Add(time.Minute)
	task := p.Task(QueryGPUPower, slot)
	if task.RunID == PrometheusUploadTask(p.ClusterID, p.SourceID, QueryGPUPower, slot).RunID ||
		task.RunID == p.Task(QueryGPUTemperature, slot).RunID || task.RunID == p.Task(QueryGPUPower, slot.Add(CoolingUploadInterval)).RunID {
		t.Fatal("cooling task identity collided")
	}
	p.Revision++
	if task.RunID == p.Task(QueryGPUPower, slot).RunID {
		t.Fatal("task identity was reused across profile revisions")
	}
}

func TestCoolingUploadReportClockAndAuthority(t *testing.T) {
	p := coolingTestProfile()
	hash := ChecksumSHA256([]byte("profile bytes")).String()
	slot := p.StartsAt.Add(CoolingUploadInterval)
	complete := slot.Add(time.Second)
	result := CollectionResult{Task: p.Task(QueryGPUPower, slot), Status: ResultSucceeded, StartedAt: slot, CompletedAt: complete,
		Coverage: Coverage{SeriesReturned: len(p.Assets), Complete: true}}
	for _, asset := range p.Assets {
		identity := EntityIdentity{ClusterID: p.ClusterID, Kind: EntityGPU, NodeID: asset.NodeID, PhysicalGPUUUID: asset.GPUUUID}
		result.Observations = append(result.Observations, Observation{
			ID: ObservationID(asset.GPUUUID), SchemaVersion: 1, ClusterID: p.ClusterID, SourceID: p.SourceID, Kind: "gpu_power",
			EntityKey: identity.Key(), Metric: "DCGM_FI_DEV_POWER_USAGE", Unit: "watts",
			Labels: []Label{{Name: "Hostname", Value: string(asset.NodeID)}, {Name: "UUID", Value: string(asset.GPUUUID)}},
			Value:  150, ObservedAt: slot.Add(-1250 * time.Millisecond), CollectedAt: complete, SourceReference: DCGMSourceReference(QueryGPUPower),
		})
	}
	report := CoolingUploadReport{CoolingUploadVersion, p.ProfileID, p.Revision, hash, result}
	if err := report.Validate(p, hash, slot.Add(CoolingUploadRetention)); err != nil {
		t.Fatal(err)
	}
	if err := report.Validate(p, hash, slot.Add(CoolingUploadRetention+time.Millisecond)); err == nil {
		t.Fatal("expired report accepted")
	}
	for name, mutate := range map[string]func(*CoolingUploadReport){
		"hash":               func(r *CoolingUploadReport) { r.ProfileHash = ChecksumSHA256([]byte("altered profile")).String() },
		"authority revision": func(r *CoolingUploadReport) { r.ProfileRevision++ },
		"version":            func(r *CoolingUploadReport) { r.Version = 1 },
		"foreign task":       func(r *CoolingUploadReport) { r.Result.Task.ClusterID = "foreign" },
		"incomplete success": func(r *CoolingUploadReport) {
			r.Result.Observations = r.Result.Observations[:1]
			r.Result.Coverage.SeriesReturned--
		},
		"future source clock":     func(r *CoolingUploadReport) { r.Result.Observations[0].ObservedAt = slot.Add(time.Millisecond) },
		"prior slot source clock": func(r *CoolingUploadReport) { r.Result.Observations[0].ObservedAt = slot.Add(-CoolingUploadInterval) },
		"impossible source clock": func(r *CoolingUploadReport) { r.Result.Observations[0].ObservedAt = slot.Add(-time.Nanosecond) },
		"foreign GPU": func(r *CoolingUploadReport) {
			r.Result.Observations[0].Labels = []Label{{"Hostname", "node-a"}, {"UUID", "GPU-2"}}
		},
		"foreign field":          func(r *CoolingUploadReport) { r.Result.Observations[0].Metric = "DCGM_FI_DEV_POWER_MGMT_LIMIT" },
		"unsupported sentinel":   func(r *CoolingUploadReport) { r.Result.Observations[0].Value = 140737488355330 },
		"untrusted source clock": func(r *CoolingUploadReport) { r.Result.Observations[0].SourceReference = "prometheus:unreviewed" },
		"untrusted field state": func(r *CoolingUploadReport) {
			r.Result.Coverage.MetricFields = []DCGMFieldEvidence{{State: "SUPPORTED"}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := report
			r.Result.Observations = slices.Clone(report.Result.Observations)
			mutate(&r)
			if err := r.Validate(p, hash, complete); err == nil {
				t.Fatal("invalid report accepted")
			}
		})
	}
}

func TestContinuousCoolingProfileHasExplicitLifecycle(t *testing.T) {
	p := coolingTestProfile()
	p.Version = CoolingUploadProductionVersion
	p.EndsAt = time.Time{}
	p.State = "ENABLED"
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	if !p.ActiveAt(p.StartsAt.Add(365 * 24 * time.Hour)) {
		t.Fatal("continuous authority expired")
	}
	v2 := p
	v2.Version = CoolingUploadVersion
	v2.State = ""
	v2.EndsAt = p.StartsAt.Add(time.Hour)
	if p.Task(QueryGPUPower, p.StartsAt).RunID == v2.Task(QueryGPUPower, p.StartsAt).RunID {
		t.Fatal("versioned task identities collided")
	}
	for name, mutate := range map[string]func(*CoolingUploadProfile){
		"implicit state":   func(p *CoolingUploadProfile) { p.State = "" },
		"unreviewed state": func(p *CoolingUploadProfile) { p.State = "ACTIVE" },
		"fake end":         func(p *CoolingUploadProfile) { p.EndsAt = p.StartsAt.Add(24 * time.Hour) },
		"v2 unbounded":     func(p *CoolingUploadProfile) { p.Version = CoolingUploadVersion; p.State = "" },
		"v2 production":    func(p *CoolingUploadProfile) { p.Version = CoolingUploadVersion; p.EndsAt = p.StartsAt.Add(time.Hour) },
	} {
		t.Run(name, func(t *testing.T) {
			bad := p
			mutate(&bad)
			if bad.Validate() == nil {
				t.Fatal("invalid lifecycle accepted")
			}
		})
	}
	p.State = "DISABLED"
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	if p.ActiveAt(p.StartsAt) || p.ActiveAt(p.StartsAt.Add(time.Hour)) {
		t.Fatal("disabled authority collected")
	}
}

func TestContinuousCoolingReportVersionAndDisabledAdmission(t *testing.T) {
	p := coolingTestProfile()
	p.Version = CoolingUploadProductionVersion
	p.State = "ENABLED"
	p.EndsAt = time.Time{}
	slot := p.StartsAt.Add(48 * time.Hour)
	hash := ChecksumSHA256([]byte("v3")).String()
	report := CoolingUploadReport{Version: p.Version, ProfileID: p.ProfileID, ProfileRevision: p.Revision, ProfileHash: hash,
		Result: CollectionResult{Task: p.Task(QueryGPUPower, slot), Status: ResultPartial, StartedAt: slot, CompletedAt: slot, Failures: []CollectionFailure{{Code: FailurePartialData, Message: "missing samples"}}}}
	if err := report.Validate(p, hash, slot); err != nil {
		t.Fatal(err)
	}
	report.Version = CoolingUploadVersion
	if report.Validate(p, hash, slot) == nil {
		t.Fatal("cross-version report accepted")
	}
	report.Version = p.Version
	p.State = "DISABLED"
	if report.Validate(p, hash, slot) == nil {
		t.Fatal("disabled report accepted")
	}
}
