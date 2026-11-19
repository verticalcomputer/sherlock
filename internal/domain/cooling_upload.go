package domain

import (
	"cmp"
	"fmt"
	"math"
	"slices"
	"strings"
	"time"
)

const (
	CoolingUploadPath      = "/collector/v2/prometheus/cooling-reports"
	CoolingUploadRunPrefix = "prometheus-cooling-v2-"
	CoolingUploadVersion   = 2
	// V3 versions profile/report authority, not the existing authenticated V2 transport.
	CoolingUploadProductionVersion = 3
	CoolingUploadInterval          = 15 * time.Second
	CoolingUploadRetention         = 15 * time.Minute
	CoolingUploadSourceTimeout     = 8 * time.Second
	CoolingUploadMaxWindow         = 24 * time.Hour
	CoolingUploadMaxAssets         = 8
	CoolingUploadMaxNodes          = 2
	CoolingUploadMaxBytes          = 1 << 20
)

type CoolingUploadAsset struct {
	NodeID  StableNodeID    `json:"node_id"`
	GPUUUID PhysicalGPUUUID `json:"gpu_uuid"`
}

type CoolingUploadProfile struct {
	Version           int                  `json:"version"`
	ProfileID         string               `json:"profile_id"`
	Revision          int64                `json:"revision"`
	CollectorID       CollectorID          `json:"collector_id"`
	ClusterID         ClusterID            `json:"cluster_id"`
	SourceID          SourceID             `json:"source_id"`
	InventoryRevision string               `json:"inventory_revision"`
	StartsAt          time.Time            `json:"starts_at"`
	EndsAt            time.Time            `json:"ends_at"`
	Assets            []CoolingUploadAsset `json:"assets"`
	State             string               `json:"state,omitempty"`
}

func (p CoolingUploadProfile) Validate() error {
	if (p.Version != CoolingUploadVersion && p.Version != CoolingUploadProductionVersion) || p.Revision <= 0 {
		return fmt.Errorf("invalid cooling upload profile version or revision")
	}
	for _, id := range []string{p.ProfileID, string(p.CollectorID), string(p.ClusterID), string(p.SourceID), p.InventoryRevision} {
		if !validDCGMIdentityToken(id) {
			return fmt.Errorf("invalid cooling upload profile identity")
		}
	}
	if p.StartsAt.IsZero() || !alignedCoolingUploadSlot(p.StartsAt) {
		return fmt.Errorf("invalid cooling upload profile start")
	}
	switch p.Version {
	case CoolingUploadVersion:
		if p.State != "" || !alignedCoolingUploadSlot(p.EndsAt) || !p.EndsAt.After(p.StartsAt) || p.EndsAt.Sub(p.StartsAt) > CoolingUploadMaxWindow {
			return fmt.Errorf("invalid cooling upload profile window")
		}
	case CoolingUploadProductionVersion:
		if !p.EndsAt.IsZero() || (p.State != "ENABLED" && p.State != "DISABLED") {
			return fmt.Errorf("invalid continuous cooling upload state")
		}
	}
	if len(p.Assets) == 0 || len(p.Assets) > CoolingUploadMaxAssets || !slices.IsSortedFunc(p.Assets, compareCoolingUploadAssets) {
		return fmt.Errorf("invalid cooling upload profile asset bounds or order")
	}
	nodes := make(map[StableNodeID]bool, CoolingUploadMaxNodes)
	gpus := make(map[PhysicalGPUUUID]bool, len(p.Assets))
	for _, asset := range p.Assets {
		if !validDCGMIdentityToken(string(asset.NodeID)) || !validDCGMIdentityToken(string(asset.GPUUUID)) ||
			!strings.HasPrefix(string(asset.GPUUUID), "GPU-") || len(asset.GPUUUID) == len("GPU-") || gpus[asset.GPUUUID] {
			return fmt.Errorf("invalid or duplicate cooling upload GPU identity")
		}
		nodes[asset.NodeID], gpus[asset.GPUUUID] = true, true
	}
	if len(nodes) > CoolingUploadMaxNodes {
		return fmt.Errorf("cooling upload profile exceeds its node limit")
	}
	return nil
}

func compareCoolingUploadAssets(a, b CoolingUploadAsset) int {
	if node := cmp.Compare(a.NodeID, b.NodeID); node != 0 {
		return node
	}
	return cmp.Compare(a.GPUUUID, b.GPUUUID)
}

func alignedCoolingUploadSlot(slot time.Time) bool {
	return slot.Equal(slot.Truncate(CoolingUploadInterval))
}

// ActiveAt is collection authority, not proof of receipt admission. V3 has no
// time-based stop; an explicit higher disabled revision stops local acquisition.
func (p CoolingUploadProfile) ActiveAt(slot time.Time) bool {
	if slot.Before(p.StartsAt) {
		return false
	}
	if p.Version == CoolingUploadProductionVersion {
		return p.State == "ENABLED"
	}
	return p.Version == CoolingUploadVersion && slot.Before(p.EndsAt)
}

func (p CoolingUploadProfile) Task(query QueryKind, slot time.Time) CollectionTask {
	slot = slot.UTC()
	identityVersion := "prometheus-cooling-v2"
	if p.Version == CoolingUploadProductionVersion {
		identityVersion = "prometheus-cooling-v3"
	}
	hash := ChecksumSHA256([]byte(fmt.Sprintf(identityVersion+"\x00%s\x00%d\x00%s\x00%s\x00%s\x00%s\x00%s",
		p.ProfileID, p.Revision, p.CollectorID, p.ClusterID, p.SourceID, query, slot.Format(time.RFC3339))))
	// Keep the reserved upload namespace recognized by existing provenance
	// readers; the digest binds V3 separately without altering V2 identities.
	id := CoolingUploadRunPrefix + hash.String()
	return CollectionTask{
		RunID: RunID(id), ClusterID: p.ClusterID, SourceID: p.SourceID, Query: query, ScheduledFor: slot,
		Deadline: slot.Add(CoolingUploadInterval), MaxSeries: len(p.Assets), MaxBytes: CoolingUploadMaxBytes, IdempotencyKey: id,
	}
}

func CoolingUploadQueries() []QueryKind {
	return []QueryKind{QueryGPUTemperature, QueryGPUPower}
}

func CoolingUploadField(query QueryKind) (DCGMField, bool) {
	switch query {
	case QueryGPUTemperature, QueryGPUPower:
		return DCGMFields(query)[0], true
	default:
		return DCGMField{}, false
	}
}

// CoolingUploadValueValid excludes DCGM sentinels and invalid sensor values.
func CoolingUploadValueValid(query QueryKind, value float64) bool {
	field, ok := CoolingUploadField(query)
	minimum := 0.0
	if query == QueryGPUTemperature {
		minimum = -273.15
	}
	return ok && value >= minimum && value < 140737488355328 && (field.Double || math.Trunc(value) == value)
}

type CoolingUploadReport struct {
	Version         int              `json:"version"`
	ProfileID       string           `json:"profile_id"`
	ProfileRevision int64            `json:"profile_revision"`
	ProfileHash     string           `json:"profile_hash"`
	Result          CollectionResult `json:"result"`
}

func (r CoolingUploadReport) Validate(p CoolingUploadProfile, hash string, now time.Time) error {
	if err := p.Validate(); err != nil {
		return err
	}
	digest, err := ParseSHA256(hash)
	if err != nil || digest.String() != hash || r.Version != p.Version ||
		r.ProfileID != p.ProfileID || r.ProfileRevision != p.Revision || r.ProfileHash != hash {
		return fmt.Errorf("cooling upload report does not match the enrolled profile")
	}
	result := r.Result
	task := result.Task
	field, ok := CoolingUploadField(task.Query)
	slot := task.ScheduledFor
	if !ok || !alignedCoolingUploadSlot(slot) || !p.ActiveAt(slot) ||
		slot.After(now) || slot.Before(now.Add(-CoolingUploadRetention)) {
		return fmt.Errorf("invalid cooling upload query or slot")
	}
	if err := validateCollectionResult(result, p.Task(task.Query, slot)); err != nil {
		return err
	}
	if result.StartedAt.Before(slot) || result.CompletedAt.After(task.Deadline) || result.CompletedAt.After(now.Add(time.Second)) ||
		result.Coverage.SeriesExpected != nil || len(result.Coverage.ExpectedTargets) != 0 || len(result.Coverage.MetricFields) != 0 ||
		len(result.Observations) != result.Coverage.SeriesReturned || len(result.Failures) > 1 || result.Status == ResultNoData ||
		(result.Status == ResultSucceeded && len(result.Observations) != len(p.Assets)) {
		return fmt.Errorf("invalid cooling upload result bounds")
	}
	missing := make(map[CoolingUploadAsset]bool, len(p.Assets))
	for _, asset := range p.Assets {
		missing[asset] = true
	}
	for _, o := range result.Observations {
		if len(o.Labels) != 2 || o.Labels[0].Name != "Hostname" || o.Labels[1].Name != "UUID" {
			return fmt.Errorf("invalid cooling upload observation labels")
		}
		asset := CoolingUploadAsset{NodeID: StableNodeID(o.Labels[0].Value), GPUUUID: PhysicalGPUUUID(o.Labels[1].Value)}
		identity := EntityIdentity{ClusterID: p.ClusterID, Kind: EntityGPU, NodeID: asset.NodeID, PhysicalGPUUUID: asset.GPUUUID}
		if !missing[asset] || o.EntityKey != identity.Key() || o.SourceReference != DCGMSourceReference(task.Query) ||
			o.Metric != field.Name || o.Unit != field.Unit || o.Kind != strings.TrimPrefix(string(task.Query), "dcgm_") ||
			!CoolingUploadValueValid(task.Query, o.Value) || !o.ObservedAt.After(slot.Add(-CoolingUploadInterval)) ||
			o.ObservedAt.After(slot) || o.ObservedAt.Before(p.StartsAt) ||
			!o.ObservedAt.Equal(o.ObservedAt.Truncate(time.Millisecond)) || o.Semantics != nil {
			return fmt.Errorf("invalid cooling upload observation identity, value, or slot")
		}
		delete(missing, asset)
	}
	return nil
}
