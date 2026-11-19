package postgres

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"testing"
	"time"
)

func TestProductionNotificationReenableDoesNotBackfill(t *testing.T) {
	now := time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC)
	old := now.Add(-time.Hour)
	fresh := now.Add(time.Second)
	cases := []struct {
		name              string
		enabled, notified bool
		entered, event    time.Time
		want              bool
	}{
		{"never notified old candidate", true, false, old, fresh, false},
		{"previously notified new worsening", true, true, old, fresh, true},
		{"previously notified old event", true, true, old, old, false},
		{"disabled recovery retained without send", false, true, old, fresh, false},
		{"new occurrence", true, false, fresh, fresh, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := productionNotificationEligible(tc.enabled, &now, tc.entered, tc.event, tc.notified, false); got != tc.want {
				t.Fatalf("eligible=%v want%v", got, tc.want)
			}
		})
	}
}

func TestProductionBenignWorseningAfterActivation(t *testing.T) {
	at := time.Now().UTC()
	old := at.Add(-time.Hour)
	fresh := at.Add(time.Second)
	if !productionNotificationEligible(true, &at, old, fresh, false, true) {
		t.Fatal("new worsening after benign episode was suppressed")
	}
	if productionNotificationEligible(true, &at, old, old, false, true) {
		t.Fatal("old worsening replayed after activation")
	}
	if productionNotificationEligible(true, &at, old, fresh, false, false) {
		t.Fatal("old unresolved candidate terminal was backfilled")
	}
}

func TestProductionProfileCacheKeepsExactImmutableIdentity(t *testing.T) {
	profile := domain.CoolingUploadProfile{Version: 3, State: "ENABLED", ProfileID: "profile", Revision: 1, CollectorID: "collector", ClusterID: "cluster", SourceID: "source", InventoryRevision: "inventory", StartsAt: time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC), Assets: []domain.CoolingUploadAsset{{NodeID: "node", GPUUUID: "GPU-1"}}}
	body, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	hash := domain.ChecksumSHA256(body).String()
	cache := productionProfileCache{}
	got, err := cache.decode(body, hash, 1)
	if err != nil {
		t.Fatal(err)
	}
	got.Assets[0].GPUUUID = "GPU-mutated"
	original := bytes.Clone(body)
	body[0] = '['
	if _, err = cache.decode(body, hash, 1); err == nil {
		t.Fatal("changed body accepted under cached identity")
	}
	got, err = cache.decode(original, hash, 1)
	if err != nil || got.Assets[0].GPUUUID != "GPU-1" {
		t.Fatalf("caller mutated cached witness: %+v %v", got, err)
	}
	if _, err = cache.decode(original, hash, 2); err == nil {
		t.Fatal("wrong revision accepted")
	}
	if _, err = cache.decode(original, "bad", 1); err == nil {
		t.Fatal("malformed identity accepted")
	}
	profile.Revision = 2
	next, _ := json.Marshal(profile)
	if _, err = cache.decode(next, domain.ChecksumSHA256(next).String(), 2); err != nil {
		t.Fatal("distinct compatible revision", err)
	}
	for len(cache) < 256 {
		cache[productionProfileKey{fmt.Sprintf("%064d", len(cache)), 99}] = productionCachedProfile{}
	}
	profile.Revision = 3
	next, _ = json.Marshal(profile)
	if _, err = cache.decode(next, domain.ChecksumSHA256(next).String(), 3); !errors.Is(err, ErrAssessmentCapacity) {
		t.Fatalf("capacity not enforced: %v", err)
	}
}
