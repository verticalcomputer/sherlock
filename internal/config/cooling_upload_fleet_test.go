package config

import (
	"encoding/json"
	"fmt"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCoolingProfileFleetFilesAndSharedAuthority(t *testing.T) {
	t.Setenv("SHERLOCK_PROMETHEUS_COOLING_PROFILE_FILE", "")
	t.Setenv("SHERLOCK_PROMETHEUS_COOLING_PROFILE_FILES", "")
	var p domain.CoolingUploadProfile
	if err := json.Unmarshal([]byte(testCoolingProfileJSON), &p); err != nil {
		t.Fatal(err)
	}
	p.Version = 3
	p.State = "ENABLED"
	p.EndsAt = time.Time{}
	p.Assets = nil
	for i := range 128 {
		p.Assets = append(p.Assets, domain.CoolingUploadAsset{NodeID: domain.StableNodeID(fmt.Sprintf("node-%02d-", i/8) + strings.Repeat("x", 90)), GPUUUID: domain.PhysicalGPUUUID(fmt.Sprintf("GPU-%03d-", i) + strings.Repeat("y", 90))})
	}
	write := func(name string, p domain.CoolingUploadProfile) string {
		t.Helper()
		b, e := json.Marshal(p)
		if e != nil {
			t.Fatal(e)
		}
		path := filepath.Join(t.TempDir(), name)
		if e = os.WriteFile(path, b, 0600); e != nil {
			t.Fatal(e)
		}
		return path
	}
	one := write("one", p)
	raw, _ := os.ReadFile(one)
	if len(raw) <= 16<<10 {
		t.Fatal("test must exceed old byte limit")
	}
	t.Setenv("SHERLOCK_PROMETHEUS_COOLING_PROFILE_FILE", one)
	if _, _, err := LoadCoolingUploadProfile(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SHERLOCK_PROMETHEUS_COOLING_PROFILE_FILE", "")
	second := p
	second.ProfileID = "second"
	second.CollectorID = "collector-2"
	second.ClusterID = "cluster-2"
	second.SourceID = "source-2"
	two := write("two", second)
	set := func(paths ...string) {
		b, _ := json.Marshal(paths)
		t.Setenv("SHERLOCK_PROMETHEUS_COOLING_PROFILE_FILES", string(b))
	}
	set(one, two)
	profiles, e := LoadCoolingUploadProfiles()
	if e != nil || len(profiles) != 2 {
		t.Fatalf("profiles=%d err=%v", len(profiles), e)
	}
	if _, _, e := LoadCoolingUploadProfile(); e == nil {
		t.Fatal("collector accepted shared intake settings")
	}
	for _, paths := range [][]string{{one, one}, {one, two, two}, {}} {
		set(paths...)
		if _, e := LoadCoolingUploadProfiles(); e == nil {
			t.Fatal("invalid profile set accepted")
		}
	}
	second.ClusterID = p.ClusterID
	set(one, write("same-cluster", second))
	if _, e := LoadCoolingUploadProfiles(); e == nil {
		t.Fatal("two profiles for same cluster accepted")
	}
	set(one, two)
	t.Setenv("SHERLOCK_PROMETHEUS_COOLING_PROFILE_FILE", one)
	if _, e := LoadCoolingUploadProfiles(); e == nil {
		t.Fatal("ambiguous single/shared config accepted")
	}
	t.Setenv("SHERLOCK_PROMETHEUS_COOLING_PROFILE_FILES", "")
	if e := os.WriteFile(one, append(raw, []byte(strings.Repeat(" ", 64<<10))...), 0600); e != nil {
		t.Fatal(e)
	}
	if _, _, e := LoadCoolingUploadProfile(); e == nil {
		t.Fatal("oversize V3 accepted")
	}
	// Valid V2 JSON padded past its original private-file bound remains invalid.
	if e := os.WriteFile(one, []byte(testCoolingProfileJSON+strings.Repeat(" ", 16<<10)), 0600); e != nil {
		t.Fatal(e)
	}
	if _, _, e := LoadCoolingUploadProfile(); e == nil {
		t.Fatal("V2 byte limit widened")
	}
}
