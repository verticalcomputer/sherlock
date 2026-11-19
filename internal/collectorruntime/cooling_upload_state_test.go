package collectorruntime

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

func TestCoolingAppliedStateRejectsRestartRollback(t *testing.T) {
	now := time.Now().UTC().Truncate(domain.CoolingUploadInterval)
	spool := coolingSpoolForTest(t, now, nil)
	p := spool.profile
	p.Version = domain.CoolingUploadProductionVersion
	p.EndsAt = time.Time{}
	p.State = "ENABLED"
	hash := domain.ChecksumSHA256([]byte("enabled")).String()
	apply := func(p domain.CoolingUploadProfile, h string) {
		t.Helper()
		if err := applyCoolingUploadState(spool.dir, p, h); err != nil {
			t.Fatal(err)
		}
	}
	apply(p, hash)
	apply(p, hash)
	if err := applyCoolingUploadState(spool.dir, p, domain.ChecksumSHA256([]byte("changed")).String()); err == nil {
		t.Fatal("same revision changed bytes")
	}
	disabled := p
	disabled.Revision++
	disabled.State = "DISABLED"
	dh := domain.ChecksumSHA256([]byte("disabled")).String()
	apply(disabled, dh)
	apply(disabled, dh)
	if err := applyCoolingUploadState(spool.dir, p, hash); err == nil {
		t.Fatal("stale restart resurrected disabled source")
	}
	if err := applyCoolingUploadState(spool.dir, spool.profile, spool.hash); err == nil {
		t.Fatal("V2 downgrade bypassed disable")
	}
	foreign := disabled
	foreign.Revision++
	foreign.ProfileID = "other"
	if err := applyCoolingUploadState(spool.dir, foreign, hash); err == nil {
		t.Fatal("changed profile identity bypassed durable revision")
	}
	reenrolled := disabled
	reenrolled.Revision++
	reenrolled.State = "ENABLED"
	apply(reenrolled, hash)
	entries, err := spool.entries()
	if err != nil || len(entries) != 0 {
		t.Fatalf("state consumed report budget: %v %v", entries, err)
	}
}

func TestCoolingAppliedStateRejectsMalformedState(t *testing.T) {
	spool := coolingSpoolForTest(t, time.Now().UTC().Truncate(domain.CoolingUploadInterval), nil)
	p := spool.profile
	p.Version = 3
	p.State = "ENABLED"
	p.EndsAt = time.Time{}
	path := filepath.Join(spool.dir, coolingStateFile)
	if err := os.WriteFile(path, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if applyCoolingUploadState(spool.dir, p, spool.hash) == nil {
		t.Fatal("malformed local state silently reset")
	}
}

func TestDisabledCoolingProfileDoesNotReadSources(t *testing.T) {
	now := time.Now().UTC().Truncate(domain.CoolingUploadInterval)
	s := coolingSpoolForTest(t, now, nil)
	s.profile.Version = 3
	s.profile.State = "DISABLED"
	s.profile.EndsAt = time.Time{}
	e := new(countedCoolingExecutor)
	if err := s.collect(t.Context(), e, now); err != nil {
		t.Fatal(err)
	}
	if e.calls.Load() != 0 {
		t.Fatal("disabled profile read source")
	}
}
