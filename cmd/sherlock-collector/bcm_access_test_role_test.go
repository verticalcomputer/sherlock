package main

import (
	"errors"
	"github.com/verticalcomputer/sherlock/internal/config"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"strings"
	"testing"
)

func TestBCMAccessTestRoleRefusesNoNewPrivilegesBeforeAnyClaim(t *testing.T) {
	read := func(string) ([]byte, error) { return []byte("Name:\tsherlock-collector\nNoNewPrivs:\t1\n"), nil }
	err := requireNoNewPrivilegesDisabled("linux", read)
	if err == nil || !strings.Contains(err.Error(), "NoNewPrivileges=1") {
		t.Fatalf("NoNewPrivileges=1 accepted: %v", err)
	}
}

func TestExternalBCMRoleAdvertisesCapabilityWithoutEmbeddedWorker(t *testing.T) {
	cfg := config.Collector{BCMAccessTest: config.BCMAccessTestConfig{ExternalWorker: true}}
	// The external role advertises both reviewed operations of the family:
	// they share one fixed head command and one checker.
	if got := bcmAccessTestCapabilities(cfg); len(got) != 2 || got[0] != domain.CredentialAccessTestOperation || got[1] != domain.CredentialInventoryDiscoveryOperation {
		t.Fatalf("external role capabilities = %v", got)
	}
	if got := bcmAccessTestCapabilities(config.Collector{}); len(got) != 0 {
		t.Fatalf("disabled role advertised %v", got)
	}
	worker, err := buildBCMCredentialWorker(cfg, nil, nil, nil)
	if err != nil || worker != nil {
		t.Fatalf("external role started an embedded worker: worker=%v err=%v", worker, err)
	}
}

func TestBCMAccessTestRoleRequiresVerifiedDisabledState(t *testing.T) {
	read := func(string) ([]byte, error) { return []byte("NoNewPrivs:\t0\n"), nil }
	if err := requireNoNewPrivilegesDisabled("linux", read); err != nil {
		t.Fatalf("NoNewPrivileges=0 rejected: %v", err)
	}
	if err := requireNoNewPrivilegesDisabled("darwin", read); err == nil {
		t.Fatal("non-Linux role accepted")
	}
	failing := func(string) ([]byte, error) { return nil, errors.New("missing") }
	if err := requireNoNewPrivilegesDisabled("linux", failing); err == nil {
		t.Fatal("unreadable status accepted")
	}
	if err := requireNoNewPrivilegesDisabled("linux", func(string) ([]byte, error) { return []byte("Name:\tx\n"), nil }); err == nil {
		t.Fatal("missing NoNewPrivs field accepted")
	}
}
