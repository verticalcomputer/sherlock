package main

import (
	"testing"

	"github.com/verticalcomputer/sherlock/internal/auth"
)

func TestParseHumanBootstrapCommands(t *testing.T) {
	base := []string{"--issuer", "https://vertical.cloudflareaccess.com", "--subject", "user-1"}
	tests := []struct {
		action string
		extra  []string
	}{
		{"grant-membership", []string{"--cluster", "pilot-cluster", "--role", "CLUSTER_ADMIN", "--actor", "operator"}},
		{"revoke-membership", []string{"--cluster", "pilot-cluster", "--actor", "operator"}},
		{"show-membership", []string{"--cluster", "pilot-cluster"}},
		{"grant-privilege", []string{"--cluster", "pilot-cluster", "--privilege", "RAW_EVIDENCE", "--actor", "operator"}},
		{"revoke-privilege", []string{"--cluster", "pilot-cluster", "--privilege", "RAW_EVIDENCE", "--actor", "operator"}},
		{"show-privilege", []string{"--cluster", "pilot-cluster", "--privilege", "RAW_EVIDENCE"}},
		{"grant-platform", []string{"--actor", "operator"}},
		{"revoke-platform", []string{"--actor", "operator"}},
		{"show-platform", nil},
	}
	for _, test := range tests {
		t.Run(test.action, func(t *testing.T) {
			args := append([]string{test.action}, base...)
			args = append(args, test.extra...)
			got, err := parseHumanCommand(args)
			if err != nil || got.Action != test.action || got.Principal.Subject != "user-1" {
				t.Fatalf("command=%+v err=%v", got, err)
			}
			if test.action == "grant-membership" && got.Role != auth.RoleClusterAdmin {
				t.Fatalf("role=%s", got.Role)
			}
		})
	}
}

func TestParseHumanCommandRejectsUnsafeOrConfusedScope(t *testing.T) {
	base := []string{"--issuer", "https://vertical.cloudflareaccess.com", "--subject", "user-1"}
	for _, args := range [][]string{
		{"grant-membership", "--cluster", "pilot-cluster", "--actor", "operator"},
		{"grant-membership", "--cluster", "pilot-cluster", "--role", "PLATFORM_ADMIN", "--actor", "operator"},
		{"grant-privilege", "--cluster", "pilot-cluster", "--privilege", "ROOT", "--actor", "operator"},
		{"grant-platform", "--cluster", "pilot-cluster", "--actor", "operator"},
		{"show-membership", "--cluster", "pilot-cluster", "--actor", "operator"},
		{"revoke-membership", "--cluster", "pilot-cluster"},
		{"grant-platform", "--actor", "bad\nactor"},
	} {
		full := append([]string{args[0]}, base...)
		full = append(full, args[1:]...)
		if _, err := parseHumanCommand(full); err == nil {
			t.Fatalf("accepted %v", full)
		}
	}
	if _, err := parseHumanCommand([]string{"grant-platform", "--issuer", "http://untrusted", "--subject", "user", "--actor", "operator"}); err == nil {
		t.Fatal("accepted unverified issuer")
	}
}
