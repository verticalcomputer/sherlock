package main

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/auth"
)

func TestValidIdentifier(t *testing.T) {
	for _, valid := range []string{"cluster-1", "site.example:west_2"} {
		if !validIdentifier(valid) {
			t.Fatalf("rejected valid identifier %q", valid)
		}
	}
	for _, invalid := range []string{"", "cluster one", "cluster\none"} {
		if validIdentifier(invalid) {
			t.Fatalf("accepted unsafe identifier %q", invalid)
		}
	}
}

func TestParseAPIKeyCreateCommand(t *testing.T) {
	command, err := parseAPIKeyCommand([]string{"create", "--cluster", "cluster-1", "--label", "global backend", "--expires-in", "24h", "--capability", "cluster:read", "--capability", "telemetry:read"})
	if err != nil {
		t.Fatal(err)
	}
	if command.Action != "create" || command.ClusterID != "cluster-1" || command.Label != "global backend" || command.ExpiresIn != 24*time.Hour {
		t.Fatalf("unexpected create command: %+v", command)
	}
	if len(command.Capabilities) != 2 || command.Capabilities[0] != auth.CapabilityClusterRead || command.Capabilities[1] != auth.CapabilityTelemetryRead {
		t.Fatalf("unexpected capabilities: %v", command.Capabilities)
	}
}

func TestParseAPIKeyListAndRevokeCommands(t *testing.T) {
	list, err := parseAPIKeyCommand([]string{"list", "--cluster", "cluster-1"})
	if err != nil || list.Action != "list" || list.ClusterID != "cluster-1" {
		t.Fatalf("unexpected list command=%+v err=%v", list, err)
	}
	revoke, err := parseAPIKeyCommand([]string{"revoke", "--cluster", "cluster-1", "--key-id", "AAAAAAAAAAAAAAAAAAAAAA"})
	if err != nil || revoke.PublicID != "AAAAAAAAAAAAAAAAAAAAAA" {
		t.Fatalf("unexpected revoke command=%+v err=%v", revoke, err)
	}
}

func TestParseAPIKeyCommandRejectsUnsafeInput(t *testing.T) {
	for _, arguments := range [][]string{
		{"create", "--cluster", "cluster-1", "--label", "missing capability"},
		{"create", "--cluster", "cluster-1", "--label", "bad capability", "--capability", "root"},
		{"list", "--cluster", "cluster one"},
		{"revoke", "--cluster", "cluster-1"},
		{"unknown", "--cluster", "cluster-1"},
	} {
		if _, err := parseAPIKeyCommand(arguments); err == nil {
			t.Fatalf("accepted unsafe arguments: %v", arguments)
		}
	}
}

func TestParseCredentialRotationRequiresStoppedWritersAndActor(t *testing.T) {
	command, err := parseCredentialRotationCommand([]string{"--actor", "access-operator", "--writers-stopped"})
	if err != nil || command.Actor != "access-operator" {
		t.Fatalf("command=%+v err=%v", command, err)
	}
	for _, arguments := range [][]string{{"--actor", "access-operator"}, {"--writers-stopped"}, {"--actor", "bad\nactor", "--writers-stopped"}} {
		if _, err := parseCredentialRotationCommand(arguments); err == nil {
			t.Fatalf("accepted unsafe rotation arguments: %v", arguments)
		}
	}
}

func TestParseCredentialAdminGrantAndListCommands(t *testing.T) {
	grant, err := parseCredentialAdminCommand([]string{"grant", "--cluster", "cluster-1", "--subject", "access-admin", "--actor", "operator"})
	if err != nil || grant.Action != "grant" || grant.ClusterID != "cluster-1" || grant.Subject != "access-admin" || grant.Actor != "operator" {
		t.Fatalf("unexpected grant command=%+v err=%v", grant, err)
	}
	list, err := parseCredentialAdminCommand([]string{"list", "--cluster", "cluster-1"})
	if err != nil || list.Action != "list" {
		t.Fatalf("unexpected list command=%+v err=%v", list, err)
	}
}

func TestParseCredentialAdminBindingCommands(t *testing.T) {
	for _, action := range []string{"bind-collector", "unbind-collector"} {
		command, err := parseCredentialAdminCommand([]string{action, "--cluster", "cluster-1", "--host", "fixture1-zone1-headnode", "--collector", "head-1", "--actor", "operator"})
		if err != nil || command.Action != action || command.ClusterID != "cluster-1" || command.Host != "fixture1-zone1-headnode" || command.CollectorID != "head-1" || command.Actor != "operator" {
			t.Fatalf("unexpected %s command=%+v err=%v", action, command, err)
		}
	}
	bindings, err := parseCredentialAdminCommand([]string{"list-bindings", "--cluster", "cluster-1"})
	if err != nil || bindings.Action != "list-bindings" || bindings.ClusterID != "cluster-1" {
		t.Fatalf("unexpected list-bindings command=%+v err=%v", bindings, err)
	}
}

func TestParseCredentialAdminCommandRejectsUnsafeInput(t *testing.T) {
	for _, arguments := range [][]string{
		{"bind-collector", "--cluster", "cluster-1", "--collector", "head-1", "--actor", "operator"},
		{"bind-collector", "--cluster", "cluster-1", "--host", "fixture1-zone1-headnode", "--actor", "operator"},
		{"bind-collector", "--cluster", "cluster-1", "--host", "fixture1-zone1-headnode", "--collector", "head-1"},
		{"bind-collector", "--cluster", "cluster-1", "--host", "bad host", "--collector", "head-1", "--actor", "operator"},
		{"bind-collector", "--cluster", "cluster-1", "--host", "head", "--collector", "head one", "--actor", "operator"},
		{"unbind-collector", "--cluster", "cluster one", "--host", "head", "--collector", "head-1", "--actor", "operator"},
		{"unbind-collector", "--cluster", "cluster-1", "--host", "head", "--collector", "head-1", "--actor", "bad\nactor"},
		{"list-bindings"},
		{"bind-target", "--cluster", "cluster-1", "--host", "head", "--collector", "head-1", "--actor", "operator"},
		{"grant", "--cluster", "cluster-1", "--subject", "access-admin"},
	} {
		if _, err := parseCredentialAdminCommand(arguments); err == nil {
			t.Fatalf("accepted unsafe credential administrator arguments: %v", arguments)
		}
	}
}

func TestLoadAPIKeyHashKey(t *testing.T) {
	encoded := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x2a}, 32))
	decoded, err := loadAPIKeyHashKey(encoded)
	if err != nil || len(decoded) != 32 {
		t.Fatalf("decoded key length=%d err=%v", len(decoded), err)
	}
	if _, err := loadAPIKeyHashKey("short"); err == nil {
		t.Fatal("accepted short API-key hash key")
	}
}

func TestRunPrintsUsageWithoutConfiguration(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if status := run([]string{"api-key", "create"}, &stdout, &stderr); status != 2 {
		t.Fatalf("status=%d", status)
	}
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), "sherlock-admin api-key create") {
		t.Fatalf("unexpected output stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}
