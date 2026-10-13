package diagnosticrunner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeInventory(t *testing.T, name, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func validSSHContract() string {
	return `{
  "schema_version": "sherlock.ssh-target-auth.v1",
  "authentication_profiles": [
    {"id":"pilot-key","method":"public_key","credential_source":"head_local_persistent","credential_reference":"pilot-key-v1"}
  ],
  "targets": [
    {"id":"comp001","address":"comp001.pilot.internal","port":22,"username":"sherlock-runner","authentication_profile":"pilot-key","principal_constraint":"authorized_key_force_command"},
    {"id":"comp002","address":"10.67.80.12","port":2222,"username":"sherlock-runner","authentication_profile":"pilot-key","principal_constraint":"authorized_key_force_command"}
  ]
}`
}

func TestLoadSSHTargetAuthenticationReadsVersionedContract(t *testing.T) {
	path := writeInventory(t, "ssh-inventory.json", validSSHContract())
	inventory, err := LoadSSHTargetAuthentication(path)
	if err != nil {
		t.Fatalf("a valid inventory did not load: %v", err)
	}
	if inventory.SchemaVersion != SSHTargetAuthenticationSchemaV1 || inventory.Targets["comp001"].Address != "comp001.pilot.internal" || inventory.Targets["comp002"].Port != 2222 {
		t.Fatalf("inventory = %#v", inventory)
	}
	profile := inventory.AuthenticationProfiles["pilot-key"]
	if profile.Method != SSHAuthenticationPublicKey || profile.CredentialReference != "pilot-key-v1" {
		t.Fatalf("profile = %#v", profile)
	}
}

func TestLoadSSHTargetAuthenticationAcceptsOnlyNonSecretPasswordMetadata(t *testing.T) {
	contents := strings.Replace(validSSHContract(), `"method":"public_key"`, `"method":"password"`, 1)
	contents = strings.Replace(contents, `"credential_reference":"pilot-key-v1"`, `"credential_reference":"pilot-password-v1"`, 1)
	contents = strings.ReplaceAll(contents, `"principal_constraint":"authorized_key_force_command"`, `"principal_constraint":"dedicated_sshd_force_command"`)
	inventory, err := LoadSSHTargetAuthentication(writeInventory(t, "ssh-target-auth.v1.json", contents))
	if err != nil {
		t.Fatalf("password metadata did not load: %v", err)
	}
	if profile := inventory.AuthenticationProfiles["pilot-key"]; profile.Method != SSHAuthenticationPassword || profile.CredentialReference != "pilot-password-v1" {
		t.Fatalf("profile = %#v", profile)
	}

	secret := "credential-value-must-not-escape"
	withSecret := strings.Replace(contents, `"credential_reference":"pilot-password-v1"`, `"credential_reference":"pilot-password-v1","password":"`+secret+`"`, 1)
	_, err = LoadSSHTargetAuthentication(writeInventory(t, "ssh-target-auth.v1.json", withSecret))
	if err == nil {
		t.Fatal("a credential-bearing profile was accepted")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatal("credential value escaped through the decoder error")
	}
}

// The alias is the only value in this file that reaches an SSH command line.
// An entry that could lead with a dash or carry a host:port is refused at load
// rather than relying on the `--` separator alone.
func TestLoadSSHTargetAuthenticationRefusesUnsafeOrSecretBearingEntries(t *testing.T) {
	for name, contents := range map[string]string{
		"legacy unversioned contract": `{"comp001":"comp001.pilot.internal"}`,
		"unknown schema version":      strings.Replace(validSSHContract(), SSHTargetAuthenticationSchemaV1, "sherlock.ssh-target-auth.v2", 1),
		"embedded password":           strings.Replace(validSSHContract(), `"credential_reference":"pilot-key-v1"`, `"credential_reference":"pilot-key-v1","password":"must-never-load"`, 1),
		"interactive source":          strings.Replace(validSSHContract(), "head_local_persistent", "interactive_single_use", 1),
		"password constrained by key": strings.Replace(validSSHContract(), `"method":"public_key"`, `"method":"password"`, 1),
		"unsafe address":              strings.Replace(validSSHContract(), "comp001.pilot.internal", "-oProxyCommand=evil", 1),
		"unknown profile":             strings.Replace(validSSHContract(), `"authentication_profile":"pilot-key"`, `"authentication_profile":"missing"`, 1),
		"duplicate profile":           strings.Replace(validSSHContract(), `{"id":"pilot-key","method":"public_key","credential_source":"head_local_persistent","credential_reference":"pilot-key-v1"}`, `{"id":"pilot-key","method":"public_key","credential_source":"head_local_persistent","credential_reference":"pilot-key-v1"},{"id":"pilot-key","method":"password","credential_source":"head_local_persistent","credential_reference":"pilot-password-v1"}`, 1),
		"empty document":              `{}`,
		"trailing data":               validSSHContract() + ` {}`,
		"not an object":               `["comp001"]`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadSSHTargetAuthentication(writeInventory(t, "ssh-inventory.json", contents)); err == nil {
				t.Fatalf("%s was accepted", name)
			}
		})
	}
}

func TestLoadSSHTargetAuthenticationRefusesAnUnprotectedFile(t *testing.T) {
	path := writeInventory(t, "ssh-inventory.json", validSSHContract())
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSSHTargetAuthentication(path); err == nil {
		t.Fatal("a world-writable inventory was accepted")
	}
	if _, err := LoadSSHTargetAuthentication("ssh-inventory.json"); err == nil {
		t.Fatal("a relative path was accepted")
	}
}
