package scripts_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/commandpack"
	"golang.org/x/crypto/ssh"
)

func TestM12BundleBuildsVerifiedLinuxRelease(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("pilot scripts require a POSIX shell")
	}
	root := repositoryRoot(t)
	packFile, rootsFile := writeVerifiedPack(t)
	publicKey, knownHosts := writeSSHFixtures(t)
	output := filepath.Join(t.TempDir(), "bundle")

	command := exec.Command("sh", filepath.Join(root, "scripts/m12-pilot-build-bundle.sh"),
		"--out", output,
		"--pack", packFile,
		"--trust-roots", rootsFile,
		"--known-hosts", knownHosts,
		"--claimant-public-key", publicKey,
	)
	command.Dir = root
	if result, err := command.CombinedOutput(); err != nil {
		t.Fatalf("bundle build failed: %v\n%s", err, result)
	}

	runner := filepath.Join(output, "compute/usr/local/bin/sherlock-runner")
	binary, err := os.ReadFile(runner)
	if err != nil {
		t.Fatal(err)
	}
	if len(binary) < 4 || string(binary[:4]) != "\x7fELF" {
		t.Fatal("bundle runner is not an ELF binary")
	}
	authorized, err := os.ReadFile(filepath.Join(output, "compute/etc/ssh/authorized_keys/sherlock-runner"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(authorized), `restrict,command="/usr/local/libexec/sherlock-runner-force-command" ssh-ed25519 `) {
		t.Fatalf("unexpected authorized key policy: %s", authorized)
	}
	for _, relative := range []string{
		"head/etc/sherlock/diagnostics/target-roles.json",
		"head/etc/sherlock/diagnostics/ssh-target-auth.v1.json",
		"head/etc/sherlock/diagnostics/known_hosts",
		"compute/etc/ssh/sshd_config.d/90-sherlock-runner.conf",
		"compute/usr/local/libexec/sherlock-runner-force-command",
		"PACK_METADATA.json",
		"SHA256SUMS",
	} {
		if _, err := os.Stat(filepath.Join(output, relative)); err != nil {
			t.Errorf("bundle is missing %s: %v", relative, err)
		}
	}
}

func TestM12BundleRejectsAnUnscopedKnownHostsFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("pilot scripts require a POSIX shell")
	}
	root := repositoryRoot(t)
	packFile, rootsFile := writeVerifiedPack(t)
	publicKey, knownHosts := writeSSHFixtures(t)
	extraKey, err := os.ReadFile(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(knownHosts, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(append([]byte("unrelated.example "), extraKey...)); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "bundle")
	command := exec.Command("sh", filepath.Join(root, "scripts/m12-pilot-build-bundle.sh"),
		"--out", output,
		"--pack", packFile,
		"--trust-roots", rootsFile,
		"--known-hosts", knownHosts,
		"--claimant-public-key", publicKey,
	)
	command.Dir = root
	if result, err := command.CombinedOutput(); err == nil || !strings.Contains(string(result), "exactly one target entry") {
		t.Fatalf("unscoped known-hosts result: err=%v output=%s", err, result)
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatal("failed validation left an output directory")
	}
}

func TestM12PreflightIsDryRunUnlessExplicitlyEnabled(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("pilot scripts require a POSIX shell")
	}
	root := repositoryRoot(t)
	directory := t.TempDir()
	invocation := filepath.Join(directory, "ssh-invocation")
	standardInput := filepath.Join(directory, "ssh-input")
	fakeSSH := filepath.Join(directory, "ssh")
	contents := "#!/bin/sh\nprintf '%s\\n' \"$*\" >\"$M12_TEST_INVOCATION\"\ncat >\"$M12_TEST_STDIN\"\n"
	if err := os.WriteFile(fakeSSH, []byte(contents), 0o700); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(root, "scripts/m12-pilot-preflight.sh")
	environment := append(os.Environ(), "PATH="+directory+":"+os.Getenv("PATH"), "M12_TEST_INVOCATION="+invocation, "M12_TEST_STDIN="+standardInput)

	dryRun := exec.Command("sh", script)
	dryRun.Env = environment
	result, err := dryRun.CombinedOutput()
	if err != nil {
		t.Fatalf("dry run failed: %v\n%s", err, result)
	}
	if !strings.Contains(string(result), "authorization required") {
		t.Fatalf("dry-run boundary not reported: %s", result)
	}
	if _, err := os.Stat(invocation); !os.IsNotExist(err) {
		t.Fatal("dry run invoked ssh")
	}

	execute := exec.Command("sh", script, "--execute-read-only")
	execute.Env = environment
	if result, err := execute.CombinedOutput(); err != nil {
		t.Fatalf("mocked execution failed: %v\n%s", err, result)
	}
	arguments, err := os.ReadFile(invocation)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(arguments), "synthetic-head-gateway sh -s") {
		t.Fatalf("unexpected ssh route: %s", arguments)
	}
	remoteScript, err := os.ReadFile(standardInput)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"fixture_user_1@192.0.2.250", "StrictHostKeyChecking=yes", "/usr/bin/nvidia-smi"} {
		if !strings.Contains(string(remoteScript), required) {
			t.Errorf("remote preflight is missing %q", required)
		}
	}
	for _, forbidden := range []string{"sudo ", "nvidia-smi --", "PasswordAuthentication=yes"} {
		if strings.Contains(string(remoteScript), forbidden) {
			t.Errorf("remote preflight contains forbidden operation %q", forbidden)
		}
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	directory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Dir(directory)
}

func writeSSHFixtures(t *testing.T) (string, string) {
	t.Helper()
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPublic, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	publicKey := filepath.Join(directory, "claimant.pub")
	knownHosts := filepath.Join(directory, "known_hosts")
	encoded := ssh.MarshalAuthorizedKey(sshPublic)
	if err := os.WriteFile(publicKey, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(knownHosts, append([]byte("192.0.2.250 "), encoded...), 0o600); err != nil {
		t.Fatal(err)
	}
	return publicKey, knownHosts
}

func writeVerifiedPack(t *testing.T) (string, string) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	definitions, err := commandpack.PilotDefinitions(commandpack.PilotIdentities{
		NvidiaSMI:  commandpack.ExecutableIdentity{Path: "/usr/bin/nvidia-smi", SHA256: strings.Repeat("a", 64)},
		Journalctl: commandpack.ExecutableIdentity{Path: "/usr/bin/journalctl", SHA256: strings.Repeat("b", 64)},
		Scontrol:   commandpack.ExecutableIdentity{Path: "/usr/bin/scontrol", SHA256: strings.Repeat("c", 64)},
	})
	if err != nil {
		t.Fatal(err)
	}
	pack := commandpack.Pack{
		SchemaVersion: commandpack.SchemaVersion,
		ID:            "pilot.test",
		Version:       "1.0.0",
		Issuer:        "test-issuer",
		IssuedAt:      now.Add(-time.Minute),
		ExpiresAt:     now.Add(time.Hour),
		MinimumRunner: "1.0.0",
		MaximumRunner: "2.0.0",
		Reviews: []commandpack.Review{
			{ReviewerID: "alice", ReviewedAt: now.Add(-3 * time.Minute), Approved: true},
			{ReviewerID: "bob", ReviewedAt: now.Add(-2 * time.Minute), Approved: true},
		},
		Definitions: definitions,
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	release, err := commandpack.Sign(pack, "test-root", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	encodedPack, err := commandpack.EncodeRelease(release)
	if err != nil {
		t.Fatal(err)
	}
	encodedRoots, err := json.Marshal([]struct {
		ID          string    `json:"id"`
		Issuer      string    `json:"issuer"`
		PublicKey   []byte    `json:"public_key"`
		ActivatesAt time.Time `json:"activates_at"`
		RetiresAt   time.Time `json:"retires_at"`
	}{{"test-root", "test-issuer", publicKey, now.Add(-time.Hour), now.Add(2 * time.Hour)}})
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	packFile := filepath.Join(directory, "pack.json")
	rootsFile := filepath.Join(directory, "trust-roots.json")
	if err := os.WriteFile(packFile, encodedPack, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rootsFile, encodedRoots, 0o600); err != nil {
		t.Fatal(err)
	}
	return packFile, rootsFile
}
