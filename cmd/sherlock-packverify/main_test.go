package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/commandpack"
)

func TestRunVerifiesRequiredPilotDefinitions(t *testing.T) {
	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	packFile, rootsFile := writeVerifiedPack(t, now)
	var output bytes.Buffer
	err := run([]string{
		"-pack", packFile, "-trust-roots", rootsFile, "-runner-version", "1.4.0",
		"-require-definition", "gpu.ecc_counters@1.0.0", "-require-definition", "gpu.row_remap@1.1.0",
		"-require-definition", "gpu.retired_pages@1.0.0",
	}, &output, now)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"pack_id":"pilot.test"`) || !strings.Contains(output.String(), `"runner_version":"1.4.0"`) {
		t.Fatalf("metadata = %s", output.String())
	}
	if !strings.Contains(output.String(), `"id":"gpu.ecc_counters"`) || !strings.Contains(output.String(), `"sha256":"`) {
		t.Fatalf("required definition metadata = %s", output.String())
	}
	if err := run([]string{"-pack", packFile, "-trust-roots", rootsFile, "-runner-version", "1.4.0", "-require-definition", "missing@1.0.0"}, &bytes.Buffer{}, now); err == nil {
		t.Fatal("missing required definition was accepted")
	}
	if err := run([]string{"-pack", packFile, "-trust-roots", rootsFile, "-runner-version", "1.4.0", "-require-definition", "gpu.row_remap"}, &bytes.Buffer{}, now); err == nil {
		t.Fatal("unversioned required definition was accepted")
	}
	if err := run([]string{"-pack", packFile, "-trust-roots", rootsFile, "-runner-version", "1.4.0", "-require-definition", "gpu.row_remap@1.0.0"}, &bytes.Buffer{}, now); err == nil {
		t.Fatal("obsolete required definition version was accepted")
	}
	if err := run([]string{"-pack", packFile, "-trust-roots", rootsFile, "-runner-version", "1.4.0"}, &bytes.Buffer{}, now.Add(2*time.Hour)); err == nil {
		t.Fatal("expired pack was accepted")
	}
}

func writeVerifiedPack(t *testing.T, now time.Time) (string, string) {
	t.Helper()
	identities := commandpack.PilotIdentities{
		NvidiaSMI:  commandpack.ExecutableIdentity{Path: "/usr/bin/nvidia-smi", SHA256: strings.Repeat("a", 64)},
		Journalctl: commandpack.ExecutableIdentity{Path: "/usr/bin/journalctl", SHA256: strings.Repeat("b", 64)},
		Scontrol:   commandpack.ExecutableIdentity{Path: "/usr/bin/scontrol", SHA256: strings.Repeat("c", 64)},
	}
	definitions, err := commandpack.PilotDefinitions(identities)
	if err != nil {
		t.Fatal(err)
	}
	pack := commandpack.Pack{
		SchemaVersion: commandpack.SchemaVersion, ID: "pilot.test", Version: "1.0.0", Issuer: "test-issuer",
		IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), MinimumRunner: "1.0.0", MaximumRunner: "2.0.0",
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
