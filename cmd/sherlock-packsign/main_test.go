package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/commandpack"
)

func signArguments(directory string, extra ...string) []string {
	return append([]string{
		"-out", directory,
		"-nvidia-smi-sha256", strings.Repeat("a", 64),
		"-journalctl-sha256", strings.Repeat("b", 64),
		"-scontrol-sha256", strings.Repeat("c", 64),
		"-reviewer", "alice",
	}, extra...)
}

// The only thing that matters about the output is that the processes which
// verify it accept it, so the test loads it the way they do.
func TestSignedPackVerifiesThroughTheLoaderEveryProcessUses(t *testing.T) {
	directory := t.TempDir()
	if err := run(signArguments(directory), &bytes.Buffer{}); err != nil {
		t.Fatalf("signing failed: %v", err)
	}
	catalog, err := commandpack.LoadVerifiedCatalog(filepath.Join(directory, "pack.json"), filepath.Join(directory, "trust-roots.json"), "1.4.0", time.Now().UTC())
	if err != nil {
		t.Fatalf("the signed pack did not verify: %v", err)
	}
	for definition, version := range map[string]string{"gpu.ecc_counters": "1.0.0", "gpu.row_remap": "1.1.0", "gpu.retired_pages": "1.0.0"} {
		if _, _, found := catalog.Lookup(definition, version); !found {
			t.Fatalf("%s@%s is missing from the signed pack", definition, version)
		}
	}
	// Every consumer refuses a group- or world-writable pack, so writing one
	// loosely here would only fail later, further from the cause.
	for _, name := range []string{"pack.json", "trust-roots.json", "signing-key.pem"} {
		info, err := os.Stat(filepath.Join(directory, name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s is mode %o", name, info.Mode().Perm())
		}
	}
}

// Re-signing with the same root must keep the same trust anchor, or every
// target needs new trust-root material for a routine digest change.
func TestReusingASigningKeyKeepsTheTrustAnchor(t *testing.T) {
	first := t.TempDir()
	if err := run(signArguments(first), &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(filepath.Join(first, "trust-roots.json"))
	if err != nil {
		t.Fatal(err)
	}
	second := t.TempDir()
	if err := run(signArguments(second, "-signing-key", filepath.Join(first, "signing-key.pem")), &bytes.Buffer{}); err != nil {
		t.Fatalf("re-signing failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(second, "signing-key.pem")); !os.IsNotExist(err) {
		t.Fatal("re-signing wrote a second copy of the signing key")
	}
	reused, err := os.ReadFile(filepath.Join(second, "trust-roots.json"))
	if err != nil {
		t.Fatal(err)
	}
	// The validity window moves with the release; the public key must not.
	if !bytes.Contains(reused, publicKeyField(t, original)) {
		t.Fatal("re-signing changed the trust root's public key")
	}
}

func publicKeyField(t *testing.T, document []byte) []byte {
	t.Helper()
	marker := []byte(`"public_key":"`)
	start := bytes.Index(document, marker)
	if start < 0 {
		t.Fatal("the trust root carries no public key")
	}
	start += len(marker)
	end := bytes.IndexByte(document[start:], '"')
	if end < 0 {
		t.Fatal("the trust root public key is unterminated")
	}
	return document[start : start+end]
}

// A digest is either declared or read from a binary that is actually here.
// Guessing one would sign a pack that pins nothing.
func TestSigningRefusesADigestItCannotEstablish(t *testing.T) {
	directory := t.TempDir()
	err := run([]string{
		"-out", directory,
		"-nvidia-smi", filepath.Join(directory, "absent-nvidia-smi"),
		"-journalctl-sha256", strings.Repeat("b", 64),
		"-scontrol-sha256", strings.Repeat("c", 64),
		"-reviewer", "alice",
	}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "nvidia-smi") {
		t.Fatalf("an unestablished digest was accepted: %v", err)
	}
}

// At least one approving reviewer is a pack invariant, not a convention.
func TestSigningRefusesAnUnreviewedPack(t *testing.T) {
	directory := t.TempDir()
	if err := run(signArguments(directory)[:len(signArguments(directory))-2], &bytes.Buffer{}); err == nil {
		t.Fatal("a pack with no reviewer was signed")
	}
	if err := run([]string{"-nvidia-smi-sha256", strings.Repeat("a", 64)}, &bytes.Buffer{}); err == nil {
		t.Fatal("signing without an output directory was accepted")
	}
}
