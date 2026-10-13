package commandpack

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func loaderPack(t *testing.T) Pack {
	t.Helper()
	issued := time.Date(2026, 8, 22, 9, 0, 0, 0, time.UTC)
	return Pack{
		SchemaVersion: SchemaVersion, ID: "standard.readonly", Version: "1.1.0", Issuer: "sherlock.security",
		IssuedAt: issued, ExpiresAt: issued.Add(24 * time.Hour), MinimumRunner: "1.2.0", MaximumRunner: "1.9.0",
		Reviews: []Review{
			{ReviewerID: "alice", ReviewedAt: issued.Add(-2 * time.Minute), Approved: true},
			{ReviewerID: "bob", ReviewedAt: issued.Add(-time.Minute), Approved: true},
		},
		Definitions: []Definition{{
			ID: "gpu.inventory", Version: "1.0.0", Owner: "gpu-operations", Purpose: "Read bounded GPU identity",
			SupportedCapabilities: []string{"gpu.read"}, Risk: RiskLow,
			ExecutablePath: "/usr/bin/nvidia-smi", ExecutableSHA256: strings.Repeat("a", 64),
			Arguments:    []ArgumentToken{{Literal: "--query-gpu=index"}, {Literal: "--format=csv,noheader"}},
			Targets:      TargetConstraints{Roles: []TargetRole{TargetCompute}, NamePattern: `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`, MaximumCount: 8},
			Limits:       Limits{TimeoutSeconds: 30, MaximumOutputBytes: 4 << 20, MaximumConcurrency: 8},
			OutputSchema: "nvidia.inventory.v1",
		}},
	}
}

// writeLoaderFiles produces the two documents a verifying process is given, and
// returns their paths plus the time at which they verify.
func writeLoaderFiles(t *testing.T, pack Pack) (packFile, rootsFile string, validAt time.Time) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	release, err := Sign(pack, "root.current", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeRelease(release)
	if err != nil {
		t.Fatal(err)
	}
	roots := []trustRootDocument{{
		ID: "root.current", Issuer: pack.Issuer, PublicKey: publicKey,
		ActivatesAt: pack.IssuedAt.Add(-time.Hour), RetiresAt: pack.ExpiresAt.Add(time.Hour),
	}}
	rootBytes, err := json.Marshal(roots)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	packFile = filepath.Join(directory, "pack.json")
	rootsFile = filepath.Join(directory, "trust-roots.json")
	writeProtected(t, packFile, encoded)
	writeProtected(t, rootsFile, rootBytes)
	return packFile, rootsFile, pack.IssuedAt.Add(time.Minute)
}

func writeProtected(t *testing.T, path string, payload []byte) {
	t.Helper()
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLoadVerifiedCatalogReturnsTheDefinitionsTheSignatureJustifies(t *testing.T) {
	packFile, rootsFile, validAt := writeLoaderFiles(t, loaderPack(t))
	catalog, err := LoadVerifiedCatalog(packFile, rootsFile, "1.4.0", validAt)
	if err != nil {
		t.Fatalf("a correctly signed pack did not load: %v", err)
	}
	id, version := catalog.PackIdentity()
	if id != "standard.readonly" || version != "1.1.0" {
		t.Fatalf("catalog identity is wrong: %q %q", id, version)
	}
	if _, _, found := catalog.Lookup("gpu.inventory", "1.0.0"); !found {
		t.Fatal("the reviewed definition is missing from the verified catalog")
	}
}

// A pack whose bytes were changed after signing must produce no catalog at all.
// Partial acceptance is what the signature exists to prevent.
func TestLoadVerifiedCatalogRefusesATamperedPack(t *testing.T) {
	pack := loaderPack(t)
	packFile, rootsFile, validAt := writeLoaderFiles(t, pack)
	payload, err := os.ReadFile(packFile)
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(payload), "--query-gpu=index", "--gpu-reset=0000", 1)
	if tampered == string(payload) {
		t.Fatal("the test did not modify the pack")
	}
	writeProtected(t, packFile, []byte(tampered))
	if _, err := LoadVerifiedCatalog(packFile, rootsFile, "1.4.0", validAt); err == nil {
		t.Fatal("a tampered pack produced a catalog")
	}
}

func TestLoadVerifiedCatalogRefusesAnIncompatibleRunner(t *testing.T) {
	packFile, rootsFile, validAt := writeLoaderFiles(t, loaderPack(t))
	_, err := LoadVerifiedCatalog(packFile, rootsFile, "2.0.0", validAt)
	if !errors.Is(err, ErrIncompatible) {
		t.Fatalf("expected an incompatible-runner refusal, got %v", err)
	}
}

func TestLoadVerifiedCatalogRefusesAnExpiredRelease(t *testing.T) {
	pack := loaderPack(t)
	packFile, rootsFile, _ := writeLoaderFiles(t, pack)
	if _, err := LoadVerifiedCatalog(packFile, rootsFile, "1.4.0", pack.ExpiresAt.Add(time.Minute)); err == nil {
		t.Fatal("an expired release produced a catalog")
	}
}

// A pack an unprivileged user can rewrite, or a path that resolves elsewhere,
// is a command-injection primitive. These properties are checked before the
// signature, so a hostile file is never even parsed.
func TestReadProtectedFileRefusesUnsafePaths(t *testing.T) {
	directory := t.TempDir()
	regular := filepath.Join(directory, "document.json")
	writeProtected(t, regular, []byte(`{}`))

	if _, err := ReadProtectedFile("relative/document.json", 1<<20); err == nil {
		t.Fatal("a relative path was accepted")
	}
	if _, err := ReadProtectedFile(directory+"/./document.json", 1<<20); err == nil {
		t.Fatal("an unclean path was accepted")
	}
	link := filepath.Join(directory, "link.json")
	if err := os.Symlink(regular, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadProtectedFile(link, 1<<20); err == nil {
		t.Fatal("a symlinked path was accepted")
	}
	writable := filepath.Join(directory, "writable.json")
	writeProtected(t, writable, []byte(`{}`))
	if err := os.Chmod(writable, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadProtectedFile(writable, 1<<20); err == nil {
		t.Fatal("a group- and world-writable file was accepted")
	}
	if _, err := ReadProtectedFile(regular, 1); err == nil {
		t.Fatal("a file larger than the bound was accepted")
	}
	empty := filepath.Join(directory, "empty.json")
	writeProtected(t, empty, nil)
	if _, err := ReadProtectedFile(empty, 1<<20); err == nil {
		t.Fatal("an empty file was accepted")
	}
}

func TestLoadTargetRolesReadsAndScreensTheInventory(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "inventory.json")
	writeProtected(t, path, []byte(`{"pilot-cluster":{"head01":"HEAD","comp001":"COMPUTE"}}`))
	inventory, err := LoadTargetRoles(path)
	if err != nil {
		t.Fatalf("a valid inventory did not load: %v", err)
	}
	if inventory["pilot-cluster"]["comp001"] != TargetCompute || inventory["pilot-cluster"]["head01"] != TargetHead {
		t.Fatalf("roles were not read: %v", inventory)
	}

	unknownRole := filepath.Join(directory, "unknown-role.json")
	writeProtected(t, unknownRole, []byte(`{"pilot-cluster":{"comp001":"STORAGE"}}`))
	if _, err := LoadTargetRoles(unknownRole); err == nil {
		t.Fatal("an unknown target role was accepted")
	}

	trailing := filepath.Join(directory, "trailing.json")
	writeProtected(t, trailing, []byte(`{"pilot-cluster":{"comp001":"COMPUTE"}} {"other":{}}`))
	if _, err := LoadTargetRoles(trailing); err == nil {
		t.Fatal("a document with trailing data was accepted")
	}

	emptyCluster := filepath.Join(directory, "empty-cluster.json")
	writeProtected(t, emptyCluster, []byte(`{"pilot-cluster":{}}`))
	if _, err := LoadTargetRoles(emptyCluster); err == nil {
		t.Fatal("a cluster with no targets was accepted")
	}
}
