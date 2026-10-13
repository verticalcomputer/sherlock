package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/remediation"
)

func TestSignAndVerifyReleaseThroughPublicOnlyRoot(t *testing.T) {
	directory, now := fixture(t)
	output := filepath.Join(directory, "release.json")
	var signed bytes.Buffer
	if err := run(signArgs(directory, output, now), &signed); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if strings.Contains(signed.String(), "PRIVATE KEY") || strings.Contains(signed.String(), "signing-key") {
		t.Fatalf("signing output exposed key material or key identity: %s", signed.String())
	}
	var verified bytes.Buffer
	if err := run([]string{"verify", "-release", output, "-public-roots", filepath.Join(directory, "roots.json"), "-at", now.Format(time.RFC3339)}, &verified); err != nil {
		t.Fatalf("verify: %v", err)
	}
	for _, recipe := range remediation.BuiltinRecipes(now.Add(time.Hour)) {
		if !strings.Contains(verified.String(), string(recipe.ID)+"@"+recipe.Version) {
			t.Fatalf("safe coordinate missing for %s: %s", recipe.ID, verified.String())
		}
	}
}

func TestSigningRejectsIncompleteRollbackSetBeforeWriting(t *testing.T) {
	directory, now := fixture(t)
	var recipes []remediation.Recipe
	readJSON(t, filepath.Join(directory, "recipes.json"), &recipes)
	writeJSON(t, filepath.Join(directory, "recipes.json"), recipes[:1])
	output := filepath.Join(directory, "release.json")
	err := run(signArgs(directory, output, now), &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "validate complete recipe set") {
		t.Fatalf("incomplete rollback set was signed: %v", err)
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatalf("signing left an output artifact: %v", err)
	}
}

func TestVerifyRejectsTamperedReleaseAndOutputNeverOverwrites(t *testing.T) {
	directory, now := fixture(t)
	output := filepath.Join(directory, "release.json")
	if err := run(signArgs(directory, output, now), &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if err := run(signArgs(directory, output, now), &bytes.Buffer{}); err == nil {
		t.Fatal("existing release was overwritten")
	}
	var release remediation.SignedRecipeRelease
	readJSON(t, output, &release)
	release.Recipes[0].Owner = "tampered"
	writeJSON(t, output, release)
	err := run([]string{"verify", "-release", output, "-public-roots", filepath.Join(directory, "roots.json"), "-at", now.Format(time.RFC3339)}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "verify release") {
		t.Fatalf("tampered release verified: %v", err)
	}
}

func TestSigningRefusesLooseOrNonRegularPrivateKey(t *testing.T) {
	directory, now := fixture(t)
	key := filepath.Join(directory, "key.pem")
	if err := os.Chmod(key, 0o644); err != nil {
		t.Fatal(err)
	}
	err := run(signArgs(directory, filepath.Join(directory, "release.json"), now), &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "inaccessible") {
		t.Fatalf("group-readable key was accepted: %v", err)
	}
}

func TestStrictJSONRejectsDuplicateFieldsAndOversizeDocuments(t *testing.T) {
	directory := t.TempDir()
	duplicate := filepath.Join(directory, "duplicate.json")
	if err := os.WriteFile(duplicate, []byte(`{"ID":"one","ID":"two"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var root remediation.RecipeTrustRoot
	if err := readStrictJSON(duplicate, &root); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate JSON field was accepted: %v", err)
	}
	over := filepath.Join(directory, "over.json")
	if err := os.WriteFile(over, bytes.Repeat([]byte("x"), maxJSONBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := readStrictJSON(over, &root); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversize JSON was accepted: %v", err)
	}
}

func fixture(t *testing.T) (string, time.Time) {
	t.Helper()
	directory := t.TempDir()
	now := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "key.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	recipes := remediation.BuiltinRecipes(now.Add(time.Hour))
	writeJSON(t, filepath.Join(directory, "recipes.json"), recipes)
	roots := []remediation.RecipeTrustRoot{{
		ID: "release-root", Issuer: "sherlock.security", PublicKey: public,
		ActivatesAt: now.Add(-time.Hour), RetiresAt: now.Add(30 * time.Minute),
	}}
	writeJSON(t, filepath.Join(directory, "roots.json"), roots)
	return directory, now
}

func signArgs(directory, output string, now time.Time) []string {
	return []string{"sign", "-recipes", filepath.Join(directory, "recipes.json"), "-private-key", filepath.Join(directory, "key.pem"), "-public-roots", filepath.Join(directory, "roots.json"), "-trust-root-id", "release-root", "-out", output, "-at", now.Format(time.RFC3339)}
}

func writeJSON(t *testing.T, path string, value any) {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
}

func readJSON(t *testing.T, path string, value any) {
	t.Helper()
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(payload, value); err != nil {
		t.Fatal(err)
	}
}
