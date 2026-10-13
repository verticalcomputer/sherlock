package diagnosticrunner

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/commandpack"
)

func testVerifiedPlan(t *testing.T, executable ExecutableIdentity, args, targetNames []string) commandpack.ExecutionPlan {
	catalog, invocation := testVerifiedCatalogAndInvocation(t, executable, args, targetNames)
	plan, err := catalog.Plan(invocation)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func testVerifiedCatalogAndInvocation(t *testing.T, executable ExecutableIdentity, args, targetNames []string) (*commandpack.Catalog, commandpack.Invocation) {
	t.Helper()
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	tokens := make([]commandpack.ArgumentToken, len(args))
	for index, argument := range args {
		tokens[index] = commandpack.ArgumentToken{Literal: argument}
	}
	pack := commandpack.Pack{
		SchemaVersion: commandpack.SchemaVersion, ID: "runner-tests", Version: "1.0.0", Issuer: "test-issuer",
		IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), MinimumRunner: "1.0.0", MaximumRunner: "2.0.0",
		Reviews: []commandpack.Review{
			{ReviewerID: "reviewer-a", ReviewedAt: now.Add(-3 * time.Minute), Approved: true},
			{ReviewerID: "reviewer-b", ReviewedAt: now.Add(-2 * time.Minute), Approved: true},
		},
		Definitions: []commandpack.Definition{{
			ID: "test-command", Version: "1.0.0", Owner: "runner-tests", Purpose: "Exercise sealed runner plans",
			SupportedCapabilities: []string{"diagnostics.read"}, Risk: commandpack.RiskLow,
			ExecutablePath: executable.Path, ExecutableSHA256: executable.SHA256, Arguments: tokens,
			Targets: commandpack.TargetConstraints{Roles: []commandpack.TargetRole{commandpack.TargetCompute}, NamePattern: `^[A-Za-z0-9._*-]+$`, MaximumCount: 16},
			Limits:  commandpack.Limits{TimeoutSeconds: 4, MaximumOutputBytes: 1024, MaximumConcurrency: 2}, OutputSchema: "test-output",
		}},
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	release, err := commandpack.Sign(pack, "test-root", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	store, err := commandpack.NewTrustStore([]commandpack.TrustRoot{{ID: "test-root", Issuer: pack.Issuer, PublicKey: publicKey, ActivatesAt: now.Add(-time.Hour), RetiresAt: now.Add(2 * time.Hour)}})
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := store.Verify(release, "1.0.0", now)
	if err != nil {
		t.Fatal(err)
	}
	targets := make([]commandpack.Target, len(targetNames))
	for index, name := range targetNames {
		targets[index] = commandpack.Target{Name: name, Role: commandpack.TargetCompute}
	}
	return catalog, commandpack.Invocation{DefinitionID: "test-command", DefinitionVersion: "1.0.0", Targets: targets}
}
