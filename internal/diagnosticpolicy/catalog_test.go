package diagnosticpolicy

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/commandpack"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/hostroles"
)

func TestVerifiedCatalogBindsDefinitionArgumentsAndInventory(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	executable := sha256.Sum256([]byte("synthetic executable"))
	pack := commandpack.Pack{
		SchemaVersion: 1, ID: "base", Version: "2.0.0", Issuer: "security", IssuedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour),
		MinimumRunner: "1.0.0", MaximumRunner: "1.9.0",
		Reviews: []commandpack.Review{{ReviewerID: "alice", ReviewedAt: now.Add(-2 * time.Hour), Approved: true}, {ReviewerID: "bob", ReviewedAt: now.Add(-2 * time.Hour), Approved: true}},
		Definitions: []commandpack.Definition{{
			ID: "gpu-query", Version: "1.3.0", Owner: "platform", Purpose: "Read GPU state", SupportedCapabilities: []string{"gpu"}, Risk: commandpack.RiskLow,
			ExecutablePath: "/usr/bin/nvidia-smi", ExecutableSHA256: hex.EncodeToString(executable[:]), Arguments: []commandpack.ArgumentToken{{Literal: "--query-gpu"}, {Parameter: "fields"}},
			Parameters: []commandpack.Parameter{{Name: "fields", Type: commandpack.ParameterString, Required: true, Enum: []string{"temperature.gpu"}, MaxLength: 32}},
			Targets:    commandpack.TargetConstraints{Roles: []commandpack.TargetRole{commandpack.TargetCompute}, NamePattern: `^comp[0-9]{3}$`, MaximumCount: 2},
			Limits:     commandpack.Limits{TimeoutSeconds: 10, MaximumOutputBytes: 4096, MaximumConcurrency: 2}, OutputSchema: "nvidia-smi.v1",
		}},
	}
	release, err := commandpack.Sign(pack, "root-1", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := commandpack.NewTrustStore([]commandpack.TrustRoot{{ID: "root-1", Issuer: "security", PublicKey: publicKey, ActivatesAt: now.Add(-24 * time.Hour), RetiresAt: now.Add(24 * time.Hour)}})
	if err != nil {
		t.Fatal(err)
	}
	verified, err := trust.Verify(release, "1.2.0", now)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := NewCatalogWithStaticInventory(verified, map[domain.ClusterID]map[domain.DiagnosticTarget]commandpack.TargetRole{"cluster-a": {"comp001": commandpack.TargetCompute}})
	if err != nil {
		t.Fatal(err)
	}
	reference, err := DefinitionReference(verified, "gpu-query", "1.3.0")
	if err != nil {
		t.Fatal(err)
	}
	definition, err := policy.VerifyDiagnosticDefinition(context.Background(), "cluster-a", reference, []domain.DiagnosticTarget{"comp001"}, []domain.DiagnosticArgument{{Name: "fields", Value: "temperature.gpu"}})
	if err != nil {
		t.Fatal(err)
	}
	if definition.Reference != reference || definition.Privilege != domain.DiagnosticUnprivileged || definition.Issuer != "security" {
		t.Fatalf("verified definition = %+v", definition)
	}
	if _, err := policy.Plan("cluster-a", reference, []domain.DiagnosticTarget{"comp999"}, []domain.DiagnosticArgument{{Name: "fields", Value: "temperature.gpu"}}); err == nil {
		t.Fatal("unknown target was accepted")
	}
	bad := reference
	bad.DefinitionDigest = domain.ChecksumSHA256([]byte("forged"))
	if _, err := policy.Plan("cluster-a", bad, []domain.DiagnosticTarget{"comp001"}, []domain.DiagnosticArgument{{Name: "fields", Value: "temperature.gpu"}}); err == nil {
		t.Fatal("forged definition digest was accepted")
	}
	if _, err := policy.Plan("cluster-a", reference, []domain.DiagnosticTarget{"comp001"}, []domain.DiagnosticArgument{{Name: "fields", Value: "--format=csv;rm"}}); err == nil {
		t.Fatal("argument outside signed enum was accepted")
	}
	if _, err := policy.Plan("cluster-b", reference, []domain.DiagnosticTarget{"comp001"}, []domain.DiagnosticArgument{{Name: "fields", Value: "temperature.gpu"}}); err == nil {
		t.Fatal("cross-cluster inventory reuse was accepted")
	}
}

// The derived role resolver is the gate that decides which machines are
// reached. A host whose role has aged out must be refused a plan, and a node
// that has left Slurm must lose eligibility with no operator action.
func TestPlanRefusesHostsWithoutACurrentlyConfirmedRole(t *testing.T) {
	now := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	executable := sha256.Sum256([]byte("synthetic executable"))
	pack := commandpack.Pack{
		SchemaVersion: 1, ID: "base", Version: "2.0.0", Issuer: "security", IssuedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour),
		MinimumRunner: "1.0.0", MaximumRunner: "1.9.0",
		Reviews: []commandpack.Review{{ReviewerID: "alice", ReviewedAt: now.Add(-2 * time.Hour), Approved: true}, {ReviewerID: "bob", ReviewedAt: now.Add(-2 * time.Hour), Approved: true}},
		Definitions: []commandpack.Definition{{
			ID: "gpu-query", Version: "1.3.0", Owner: "platform", Purpose: "Read GPU state", SupportedCapabilities: []string{"gpu"}, Risk: commandpack.RiskLow,
			ExecutablePath: "/usr/bin/nvidia-smi", ExecutableSHA256: hex.EncodeToString(executable[:]), Arguments: []commandpack.ArgumentToken{{Literal: "--query-gpu"}, {Parameter: "fields"}},
			Parameters: []commandpack.Parameter{{Name: "fields", Type: commandpack.ParameterString, Required: true, Enum: []string{"temperature.gpu"}, MaxLength: 32}},
			Targets:    commandpack.TargetConstraints{Roles: []commandpack.TargetRole{commandpack.TargetCompute}, NamePattern: `^comp[0-9]{3}$`, MaximumCount: 2},
			Limits:     commandpack.Limits{TimeoutSeconds: 10, MaximumOutputBytes: 4096, MaximumConcurrency: 2}, OutputSchema: "nvidia-smi.v1",
		}},
	}
	release, err := commandpack.Sign(pack, "root-1", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := commandpack.NewTrustStore([]commandpack.TrustRoot{{ID: "root-1", Issuer: "security", PublicKey: publicKey, ActivatesAt: now.Add(-24 * time.Hour), RetiresAt: now.Add(24 * time.Hour)}})
	if err != nil {
		t.Fatal(err)
	}
	verified, err := trust.Verify(release, "1.2.0", now)
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := hostroles.NewResolver(10 * time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	derived, _, err := hostroles.Derive(hostroles.Observations{ClusterID: "cluster-a", SlurmNodes: []hostroles.SlurmNode{{Name: "comp001", State: "IDLE", Partition: "gpu", ObservedAt: now}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := resolver.Replace("cluster-a", derived); err != nil {
		t.Fatal(err)
	}
	clock := now
	policy, err := NewCatalog(verified, resolver, func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	reference, err := DefinitionReference(verified, "gpu-query", "1.3.0")
	if err != nil {
		t.Fatal(err)
	}
	arguments := []domain.DiagnosticArgument{{Name: "fields", Value: "temperature.gpu"}}
	plan, err := policy.Plan("cluster-a", reference, []domain.DiagnosticTarget{"comp001"}, arguments)
	if err != nil {
		t.Fatalf("a currently confirmed compute node must be plannable: %v", err)
	}
	if len(plan.Targets()) != 1 || plan.Targets()[0].Role != commandpack.TargetCompute {
		t.Fatalf("the derived role did not reach the plan: %+v", plan.Targets())
	}
	if _, err := policy.Plan("cluster-a", reference, []domain.DiagnosticTarget{"comp999"}, arguments); err == nil {
		t.Fatal("a host with no derived role was planned")
	}

	// Time passes and nothing reconfirms the node.
	clock = now.Add(11 * time.Minute)
	if _, err := policy.Plan("cluster-a", reference, []domain.DiagnosticTarget{"comp001"}, arguments); err == nil {
		t.Fatal("a host whose role confirmation aged out was still planned")
	}

	// A fresh derivation that no longer mentions the node removes eligibility
	// permanently, with no operator action.
	clock = now.Add(12 * time.Minute)
	empty, _, err := hostroles.Derive(hostroles.Observations{ClusterID: "cluster-a", SlurmNodes: []hostroles.SlurmNode{{Name: "comp002", State: "IDLE", Partition: "gpu", ObservedAt: clock}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := resolver.Replace("cluster-a", empty); err != nil {
		t.Fatal(err)
	}
	if _, err := policy.Plan("cluster-a", reference, []domain.DiagnosticTarget{"comp001"}, arguments); err == nil {
		t.Fatal("a node removed from Slurm was still planned")
	}
	if _, err := policy.Plan("cluster-a", reference, []domain.DiagnosticTarget{"comp002"}, arguments); err != nil {
		t.Fatalf("a node Slurm now reports must become plannable: %v", err)
	}
}
