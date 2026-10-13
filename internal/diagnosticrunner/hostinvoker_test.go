package diagnosticrunner

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/commandpack"
)

const echoExecutable = "/bin/echo"

// localEchoCatalog signs a pack around a real executable on this machine, so
// local execution is exercised end to end rather than mocked. The pack is
// issued around the current time because the runner refuses a definition that
// is not active when it runs.
func localEchoCatalog(t *testing.T) *commandpack.Catalog {
	t.Helper()
	binary, err := os.ReadFile(echoExecutable)
	if err != nil {
		t.Skipf("this machine has no readable %s to execute", echoExecutable)
	}
	digest := sha256.Sum256(binary)
	now := time.Now().UTC().Truncate(time.Second)
	pack := commandpack.Pack{
		SchemaVersion: commandpack.SchemaVersion, ID: "test.local", Version: "1.0.0", Issuer: "sherlock.security",
		IssuedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour), MinimumRunner: "1.2.0", MaximumRunner: "1.9.0",
		Reviews: []commandpack.Review{
			{ReviewerID: "alice", ReviewedAt: now.Add(-2 * time.Hour), Approved: true},
			{ReviewerID: "bob", ReviewedAt: now.Add(-2 * time.Hour), Approved: true},
		},
		Definitions: []commandpack.Definition{{
			ID: "local.echo", Version: "1.0.0", Owner: "cluster-operations", Purpose: "Emit a fixed token for local execution tests",
			SupportedCapabilities: []string{"local.read"}, Risk: commandpack.RiskLow,
			ExecutablePath: echoExecutable, ExecutableSHA256: hex.EncodeToString(digest[:]),
			Arguments:    []commandpack.ArgumentToken{{Literal: "remapped_rows.pending: 0"}},
			Targets:      commandpack.TargetConstraints{Roles: []commandpack.TargetRole{commandpack.TargetCompute}, NamePattern: `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`, MaximumCount: 4},
			Limits:       commandpack.Limits{TimeoutSeconds: 30, MaximumOutputBytes: 1 << 20, MaximumConcurrency: 1},
			OutputSchema: "local.echo.v1",
		}},
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	release, err := commandpack.Sign(pack, "root.current", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	store, err := commandpack.NewTrustStore([]commandpack.TrustRoot{{
		ID: "root.current", Issuer: pack.Issuer, PublicKey: publicKey,
		ActivatesAt: pack.IssuedAt.Add(-time.Hour), RetiresAt: pack.ExpiresAt.Add(time.Hour),
	}})
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := store.Verify(release, "1.4.0", now)
	if err != nil {
		t.Fatal(err)
	}
	return catalog
}

func localRunner(t *testing.T) *Runner {
	t.Helper()
	runner, err := New(Config{MaxTimeout: time.Minute, MaxOutputBytes: 1 << 20, MaxInputBytes: 1 << 16, MaxTargets: 1, MaxConcurrency: 1, MaxSuppliedSecrets: 4, MaxSecretBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	return runner
}

func echoInvocation(targets ...commandpack.Target) commandpack.Invocation {
	return commandpack.Invocation{DefinitionID: "local.echo", DefinitionVersion: "1.0.0", Targets: targets}
}

func TestHostInvokerExecutesTheVerifiedArgvForItsOwnHost(t *testing.T) {
	catalog := localEchoCatalog(t)
	invoker, err := NewHostInvoker("head01")
	if err != nil {
		t.Fatal(err)
	}
	result, err := invoker.ExecuteInvocation(context.Background(), localRunner(t), catalog, "work-1-1",
		echoInvocation(commandpack.Target{Name: "head01", Role: commandpack.TargetCompute}), nil)
	if err != nil {
		t.Fatalf("local execution failed: %v", err)
	}
	if len(result.Targets) != 1 {
		t.Fatalf("expected one target result, got %d", len(result.Targets))
	}
	target := result.Targets[0]
	if !target.Started || target.ExitCode != 0 || target.ErrorCode != "" {
		t.Fatalf("the probe did not run cleanly: %+v", target)
	}
	if !strings.Contains(string(target.Stdout), "remapped_rows.pending: 0") {
		t.Fatalf("the probe output was not captured: %q", target.Stdout)
	}
	if result.DefinitionID != "local.echo" || result.DefinitionDigest == "" {
		t.Fatalf("the result lost its definition identity: %+v", result)
	}
}

// The runner labels each local execution with the requested target's name. If
// this host answered for another machine, the recorded evidence would name a
// node that was never contacted, and an investigation would cite it. Reaching
// another host is the SSH adapter's job precisely because the hop is what makes
// the label true.
func TestHostInvokerRefusesToAnswerForAnotherMachine(t *testing.T) {
	catalog := localEchoCatalog(t)
	invoker, err := NewHostInvoker("head01")
	if err != nil {
		t.Fatal(err)
	}
	runner := localRunner(t)
	foreign := echoInvocation(commandpack.Target{Name: "comp001", Role: commandpack.TargetCompute})
	if _, err := invoker.ExecuteInvocation(context.Background(), runner, catalog, "work-1-1", foreign, nil); !errors.Is(err, ErrForeignTarget) {
		t.Fatalf("expected a foreign-target refusal, got %v", err)
	}
	fanOut := echoInvocation(
		commandpack.Target{Name: "head01", Role: commandpack.TargetCompute},
		commandpack.Target{Name: "comp001", Role: commandpack.TargetCompute},
	)
	if _, err := invoker.ExecuteInvocation(context.Background(), runner, catalog, "work-1-1", fanOut, nil); !errors.Is(err, ErrForeignTarget) {
		t.Fatalf("expected a fan-out refusal, got %v", err)
	}
	if _, err := invoker.ExecuteInvocation(context.Background(), runner, catalog, "work-1-1", echoInvocation(), nil); !errors.Is(err, ErrForeignTarget) {
		t.Fatalf("expected an empty target set to be refused, got %v", err)
	}
}

func TestHostInvokerRefusesAnInvocationTheCatalogDoesNotJustify(t *testing.T) {
	catalog := localEchoCatalog(t)
	invoker, err := NewHostInvoker("head01")
	if err != nil {
		t.Fatal(err)
	}
	unknown := commandpack.Invocation{DefinitionID: "local.reset", DefinitionVersion: "1.0.0", Targets: []commandpack.Target{{Name: "head01", Role: commandpack.TargetCompute}}}
	if _, err := invoker.ExecuteInvocation(context.Background(), localRunner(t), catalog, "work-1-1", unknown, nil); err == nil {
		t.Fatal("a definition absent from the verified catalog was executed")
	}
	wrongRole := echoInvocation(commandpack.Target{Name: "head01", Role: commandpack.TargetHead})
	if _, err := invoker.ExecuteInvocation(context.Background(), localRunner(t), catalog, "work-1-1", wrongRole, nil); err == nil {
		t.Fatal("a target outside the definition's role policy was executed")
	}
}

func TestNewHostInvokerRequiresAHostName(t *testing.T) {
	if _, err := NewHostInvoker(""); err == nil {
		t.Fatal("an invoker with no host identity was constructed")
	}
}
