package commandpack

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestSignedReleaseVerificationAndPlanning(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pack := validPack()
	release, err := Sign(pack, "root.current", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeRelease(release)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeRelease(encoded)
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewTrustStore([]TrustRoot{{ID: "root.current", Issuer: pack.Issuer, PublicKey: publicKey, ActivatesAt: pack.IssuedAt.Add(-time.Hour), RetiresAt: pack.ExpiresAt.Add(time.Hour)}})
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := store.Verify(decoded, "1.4.0", pack.IssuedAt.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := catalog.Plan(Invocation{DefinitionID: "gpu.query", DefinitionVersion: "1.0.0", Arguments: []ArgumentValue{{Name: "format", String: stringPointer("csv")}, {Name: "gpu", Integer: int64Pointer(2)}}, Targets: []Target{{Name: "comp007", Role: TargetCompute}}})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"/usr/bin/nvidia-smi", "--query-gpu", "csv", "--id", "2"}
	argv := plan.Argv()
	if !slicesEqual(argv, want) {
		t.Fatalf("argv = %#v, want %#v", argv, want)
	}
	_, executableSHA256 := plan.ExecutableIdentity()
	_, _, planDigest := plan.DefinitionIdentity()
	if executableSHA256 != pack.Definitions[0].ExecutableSHA256 || !sha256Pattern.MatchString(planDigest) {
		t.Fatalf("plan did not preserve executable identity or definition digest: %#v", plan)
	}
	notBefore, validBefore := plan.Validity()
	if !notBefore.Equal(pack.IssuedAt) || !validBefore.Equal(pack.ExpiresAt) {
		t.Fatalf("plan validity = [%s, %s), want [%s, %s)", notBefore, validBefore, pack.IssuedAt, pack.ExpiresAt)
	}
	argv[0] = "/tmp/replaced"
	if plan.Argv()[0] != pack.Definitions[0].ExecutablePath {
		t.Fatal("execution plan exposed mutable argv")
	}
	if id, version := catalog.PackIdentity(); id != pack.ID || version != pack.Version {
		t.Fatalf("identity = %s@%s", id, version)
	}
	metadata := catalog.Metadata()
	if metadata.PackID != pack.ID || metadata.PackVersion != pack.Version || metadata.Issuer != pack.Issuer || !metadata.IssuedAt.Equal(pack.IssuedAt) || !metadata.ExpiresAt.Equal(pack.ExpiresAt) {
		t.Fatalf("metadata = %#v", metadata)
	}
	definition, digest, ok := catalog.Lookup("gpu.query", "1.0.0")
	if !ok || digest != planDigest {
		t.Fatalf("lookup digest = %q, %v", digest, ok)
	}
	definition.Arguments[0].Literal = "--tampered"
	*definition.Parameters[1].Minimum = 99
	second, secondDigest, ok := catalog.Lookup("gpu.query", "1.0.0")
	if !ok || second.Arguments[0].Literal == "--tampered" || *second.Parameters[1].Minimum == 99 || secondDigest != digest {
		t.Fatal("catalog lookup exposed mutable definition state")
	}
}

func TestReleaseTamperingAndUnknownRootFailClosed(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	pack := validPack()
	release, err := Sign(pack, "root.current", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	store, _ := NewTrustStore([]TrustRoot{{ID: "root.current", Issuer: pack.Issuer, PublicKey: publicKey, ActivatesAt: pack.IssuedAt.Add(-time.Hour), RetiresAt: pack.ExpiresAt.Add(time.Hour)}})
	now := pack.IssuedAt.Add(time.Minute)

	tampered := release
	tampered.Pack.Definitions = append([]Definition(nil), release.Pack.Definitions...)
	tampered.Pack.Definitions[0].ExecutablePath = "/tmp/nvidia-smi"
	if _, err := store.Verify(tampered, "1.4.0", now); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("tampered verification error = %v", err)
	}
	tamperedDigest := release
	tamperedDigest.Pack.Definitions = append([]Definition(nil), release.Pack.Definitions...)
	tamperedDigest.Pack.Definitions[0].ExecutableSHA256 = strings.Repeat("b", 64)
	if _, err := store.Verify(tamperedDigest, "1.4.0", now); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("tampered executable digest error = %v", err)
	}
	unknown := release
	unknown.TrustRootID = "root.unknown"
	if _, err := store.Verify(unknown, "1.4.0", now); !errors.Is(err, ErrUnknownRoot) {
		t.Fatalf("unknown-root error = %v", err)
	}
	badSignature := release
	badSignature.Signature = bytes.Clone(release.Signature)
	badSignature.Signature[0] ^= 0xff
	if _, err := store.Verify(badSignature, "1.4.0", now); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("signature error = %v", err)
	}
}

func TestTrustRootActivationAndRotation(t *testing.T) {
	oldPublic, oldPrivate, _ := ed25519.GenerateKey(rand.Reader)
	newPublic, newPrivate, _ := ed25519.GenerateKey(rand.Reader)
	pack := validPack()
	oldRelease, _ := Sign(pack, "root.old", oldPrivate)
	newPack := clonePack(pack)
	newPack.Version = "2.0.0"
	newPack.IssuedAt = pack.IssuedAt.Add(10 * time.Minute)
	newPack.ExpiresAt = pack.ExpiresAt.Add(10 * time.Minute)
	for index := range newPack.Reviews {
		newPack.Reviews[index].ReviewedAt = newPack.IssuedAt.Add(-time.Minute)
	}
	newRelease, _ := Sign(newPack, "root.new", newPrivate)
	activation := pack.IssuedAt.Add(5 * time.Minute)
	retirement := pack.IssuedAt.Add(20 * time.Minute)
	store, err := NewTrustStore([]TrustRoot{
		{ID: "root.old", Issuer: pack.Issuer, PublicKey: oldPublic, ActivatesAt: pack.IssuedAt.Add(-time.Hour), RetiresAt: retirement},
		{ID: "root.new", Issuer: pack.Issuer, PublicKey: newPublic, ActivatesAt: activation, RetiresAt: pack.ExpiresAt.Add(time.Hour)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Verify(newRelease, "1.4.0", activation.Add(-time.Second)); !errors.Is(err, ErrInactiveRoot) {
		t.Fatalf("pre-activation error = %v", err)
	}
	overlap := pack.IssuedAt.Add(11 * time.Minute)
	oldCatalog, err := store.Verify(oldRelease, "1.4.0", overlap)
	if err != nil {
		t.Fatalf("old root should remain valid during overlap: %v", err)
	}
	oldPlan, err := oldCatalog.Plan(validInvocation())
	if err != nil {
		t.Fatal(err)
	}
	_, oldValidBefore := oldPlan.Validity()
	if !oldValidBefore.Equal(retirement) {
		t.Fatalf("old-root plan valid before %s, want retirement %s", oldValidBefore, retirement)
	}
	if _, err := store.Verify(newRelease, "1.4.0", overlap); err != nil {
		t.Fatalf("new root should be active: %v", err)
	}
	if _, err := store.Verify(oldRelease, "1.4.0", retirement); !errors.Is(err, ErrInactiveRoot) {
		t.Fatalf("retired-root error = %v", err)
	}
}

func TestStrictCanonicalReleaseEncoding(t *testing.T) {
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	release, _ := Sign(validPack(), "root.current", privateKey)
	encoded, _ := EncodeRelease(release)
	if _, err := DecodeRelease(append(encoded, '\n')); !errors.Is(err, ErrInvalidRelease) {
		t.Fatalf("noncanonical error = %v", err)
	}
	var object map[string]any
	if err := json.Unmarshal(encoded, &object); err != nil {
		t.Fatal(err)
	}
	object["unknown"] = true
	withUnknown, _ := json.Marshal(object)
	if _, err := DecodeRelease(withUnknown); !errors.Is(err, ErrInvalidRelease) {
		t.Fatalf("unknown-field error = %v", err)
	}
}

func TestValidationAndInvocationBypassesRejected(t *testing.T) {
	pack := validPack()
	tests := []struct {
		name   string
		mutate func(*Pack)
	}{
		{"no reviewer", func(p *Pack) { p.Reviews = nil }},
		{"duplicate reviewer", func(p *Pack) { p.Reviews = append(p.Reviews, p.Reviews[0]) }},
		{"relative executable", func(p *Pack) { p.Definitions[0].ExecutablePath = "nvidia-smi" }},
		{"missing executable digest", func(p *Pack) { p.Definitions[0].ExecutableSHA256 = "" }},
		{"uppercase executable digest", func(p *Pack) { p.Definitions[0].ExecutableSHA256 = strings.Repeat("A", 64) }},
		{"optional positional parameter", func(p *Pack) { p.Definitions[0].Parameters[0].Required = false }},
		{"unknown risk", func(p *Pack) { p.Definitions[0].Risk = "UNKNOWN" }},
		{"unanchored target pattern", func(p *Pack) { p.Definitions[0].Targets.NamePattern = `comp[0-9]+` }},
		{"unordered definitions", func(p *Pack) { p.Definitions = append(p.Definitions, p.Definitions[0]) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := clonePack(pack)
			test.mutate(&candidate)
			if err := ValidatePack(candidate); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}

	catalog := newCatalog(pack, pack.IssuedAt, pack.ExpiresAt)
	base := validInvocation()
	invocations := []Invocation{
		{DefinitionID: base.DefinitionID, DefinitionVersion: base.DefinitionVersion, Arguments: []ArgumentValue{{Name: "format", String: stringPointer("csv")}, {Name: "gpu", String: stringPointer("1")}}, Targets: base.Targets},
		{DefinitionID: base.DefinitionID, DefinitionVersion: base.DefinitionVersion, Arguments: []ArgumentValue{{Name: "format", String: stringPointer("csv;id")}, {Name: "gpu", Integer: int64Pointer(1)}}, Targets: base.Targets},
		{DefinitionID: base.DefinitionID, DefinitionVersion: base.DefinitionVersion, Arguments: base.Arguments, Targets: []Target{{Name: "head001", Role: TargetHead}}},
		{DefinitionID: base.DefinitionID, DefinitionVersion: base.DefinitionVersion, Arguments: base.Arguments, Targets: []Target{{Name: "comp007", Role: TargetCompute}, {Name: "comp007", Role: TargetCompute}}},
	}
	for index, invocation := range invocations {
		if _, err := catalog.Plan(invocation); err == nil {
			t.Fatalf("bypass %d was accepted", index)
		}
	}
}

func validPack() Pack {
	now := time.Date(2026, time.August, 20, 10, 0, 0, 0, time.UTC)
	minimum, maximum := int64(0), int64(7)
	return Pack{SchemaVersion: SchemaVersion, ID: "standard.readonly", Version: "1.0.0", Issuer: "sherlock.security", IssuedAt: now, ExpiresAt: now.Add(24 * time.Hour), MinimumRunner: "1.2.0", MaximumRunner: "1.9.0",
		Reviews: []Review{{ReviewerID: "alice", ReviewedAt: now.Add(-time.Minute), Approved: true}},
		Definitions: []Definition{{ID: "gpu.query", Version: "1.0.0", Owner: "gpu-operations", Purpose: "Read bounded GPU inventory fields", SupportedCapabilities: []string{"gpu.read"}, Risk: RiskLow, ExecutablePath: "/usr/bin/nvidia-smi", ExecutableSHA256: strings.Repeat("a", 64),
			Arguments:  []ArgumentToken{{Literal: "--query-gpu"}, {Parameter: "format"}, {Literal: "--id"}, {Parameter: "gpu"}},
			Parameters: []Parameter{{Name: "format", Type: ParameterString, Required: true, Enum: []string{"csv", "json"}, MaxLength: 4}, {Name: "gpu", Type: ParameterInteger, Required: true, Minimum: &minimum, Maximum: &maximum}},
			Targets:    TargetConstraints{Roles: []TargetRole{TargetCompute}, NamePattern: `^comp[0-9]{3}$`, MaximumCount: 8}, Limits: Limits{TimeoutSeconds: 30, MaximumOutputBytes: 1 << 20, MaximumConcurrency: 4}, OutputSchema: "gpu.inventory.v1"}},
	}
}

func validInvocation() Invocation {
	return Invocation{DefinitionID: "gpu.query", DefinitionVersion: "1.0.0", Arguments: []ArgumentValue{{Name: "format", String: stringPointer("csv")}, {Name: "gpu", Integer: int64Pointer(1)}}, Targets: []Target{{Name: "comp007", Role: TargetCompute}}}
}

func clonePack(pack Pack) Pack {
	encoded, _ := json.Marshal(pack)
	var result Pack
	_ = json.Unmarshal(encoded, &result)
	return result
}
func slicesEqual(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
func stringPointer(value string) *string { return &value }
func int64Pointer(value int64) *int64    { return &value }

func FuzzDecodeReleaseFailsClosed(f *testing.F) {
	_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	release, _ := Sign(validPack(), "root.current", privateKey)
	encoded, _ := EncodeRelease(release)
	f.Add(encoded)
	f.Add([]byte(`{"schema_version":1}`))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, input []byte) {
		decoded, err := DecodeRelease(input)
		if err != nil {
			return
		}
		canonical, err := EncodeRelease(decoded)
		if err != nil {
			t.Fatalf("decoded release failed re-encoding: %v", err)
		}
		if !bytes.Equal(input, canonical) {
			t.Fatal("decoder accepted noncanonical input")
		}
	})
}
