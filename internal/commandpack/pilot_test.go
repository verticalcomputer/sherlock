package commandpack

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestPilotDefinitionsAreValidatedExactArgv(t *testing.T) {
	definitions, err := PilotDefinitions(PilotIdentities{NvidiaSMI: ExecutableIdentity{Path: "/usr/bin/nvidia-smi", SHA256: strings.Repeat("a", 64)}, Journalctl: ExecutableIdentity{Path: "/usr/bin/journalctl", SHA256: strings.Repeat("b", 64)}, Scontrol: ExecutableIdentity{Path: "/usr/bin/scontrol", SHA256: strings.Repeat("c", 64)}})
	if err != nil {
		t.Fatal(err)
	}
	// Keyed by id@version: two versions of one definition may ship together, and
	// an ID-keyed map would silently keep only the last of them.
	byID := map[string]Definition{}
	for _, definition := range definitions {
		byID[definition.ID+"@"+definition.Version] = definition
	}
	if len(definitions) != 9 || len(byID) != 9 {
		t.Fatalf("definitions = %d unique of %d", len(byID), len(definitions))
	}
	privileged := byID["node.kernel_xid@1.0.0"]
	if !privileged.RequiresPrivilege || privileged.SudoRule == "" {
		t.Fatalf("node.kernel_xid@1.0.0 = %#v", privileged)
	}
	// The unprivileged variant reads the same journal through a group membership
	// instead of a sudo rule, which is what lets the agentless route plan it.
	unprivileged := byID["node.kernel_xid@2.0.0"]
	if unprivileged.RequiresPrivilege || unprivileged.SudoRule != "" || unprivileged.Risk == RiskPrivileged {
		t.Fatalf("node.kernel_xid@2.0.0 requires privilege: %#v", unprivileged)
	}
	if unprivileged.OutputSchema != privileged.OutputSchema || unprivileged.ExecutablePath != privileged.ExecutablePath {
		t.Fatalf("node.kernel_xid@2.0.0 changed the parsed schema or binary: %#v", unprivileged)
	}
	if len(unprivileged.Parameters) != 0 {
		t.Fatalf("node.kernel_xid@2.0.0 takes a parameter, so its argv is not pinned: %#v", unprivileged.Parameters)
	}
	// The M12 additions close the ECC gap without privilege. Exactly one
	// definition in the reviewed set may require it, and it is not one of these.
	for _, id := range []string{"gpu.ecc_counters@1.0.0", "gpu.retired_pages@1.0.0", "gpu.row_remap@1.1.0"} {
		definition, exists := byID[id]
		if !exists {
			t.Fatalf("%s is missing from the reviewed set", id)
		}
		if definition.RequiresPrivilege || definition.SudoRule != "" || definition.Risk == RiskPrivileged {
			t.Fatalf("%s requires privilege: %#v", id, definition)
		}
		if len(definition.Parameters) != 0 {
			t.Fatalf("%s takes a parameter, so its argv is not fully pinned: %#v", id, definition.Parameters)
		}
		if !slices.Equal(definition.Targets.Roles, []TargetRole{TargetCompute}) {
			t.Fatalf("%s does not target COMPUTE only: %v", id, definition.Targets.Roles)
		}
	}
	privilegedCount := 0
	for _, definition := range definitions {
		if definition.RequiresPrivilege {
			privilegedCount++
		}
		for _, token := range definition.Arguments {
			if token.Literal == "sh" || token.Literal == "-c" {
				t.Fatalf("shell token in %s", definition.ID)
			}
			// No definition may admit a wildcard argument: read-only is a property
			// of the exact argv, and nvidia-smi with a free argument also resets
			// devices, toggles ECC, and sets power limits.
			if strings.ContainsAny(token.Literal, "*?") {
				t.Fatalf("wildcard argument %q in %s", token.Literal, definition.ID)
			}
		}
		if strings.ContainsAny(definition.SudoRule, "*?") {
			t.Fatalf("wildcard sudo rule in %s: %s", definition.ID, definition.SudoRule)
		}
	}
	if privilegedCount != 1 {
		t.Fatalf("privileged definitions = %d, want exactly the one that predates M12", privilegedCount)
	}
	type summary struct {
		ID            string   `json:"id"`
		Version       string   `json:"version"`
		Arguments     []string `json:"arguments"`
		OutputSchema  string   `json:"output_schema"`
		Privileged    bool     `json:"privileged"`
		MaximumOutput int      `json:"maximum_output_bytes"`
	}
	got := make([]summary, 0, len(definitions))
	for _, definition := range definitions {
		arguments := make([]string, 0, len(definition.Arguments))
		for _, token := range definition.Arguments {
			if token.Literal != "" {
				arguments = append(arguments, token.Literal)
			} else {
				arguments = append(arguments, "{{"+token.Parameter+"}}")
			}
		}
		got = append(got, summary{ID: definition.ID, Version: definition.Version, Arguments: arguments, OutputSchema: definition.OutputSchema, Privileged: definition.RequiresPrivilege, MaximumOutput: definition.Limits.MaximumOutputBytes})
	}
	encoded, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded, '\n')
	want, err := os.ReadFile(filepath.Join("testdata", "pilot-summary.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != string(want) {
		t.Fatalf("pilot definition summary changed\ngot:\n%s\nwant:\n%s", encoded, want)
	}
}

func TestPilotDefinitionsRequirePinnedExecutableIdentities(t *testing.T) {
	_, err := PilotDefinitions(PilotIdentities{})
	if err == nil {
		t.Fatal("empty identities accepted")
	}
}

// The rules that keep a privileged argv pinned must be mechanical, because a
// reviewer cannot reliably see that a regular expression admits a leading dash
// and that a dash makes a value a flag which overrides an earlier one.
func TestPrivilegedDefinitionRefusesWildcardsAndDashCapableParameters(t *testing.T) {
	base := func() Definition {
		return Definition{
			ID: "node.kernel_probe", Version: "1.0.0", Owner: "gpu-operations", Purpose: "probe",
			SupportedCapabilities: []string{"kernel.read"}, Risk: RiskPrivileged,
			ExecutablePath: "/usr/bin/journalctl", ExecutableSHA256: strings.Repeat("b", 64),
			Arguments: []ArgumentToken{{Literal: "--dmesg"}}, RequiresPrivilege: true,
			SudoRule: "sherlock ALL=(root) NOPASSWD: /usr/bin/journalctl --dmesg",
			Targets:  TargetConstraints{Roles: []TargetRole{TargetCompute}, NamePattern: `^[A-Za-z0-9]{1,64}$`, MaximumCount: 4},
			Limits:   Limits{TimeoutSeconds: 30, MaximumOutputBytes: 1 << 20, MaximumConcurrency: 1}, OutputSchema: "kernel.probe.v1",
		}
	}
	if err := ValidateDefinition(base()); err != nil {
		t.Fatalf("the pinned baseline must validate: %v", err)
	}

	wildcard := base()
	wildcard.SudoRule = "sherlock ALL=(root) NOPASSWD: /usr/bin/journalctl *"
	if err := ValidateDefinition(wildcard); err == nil {
		t.Fatal("a wildcard sudo rule was accepted")
	}
	glob := base()
	glob.SudoRule = "sherlock ALL=(root) NOPASSWD: /usr/bin/journalctl --dmes?"
	if err := ValidateDefinition(glob); err == nil {
		t.Fatal("a single-character glob in a sudo rule was accepted")
	}

	withParameter := func(parameter Parameter) Definition {
		definition := base()
		definition.Arguments = append(definition.Arguments, ArgumentToken{Parameter: parameter.Name})
		definition.Parameters = []Parameter{parameter}
		return definition
	}
	minimum := func(value int64) *int64 { return &value }

	// A free-form pattern is refused even when it happens to exclude a dash,
	// because the validator cannot decide that and a reviewer cannot see it.
	pattern := withParameter(Parameter{Name: "unit", Type: ParameterString, Required: true, Pattern: `^[A-Za-z0-9]{1,64}$`, MaxLength: 64})
	if err := ValidateDefinition(pattern); err == nil {
		t.Fatal("a pattern-constrained string reached a privileged argv")
	}
	dashEnum := withParameter(Parameter{Name: "unit", Type: ParameterString, Required: true, Enum: []string{"--vacuum-time=1s"}, MaxLength: 64})
	if err := ValidateDefinition(dashEnum); err == nil {
		t.Fatal("an enum value that would be read as a flag was accepted")
	}
	negative := withParameter(Parameter{Name: "lines", Type: ParameterInteger, Required: true, Minimum: minimum(-1), Maximum: minimum(100)})
	if err := ValidateDefinition(negative); err == nil {
		t.Fatal("an integer that can render a leading dash was accepted")
	}
	unbounded := withParameter(Parameter{Name: "lines", Type: ParameterInteger, Required: true})
	if err := ValidateDefinition(unbounded); err == nil {
		t.Fatal("an integer with no declared minimum was accepted")
	}

	safeEnum := withParameter(Parameter{Name: "unit", Type: ParameterString, Required: true, Enum: []string{"kernel", "nvidia"}, MaxLength: 64})
	if err := ValidateDefinition(safeEnum); err != nil {
		t.Fatalf("a closed enum with no dash-leading value must be accepted: %v", err)
	}
	safeInteger := withParameter(Parameter{Name: "lines", Type: ParameterInteger, Required: true, Minimum: minimum(0), Maximum: minimum(2000)})
	if err := ValidateDefinition(safeInteger); err != nil {
		t.Fatalf("a non-negative bounded integer must be accepted: %v", err)
	}

	// The same parameter is unaffected on an unprivileged definition, whose argv
	// is not the thing a sudo rule pins. slurm.node_detail relies on this.
	unprivileged := pattern
	unprivileged.Risk, unprivileged.RequiresPrivilege, unprivileged.SudoRule = RiskLow, false, ""
	if err := ValidateDefinition(unprivileged); err != nil {
		t.Fatalf("an unprivileged definition must keep its pattern-constrained parameter: %v", err)
	}
}

// The reviewed set must survive the whole trust path, and the argv that reaches
// a host must be exactly what was signed. The pack digest changing is the point
// of a pack addition; what must not change is any argument.
func TestPilotPackSignsVerifiesAndPlansTheExactECCArgv(t *testing.T) {
	definitions, err := PilotDefinitions(PilotIdentities{NvidiaSMI: ExecutableIdentity{Path: "/usr/bin/nvidia-smi", SHA256: strings.Repeat("a", 64)}, Journalctl: ExecutableIdentity{Path: "/usr/bin/journalctl", SHA256: strings.Repeat("b", 64)}, Scontrol: ExecutableIdentity{Path: "/usr/bin/scontrol", SHA256: strings.Repeat("c", 64)}})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.August, 22, 10, 0, 0, 0, time.UTC)
	pack := Pack{SchemaVersion: SchemaVersion, ID: "standard.readonly", Version: "1.1.0", Issuer: "sherlock.security", IssuedAt: now, ExpiresAt: now.Add(24 * time.Hour), MinimumRunner: "1.2.0", MaximumRunner: "1.9.0",
		Reviews:     []Review{{ReviewerID: "alice", ReviewedAt: now.Add(-time.Minute), Approved: true}},
		Definitions: definitions}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	withECC, err := CanonicalBytes(pack)
	if err != nil {
		t.Fatalf("the reviewed set with the ECC additions must validate and encode: %v", err)
	}
	// The digest is expected to move, and it must move: a pack that added
	// reviewed definitions but hashed the same would mean they are not signed.
	withoutECC := pack
	withoutECC.Definitions = slices.DeleteFunc(slices.Clone(definitions), func(definition Definition) bool {
		return strings.HasPrefix(definition.ID, "gpu.ecc_") || strings.HasPrefix(definition.ID, "gpu.retired_") || strings.HasPrefix(definition.ID, "gpu.row_")
	})
	baseline, err := CanonicalBytes(withoutECC)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(sha256Of(withECC), sha256Of(baseline)) {
		t.Fatal("adding reviewed definitions did not change the pack digest")
	}

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
	type expectedDefinition struct {
		version string
		argv    []string
	}
	wantDefinitions := map[string]expectedDefinition{
		"gpu.ecc_counters":  {version: "1.0.0", argv: []string{"/usr/bin/nvidia-smi", "--query-gpu=index,uuid,ecc.errors.corrected.volatile.total,ecc.errors.uncorrected.volatile.total,ecc.errors.corrected.aggregate.total,ecc.errors.uncorrected.aggregate.total", "--format=csv,noheader,nounits"}},
		"gpu.retired_pages": {version: "1.0.0", argv: []string{"/usr/bin/nvidia-smi", "--query-gpu=index,uuid,retired_pages.single_bit_ecc.count,retired_pages.double_bit.count,retired_pages.pending", "--format=csv,noheader,nounits"}},
		"gpu.row_remap":     {version: "1.1.0", argv: []string{"/usr/bin/nvidia-smi", "--query-remapped-rows=remapped_rows.pending,remapped_rows.failure,remapped_rows.correctable,remapped_rows.uncorrectable", "--format=csv,noheader,nounits"}},
	}
	for id, want := range wantDefinitions {
		plan, err := catalog.Plan(Invocation{DefinitionID: id, DefinitionVersion: want.version, Targets: []Target{{Name: "comp007", Role: TargetCompute}}})
		if err != nil {
			t.Fatalf("plan %s: %v", id, err)
		}
		if !slices.Equal(plan.Argv(), want.argv) {
			t.Fatalf("%s argv = %v, want %v", id, plan.Argv(), want.argv)
		}
		if plan.RequiresPrivilege() || plan.SudoRule() != "" {
			t.Fatalf("%s planned with privilege", id)
		}
		// A COMPUTE-only definition must not be plannable against the head node.
		if _, err := catalog.Plan(Invocation{DefinitionID: id, DefinitionVersion: want.version, Targets: []Target{{Name: "comp007", Role: TargetHead}}}); err == nil {
			t.Fatalf("%s was planned against a HEAD target", id)
		}
		// No argument may be supplied: the argv is closed.
		if _, err := catalog.Plan(Invocation{DefinitionID: id, DefinitionVersion: want.version, Arguments: []ArgumentValue{{Name: "extra", String: stringPointer("--gpu-reset")}}, Targets: []Target{{Name: "comp007", Role: TargetCompute}}}); err == nil {
			t.Fatalf("%s accepted a supplied argument", id)
		}
	}
	if _, err := catalog.Plan(Invocation{DefinitionID: "gpu.row_remap", DefinitionVersion: "1.0.0", Targets: []Target{{Name: "comp007", Role: TargetCompute}}}); err == nil {
		t.Fatal("obsolete gpu.row_remap@1.0.0 remained plannable")
	}
}

func sha256Of(value []byte) []byte {
	digest := sha256.Sum256(value)
	return digest[:]
}
