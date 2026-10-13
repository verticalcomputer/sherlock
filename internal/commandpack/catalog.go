package commandpack

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"time"
)

type Catalog struct {
	metadata       CatalogMetadata
	definitions    map[string]catalogDefinition
	validNotBefore time.Time
	validBefore    time.Time
}

type catalogDefinition struct {
	definition Definition
	digest     string
}

func newCatalog(pack Pack, validNotBefore, validBefore time.Time) *Catalog {
	definitions := make(map[string]catalogDefinition, len(pack.Definitions))
	for _, definition := range pack.Definitions {
		cloned := cloneDefinition(definition)
		definitions[definition.ID+"@"+definition.Version] = catalogDefinition{definition: cloned, digest: definitionDigest(cloned)}
	}
	return &Catalog{
		metadata:       CatalogMetadata{PackID: pack.ID, PackVersion: pack.Version, Issuer: pack.Issuer, IssuedAt: pack.IssuedAt, ExpiresAt: pack.ExpiresAt},
		definitions:    definitions,
		validNotBefore: validNotBefore,
		validBefore:    validBefore,
	}
}

func (catalog *Catalog) PackIdentity() (string, string) {
	if catalog == nil {
		return "", ""
	}
	return catalog.metadata.PackID, catalog.metadata.PackVersion
}

func (catalog *Catalog) Metadata() CatalogMetadata {
	if catalog == nil {
		return CatalogMetadata{}
	}
	return catalog.metadata
}

// Lookup returns a defensive copy and its deterministic lowercase SHA-256
// digest. The digest covers the canonical definition bytes signed in the pack.
func (catalog *Catalog) Lookup(id, version string) (Definition, string, bool) {
	if catalog == nil {
		return Definition{}, "", false
	}
	entry, exists := catalog.definitions[id+"@"+version]
	if !exists {
		return Definition{}, "", false
	}
	return cloneDefinition(entry.definition), entry.digest, true
}

func (catalog *Catalog) Plan(invocation Invocation) (ExecutionPlan, error) {
	if catalog == nil {
		return ExecutionPlan{}, fmt.Errorf("command catalog is unavailable")
	}
	entry, exists := catalog.definitions[invocation.DefinitionID+"@"+invocation.DefinitionVersion]
	if !exists {
		return ExecutionPlan{}, fmt.Errorf("command definition is not present in the verified catalog")
	}
	definition := entry.definition
	if len(invocation.Arguments) > len(definition.Parameters) {
		return ExecutionPlan{}, fmt.Errorf("invocation contains unknown arguments")
	}
	values := make(map[string]string, len(definition.Parameters))
	previous := ""
	for _, argument := range invocation.Arguments {
		if !validID(argument.Name) || argument.Name <= previous {
			return ExecutionPlan{}, fmt.Errorf("arguments must be uniquely and canonically ordered")
		}
		previous = argument.Name
		index := slices.IndexFunc(definition.Parameters, func(parameter Parameter) bool { return parameter.Name == argument.Name })
		if index < 0 {
			return ExecutionPlan{}, fmt.Errorf("unknown argument %q", argument.Name)
		}
		converted, err := validateValue(definition.Parameters[index], argument)
		if err != nil {
			return ExecutionPlan{}, fmt.Errorf("argument %q: %w", argument.Name, err)
		}
		values[argument.Name] = converted
	}
	for _, parameter := range definition.Parameters {
		if _, exists := values[parameter.Name]; parameter.Required && !exists {
			return ExecutionPlan{}, fmt.Errorf("required argument %q is missing", parameter.Name)
		}
	}
	if len(invocation.Targets) < 1 || len(invocation.Targets) > definition.Targets.MaximumCount {
		return ExecutionPlan{}, fmt.Errorf("target count exceeds definition policy")
	}
	namePattern := regexp.MustCompile(definition.Targets.NamePattern)
	seen := make(map[string]struct{}, len(invocation.Targets))
	targets := slices.Clone(invocation.Targets)
	for _, target := range targets {
		if !namePattern.MatchString(target.Name) || !slices.Contains(definition.Targets.Roles, target.Role) {
			return ExecutionPlan{}, fmt.Errorf("target is outside definition policy")
		}
		if _, duplicate := seen[target.Name]; duplicate {
			return ExecutionPlan{}, fmt.Errorf("target set contains a duplicate")
		}
		seen[target.Name] = struct{}{}
	}
	argv := make([]string, 0, len(definition.Arguments)+1)
	argv = append(argv, definition.ExecutablePath)
	for _, token := range definition.Arguments {
		if token.Parameter != "" {
			if value, ok := values[token.Parameter]; ok {
				argv = append(argv, value)
			}
		} else {
			argv = append(argv, token.Literal)
		}
	}
	return ExecutionPlan{definitionID: definition.ID, definitionVersion: definition.Version, definitionDigest: entry.digest, executablePath: definition.ExecutablePath, executableSHA256: definition.ExecutableSHA256, argv: argv, targets: targets, risk: definition.Risk, requiresPrivilege: definition.RequiresPrivilege, sudoRule: definition.SudoRule, limits: definition.Limits, validNotBefore: catalog.validNotBefore, validBefore: catalog.validBefore}, nil
}

func (plan ExecutionPlan) DefinitionIdentity() (id, version, digest string) {
	return plan.definitionID, plan.definitionVersion, plan.definitionDigest
}

func (plan ExecutionPlan) ExecutableIdentity() (path, sha256 string) {
	return plan.executablePath, plan.executableSHA256
}

func (plan ExecutionPlan) Argv() []string { return slices.Clone(plan.argv) }

func (plan ExecutionPlan) Targets() []Target { return slices.Clone(plan.targets) }

func (plan ExecutionPlan) Risk() Risk { return plan.risk }

func (plan ExecutionPlan) RequiresPrivilege() bool { return plan.requiresPrivilege }

func (plan ExecutionPlan) SudoRule() string { return plan.sudoRule }

func (plan ExecutionPlan) Limits() Limits { return plan.limits }

// Validity returns an inclusive not-before and exclusive not-after bound. The
// latter is the earlier of pack expiry and trust-root retirement.
func (plan ExecutionPlan) Validity() (notBefore, before time.Time) {
	return plan.validNotBefore, plan.validBefore
}

func definitionDigest(definition Definition) string {
	encoded, err := json.Marshal(definition)
	if err != nil {
		panic("validated command definition cannot fail JSON encoding")
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func validateValue(parameter Parameter, value ArgumentValue) (string, error) {
	setValues := 0
	if value.String != nil {
		setValues++
	}
	if value.Integer != nil {
		setValues++
	}
	if value.Boolean != nil {
		setValues++
	}
	if setValues != 1 {
		return "", fmt.Errorf("must contain exactly one typed value")
	}
	var converted string
	switch parameter.Type {
	case ParameterString:
		if value.String == nil || len(*value.String) > parameter.MaxLength || len(*value.String) == 0 {
			return "", fmt.Errorf("must be a bounded non-empty string")
		}
		text := *value.String
		converted = text
		if len(parameter.Enum) > 0 && !slices.Contains(parameter.Enum, text) {
			return "", fmt.Errorf("is outside the allowed enum")
		}
		if parameter.Pattern != "" && !regexp.MustCompile(parameter.Pattern).MatchString(text) {
			return "", fmt.Errorf("does not match the allowed pattern")
		}
	case ParameterInteger:
		if value.Integer == nil {
			return "", fmt.Errorf("must be an int64")
		}
		integer := *value.Integer
		if parameter.Minimum != nil && integer < *parameter.Minimum || parameter.Maximum != nil && integer > *parameter.Maximum {
			return "", fmt.Errorf("is outside the allowed range")
		}
		converted = strconv.FormatInt(integer, 10)
	case ParameterBoolean:
		if value.Boolean == nil {
			return "", fmt.Errorf("must be a boolean")
		}
		boolean := *value.Boolean
		converted = strconv.FormatBool(boolean)
	}
	return converted, nil
}

func cloneDefinition(value Definition) Definition {
	value.Arguments = slices.Clone(value.Arguments)
	value.Parameters = slices.Clone(value.Parameters)
	for i := range value.Parameters {
		value.Parameters[i].Enum = slices.Clone(value.Parameters[i].Enum)
		value.Parameters[i].Minimum = cloneInt64(value.Parameters[i].Minimum)
		value.Parameters[i].Maximum = cloneInt64(value.Parameters[i].Maximum)
	}
	value.Targets.Roles = slices.Clone(value.Targets.Roles)
	value.SupportedCapabilities = slices.Clone(value.SupportedCapabilities)
	return value
}

func cloneInt64(value *int64) *int64 {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}
