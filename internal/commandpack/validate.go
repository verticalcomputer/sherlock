package commandpack

import (
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
)

var identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
var versionPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)
var sha256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

func ValidatePack(pack Pack) error {
	if pack.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported command-pack schema version %d", pack.SchemaVersion)
	}
	if !validID(pack.ID) || !validID(pack.Issuer) || !validVersion(pack.Version) {
		return fmt.Errorf("command-pack identity, issuer, or version is invalid")
	}
	if !canonicalTime(pack.IssuedAt) || !canonicalTime(pack.ExpiresAt) || !pack.ExpiresAt.After(pack.IssuedAt) {
		return fmt.Errorf("command-pack validity interval is invalid")
	}
	if !validVersion(pack.MinimumRunner) || !validVersion(pack.MaximumRunner) || compareVersion(pack.MinimumRunner, pack.MaximumRunner) > 0 {
		return fmt.Errorf("command-pack runner compatibility is invalid")
	}
	if err := validateReviews(pack.Reviews, pack.IssuedAt); err != nil {
		return err
	}
	if len(pack.Definitions) == 0 || len(pack.Definitions) > 1024 {
		return fmt.Errorf("command-pack must contain between 1 and 1024 definitions")
	}
	previous := ""
	for _, definition := range pack.Definitions {
		key := definition.ID + "@" + definition.Version
		if key <= previous {
			return fmt.Errorf("command definitions must be uniquely and canonically ordered")
		}
		previous = key
		if err := ValidateDefinition(definition); err != nil {
			return fmt.Errorf("definition %q: %w", definition.ID, err)
		}
	}
	return nil
}

func validateReviews(reviews []Review, issuedAt time.Time) error {
	if len(reviews) < 1 || len(reviews) > 32 {
		return fmt.Errorf("command-pack requires at least one review")
	}
	previous := ""
	for _, review := range reviews {
		if !validID(review.ReviewerID) || review.ReviewerID <= previous || !review.Approved || !canonicalTime(review.ReviewedAt) || review.ReviewedAt.After(issuedAt) {
			return fmt.Errorf("command-pack reviews must be approved by distinct, canonically ordered reviewers before issuance")
		}
		previous = review.ReviewerID
	}
	return nil
}

func ValidateDefinition(definition Definition) error {
	if !validID(definition.ID) || !validVersion(definition.Version) || !validText(definition.Owner, 256) || !validText(definition.Purpose, 2048) {
		return fmt.Errorf("identity, owner, purpose, or version is invalid")
	}
	if definition.Risk != RiskLow && definition.Risk != RiskModerate && definition.Risk != RiskPrivileged {
		return fmt.Errorf("risk is invalid")
	}
	if !filepath.IsAbs(definition.ExecutablePath) || filepath.Clean(definition.ExecutablePath) != definition.ExecutablePath || strings.ContainsAny(definition.ExecutablePath, "\x00\r\n") {
		return fmt.Errorf("executable path must be absolute and clean")
	}
	if !sha256Pattern.MatchString(definition.ExecutableSHA256) {
		return fmt.Errorf("executable SHA-256 must contain exactly 64 lowercase hexadecimal characters")
	}
	if definition.RequiresPrivilege != (definition.Risk == RiskPrivileged) || (definition.RequiresPrivilege && !validText(definition.SudoRule, 512)) || (!definition.RequiresPrivilege && definition.SudoRule != "") {
		return fmt.Errorf("privilege and exact sudo rule are inconsistent")
	}
	// Read-only is a property of the exact argv and never of the binary.
	// nvidia-smi also resets devices, toggles ECC, and sets power limits, and
	// journalctl also rotates and vacuums logs, so a sudo rule that admits any
	// argument is an outage or evidence-destruction primitive rather than a
	// read. Enforce the review rule instead of relying on a reviewer's eye.
	if definition.RequiresPrivilege && strings.ContainsAny(definition.SudoRule, "*?") {
		return fmt.Errorf("a privileged sudo rule must pin the exact argv and may not contain a wildcard")
	}
	if !sortedUniqueStrings(definition.SupportedCapabilities, 64) {
		return fmt.Errorf("capabilities must be non-empty, valid, unique, and canonically ordered")
	}
	parameters := make(map[string]Parameter, len(definition.Parameters))
	previous := ""
	for _, parameter := range definition.Parameters {
		if parameter.Name <= previous || !validID(parameter.Name) {
			return fmt.Errorf("parameters must be uniquely and canonically ordered")
		}
		previous = parameter.Name
		if err := validateParameter(parameter); err != nil {
			return fmt.Errorf("parameter %q: %w", parameter.Name, err)
		}
		parameters[parameter.Name] = parameter
	}
	if len(definition.Arguments) > 128 {
		return fmt.Errorf("argument template exceeds limit")
	}
	used := make(map[string]bool, len(parameters))
	for _, token := range definition.Arguments {
		if (token.Literal == "") == (token.Parameter == "") || strings.ContainsRune(token.Literal, '\x00') {
			return fmt.Errorf("each argument token must contain exactly one safe literal or parameter")
		}
		if token.Parameter != "" {
			parameter, ok := parameters[token.Parameter]
			if !ok {
				return fmt.Errorf("argument template references unknown parameter %q", token.Parameter)
			}
			if !parameter.Required {
				return fmt.Errorf("positional parameter %q must be required", token.Parameter)
			}
			used[token.Parameter] = true
		}
	}
	for name := range parameters {
		if !used[name] {
			return fmt.Errorf("parameter %q is unused", name)
		}
	}
	if definition.RequiresPrivilege {
		for name := range used {
			if err := validatePrivilegedParameter(parameters[name]); err != nil {
				return fmt.Errorf("privileged parameter %q: %w", name, err)
			}
		}
	}
	if err := validateTargets(definition.Targets); err != nil {
		return err
	}
	if definition.Limits.TimeoutSeconds < 1 || definition.Limits.TimeoutSeconds > 3600 || definition.Limits.MaximumOutputBytes < 1 || definition.Limits.MaximumOutputBytes > 64<<20 || definition.Limits.MaximumConcurrency < 1 || definition.Limits.MaximumConcurrency > definition.Targets.MaximumCount {
		return fmt.Errorf("execution limits are invalid")
	}
	if !validID(definition.OutputSchema) {
		return fmt.Errorf("output schema is invalid")
	}
	return nil
}

func validateParameter(parameter Parameter) error {
	if parameter.Type != ParameterString && parameter.Type != ParameterInteger && parameter.Type != ParameterBoolean {
		return fmt.Errorf("type is invalid")
	}
	if len(parameter.Enum) > 128 || (len(parameter.Enum) > 0 && !sortedUniqueStrings(parameter.Enum, 256)) {
		return fmt.Errorf("enum is invalid or not canonically ordered")
	}
	if parameter.Pattern != "" {
		if parameter.Type != ParameterString || len(parameter.Pattern) > 256 || !strings.HasPrefix(parameter.Pattern, "^") || !strings.HasSuffix(parameter.Pattern, "$") {
			return fmt.Errorf("pattern must be a bounded anchored string pattern")
		}
		if _, err := regexp.Compile(parameter.Pattern); err != nil {
			return fmt.Errorf("pattern is invalid")
		}
	}
	if parameter.Type != ParameterString && (parameter.MaxLength != 0 || len(parameter.Enum) != 0 || parameter.Pattern != "") {
		return fmt.Errorf("string constraints used for non-string parameter")
	}
	if parameter.Type != ParameterInteger && (parameter.Minimum != nil || parameter.Maximum != nil) {
		return fmt.Errorf("numeric constraints used for non-integer parameter")
	}
	if parameter.Type == ParameterString && (parameter.MaxLength < 1 || parameter.MaxLength > 4096) {
		return fmt.Errorf("string maximum length is required and bounded")
	}
	if parameter.Minimum != nil && parameter.Maximum != nil && *parameter.Minimum > *parameter.Maximum {
		return fmt.Errorf("numeric range is inverted")
	}
	return nil
}

// validatePrivilegedParameter keeps a parameter that reaches a privileged argv
// unable to emit a leading dash. A value that can start with a dash is read as
// a flag, and a later flag overrides an earlier one, which defeats the exact
// argv the sudo rule pins.
//
// The rule is enforced by requiring a closed set of candidate values rather
// than by analysing a pattern. Whether an arbitrary regular expression can
// match a leading dash is not something a reviewer can check reliably by eye,
// and not something this validator can decide, so a free-form string parameter
// is refused for a privileged definition. An unprivileged definition is
// unaffected: its argv is not the thing a sudo rule pins.
func validatePrivilegedParameter(parameter Parameter) error {
	switch parameter.Type {
	case ParameterBoolean:
		return nil
	case ParameterInteger:
		if parameter.Minimum == nil || *parameter.Minimum < 0 {
			return fmt.Errorf("must declare a minimum of zero or greater, or it can render a leading dash")
		}
		return nil
	case ParameterString:
		if len(parameter.Enum) == 0 {
			return fmt.Errorf("must be constrained to an explicit enum, because a pattern cannot be checked for a leading dash")
		}
		for _, value := range parameter.Enum {
			if strings.HasPrefix(value, "-") {
				return fmt.Errorf("enum value %q would be read as a flag", value)
			}
		}
		return nil
	}
	return fmt.Errorf("type is invalid")
}

func validateTargets(targets TargetConstraints) error {
	if targets.MaximumCount < 1 || targets.MaximumCount > 1024 || len(targets.Roles) == 0 || len(targets.Roles) > 3 || len(targets.NamePattern) > 256 || !strings.HasPrefix(targets.NamePattern, "^") || !strings.HasSuffix(targets.NamePattern, "$") {
		return fmt.Errorf("target constraints are invalid")
	}
	if _, err := regexp.Compile(targets.NamePattern); err != nil {
		return fmt.Errorf("target name pattern is invalid")
	}
	if !slices.IsSorted(targets.Roles) {
		return fmt.Errorf("target roles are not canonically ordered")
	}
	for index, role := range targets.Roles {
		if role != TargetHead && role != TargetCompute && role != TargetBMCGateway || index > 0 && role == targets.Roles[index-1] {
			return fmt.Errorf("target roles are invalid or duplicated")
		}
	}
	return nil
}

func validID(value string) bool      { return identifierPattern.MatchString(value) }
func validVersion(value string) bool { return versionPattern.MatchString(value) }
func validText(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && !strings.ContainsAny(value, "\x00\r\n")
}
func canonicalTime(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Nanosecond() == 0
}

func sortedUniqueStrings(values []string, maxLength int) bool {
	if len(values) == 0 || !slices.IsSorted(values) {
		return false
	}
	for index, value := range values {
		if !validText(value, maxLength) || index > 0 && value == values[index-1] {
			return false
		}
	}
	return true
}

func compareVersion(left, right string) int {
	var l, r [3]int
	fmt.Sscanf(left, "%d.%d.%d", &l[0], &l[1], &l[2])
	fmt.Sscanf(right, "%d.%d.%d", &r[0], &r[1], &r[2])
	return slices.Compare(l[:], r[:])
}
