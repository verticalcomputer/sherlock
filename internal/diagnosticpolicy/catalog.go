// Package diagnosticpolicy adapts a signature-verified command-pack catalog
// to Sherlock's diagnostic application ports.
package diagnosticpolicy

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"time"

	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/commandpack"
	"github.com/verticalcomputer/sherlock/internal/domain"
	"github.com/verticalcomputer/sherlock/internal/hostroles"
)

// RoleResolver reports the derived role of one host at one instant, and false
// when the host is unknown or its role has not been confirmed recently enough
// to target. Derivation is deterministic code over observations; a model can
// neither supply nor influence an answer here.
type RoleResolver interface {
	Role(domain.ClusterID, domain.DiagnosticTarget, time.Time) (hostroles.Entry, bool)
}

type Catalog struct {
	verified *commandpack.Catalog
	roles    RoleResolver
	clock    func() time.Time
}

// NewCatalog builds a policy catalog over a derived, expiring host-role
// resolver. A static operator-maintained map does not scale across clusters and
// cannot notice that a node has left, so roles come from a resolver that is
// refreshed on a schedule.
func NewCatalog(verified *commandpack.Catalog, roles RoleResolver, clock func() time.Time) (*Catalog, error) {
	if verified == nil || roles == nil || clock == nil {
		return nil, errors.New("verified command catalog, host role resolver, and clock are required")
	}
	return &Catalog{verified: verified, roles: roles, clock: clock}, nil
}

// NewCatalogWithStaticInventory keeps a fixed inventory usable for a
// single-cluster deployment and for tests. The entries never expire, which is
// exactly why it must not be used where hosts come and go.
func NewCatalogWithStaticInventory(verified *commandpack.Catalog, inventory map[domain.ClusterID]map[domain.DiagnosticTarget]commandpack.TargetRole) (*Catalog, error) {
	if verified == nil || len(inventory) == 0 {
		return nil, errors.New("verified command catalog and target inventory are required")
	}
	static := staticRoles{}
	for clusterID, targets := range inventory {
		if clusterID == "" || len(targets) == 0 {
			return nil, errors.New("diagnostic cluster inventory is invalid")
		}
		for target, role := range targets {
			if target == "" || (role != commandpack.TargetHead && role != commandpack.TargetCompute && role != commandpack.TargetBMCGateway) {
				return nil, errors.New("diagnostic target inventory is invalid")
			}
			static[staticKey{clusterID, target}] = role
		}
	}
	return &Catalog{verified: verified, roles: static, clock: time.Now}, nil
}

type staticKey struct {
	cluster domain.ClusterID
	target  domain.DiagnosticTarget
}

type staticRoles map[staticKey]commandpack.TargetRole

func (roles staticRoles) Role(clusterID domain.ClusterID, target domain.DiagnosticTarget, now time.Time) (hostroles.Entry, bool) {
	role, exists := roles[staticKey{clusterID, target}]
	if !exists {
		return hostroles.Entry{}, false
	}
	return hostroles.Entry{ClusterID: clusterID, Target: target, Role: role, Sources: []hostroles.Source{hostroles.SourceSlurm}, Reason: "static operator-maintained inventory", ConfirmedAt: now}, true
}

func (catalog *Catalog) VerifyDiagnosticDefinition(_ context.Context, clusterID domain.ClusterID, reference domain.DiagnosticDefinitionRef, targets []domain.DiagnosticTarget, arguments []domain.DiagnosticArgument) (application.VerifiedDiagnosticDefinition, error) {
	plan, err := catalog.plan(clusterID, reference, targets, arguments)
	if err != nil {
		return application.VerifiedDiagnosticDefinition{}, err
	}
	metadata := catalog.verified.Metadata()
	privilege := domain.DiagnosticUnprivileged
	if plan.RequiresPrivilege() {
		privilege = domain.DiagnosticPrivileged
	}
	return application.VerifiedDiagnosticDefinition{Reference: reference, Privilege: privilege, Issuer: metadata.Issuer, ExpiresAt: metadata.ExpiresAt}, nil
}

// Plan revalidates the exact reference, typed arguments, and inventory-backed
// target roles and returns a sealed plan constructible only by commandpack.
func (catalog *Catalog) Plan(clusterID domain.ClusterID, reference domain.DiagnosticDefinitionRef, targets []domain.DiagnosticTarget, arguments []domain.DiagnosticArgument) (commandpack.ExecutionPlan, error) {
	return catalog.plan(clusterID, reference, targets, arguments)
}

func (catalog *Catalog) plan(clusterID domain.ClusterID, reference domain.DiagnosticDefinitionRef, targets []domain.DiagnosticTarget, arguments []domain.DiagnosticArgument) (commandpack.ExecutionPlan, error) {
	if catalog == nil || catalog.verified == nil {
		return commandpack.ExecutionPlan{}, errors.New("verified command catalog is unavailable")
	}
	if err := reference.Validate(); err != nil {
		return commandpack.ExecutionPlan{}, err
	}
	metadata := catalog.verified.Metadata()
	if reference.PackID != metadata.PackID || reference.PackVersion != metadata.PackVersion {
		return commandpack.ExecutionPlan{}, errors.New("diagnostic reference does not match the verified pack")
	}
	definition, digest, found := catalog.verified.Lookup(string(reference.DefinitionID), reference.DefinitionVersion)
	if !found || digest != reference.DefinitionDigest.String() {
		return commandpack.ExecutionPlan{}, errors.New("diagnostic reference does not match the signed definition")
	}
	values, err := typedArguments(definition, arguments)
	if err != nil {
		return commandpack.ExecutionPlan{}, err
	}
	resolvedTargets := make([]commandpack.Target, len(targets))
	now := catalog.clock()
	for index, target := range targets {
		// An unknown host and a host whose role has not been confirmed recently
		// are both ineligible. Neither is distinguished to the caller: a stale
		// entry is not a weaker form of known, it is not known.
		entry, eligible := catalog.roles.Role(clusterID, target, now)
		if !eligible {
			return commandpack.ExecutionPlan{}, errors.New("diagnostic target has no currently confirmed role")
		}
		resolvedTargets[index] = commandpack.Target{Name: string(target), Role: entry.Role}
	}
	return catalog.verified.Plan(commandpack.Invocation{DefinitionID: string(reference.DefinitionID), DefinitionVersion: reference.DefinitionVersion, Arguments: values, Targets: resolvedTargets})
}

func typedArguments(definition commandpack.Definition, arguments []domain.DiagnosticArgument) ([]commandpack.ArgumentValue, error) {
	if len(arguments) != len(definition.Parameters) {
		return nil, errors.New("diagnostic arguments do not exactly match the signed schema")
	}
	parameters := make(map[string]commandpack.Parameter, len(definition.Parameters))
	for _, parameter := range definition.Parameters {
		parameters[parameter.Name] = parameter
	}
	ordered := slices.Clone(arguments)
	slices.SortFunc(ordered, func(left, right domain.DiagnosticArgument) int { return compare(left.Name, right.Name) })
	values := make([]commandpack.ArgumentValue, 0, len(ordered))
	previous := ""
	for _, argument := range ordered {
		parameter, exists := parameters[argument.Name]
		if !exists || argument.Name == previous {
			return nil, errors.New("diagnostic arguments contain an unknown or duplicate name")
		}
		previous = argument.Name
		value := commandpack.ArgumentValue{Name: argument.Name}
		switch parameter.Type {
		case commandpack.ParameterString:
			parsed := argument.Value
			value.String = &parsed
		case commandpack.ParameterInteger:
			parsed, err := strconv.ParseInt(argument.Value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("diagnostic argument %q is not an integer", argument.Name)
			}
			value.Integer = &parsed
		case commandpack.ParameterBoolean:
			if argument.Value != "true" && argument.Value != "false" {
				return nil, fmt.Errorf("diagnostic argument %q is not a canonical boolean", argument.Name)
			}
			parsed, _ := strconv.ParseBool(argument.Value)
			value.Boolean = &parsed
		default:
			return nil, errors.New("signed definition contains an unsupported parameter type")
		}
		values = append(values, value)
	}
	return values, nil
}

func DefinitionReference(catalog *commandpack.Catalog, id, version string) (domain.DiagnosticDefinitionRef, error) {
	if catalog == nil {
		return domain.DiagnosticDefinitionRef{}, errors.New("verified command catalog is unavailable")
	}
	metadata := catalog.Metadata()
	_, digest, found := catalog.Lookup(id, version)
	decoded, err := hex.DecodeString(digest)
	if !found || err != nil || len(decoded) != 32 {
		return domain.DiagnosticDefinitionRef{}, errors.New("signed diagnostic definition is unavailable")
	}
	result := domain.DiagnosticDefinitionRef{PackID: metadata.PackID, PackVersion: metadata.PackVersion, DefinitionID: domain.DiagnosticDefinitionID(id), DefinitionVersion: version}
	copy(result.DefinitionDigest[:], decoded)
	return result, nil
}

func compare(left, right string) int {
	if left < right {
		return -1
	}
	if left > right {
		return 1
	}
	return 0
}
