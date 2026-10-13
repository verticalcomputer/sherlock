package remediation

import (
	"fmt"
	"slices"
	"strconv"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

// RejectionCode is the closed set of reasons a proposal or a target resolution
// is refused, so a test can assert the exact reason rather than a message.
type RejectionCode string

const (
	RejectUnknownRecipe          RejectionCode = "UNKNOWN_RECIPE"
	RejectUnknownArgument        RejectionCode = "UNKNOWN_ARGUMENT"
	RejectMissingArgument        RejectionCode = "MISSING_REQUIRED_ARGUMENT"
	RejectDuplicateArgument      RejectionCode = "DUPLICATE_ARGUMENT"
	RejectInvalidArgumentValue   RejectionCode = "INVALID_ARGUMENT_VALUE"
	RejectInvalidTarget          RejectionCode = "INVALID_TARGET"
	RejectTargetCountExceeded    RejectionCode = "TARGET_COUNT_EXCEEDED"
	RejectTargetOutOfScope       RejectionCode = "TARGET_OUT_OF_SCOPE"
	RejectCrossClusterTarget     RejectionCode = "CROSS_CLUSTER_TARGET"
	RejectTargetDrift            RejectionCode = "TARGET_DRIFT"
	RejectPopulationDrift        RejectionCode = "POPULATION_DRIFT"
	RejectBlastRadiusExceeded    RejectionCode = "BLAST_RADIUS_EXCEEDED"
	RejectNoResolvedTargets      RejectionCode = "NO_RESOLVED_TARGETS"
	RejectInvalidRationale       RejectionCode = "INVALID_RATIONALE"
	RejectInvalidCitation        RejectionCode = "INVALID_CITATION"
	RejectRecipeExpired          RejectionCode = "RECIPE_EXPIRED"
	RejectInvalidInventory       RejectionCode = "INVALID_INVENTORY"
	RejectInvalidCluster         RejectionCode = "INVALID_CLUSTER"
	RejectRollbackTargetNotFound RejectionCode = "ROLLBACK_TARGET_NOT_EXECUTED"
)

// RejectionError carries only a code. It deliberately never echoes the
// offending value: a rejected argument may be a credential or an injection
// payload, and an error string is a channel into logs.
type RejectionError struct {
	Code RejectionCode
}

func (e RejectionError) Error() string {
	return fmt.Sprintf("remediation proposal rejected: %s", e.Code)
}

func reject(code RejectionCode) error { return RejectionError{Code: code} }

// MaxRationaleBytes bounds the one free-text field a model may emit. The
// rationale is displayed and stored, never interpreted: it takes no part in any
// decision, is never used to build an argument, and is never persisted into a
// row that feeds model context.
const MaxRationaleBytes = 4096

const (
	maxProposedArguments = 32
	maxProposedTargets   = domain.MaxRemediationTargets
	maxProposedCitations = 64
)

type ProposedArgument struct {
	Name  string
	Value string
}

// RemediationProposal is the only artifact a model may produce. It carries no
// digest, operation, privilege, tier, command, path, capability, policy
// reference, cluster or target role; every one of those is rederived by
// Sherlock from the compiled catalog and from durable joined rows.
//
// Citations are ledger entry identifiers rather than evidence identifiers:
// investigation_evidence.evidence_id is nullable and unique only within an
// investigation, so ledger_entry_id is the only key that identifies a row.
type RemediationProposal struct {
	RecipeID       domain.RecipeID
	RecipeVersion  string
	Arguments      []ProposedArgument
	Targets        []domain.RemediationTarget
	Rationale      string
	LedgerEntryIDs []string
}

// AdmitProposal turns an untrusted proposal into typed arguments, or refuses it
// with a closed code. The authenticated cluster is a parameter rather than a
// proposal field: the proposal has no say in which cluster it acts on.
//
// Every check is exact: an ENUM value must be byte-equal to a declared allowed
// value, with no trimming, case folding, unicode normalization or prefix
// matching, so "NORMAL; rm -rf /", "NORMAL\n" and a homoglyph of "NORMAL" are
// all simply not the value "NORMAL".
func AdmitProposal(catalog *Catalog, clusterID domain.ClusterID, proposal RemediationProposal) (domain.TypedArguments, error) {
	if catalog == nil {
		return nil, reject(RejectUnknownRecipe)
	}
	if clusterID == "" || !validRemediationToken(string(clusterID)) {
		return nil, reject(RejectInvalidCluster)
	}
	if !validRemediationToken(string(proposal.RecipeID)) || !validRemediationToken(proposal.RecipeVersion) {
		return nil, reject(RejectUnknownRecipe)
	}
	recipe, found := catalog.Lookup(proposal.RecipeID, proposal.RecipeVersion)
	if !found {
		return nil, reject(RejectUnknownRecipe)
	}
	if len(proposal.Arguments) > maxProposedArguments {
		return nil, reject(RejectUnknownArgument)
	}

	parameters := make(map[string]Parameter, len(recipe.Parameters))
	for _, parameter := range recipe.Parameters {
		parameters[parameter.Name] = parameter
	}
	seen := make(map[string]struct{}, len(proposal.Arguments))
	admitted := make(domain.TypedArguments, 0, len(proposal.Arguments))
	for _, argument := range proposal.Arguments {
		parameter, declared := parameters[argument.Name]
		if !declared {
			return nil, reject(RejectUnknownArgument)
		}
		if _, duplicate := seen[argument.Name]; duplicate {
			return nil, reject(RejectDuplicateArgument)
		}
		seen[argument.Name] = struct{}{}
		typed, err := parseArgument(parameter, argument.Value)
		if err != nil {
			return nil, err
		}
		admitted = append(admitted, typed)
	}
	for _, parameter := range recipe.Parameters {
		if _, present := seen[parameter.Name]; parameter.Required && !present {
			return nil, reject(RejectMissingArgument)
		}
	}
	slices.SortFunc(admitted, func(left, right domain.TypedArgument) int {
		if left.Name < right.Name {
			return -1
		}
		if left.Name > right.Name {
			return 1
		}
		return 0
	})

	if len(proposal.Targets) < 1 {
		return nil, reject(RejectNoResolvedTargets)
	}
	deduplicated := make([]domain.RemediationTarget, 0, len(proposal.Targets))
	for _, target := range proposal.Targets {
		if !domain.ValidRemediationTarget(string(target)) {
			return nil, reject(RejectInvalidTarget)
		}
		if !slices.Contains(deduplicated, target) {
			deduplicated = append(deduplicated, target)
		}
	}
	if len(deduplicated) > recipe.MaxTargets || len(deduplicated) > maxProposedTargets {
		return nil, reject(RejectTargetCountExceeded)
	}

	if len(proposal.Rationale) > MaxRationaleBytes || !boundedText(proposal.Rationale) {
		return nil, reject(RejectInvalidRationale)
	}
	if len(proposal.LedgerEntryIDs) > maxProposedCitations {
		return nil, reject(RejectInvalidCitation)
	}
	for _, entryID := range proposal.LedgerEntryIDs {
		if !validRemediationToken(entryID) {
			return nil, reject(RejectInvalidCitation)
		}
	}
	return admitted, nil
}

// AdmittedTargets returns the deduplicated, canonically ordered candidate
// targets a proposal named. They are candidates only: resolution intersects
// them with durable inventory before anything acts on them.
func AdmittedTargets(proposal RemediationProposal) []domain.RemediationTarget {
	deduplicated := make([]domain.RemediationTarget, 0, len(proposal.Targets))
	for _, target := range proposal.Targets {
		if !slices.Contains(deduplicated, target) {
			deduplicated = append(deduplicated, target)
		}
	}
	slices.Sort(deduplicated)
	return deduplicated
}

func parseArgument(parameter Parameter, value string) (domain.TypedArgument, error) {
	typed := domain.TypedArgument{Name: parameter.Name, Type: parameter.Type}
	switch parameter.Type {
	case domain.ParameterEnum:
		// Byte equality against the declared set. Nothing is normalized, so an
		// argument that merely looks like an allowed value is not one.
		if !slices.Contains(parameter.AllowedValues, value) {
			return domain.TypedArgument{}, reject(RejectInvalidArgumentValue)
		}
		typed.Enum = value
	case domain.ParameterInteger:
		parsed, err := parseCanonicalInteger(value)
		if err != nil || parsed < parameter.Minimum || parsed > parameter.Maximum {
			return domain.TypedArgument{}, reject(RejectInvalidArgumentValue)
		}
		typed.Integer = parsed
	case domain.ParameterDuration:
		// Durations are canonical integer nanoseconds rather than "15m", so
		// there is exactly one spelling of every value and no parser dialect to
		// disagree about.
		parsed, err := parseCanonicalInteger(value)
		if err != nil || parsed < parameter.Minimum || parsed > parameter.Maximum {
			return domain.TypedArgument{}, reject(RejectInvalidArgumentValue)
		}
		typed.Duration = time.Duration(parsed)
	case domain.ParameterBoolean:
		if value != "true" && value != "false" {
			return domain.TypedArgument{}, reject(RejectInvalidArgumentValue)
		}
		typed.Boolean = value == "true"
	default:
		return domain.TypedArgument{}, reject(RejectInvalidArgumentValue)
	}
	return typed, nil
}

// parseCanonicalInteger accepts exactly one spelling per value: no plus sign,
// no leading zeros, no underscores, no whitespace, no base prefix.
func parseCanonicalInteger(value string) (int64, error) {
	if value == "" || len(value) > 20 {
		return 0, fmt.Errorf("value is not a canonical integer")
	}
	body := value
	if body[0] == '-' {
		body = body[1:]
	}
	if body == "" || (len(body) > 1 && body[0] == '0') {
		return 0, fmt.Errorf("value is not a canonical integer")
	}
	for index := 0; index < len(body); index++ {
		if body[index] < '0' || body[index] > '9' {
			return 0, fmt.Errorf("value is not a canonical integer")
		}
	}
	return strconv.ParseInt(value, 10, 64)
}

// boundedText rejects NUL bytes. The rationale is untrusted display text; it is
// bounded and screened here rather than wherever it is eventually rendered.
func boundedText(value string) bool {
	for index := 0; index < len(value); index++ {
		if value[index] == 0 {
			return false
		}
	}
	return true
}

// InventoryRow is one durable inventory fact. Resolution reads these rows and
// never the proposal, so a compromised planner cannot invent a target or claim
// a role for one. Source is a closed relation enum, not a free string: a row
// can never claim an unreviewed provenance.
type InventoryRow struct {
	Target     domain.RemediationTarget
	Role       domain.TargetRole
	ClusterID  domain.ClusterID
	IncidentID domain.IncidentID
	Source     domain.TargetSourceRelation
}

// ResolutionInput is the whole input of target resolution. Inventory rows come
// from the durable store; Proposed comes from the model.
type ResolutionInput struct {
	ClusterID  domain.ClusterID
	IncidentID domain.IncidentID
	Recipe     Recipe
	Inventory  []InventoryRow
	Proposed   []domain.RemediationTarget
	Now        time.Time
}

// Resolution is the intersection of what the inventory authorizes and what the
// proposal named, plus the role population the blast radius is a fraction of.
type Resolution struct {
	Targets    []domain.ResolvedTarget
	Digest     domain.SHA256
	Population int
}

// TargetList returns the resolved targets as plain identifiers, in the same
// canonical order the digest covers.
func (r Resolution) TargetList() []domain.RemediationTarget {
	targets := make([]domain.RemediationTarget, len(r.Targets))
	for index, resolved := range r.Targets {
		targets[index] = resolved.Target
	}
	return targets
}

// TargetSetDigest covers the sorted canonical target list together with each
// target's cluster and role. Preflight persists it; dispatch recomputes
// resolution from current inventory and compares.
func TargetSetDigest(resolved []domain.ResolvedTarget) domain.SHA256 {
	return domain.RemediationTargetSetDigest(resolved)
}

// ResolveTargets is a pure function of durable inventory and the proposal. The
// result is the intersection of the two, so neither side can expand it: the
// inventory cannot add a target the proposal did not name, and the proposal
// cannot add one the inventory did not authorize.
//
// The population is counted over every inventory row for this cluster in a
// permitted role, not only the rows attached to this incident. The blast radius
// is a fraction of the role's real population, and narrowing the denominator to
// the incident would let a single-incident run consume the whole allowance.
func ResolveTargets(input ResolutionInput) (Resolution, error) {
	if input.ClusterID == "" || input.IncidentID == "" || input.Now.IsZero() {
		return Resolution{}, reject(RejectInvalidInventory)
	}
	if input.Recipe.ExpiresAt.IsZero() || !input.Recipe.ExpiresAt.After(input.Now) {
		return Resolution{}, reject(RejectRecipeExpired)
	}

	population := 0
	candidates := make([]InventoryRow, 0, len(input.Inventory))
	for _, row := range input.Inventory {
		if !domain.ValidRemediationTarget(string(row.Target)) {
			return Resolution{}, reject(RejectInvalidInventory)
		}
		if err := row.Source.Validate(); err != nil {
			return Resolution{}, reject(RejectInvalidInventory)
		}
		// A row from another cluster is not filtered out quietly: its presence
		// means the caller's scoping is wrong, and continuing would mean acting
		// on an inventory nobody vouched for.
		if row.ClusterID != input.ClusterID {
			return Resolution{}, reject(RejectCrossClusterTarget)
		}
		if !slices.Contains(input.Recipe.PermittedTargetRoles, row.Role) {
			continue
		}
		population++
		if row.IncidentID != input.IncidentID {
			continue
		}
		candidates = append(candidates, row)
	}

	proposed := make([]domain.RemediationTarget, 0, len(input.Proposed))
	for _, target := range input.Proposed {
		if !domain.ValidRemediationTarget(string(target)) {
			return Resolution{}, reject(RejectInvalidTarget)
		}
		if !slices.Contains(proposed, target) {
			proposed = append(proposed, target)
		}
	}
	if len(proposed) == 0 {
		return Resolution{}, reject(RejectNoResolvedTargets)
	}

	resolved := make([]domain.ResolvedTarget, 0, len(proposed))
	for _, target := range proposed {
		index := slices.IndexFunc(candidates, func(row InventoryRow) bool { return row.Target == target })
		if index < 0 {
			// Dropping it silently would let a proposal that names one
			// authorized and one unauthorized target still execute half of
			// itself. The whole run fails instead.
			return Resolution{}, reject(RejectTargetOutOfScope)
		}
		row := candidates[index]
		resolved = append(resolved, domain.ResolvedTarget{
			Target: row.Target, Role: row.Role, ClusterID: row.ClusterID,
			ResolvedAt: input.Now.UTC(), Source: row.Source,
		})
	}
	slices.SortFunc(resolved, func(left, right domain.ResolvedTarget) int {
		if left.Target < right.Target {
			return -1
		}
		if left.Target > right.Target {
			return 1
		}
		return 0
	})

	// The fraction floors and is never rounded up to one: a percentage of a
	// tiny population must be allowed to reach zero and deny.
	permitted := population * input.Recipe.BlastRadiusPercent / 100
	switch {
	case len(resolved) < 1:
		return Resolution{}, reject(RejectNoResolvedTargets)
	case len(resolved) > input.Recipe.MaxTargets:
		return Resolution{}, reject(RejectTargetCountExceeded)
	case population < 1 || len(resolved) > permitted:
		return Resolution{}, reject(RejectBlastRadiusExceeded)
	}
	return Resolution{Targets: resolved, Digest: TargetSetDigest(resolved), Population: population}, nil
}

// DetectDrift compares a persisted target-set digest and role population
// against a fresh resolution. A digest difference means the authorized set is
// not the set that would execute, which is the "target added after proposal"
// defence; a population difference means the denominator of the blast radius
// moved, which widens the absolute permitted count without moving the digest.
func DetectDrift(persisted domain.SHA256, pinnedPopulation int, current Resolution) error {
	if persisted != current.Digest {
		return reject(RejectTargetDrift)
	}
	if pinnedPopulation < 1 || pinnedPopulation != current.Population {
		return reject(RejectPopulationDrift)
	}
	return nil
}

// AuthorizeRollbackTargets restricts a rollback to targets that are both in the
// persisted resolved set and known to have actually executed. Rolling back a
// target that was never mutated is not a safe no-op: it is an unreviewed
// forward action on a target the run never touched.
func AuthorizeRollbackTargets(resolved []domain.ResolvedTarget, executed, requested []domain.RemediationTarget) ([]domain.ResolvedTarget, error) {
	if len(requested) == 0 {
		return nil, reject(RejectNoResolvedTargets)
	}
	authorized := make([]domain.ResolvedTarget, 0, len(requested))
	for _, target := range requested {
		if !slices.Contains(executed, target) {
			return nil, reject(RejectRollbackTargetNotFound)
		}
		index := slices.IndexFunc(resolved, func(entry domain.ResolvedTarget) bool { return entry.Target == target })
		if index < 0 {
			return nil, reject(RejectTargetOutOfScope)
		}
		if slices.ContainsFunc(authorized, func(entry domain.ResolvedTarget) bool { return entry.Target == target }) {
			continue
		}
		authorized = append(authorized, resolved[index])
	}
	slices.SortFunc(authorized, func(left, right domain.ResolvedTarget) int {
		if left.Target < right.Target {
			return -1
		}
		if left.Target > right.Target {
			return 1
		}
		return 0
	})
	return authorized, nil
}

// EvaluateConditions folds per-target observations into one result per declared
// condition. A condition is SATISFIED only when every resolved target was
// observed inside the condition's window and every observation was satisfied;
// a missing or stale observation yields UNOBSERVED, which is distinct from
// UNSATISFIED and equally insufficient for success.
func EvaluateConditions(specs []ConditionSpec, targets []domain.ResolvedTarget, observations []domain.ConditionObservation, now time.Time) []domain.RemediationConditionResult {
	results := make([]domain.RemediationConditionResult, 0, len(specs))
	for _, spec := range specs {
		results = append(results, domain.RemediationConditionResult{
			ConditionID: spec.ID, Result: evaluateCondition(spec, targets, observations, now),
		})
	}
	slices.SortFunc(results, func(left, right domain.RemediationConditionResult) int {
		if left.ConditionID < right.ConditionID {
			return -1
		}
		if left.ConditionID > right.ConditionID {
			return 1
		}
		return 0
	})
	return results
}

func evaluateCondition(spec ConditionSpec, targets []domain.ResolvedTarget, observations []domain.ConditionObservation, now time.Time) domain.ConditionResult {
	if len(targets) == 0 {
		return domain.ConditionUnobserved
	}
	result := domain.ConditionSatisfied
	for _, target := range targets {
		index := slices.IndexFunc(observations, func(observation domain.ConditionObservation) bool {
			return observation.ConditionID == spec.ID && observation.Target == target.Target &&
				!observation.ObservedAt.IsZero() && !observation.ObservedAt.After(now) &&
				!observation.ObservedAt.Before(now.Add(-spec.Window))
		})
		if index < 0 {
			return domain.ConditionUnobserved
		}
		switch observations[index].Result {
		case domain.ConditionUnsatisfied:
			return domain.ConditionUnsatisfied
		case domain.ConditionUnobserved:
			result = domain.ConditionUnobserved
		}
	}
	return result
}
