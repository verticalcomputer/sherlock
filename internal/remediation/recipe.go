// Package remediation holds Sherlock's repair vocabulary: digest-pinned
// recipes, a pure policy core, deterministic target resolution, and condition
// evaluation. It contains no adapter and performs no I/O.
//
// The design premise is that the planner is untrusted. A model may produce only
// a RemediationProposal: a recipe coordinate, typed argument values and
// candidate targets. Operation, privilege, tier, assurance, target roles and
// blast radius are rederived here from the compiled catalog and from durable
// inventory.
package remediation

import (
	"encoding/binary"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

const RecipeSchemaVersion = "sherlock.remediation-recipe.v1"

// RecipeOperation is the entire executable vocabulary of the system. It is
// declared in the domain, because the execution unit carries it and the
// application layer must be able to name an execution without importing an
// adapter package. It is aliased here so a recipe still reads as owning its
// own operation.
type RecipeOperation = domain.RecipeOperation

const (
	OperationEvidenceCollectionRequeue = domain.OperationEvidenceCollectionRequeue
	OperationEvidenceCollectionRestore = domain.OperationEvidenceCollectionRestore
)

type ConditionKind string

const (
	ConditionEvidenceFreshness ConditionKind = "EVIDENCE_FRESHNESS"
	ConditionStreamStale       ConditionKind = "STREAM_STALE"
	ConditionStreamFresh       ConditionKind = "STREAM_FRESH"
	ConditionNoActiveRun       ConditionKind = "NO_ACTIVE_RUN"
	ConditionScheduleRestored  ConditionKind = "SCHEDULE_RESTORED"
)

func (k ConditionKind) Validate() error {
	switch k {
	case ConditionEvidenceFreshness, ConditionStreamStale, ConditionStreamFresh, ConditionNoActiveRun, ConditionScheduleRestored:
		return nil
	default:
		return fmt.Errorf("unknown condition kind %q", k)
	}
}

type Parameter struct {
	Name          string
	Type          domain.ParameterType
	Required      bool
	AllowedValues []string
	Minimum       int64
	Maximum       int64
}

type EvidenceRequirement struct {
	Class       string
	MaxAge      time.Duration
	MinCoverage int
}

type ConditionSpec struct {
	ID     string
	Kind   ConditionKind
	Target domain.TargetRole
	Window time.Duration
}

// RecipeReview records that a human looked at a recipe before it shipped. It is
// validated data, not cryptography: M14's trust boundary is the compiled source
// tree, and a signature scheme is required only once the catalog stops being
// compiled in.
type RecipeReview struct {
	Reviewer   string
	ReviewedAt time.Time
}

// Recipe is declarative data, not an executable plugin. It is digest-pinned:
// the catalog verifies every recipe at load and a run persists the digest, so
// an altered definition fails closed at every later stage.
type Recipe struct {
	Schema                 string
	ID                     domain.RecipeID
	Version                string
	Digest                 domain.SHA256
	Owner                  string
	ExpiresAt              time.Time
	Reviews                []RecipeReview
	Assurance              domain.AssuranceClass
	Tier                   domain.AutonomyTier
	Privilege              domain.RemediationPrivilege
	AppliesToIncidentKinds []string
	RequiredEvidence       []EvidenceRequirement
	Operation              RecipeOperation
	Parameters             []Parameter
	PermittedTargetRoles   []domain.TargetRole
	MaxTargets             int
	MaxConcurrency         int
	BlastRadiusPercent     int
	CanaryTargets          int
	Preconditions          []ConditionSpec
	Postconditions         []ConditionSpec
	ObservationWindow      time.Duration
	MaxAttempts            int
	Cooldown               time.Duration
	// RollbackRecipe is a full digest-pinned reference rather than a bare
	// identifier. An ID alone carried no version and no digest, so a different
	// rollback definition — with a different tier, privilege or role set — could
	// answer to the same name and turn a Tier 1 repair into an escalation.
	RollbackRecipe       domain.RemediationRecipeRef
	RollbackVerification []ConditionSpec
	RequiredCapabilities []string
	RedactionClass       string
	AuditRequired        bool
}

// Ref is the digest-pinned coordinate persisted on a run.
func (r Recipe) Ref() domain.RemediationRecipeRef {
	return domain.RemediationRecipeRef{ID: r.ID, Version: r.Version, Digest: r.Digest}
}

func (r Recipe) HasRollback() bool { return !r.RollbackRecipe.IsZero() }

// CanonicalBytes deterministically encodes every field except Digest in a fixed
// order, with every variable-length segment length-prefixed. The length prefix
// rather than a delimiter is what makes the encoding unambiguous: two recipes
// that differ only by where a field boundary falls cannot collide.
//
// Order-significant sequences (parameters, conditions) keep their declared
// order; sets whose order carries no meaning (incident kinds, target roles,
// capabilities) are sorted so the same recipe written two ways digests alike.
func (r Recipe) CanonicalBytes() []byte {
	payload := make([]byte, 0, 1024)
	payload = appendField(payload, []byte(r.Schema))
	payload = appendField(payload, []byte(r.ID))
	payload = appendField(payload, []byte(r.Version))
	payload = appendField(payload, []byte(r.Owner))
	payload = appendInt(payload, r.ExpiresAt.UTC().UnixNano())

	payload = appendCount(payload, len(r.Reviews))
	for _, review := range sortedReviews(r.Reviews) {
		payload = appendField(payload, []byte(review.Reviewer))
		payload = appendInt(payload, review.ReviewedAt.UTC().UnixNano())
	}

	payload = appendField(payload, []byte(r.Assurance))
	payload = appendInt(payload, int64(r.Tier))
	payload = appendField(payload, []byte(r.Privilege))
	payload = appendStringSet(payload, r.AppliesToIncidentKinds)

	payload = appendCount(payload, len(r.RequiredEvidence))
	for _, requirement := range sortedEvidence(r.RequiredEvidence) {
		payload = appendField(payload, []byte(requirement.Class))
		payload = appendInt(payload, int64(requirement.MaxAge))
		payload = appendInt(payload, int64(requirement.MinCoverage))
	}

	payload = appendField(payload, []byte(r.Operation))

	payload = appendCount(payload, len(r.Parameters))
	for _, parameter := range r.Parameters {
		payload = appendField(payload, []byte(parameter.Name))
		payload = appendField(payload, []byte(parameter.Type))
		payload = appendInt(payload, boolToInt(parameter.Required))
		payload = appendStringSet(payload, parameter.AllowedValues)
		payload = appendInt(payload, parameter.Minimum)
		payload = appendInt(payload, parameter.Maximum)
	}

	roles := make([]string, len(r.PermittedTargetRoles))
	for index, role := range r.PermittedTargetRoles {
		roles[index] = string(role)
	}
	payload = appendStringSet(payload, roles)

	payload = appendInt(payload, int64(r.MaxTargets))
	payload = appendInt(payload, int64(r.MaxConcurrency))
	payload = appendInt(payload, int64(r.BlastRadiusPercent))
	payload = appendInt(payload, int64(r.CanaryTargets))
	payload = appendConditions(payload, r.Preconditions)
	payload = appendConditions(payload, r.Postconditions)
	payload = appendInt(payload, int64(r.ObservationWindow))
	payload = appendInt(payload, int64(r.MaxAttempts))
	payload = appendInt(payload, int64(r.Cooldown))
	payload = appendField(payload, []byte(r.RollbackRecipe.ID))
	payload = appendField(payload, []byte(r.RollbackRecipe.Version))
	payload = appendField(payload, r.RollbackRecipe.Digest[:])
	payload = appendConditions(payload, r.RollbackVerification)
	payload = appendStringSet(payload, r.RequiredCapabilities)
	payload = appendField(payload, []byte(r.RedactionClass))
	payload = appendInt(payload, boolToInt(r.AuditRequired))
	return payload
}

func (r Recipe) ComputeDigest() domain.SHA256 {
	return domain.ChecksumSHA256(r.CanonicalBytes())
}

// DigestMismatchError is distinct from every other validation failure: a
// recipe that fails structural validation is malformed, but one whose digest
// does not cover its own bytes has been altered after review.
type DigestMismatchError struct {
	RecipeID domain.RecipeID
	Version  string
}

func (e DigestMismatchError) Error() string {
	return fmt.Sprintf("remediation recipe %s@%s digest does not cover its canonical bytes", e.RecipeID, e.Version)
}

// RollbackViolationError reports a rollback that could do more than the forward
// action it undoes. Its code is a closed value so a catalog rejection and a
// policy denial name the same fault identically.
type RollbackViolationError struct {
	RecipeID domain.RecipeID
	Code     string
}

func (e RollbackViolationError) Error() string {
	return fmt.Sprintf("remediation recipe %s declares an over-broad rollback: %s", e.RecipeID, e.Code)
}

const (
	RollbackViolationTier         = "ROLLBACK_TIER_EXCEEDED"
	RollbackViolationRole         = "ROLLBACK_ROLE_EXCEEDED"
	RollbackViolationUnresolved   = "ROLLBACK_UNRESOLVED"
	RollbackViolationNested       = "ROLLBACK_NESTED"
	RollbackViolationSelfRollback = "ROLLBACK_SELF"
)

// WithComputedDigest returns the recipe with its digest filled in. Catalog
// construction uses it so no digest is ever hardcoded in source, where it could
// drift silently away from the definition it claims to cover.
func (r Recipe) WithComputedDigest() Recipe {
	r.Digest = r.ComputeDigest()
	return r
}

const maxRecipeCollection = 32

// Validate enforces every structural rule, this milestone's scope boundary, and
// the whole rollback-containment relation. The rollback recipe is passed in
// rather than looked up, because validation is pure: the caller resolves the
// digest-pinned reference from the compiled catalog and hands over exactly the
// definition the reference names.
//
// The scope checks are equalities, not ceilings. "Tier at most 1" would admit
// an unset tier 0, which no recipe author ever chose; only TierSherlockOwnedRepair,
// SHERLOCK_INTERNAL and SIMULATED are executable in this build.
func (r Recipe) Validate(now time.Time, rollback *Recipe) error {
	if r.Schema != RecipeSchemaVersion {
		return fmt.Errorf("unsupported remediation recipe schema %q", r.Schema)
	}
	if !validRemediationToken(string(r.ID)) || !validRemediationToken(r.Version) || !validRemediationToken(r.Owner) {
		return fmt.Errorf("remediation recipe identity is invalid")
	}
	if !validRemediationToken(r.RedactionClass) {
		return fmt.Errorf("remediation recipe redaction class is invalid")
	}
	if err := r.Assurance.Validate(); err != nil {
		return err
	}
	if !r.Assurance.Implemented() && !isCollectionRequestRecipe(r) {
		return fmt.Errorf("assurance class %q is not permitted in this build", r.Assurance)
	}
	if err := r.Tier.Validate(); err != nil {
		return err
	}
	if !r.Tier.Implemented() {
		return fmt.Errorf("remediation tier %d is not implemented", int(r.Tier))
	}
	if err := r.Privilege.Validate(); err != nil {
		return err
	}
	if !r.Privilege.Implemented() {
		return fmt.Errorf("remediation privilege %q is not permitted in this build", r.Privilege)
	}
	if err := r.Operation.Validate(); err != nil {
		return err
	}
	if r.ExpiresAt.IsZero() {
		return fmt.Errorf("remediation recipe expiry is required")
	}
	if !now.IsZero() && !r.ExpiresAt.After(now) {
		return fmt.Errorf("remediation recipe %s@%s has expired", r.ID, r.Version)
	}
	if !r.AuditRequired {
		return fmt.Errorf("remediation recipe must require an audit record")
	}
	if err := r.validateReviews(); err != nil {
		return err
	}
	if err := validateStringSet(r.AppliesToIncidentKinds, "incident kind", true); err != nil {
		return err
	}
	if err := validateStringSet(r.RequiredCapabilities, "required capability", false); err != nil {
		return err
	}
	if len(r.RequiredEvidence) < 1 || len(r.RequiredEvidence) > maxRecipeCollection {
		return fmt.Errorf("remediation recipe must declare between 1 and %d evidence requirements", maxRecipeCollection)
	}
	for _, requirement := range r.RequiredEvidence {
		if !validRemediationToken(requirement.Class) || requirement.MaxAge <= 0 ||
			requirement.MinCoverage < 1 || requirement.MinCoverage > 100 {
			return fmt.Errorf("remediation recipe evidence requirement is invalid")
		}
	}
	if err := r.validateParameters(); err != nil {
		return err
	}
	if len(r.PermittedTargetRoles) < 1 || len(r.PermittedTargetRoles) > maxRecipeCollection {
		return fmt.Errorf("remediation recipe must permit between 1 and %d target roles", maxRecipeCollection)
	}
	previousRole := domain.TargetRole("")
	for _, role := range slices.Sorted(slices.Values(r.PermittedTargetRoles)) {
		if err := role.Validate(); err != nil {
			return err
		}
		if role == previousRole {
			return fmt.Errorf("remediation recipe target roles must be unique")
		}
		previousRole = role
	}
	if r.MaxTargets < 1 || r.MaxTargets > domain.MaxRemediationTargets {
		return fmt.Errorf("remediation recipe maximum targets must be between 1 and %d", domain.MaxRemediationTargets)
	}
	if r.MaxConcurrency < 1 || r.MaxConcurrency > r.MaxTargets {
		return fmt.Errorf("remediation recipe concurrency must be between 1 and its maximum target count")
	}
	if r.BlastRadiusPercent < 1 || r.BlastRadiusPercent > 100 {
		return fmt.Errorf("remediation recipe blast radius must be between 1 and 100 percent")
	}
	if r.CanaryTargets < 1 || r.CanaryTargets > r.MaxTargets {
		return fmt.Errorf("remediation recipe canary targets must be between 1 and its maximum target count")
	}
	if r.MaxAttempts < 1 || r.MaxAttempts > 3 {
		return fmt.Errorf("remediation recipe maximum attempts must be between 1 and 3")
	}
	if r.ObservationWindow <= 0 || r.Cooldown < 0 {
		return fmt.Errorf("remediation recipe observation window and cooldown are invalid")
	}
	if err := validateConditionSpecs(r.Preconditions, "precondition", 1); err != nil {
		return err
	}
	if err := validateConditionSpecs(r.Postconditions, "postcondition", 1); err != nil {
		return err
	}
	if err := validateConditionSpecs(r.RollbackVerification, "rollback verification", 0); err != nil {
		return err
	}
	if err := r.validateRollback(rollback); err != nil {
		return err
	}
	if r.Digest != r.ComputeDigest() {
		return DigestMismatchError{RecipeID: r.ID, Version: r.Version}
	}
	return nil
}

// validateRollback enforces the containment relation between a forward recipe
// and the rollback that undoes it. Every clause exists because its absence was
// an escalation: an operator must never be able to reach further by failing
// than by succeeding, and a rollback that could itself be rolled back would be
// a forward mutation wearing a rollback's name.
func (r Recipe) validateRollback(rollback *Recipe) error {
	if !r.HasRollback() {
		if len(r.RollbackVerification) != 0 {
			return fmt.Errorf("remediation recipe declares rollback verification without a rollback recipe")
		}
		return nil
	}
	if err := r.RollbackRecipe.Validate(); err != nil {
		return err
	}
	if r.RollbackRecipe.ID == r.ID {
		return RollbackViolationError{RecipeID: r.ID, Code: RollbackViolationSelfRollback}
	}
	if len(r.RollbackVerification) < 1 {
		return fmt.Errorf("remediation recipe declaring a rollback must declare rollback verification")
	}
	if rollback == nil {
		return RollbackViolationError{RecipeID: r.ID, Code: RollbackViolationUnresolved}
	}
	if !rollback.Ref().Matches(r.RollbackRecipe) {
		return RollbackViolationError{RecipeID: r.ID, Code: RollbackViolationUnresolved}
	}
	if rollback.HasRollback() {
		return RollbackViolationError{RecipeID: r.ID, Code: RollbackViolationNested}
	}
	if rollback.Tier > r.Tier || rollback.Privilege.Rank() > r.Privilege.Rank() {
		return RollbackViolationError{RecipeID: r.ID, Code: RollbackViolationTier}
	}
	if rollback.Assurance != r.Assurance {
		return RollbackViolationError{RecipeID: r.ID, Code: RollbackViolationTier}
	}
	if rollback.MaxTargets > r.MaxTargets {
		return RollbackViolationError{RecipeID: r.ID, Code: RollbackViolationRole}
	}
	for _, role := range rollback.PermittedTargetRoles {
		if !slices.Contains(r.PermittedTargetRoles, role) {
			return RollbackViolationError{RecipeID: r.ID, Code: RollbackViolationRole}
		}
	}
	return nil
}

func (r Recipe) validateReviews() error {
	if len(r.Reviews) < 1 || len(r.Reviews) > maxRecipeCollection {
		return fmt.Errorf("remediation recipe must record between 1 and %d reviews", maxRecipeCollection)
	}
	seen := make(map[string]struct{}, len(r.Reviews))
	for _, review := range r.Reviews {
		if !validRemediationToken(review.Reviewer) || review.ReviewedAt.IsZero() {
			return fmt.Errorf("remediation recipe review is invalid")
		}
		if _, exists := seen[review.Reviewer]; exists {
			return fmt.Errorf("remediation recipe reviewers must be distinct")
		}
		seen[review.Reviewer] = struct{}{}
	}
	return nil
}

func (r Recipe) validateParameters() error {
	if len(r.Parameters) > maxRecipeCollection {
		return fmt.Errorf("remediation recipe declares too many parameters")
	}
	seen := make(map[string]struct{}, len(r.Parameters))
	for _, parameter := range r.Parameters {
		if !validRemediationToken(parameter.Name) {
			return fmt.Errorf("remediation recipe parameter name is invalid")
		}
		// A credential is not a repair argument. It is refused by name here as
		// well as by type, because the reviewer of a future recipe should not
		// have to reason about whether ENUM happens to be safe today.
		if credentialParameterName(parameter.Name) {
			return fmt.Errorf("credential values cannot be remediation parameters")
		}
		if _, exists := seen[parameter.Name]; exists {
			return fmt.Errorf("remediation recipe parameter names must be unique")
		}
		seen[parameter.Name] = struct{}{}
		if err := parameter.Type.Validate(); err != nil {
			return err
		}
		switch parameter.Type {
		case domain.ParameterEnum:
			if len(parameter.AllowedValues) < 1 || len(parameter.AllowedValues) > maxRecipeCollection {
				return fmt.Errorf("remediation enum parameter %q must declare allowed values", parameter.Name)
			}
			previous := ""
			for _, value := range slices.Sorted(slices.Values(parameter.AllowedValues)) {
				if !validRemediationToken(value) {
					return fmt.Errorf("remediation enum parameter %q declares an invalid allowed value", parameter.Name)
				}
				if value == previous {
					return fmt.Errorf("remediation enum parameter %q declares a duplicate allowed value", parameter.Name)
				}
				previous = value
			}
		case domain.ParameterInteger, domain.ParameterDuration:
			if len(parameter.AllowedValues) != 0 {
				return fmt.Errorf("remediation numeric parameter %q cannot declare allowed values", parameter.Name)
			}
			if parameter.Minimum > parameter.Maximum {
				return fmt.Errorf("remediation parameter %q has an inverted bound", parameter.Name)
			}
		case domain.ParameterBoolean:
			if len(parameter.AllowedValues) != 0 || parameter.Minimum != 0 || parameter.Maximum != 0 {
				return fmt.Errorf("remediation boolean parameter %q cannot declare values or bounds", parameter.Name)
			}
		}
	}
	return nil
}

func validateConditionSpecs(specs []ConditionSpec, label string, minimum int) error {
	if len(specs) < minimum || len(specs) > maxRecipeCollection {
		return fmt.Errorf("remediation recipe %s count is invalid", label)
	}
	seen := make(map[string]struct{}, len(specs))
	for _, spec := range specs {
		if !validRemediationToken(spec.ID) || spec.Window <= 0 {
			return fmt.Errorf("remediation recipe %s is invalid", label)
		}
		if _, exists := seen[spec.ID]; exists {
			return fmt.Errorf("remediation recipe %s identifiers must be unique", label)
		}
		seen[spec.ID] = struct{}{}
		if err := spec.Kind.Validate(); err != nil {
			return err
		}
		if err := spec.Target.Validate(); err != nil {
			return err
		}
	}
	return nil
}

func validateStringSet(values []string, label string, required bool) error {
	if required && len(values) < 1 {
		return fmt.Errorf("remediation recipe must declare at least one %s", label)
	}
	if len(values) > maxRecipeCollection {
		return fmt.Errorf("remediation recipe declares too many %s entries", label)
	}
	previous := ""
	for _, value := range slices.Sorted(slices.Values(values)) {
		if !validRemediationToken(value) {
			return fmt.Errorf("remediation recipe %s %q is invalid", label, value)
		}
		if value == previous {
			return fmt.Errorf("remediation recipe %s entries must be unique", label)
		}
		previous = value
	}
	return nil
}

func sortedEvidence(requirements []EvidenceRequirement) []EvidenceRequirement {
	sorted := slices.Clone(requirements)
	slices.SortFunc(sorted, func(left, right EvidenceRequirement) int {
		return strings.Compare(left.Class, right.Class)
	})
	return sorted
}

func sortedReviews(reviews []RecipeReview) []RecipeReview {
	sorted := slices.Clone(reviews)
	slices.SortFunc(sorted, func(left, right RecipeReview) int {
		return strings.Compare(left.Reviewer, right.Reviewer)
	})
	return sorted
}

func appendConditions(into []byte, specs []ConditionSpec) []byte {
	into = appendCount(into, len(specs))
	for _, spec := range specs {
		into = appendField(into, []byte(spec.ID))
		into = appendField(into, []byte(spec.Kind))
		into = appendField(into, []byte(spec.Target))
		into = appendInt(into, int64(spec.Window))
	}
	return into
}

func appendStringSet(into []byte, values []string) []byte {
	sorted := slices.Sorted(slices.Values(values))
	into = appendCount(into, len(sorted))
	for _, value := range sorted {
		into = appendField(into, []byte(value))
	}
	return into
}

// appendField writes one length-prefixed segment.
func appendField(into, field []byte) []byte {
	into = binary.BigEndian.AppendUint32(into, uint32(len(field)))
	return append(into, field...)
}

func appendCount(into []byte, count int) []byte {
	return binary.BigEndian.AppendUint32(into, uint32(count))
}

func appendInt(into []byte, value int64) []byte {
	return binary.BigEndian.AppendUint64(into, uint64(value))
}

func boolToInt(value bool) int64 {
	if value {
		return 1
	}
	return 0
}

// validRemediationToken is the one identifier charset of this subsystem. It
// delegates to the domain so the recipe schema, the plan, the attempt and the
// receipt cannot disagree about what a legal identifier is.
func validRemediationToken(value string) bool { return domain.ValidRemediationToken(value) }

func credentialParameterName(name string) bool {
	normalized := strings.NewReplacer("-", "", "_", "", ".", "").Replace(strings.ToLower(name))
	switch normalized {
	case "credential", "credentials", "password", "passwd", "secret", "token", "apikey",
		"privatekey", "username", "user", "auth", "authorization", "bearer", "sshkey", "keyfile":
		return true
	default:
		return false
	}
}
