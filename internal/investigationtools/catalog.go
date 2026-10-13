// Package investigationtools defines the model-visible tool catalog: read-only
// lookups over committed evidence, and reviewed diagnostics that observe live
// state. It contains policy metadata and argument validation only; it cannot
// execute a tool or turn model-provided values into commands.
package investigationtools

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/verticalcomputer/sherlock/internal/auth"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

const SchemaVersion = 1

const (
	maxDefinitions = 128
	maxArguments   = 32
	maxTargets     = 256
)

type ToolID string
type ClusterCapability string
type OperationClass string

const (
	DiagnosticECCCountersToolID  = "gpu.ecc_counters.v1"
	DiagnosticRowRemapToolID     = "gpu.row_remap.v1"
	DiagnosticRetiredPagesToolID = "gpu.retired_pages.v1"
	// DiagnosticKernelXIDToolID reads the node's own kernel journal for NVRM XID
	// lines. It is distinct from KernelXIDCorrelationToolID, which looks up
	// kernel evidence already committed: nothing in this deployment produces
	// such evidence, so the lookup answers every XID question with silence.
	DiagnosticKernelXIDToolID = "node.kernel_xid.v1"
)

// DiagnosticBinding is the reviewed, server-owned mapping from a model-visible
// tool identifier to a signed command-pack definition. Keeping the mapping in
// the tool-policy package lets execution and durable context admission validate
// the same identity without trusting model output or diagnostic source labels.
type DiagnosticBinding struct {
	DefinitionID      domain.DiagnosticDefinitionID
	DefinitionVersion string
	// ObservationLookback is how far back the definition's own output reaches.
	// Zero means the command reports live state, so its evidence observes the
	// execution instant. A journal read reports history, and evidence that
	// claimed the execution instant would understate what it covers: coverage
	// projection would report the investigated window as uninterrogated, and a
	// reader would take a seven-day excerpt for a one-second sample.
	//
	// It is declared here, beside the definition binding, because it must match
	// the signed argv and neither the model nor the target may influence it.
	ObservationLookback time.Duration
}

// DiagnosticBindingForTool returns only the fixed reviewed diagnostic
// bindings. An unknown or read-only tool has no command-pack authority.
func DiagnosticBindingForTool(toolID ToolID) (DiagnosticBinding, bool) {
	switch toolID {
	case DiagnosticECCCountersToolID:
		return DiagnosticBinding{DefinitionID: "gpu.ecc_counters", DefinitionVersion: "1.0.0"}, true
	case DiagnosticRowRemapToolID:
		return DiagnosticBinding{DefinitionID: "gpu.row_remap", DefinitionVersion: "1.1.0"}, true
	case DiagnosticRetiredPagesToolID:
		return DiagnosticBinding{DefinitionID: "gpu.retired_pages", DefinitionVersion: "1.0.0"}, true
	case DiagnosticKernelXIDToolID:
		// 2.0.0 deliberately, not 1.0.0: the executor refuses a definition that
		// requires privilege, and 1.0.0 carries a root sudo rule no execution
		// route in this deployment can satisfy. Its argv reads seven days of
		// journal, so its evidence observes seven days.
		return DiagnosticBinding{DefinitionID: "node.kernel_xid", DefinitionVersion: "2.0.0", ObservationLookback: 7 * 24 * time.Hour}, true
	default:
		return DiagnosticBinding{}, false
	}
}

// DiagnosticToolIDs lists every reviewed diagnostic tool. DiagnosticBindingForTool
// remains the single table; this exists so a caller can resolve a binding in
// reverse without restating it.
func DiagnosticToolIDs() []ToolID {
	return []ToolID{DiagnosticECCCountersToolID, DiagnosticRowRemapToolID, DiagnosticRetiredPagesToolID, DiagnosticKernelXIDToolID}
}

// DiagnosticObservationLookback reports the declared lookback for a pack
// definition. It is keyed on the definition alone because at most one version
// of a definition is ever bound to a tool, which DiagnosticBindingsAreExact
// asserts. An unbound definition observes the execution instant.
func DiagnosticObservationLookback(definitionID domain.DiagnosticDefinitionID) time.Duration {
	for _, toolID := range DiagnosticToolIDs() {
		if binding, reviewed := DiagnosticBindingForTool(toolID); reviewed && binding.DefinitionID == definitionID {
			return binding.ObservationLookback
		}
	}
	return 0
}

const (
	// OperationReadOnly is a lookup over evidence already committed to durable
	// storage. Repeating one cannot add information.
	OperationReadOnly OperationClass = "READ_ONLY"
	// OperationDiagnostic is a bounded remote execution that observes live
	// state. It reads nothing that is already stored, so its result has a
	// currency rather than an identity, and repeating one can be legitimate.
	OperationDiagnostic OperationClass = "DIAGNOSTIC"
)

// maximumReexecutionInterval bounds how long a diagnostic result may be
// treated as current. A definition claiming a longer currency would let one
// stale observation stand in for live state across an entire incident.
const maximumReexecutionInterval = time.Hour

type ArgumentKind string

const (
	ArgumentString     ArgumentKind = "STRING"
	ArgumentInteger    ArgumentKind = "INTEGER"
	ArgumentBoolean    ArgumentKind = "BOOLEAN"
	ArgumentTimestamp  ArgumentKind = "TIMESTAMP"
	ArgumentStringList ArgumentKind = "STRING_LIST"
)

type ArgumentSpec struct {
	Name             string
	Description      string
	Kind             ArgumentKind
	Required         bool
	Minimum          int64
	Maximum          int64
	MinItems         int
	MaxItems         int
	MaxLength        int
	Pattern          string
	AllowedValues    []string
	OrderInsensitive bool
}

type ScopePolicy struct {
	EntityKinds []string
	MaxTargets  int
	MaxWindow   time.Duration
}

// Definition is trusted, reviewed configuration. AllowedClusters is required:
// an empty allow-list never means all clusters.
type Definition struct {
	SchemaVersion               int
	ID                          ToolID
	Description                 string
	Operation                   OperationClass
	AllowedClusters             []domain.ClusterID
	RequiredCapabilities        []auth.Capability
	RequiredClusterCapabilities []ClusterCapability
	Scope                       ScopePolicy
	Arguments                   []ArgumentSpec
	Timeout                     time.Duration
	CostWeight                  int
	// MinimumReexecutionInterval is how long this definition's result stays
	// current. It is required for a diagnostic and meaningless for a read-only
	// lookup, whose novelty is decided by identity rather than by recency.
	MinimumReexecutionInterval time.Duration
}

// Diagnostic reports whether this definition executes remotely rather than
// reading committed evidence.
func (definition Definition) Diagnostic() bool {
	return definition.Operation == OperationDiagnostic
}

type Catalog struct {
	definitions map[ToolID]Definition
	ordered     []ToolID
}

func NewCatalog(definitions []Definition) (*Catalog, error) {
	if len(definitions) == 0 || len(definitions) > maxDefinitions {
		return nil, fmt.Errorf("tool catalog must contain between 1 and %d definitions", maxDefinitions)
	}
	catalog := &Catalog{definitions: make(map[ToolID]Definition, len(definitions))}
	for _, definition := range definitions {
		normalized, err := validateDefinition(definition)
		if err != nil {
			return nil, fmt.Errorf("validate tool %q: %w", definition.ID, err)
		}
		if _, exists := catalog.definitions[normalized.ID]; exists {
			return nil, fmt.Errorf("duplicate tool identifier %q", normalized.ID)
		}
		catalog.definitions[normalized.ID] = normalized
		catalog.ordered = append(catalog.ordered, normalized.ID)
	}
	slices.Sort(catalog.ordered)
	return catalog, nil
}

type Filter struct {
	ClusterID           domain.ClusterID
	ActorCapabilities   []auth.Capability
	ClusterCapabilities []ClusterCapability
	Scope               domain.InvestigationScope
	// AllowDiagnostics admits remote execution into the catalog. It is false by
	// default, so an investigation that was granted no diagnostic budget never
	// sees a diagnostic tool and cannot propose one: the refusal happens before
	// any provider call rather than after one.
	AllowDiagnostics bool
}

// Available returns only tools explicitly allowed by every policy dimension.
// Missing cluster identity, scope, or capabilities fail closed.
func (catalog *Catalog) Available(filter Filter) []Definition {
	if catalog == nil || filter.ClusterID == "" || filter.Scope.Validate() != nil {
		return nil
	}
	result := make([]Definition, 0, len(catalog.ordered))
	for _, id := range catalog.ordered {
		definition := catalog.definitions[id]
		if allows(definition, filter) {
			result = append(result, cloneDefinition(definition))
		}
	}
	return result
}

type ArgumentValue struct {
	Name       string
	Kind       ArgumentKind
	String     string
	Integer    int64
	Boolean    bool
	Timestamp  time.Time
	StringList []string
}

func String(name, value string) ArgumentValue {
	return ArgumentValue{Name: name, Kind: ArgumentString, String: value}
}
func Integer(name string, value int64) ArgumentValue {
	return ArgumentValue{Name: name, Kind: ArgumentInteger, Integer: value}
}
func Boolean(name string, value bool) ArgumentValue {
	return ArgumentValue{Name: name, Kind: ArgumentBoolean, Boolean: value}
}
func Timestamp(name string, value time.Time) ArgumentValue {
	return ArgumentValue{Name: name, Kind: ArgumentTimestamp, Timestamp: value.UTC()}
}
func StringList(name string, value []string) ArgumentValue {
	return ArgumentValue{Name: name, Kind: ArgumentStringList, StringList: slices.Clone(value)}
}

type Call struct {
	ToolID     ToolID
	EntityKind string
	Targets    []string
	Start      time.Time
	End        time.Time
	Arguments  []ArgumentValue
}

// AvailableToolSchema is a provider-neutral JSON Schema for one tool which has
// already passed catalog filtering. Schema is generated by Sherlock and must
// not be accepted back as authority from a model.
type AvailableToolSchema struct {
	ToolID         ToolID
	Description    string
	ArgumentSchema json.RawMessage
	SchemaVersion  string
	// Diagnostic and ReadOnly are exclusive: a diagnostic executes remotely and
	// spends the separate diagnostic grant.
	Diagnostic                 bool
	ReadOnly                   bool
	MinimumReexecutionInterval time.Duration
	MaximumFanOut              int
	CostWeight                 int
}

// AvailableSchemas returns deterministic schemas for the filtered catalog.
// The standard targets/start/end fields are always required and bounded to the
// investigation scope; tool-specific fields follow the reviewed definition.
func (catalog *Catalog) AvailableSchemas(filter Filter) ([]AvailableToolSchema, error) {
	definitions := catalog.Available(filter)
	result := make([]AvailableToolSchema, 0, len(definitions))
	for _, definition := range definitions {
		schema, err := argumentSchema(definition, filter)
		if err != nil {
			return nil, fmt.Errorf("build schema for tool %q: %w", definition.ID, err)
		}
		// The reviewed per-tool window is enforced here and would otherwise be
		// invisible to a planner that only sees the investigation scope. Carrying
		// it in the per-tool description keeps the shared targets/start/end schema
		// byte-identical across tools, so prompt factoring still applies.
		description := definition.Description + " " + windowGuidance(definition.Scope.MaxWindow)
		if definition.Diagnostic() {
			description += " " + diagnosticGuidance(definition.MinimumReexecutionInterval)
		}
		result = append(result, AvailableToolSchema{ToolID: definition.ID, Description: description, ArgumentSchema: schema, SchemaVersion: "catalog.v1", Diagnostic: definition.Diagnostic(), ReadOnly: !definition.Diagnostic(), MinimumReexecutionInterval: definition.MinimumReexecutionInterval, MaximumFanOut: min(definition.Scope.MaxTargets, len(filter.Scope.EntityIDs)), CostWeight: definition.CostWeight})
	}
	return result, nil
}

// Bounds are the reviewed limits one tool enforces, reported so a caller can
// tell a planner exactly which constraint rejected a proposal.
type Bounds struct {
	MaxTargets                 int
	MaxWindow                  time.Duration
	EntityKinds                []string
	Diagnostic                 bool
	MinimumReexecutionInterval time.Duration
}

// ToolBounds reports the enforced limits for a tool the filter may use. It
// returns false for a tool this actor, cluster, or scope cannot reach, so a
// rejection message can never disclose an unavailable tool's policy.
func (catalog *Catalog) ToolBounds(filter Filter, toolID ToolID) (Bounds, bool) {
	if catalog == nil || filter.ClusterID == "" || filter.Scope.Validate() != nil {
		return Bounds{}, false
	}
	definition, exists := catalog.definitions[toolID]
	if !exists || !allows(definition, filter) {
		return Bounds{}, false
	}
	return Bounds{MaxTargets: definition.Scope.MaxTargets, MaxWindow: definition.Scope.MaxWindow, EntityKinds: slices.Clone(definition.Scope.EntityKinds), Diagnostic: definition.Diagnostic(), MinimumReexecutionInterval: definition.MinimumReexecutionInterval}, true
}

// windowGuidance renders a reviewed window bound as a stable, human-readable
// phrase. Durations in the catalog are whole minutes or hours by construction.
func windowGuidance(window time.Duration) string {
	return "One call may span at most " + window.String() + " of time."
}

// diagnosticGuidance states the two properties a planner cannot infer from the
// argument schema: that the call executes on the cluster rather than reading
// stored evidence, and how long its result stays current. It reports only
// server-owned reviewed policy.
func diagnosticGuidance(interval time.Duration) string {
	return "This runs a reviewed command on the target hosts to observe live state, spends the separate diagnostic budget, and its result stays current for " + interval.String() + "; re-running it sooner than that is refused."
}

// DecodeCall is the sole raw model-argument boundary. It rejects duplicate and
// unknown object properties, JSON type coercion, and scope expansion before
// returning typed values.
func (catalog *Catalog) DecodeCall(filter Filter, toolID ToolID, raw json.RawMessage) (Call, error) {
	call, err := catalog.decodeCall(filter, toolID, raw)
	if err != nil {
		return Call{}, err
	}
	if err := catalog.ValidateCall(filter, call); err != nil {
		return Call{}, err
	}
	return call, nil
}

// DecodeCallBatches validates one model proposal against the complete
// investigation scope and deterministically divides its targets into bounded
// calls. Every returned call independently satisfies the reviewed tool policy;
// callers can durably execute one unseen batch and re-plan from new evidence.
func (catalog *Catalog) DecodeCallBatches(filter Filter, toolID ToolID, raw json.RawMessage, maxBatchSize int) ([]Call, error) {
	call, err := catalog.decodeCall(filter, toolID, raw)
	if err != nil {
		return nil, err
	}
	definition, exists := catalog.definitions[toolID]
	if !exists || !allows(definition, filter) {
		return nil, ErrToolUnavailable
	}
	if maxBatchSize < 1 {
		return nil, fmt.Errorf("%w: batch size is outside bounds", ErrInvalidCall)
	}
	if err := catalog.validateCall(filter, call, len(filter.Scope.EntityIDs)); err != nil {
		return nil, err
	}
	batchSize := min(maxBatchSize, definition.Scope.MaxTargets)
	targets := slices.Clone(call.Targets)
	slices.Sort(targets)
	batches := make([]Call, 0, (len(targets)+batchSize-1)/batchSize)
	for start := 0; start < len(targets); start += batchSize {
		end := min(start+batchSize, len(targets))
		batch := call
		batch.Targets = slices.Clone(targets[start:end])
		batch.Arguments = slices.Clone(call.Arguments)
		for index := range batch.Arguments {
			batch.Arguments[index].StringList = slices.Clone(batch.Arguments[index].StringList)
		}
		if err := catalog.ValidateCall(filter, batch); err != nil {
			return nil, err
		}
		batches = append(batches, batch)
	}
	return batches, nil
}

func (catalog *Catalog) decodeCall(filter Filter, toolID ToolID, raw json.RawMessage) (Call, error) {
	if len(raw) == 0 || len(raw) > 64<<10 {
		return Call{}, fmt.Errorf("%w: encoded arguments are empty or too large", ErrInvalidCall)
	}
	definition, exists := catalog.definitions[toolID]
	if !exists || !allows(definition, filter) {
		return Call{}, ErrToolUnavailable
	}
	object, err := decodeUniqueObject(raw)
	if err != nil {
		return Call{}, fmt.Errorf("%w: %v", ErrInvalidCall, err)
	}
	call := Call{ToolID: toolID, EntityKind: filter.Scope.EntityKind}
	if err := decodeRequired(object, "targets", &call.Targets); err != nil {
		return Call{}, fmt.Errorf("%w: %v", ErrInvalidCall, err)
	}
	var start, end string
	if err := decodeRequired(object, "start", &start); err != nil {
		return Call{}, fmt.Errorf("%w: %v", ErrInvalidCall, err)
	}
	if err := decodeRequired(object, "end", &end); err != nil {
		return Call{}, fmt.Errorf("%w: %v", ErrInvalidCall, err)
	}
	if call.Start, err = time.Parse(time.RFC3339Nano, start); err != nil {
		return Call{}, fmt.Errorf("%w: start must be RFC3339", ErrInvalidCall)
	}
	if call.End, err = time.Parse(time.RFC3339Nano, end); err != nil {
		return Call{}, fmt.Errorf("%w: end must be RFC3339", ErrInvalidCall)
	}
	for _, spec := range definition.Arguments {
		encoded, present := object[spec.Name]
		if !present {
			continue
		}
		value, decodeErr := decodeArgument(spec, encoded)
		if decodeErr != nil {
			return Call{}, fmt.Errorf("%w: argument %q: %v", ErrInvalidCall, spec.Name, decodeErr)
		}
		call.Arguments = append(call.Arguments, value)
		delete(object, spec.Name)
	}
	if len(object) != 0 {
		return Call{}, fmt.Errorf("%w: unknown argument", ErrInvalidCall)
	}
	return call, nil
}

var (
	ErrToolUnavailable = errors.New("investigation tool is unavailable")
	ErrInvalidCall     = errors.New("investigation tool call is invalid")
)

func (catalog *Catalog) ValidateCall(filter Filter, call Call) error {
	if catalog == nil {
		return ErrToolUnavailable
	}
	definition, exists := catalog.definitions[call.ToolID]
	if !exists || !allows(definition, filter) {
		return ErrToolUnavailable
	}
	return catalog.validateCall(filter, call, definition.Scope.MaxTargets)
}

func (catalog *Catalog) validateCall(filter Filter, call Call, maxCallTargets int) error {
	definition := catalog.definitions[call.ToolID]
	if call.EntityKind != filter.Scope.EntityKind || !slices.Contains(definition.Scope.EntityKinds, call.EntityKind) {
		return fmt.Errorf("%w: entity kind is outside scope", ErrInvalidCall)
	}
	if len(call.Targets) == 0 || len(call.Targets) > maxCallTargets {
		return fmt.Errorf("%w: target count is outside bounds", ErrInvalidCall)
	}
	allowedTargets := make(map[string]struct{}, len(filter.Scope.EntityIDs))
	for _, target := range filter.Scope.EntityIDs {
		allowedTargets[target] = struct{}{}
	}
	seenTargets := make(map[string]struct{}, len(call.Targets))
	for _, target := range call.Targets {
		if _, ok := allowedTargets[target]; !ok {
			return fmt.Errorf("%w: target is outside investigation scope", ErrInvalidCall)
		}
		if _, duplicate := seenTargets[target]; duplicate {
			return fmt.Errorf("%w: duplicate target", ErrInvalidCall)
		}
		seenTargets[target] = struct{}{}
	}
	if call.Start.IsZero() || call.End.IsZero() || call.End.Before(call.Start) || call.Start.Before(filter.Scope.Start) || call.End.After(filter.Scope.End) || call.End.Sub(call.Start) > definition.Scope.MaxWindow {
		return fmt.Errorf("%w: time window is outside bounds", ErrInvalidCall)
	}
	return validateArguments(definition.Arguments, call.Arguments)
}

// CanonicalCallKey produces a stable duplicate-detection key after validating
// the call against current cluster, actor, and scope policy.
func (catalog *Catalog) CanonicalCallKey(filter Filter, call Call) (string, error) {
	if err := catalog.ValidateCall(filter, call); err != nil {
		return "", err
	}
	definition := catalog.definitions[call.ToolID]
	targets := slices.Clone(call.Targets)
	slices.Sort(targets)
	arguments := slices.Clone(call.Arguments)
	slices.SortFunc(arguments, func(a, b ArgumentValue) int { return strings.Compare(a.Name, b.Name) })
	for index := range arguments {
		spec := findArgument(definition.Arguments, arguments[index].Name)
		arguments[index].Timestamp = arguments[index].Timestamp.UTC()
		arguments[index].StringList = slices.Clone(arguments[index].StringList)
		if spec.OrderInsensitive {
			slices.Sort(arguments[index].StringList)
		}
	}
	payload := struct {
		Version   int              `json:"version"`
		Cluster   domain.ClusterID `json:"cluster"`
		Tool      ToolID           `json:"tool"`
		Kind      string           `json:"kind"`
		Targets   []string         `json:"targets"`
		Start     string           `json:"start"`
		End       string           `json:"end"`
		Arguments []ArgumentValue  `json:"arguments"`
	}{SchemaVersion, filter.ClusterID, call.ToolID, call.EntityKind, targets, call.Start.UTC().Format(time.RFC3339Nano), call.End.UTC().Format(time.RFC3339Nano), arguments}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("encode canonical tool call: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return "toolcall:v1:" + hex.EncodeToString(digest[:]), nil
}

func validateDefinition(definition Definition) (Definition, error) {
	if definition.SchemaVersion != SchemaVersion || !validToken(string(definition.ID)) || len(definition.Description) == 0 || len(definition.Description) > 512 {
		return Definition{}, errors.New("identity, schema version, or description is invalid")
	}
	switch definition.Operation {
	case OperationReadOnly:
		if definition.MinimumReexecutionInterval != 0 {
			return Definition{}, errors.New("a read-only tool has no re-execution interval; its novelty is decided by identity")
		}
	case OperationDiagnostic:
		if definition.MinimumReexecutionInterval <= 0 || definition.MinimumReexecutionInterval > maximumReexecutionInterval {
			return Definition{}, errors.New("a diagnostic must declare how long its result stays current, within the reviewed bound")
		}
	default:
		return Definition{}, errors.New("only explicitly read-only or diagnostic tools are allowed")
	}
	if len(definition.AllowedClusters) == 0 || len(definition.AllowedClusters) > 256 || len(definition.RequiredCapabilities) == 0 || len(definition.RequiredClusterCapabilities) == 0 || len(definition.Scope.EntityKinds) == 0 || definition.Scope.MaxTargets < 1 || definition.Scope.MaxTargets > maxTargets || definition.Scope.MaxWindow <= 0 || definition.Scope.MaxWindow > 24*time.Hour {
		return Definition{}, errors.New("cluster allow-list and bounded scope are required")
	}
	if definition.Timeout <= 0 || definition.Timeout > 10*time.Minute || definition.CostWeight < 1 || definition.CostWeight > 1000 || len(definition.Arguments) > maxArguments {
		return Definition{}, errors.New("timeout, cost, or argument bounds are invalid")
	}
	if err := uniqueNonEmptyClusters(definition.AllowedClusters); err != nil {
		return Definition{}, err
	}
	if err := uniqueTokens(definition.Scope.EntityKinds); err != nil {
		return Definition{}, err
	}
	if err := uniqueCapabilities(definition.RequiredCapabilities, definition.RequiredClusterCapabilities); err != nil {
		return Definition{}, err
	}
	seen := make(map[string]struct{}, len(definition.Arguments))
	for _, argument := range definition.Arguments {
		if err := validateArgumentSpec(argument); err != nil {
			return Definition{}, err
		}
		if _, exists := seen[argument.Name]; exists {
			return Definition{}, errors.New("argument names must be unique")
		}
		seen[argument.Name] = struct{}{}
	}
	return cloneDefinition(definition), nil
}

func validateArgumentSpec(spec ArgumentSpec) error {
	if !validToken(spec.Name) || len(spec.Description) == 0 || len(spec.Description) > 256 {
		return errors.New("argument identity is invalid")
	}
	switch spec.Kind {
	case ArgumentString:
		if spec.MaxLength < 1 || spec.MaxLength > 4096 || spec.MinItems != 0 || spec.MaxItems != 0 {
			return errors.New("string argument bounds are invalid")
		}
	case ArgumentInteger:
		if spec.Minimum > spec.Maximum || spec.Pattern != "" || spec.MaxLength != 0 {
			return errors.New("integer argument bounds are invalid")
		}
	case ArgumentBoolean:
		if spec.Pattern != "" || spec.MaxLength != 0 || len(spec.AllowedValues) != 0 {
			return errors.New("boolean argument constraints are invalid")
		}
	case ArgumentTimestamp:
		if spec.Pattern != "" || spec.MaxLength != 0 || len(spec.AllowedValues) != 0 {
			return errors.New("timestamp argument constraints are invalid")
		}
	case ArgumentStringList:
		if spec.MinItems < 0 || spec.MaxItems < 1 || spec.MinItems > spec.MaxItems || spec.MaxItems > maxTargets || spec.MaxLength < 1 || spec.MaxLength > 512 {
			return errors.New("string-list bounds are invalid")
		}
	default:
		return errors.New("argument kind is unsupported")
	}
	if spec.Pattern != "" {
		if len(spec.Pattern) > 256 {
			return errors.New("argument pattern is too long")
		}
		if _, err := regexp.Compile(spec.Pattern); err != nil {
			return errors.New("argument pattern is invalid")
		}
	}
	if len(spec.AllowedValues) > 128 {
		return errors.New("argument enum is too large")
	}
	if err := uniqueTokensOrText(spec.AllowedValues); err != nil {
		return err
	}
	return nil
}

func validateArguments(specs []ArgumentSpec, values []ArgumentValue) error {
	if len(values) > maxArguments {
		return fmt.Errorf("%w: too many arguments", ErrInvalidCall)
	}
	byName := make(map[string]ArgumentValue, len(values))
	for _, value := range values {
		if _, duplicate := byName[value.Name]; duplicate {
			return fmt.Errorf("%w: duplicate argument", ErrInvalidCall)
		}
		byName[value.Name] = value
	}
	for _, spec := range specs {
		value, exists := byName[spec.Name]
		if !exists {
			if spec.Required {
				return fmt.Errorf("%w: required argument %q is missing", ErrInvalidCall, spec.Name)
			}
			continue
		}
		if value.Kind != spec.Kind {
			return fmt.Errorf("%w: argument %q has the wrong type", ErrInvalidCall, spec.Name)
		}
		if err := validateValue(spec, value); err != nil {
			return fmt.Errorf("%w: argument %q: %v", ErrInvalidCall, spec.Name, err)
		}
		delete(byName, spec.Name)
	}
	if len(byName) != 0 {
		return fmt.Errorf("%w: unknown argument", ErrInvalidCall)
	}
	return nil
}

func validateValue(spec ArgumentSpec, value ArgumentValue) error {
	switch spec.Kind {
	case ArgumentString:
		return validateString(spec, value.String)
	case ArgumentInteger:
		if value.Integer < spec.Minimum || value.Integer > spec.Maximum {
			return errors.New("integer is outside bounds")
		}
	case ArgumentTimestamp:
		if value.Timestamp.IsZero() {
			return errors.New("timestamp is required")
		}
	case ArgumentStringList:
		if len(value.StringList) < spec.MinItems || len(value.StringList) > spec.MaxItems {
			return errors.New("item count is outside bounds")
		}
		seen := map[string]struct{}{}
		for _, item := range value.StringList {
			if err := validateString(spec, item); err != nil {
				return err
			}
			if _, duplicate := seen[item]; duplicate {
				return errors.New("list contains a duplicate")
			}
			seen[item] = struct{}{}
		}
	}
	return nil
}

func validateString(spec ArgumentSpec, value string) error {
	if len(value) > spec.MaxLength || strings.IndexByte(value, 0) >= 0 {
		return errors.New("string is outside bounds")
	}
	if len(spec.AllowedValues) > 0 && !slices.Contains(spec.AllowedValues, value) {
		return errors.New("value is not in the allow-list")
	}
	if spec.Pattern != "" && !regexp.MustCompile(spec.Pattern).MatchString(value) {
		return errors.New("value does not match the required form")
	}
	return nil
}

func decodeUniqueObject(raw []byte) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, errors.New("arguments must be one JSON object")
	}
	result := make(map[string]json.RawMessage)
	for decoder.More() {
		token, err = decoder.Token()
		if err != nil {
			return nil, errors.New("argument property is invalid")
		}
		name, ok := token.(string)
		if !ok || !validToken(name) {
			return nil, errors.New("argument property name is invalid")
		}
		if _, duplicate := result[name]; duplicate {
			return nil, fmt.Errorf("argument property %q is duplicated", name)
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, errors.New("argument value is invalid")
		}
		result[name] = slices.Clone(value)
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim('}') {
		return nil, errors.New("arguments object is incomplete")
	}
	if _, err = decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("arguments contain trailing content")
	}
	return result, nil
}

func decodeRequired[T any](object map[string]json.RawMessage, name string, destination *T) error {
	value, ok := object[name]
	if !ok {
		return fmt.Errorf("required property %q is missing", name)
	}
	if err := json.Unmarshal(value, destination); err != nil {
		return fmt.Errorf("property %q has the wrong type", name)
	}
	delete(object, name)
	return nil
}

func decodeArgument(spec ArgumentSpec, raw json.RawMessage) (ArgumentValue, error) {
	switch spec.Kind {
	case ArgumentString:
		var value string
		if err := json.Unmarshal(raw, &value); err != nil {
			return ArgumentValue{}, errors.New("must be a string")
		}
		return String(spec.Name, value), nil
	case ArgumentInteger:
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		var number json.Number
		if err := decoder.Decode(&number); err != nil {
			return ArgumentValue{}, errors.New("must be an integer")
		}
		value, err := strconv.ParseInt(string(number), 10, 64)
		if err != nil {
			return ArgumentValue{}, errors.New("must be an integer")
		}
		return Integer(spec.Name, value), nil
	case ArgumentBoolean:
		var value bool
		if err := json.Unmarshal(raw, &value); err != nil {
			return ArgumentValue{}, errors.New("must be a boolean")
		}
		return Boolean(spec.Name, value), nil
	case ArgumentTimestamp:
		var encoded string
		if err := json.Unmarshal(raw, &encoded); err != nil {
			return ArgumentValue{}, errors.New("must be an RFC3339 string")
		}
		value, err := time.Parse(time.RFC3339Nano, encoded)
		if err != nil {
			return ArgumentValue{}, errors.New("must be an RFC3339 string")
		}
		return Timestamp(spec.Name, value), nil
	case ArgumentStringList:
		var value []string
		if err := json.Unmarshal(raw, &value); err != nil || value == nil {
			return ArgumentValue{}, errors.New("must be a string array")
		}
		return StringList(spec.Name, value), nil
	default:
		return ArgumentValue{}, errors.New("has an unsupported type")
	}
}

func argumentSchema(definition Definition, filter Filter) (json.RawMessage, error) {
	properties := []schemaProperty{
		{Name: "targets", Type: "array", Description: "Explicit targets within the investigation scope.", MinItems: intPointer(1), MaxItems: intPointer(definition.Scope.MaxTargets), UniqueItems: true, ItemType: "string", ItemEnum: slices.Clone(filter.Scope.EntityIDs)},
		{Name: "start", Type: "string", Description: "Inclusive RFC3339 range start within the investigation scope.", Format: "date-time"},
		{Name: "end", Type: "string", Description: "Inclusive RFC3339 range end within the investigation scope.", Format: "date-time"},
	}
	ordered := slices.Clone(definition.Arguments)
	slices.SortFunc(ordered, func(a, b ArgumentSpec) int { return strings.Compare(a.Name, b.Name) })
	required := []string{"targets", "start", "end"}
	for _, spec := range ordered {
		item := schemaProperty{Name: spec.Name, Description: spec.Description, Enum: slices.Clone(spec.AllowedValues), Pattern: spec.Pattern}
		switch spec.Kind {
		case ArgumentString:
			item.Type, item.MaxLength = "string", intPointer(spec.MaxLength)
		case ArgumentInteger:
			item.Type, item.Minimum, item.Maximum = "integer", int64Pointer(spec.Minimum), int64Pointer(spec.Maximum)
		case ArgumentBoolean:
			item.Type = "boolean"
		case ArgumentTimestamp:
			item.Type, item.Format = "string", "date-time"
		case ArgumentStringList:
			item.Type, item.MinItems, item.MaxItems, item.UniqueItems, item.ItemType, item.ItemEnum, item.ItemPattern, item.ItemMaxLength = "array", intPointer(spec.MinItems), intPointer(spec.MaxItems), true, "string", slices.Clone(spec.AllowedValues), spec.Pattern, intPointer(spec.MaxLength)
		}
		properties = append(properties, item)
		if spec.Required {
			required = append(required, spec.Name)
		}
	}
	// Build properties as raw JSON so the public schema uses standard JSON
	// Schema property names rather than exposing the intermediate typed form.
	var buffer bytes.Buffer
	buffer.WriteString(`{"type":"object","additionalProperties":false,"properties":{`)
	for index, item := range properties {
		if index > 0 {
			buffer.WriteByte(',')
		}
		name, _ := json.Marshal(item.Name)
		buffer.Write(name)
		buffer.WriteByte(':')
		encoded, err := encodeSchemaProperty(item)
		if err != nil {
			return nil, err
		}
		buffer.Write(encoded)
	}
	buffer.WriteString(`},"required":`)
	encodedRequired, _ := json.Marshal(required)
	buffer.Write(encodedRequired)
	buffer.WriteByte('}')
	return json.RawMessage(buffer.Bytes()), nil
}

type schemaProperty struct {
	Name          string   `json:"name"`
	Type          string   `json:"type"`
	Description   string   `json:"description,omitempty"`
	Format        string   `json:"format,omitempty"`
	Enum          []string `json:"enum,omitempty"`
	Pattern       string   `json:"pattern,omitempty"`
	Minimum       *int64   `json:"minimum,omitempty"`
	Maximum       *int64   `json:"maximum,omitempty"`
	MinLength     *int     `json:"minLength,omitempty"`
	MaxLength     *int     `json:"maxLength,omitempty"`
	MinItems      *int     `json:"minItems,omitempty"`
	MaxItems      *int     `json:"maxItems,omitempty"`
	UniqueItems   bool     `json:"uniqueItems,omitempty"`
	ItemType      string   `json:"item_type,omitempty"`
	ItemEnum      []string `json:"item_enum,omitempty"`
	ItemPattern   string   `json:"item_pattern,omitempty"`
	ItemMaxLength *int     `json:"item_max_length,omitempty"`
}

type emittedSchemaProperty struct {
	Type        string             `json:"type"`
	Description string             `json:"description,omitempty"`
	Format      string             `json:"format,omitempty"`
	Enum        []string           `json:"enum,omitempty"`
	Pattern     string             `json:"pattern,omitempty"`
	Minimum     *int64             `json:"minimum,omitempty"`
	Maximum     *int64             `json:"maximum,omitempty"`
	MaxLength   *int               `json:"maxLength,omitempty"`
	MinItems    *int               `json:"minItems,omitempty"`
	MaxItems    *int               `json:"maxItems,omitempty"`
	UniqueItems bool               `json:"uniqueItems,omitempty"`
	Items       *emittedSchemaItem `json:"items,omitempty"`
}

type emittedSchemaItem struct {
	Type      string   `json:"type"`
	Enum      []string `json:"enum,omitempty"`
	Pattern   string   `json:"pattern,omitempty"`
	MaxLength *int     `json:"maxLength,omitempty"`
}

func encodeSchemaProperty(value schemaProperty) ([]byte, error) {
	emitted := emittedSchemaProperty{Type: value.Type, Description: value.Description, Format: value.Format, Enum: value.Enum, Pattern: value.Pattern, Minimum: value.Minimum, Maximum: value.Maximum, MaxLength: value.MaxLength, MinItems: value.MinItems, MaxItems: value.MaxItems, UniqueItems: value.UniqueItems}
	if value.ItemType != "" {
		emitted.Items = &emittedSchemaItem{Type: value.ItemType, Enum: value.ItemEnum, Pattern: value.ItemPattern, MaxLength: value.ItemMaxLength}
	}
	return json.Marshal(emitted)
}

func intPointer(value int) *int       { return &value }
func int64Pointer(value int64) *int64 { return &value }

func allows(definition Definition, filter Filter) bool {
	return (!definition.Diagnostic() || filter.AllowDiagnostics) &&
		slices.Contains(definition.AllowedClusters, filter.ClusterID) &&
		containsAll(filter.ActorCapabilities, definition.RequiredCapabilities) &&
		containsAll(filter.ClusterCapabilities, definition.RequiredClusterCapabilities) &&
		slices.Contains(definition.Scope.EntityKinds, filter.Scope.EntityKind)
}

func containsAll[T comparable](available, required []T) bool {
	for _, wanted := range required {
		if !slices.Contains(available, wanted) {
			return false
		}
	}
	return true
}

func cloneDefinition(value Definition) Definition {
	value.AllowedClusters = slices.Clone(value.AllowedClusters)
	value.RequiredCapabilities = slices.Clone(value.RequiredCapabilities)
	value.RequiredClusterCapabilities = slices.Clone(value.RequiredClusterCapabilities)
	value.Scope.EntityKinds = slices.Clone(value.Scope.EntityKinds)
	value.Arguments = slices.Clone(value.Arguments)
	for i := range value.Arguments {
		value.Arguments[i].AllowedValues = slices.Clone(value.Arguments[i].AllowedValues)
	}
	return value
}

func findArgument(specs []ArgumentSpec, name string) ArgumentSpec {
	for _, spec := range specs {
		if spec.Name == name {
			return spec
		}
	}
	return ArgumentSpec{}
}
func validToken(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._:-", r)) {
			return false
		}
	}
	return true
}
func uniqueNonEmptyClusters(values []domain.ClusterID) error {
	seen := map[domain.ClusterID]struct{}{}
	for _, value := range values {
		if value == "" {
			return errors.New("cluster allow-list contains an empty identifier")
		}
		if _, ok := seen[value]; ok {
			return errors.New("cluster allow-list contains a duplicate")
		}
		seen[value] = struct{}{}
	}
	return nil
}
func uniqueTokens(values []string) error {
	for _, value := range values {
		if !validToken(value) {
			return errors.New("scope contains an invalid token")
		}
	}
	return uniqueTokensOrText(values)
}
func uniqueTokensOrText(values []string) error {
	seen := map[string]struct{}{}
	for _, value := range values {
		if len(value) > 512 || strings.IndexByte(value, 0) >= 0 {
			return errors.New("allow-list value is invalid")
		}
		if _, ok := seen[value]; ok {
			return errors.New("allow-list contains a duplicate")
		}
		seen[value] = struct{}{}
	}
	return nil
}
func uniqueCapabilities(actor []auth.Capability, cluster []ClusterCapability) error {
	seenActor := map[auth.Capability]struct{}{}
	for _, value := range actor {
		if _, err := auth.ParseCapability(string(value)); err != nil {
			return errors.New("unknown actor capability")
		}
		if _, ok := seenActor[value]; ok {
			return errors.New("actor capability contains a duplicate")
		}
		seenActor[value] = struct{}{}
	}
	seenCluster := map[ClusterCapability]struct{}{}
	for _, value := range cluster {
		if !validToken(string(value)) {
			return errors.New("cluster capability is invalid")
		}
		if _, ok := seenCluster[value]; ok {
			return errors.New("cluster capability contains a duplicate")
		}
		seenCluster[value] = struct{}{}
	}
	return nil
}
