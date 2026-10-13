package domain

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"
	"time"
)

// KernelXIDArtifactSchemaVersion names the only durable representation that
// GP-06d permits. It contains structured facts from the signed diagnostic, not
// journal text, hostnames, paths, labels, or source messages.
const (
	KernelXIDArtifactSchemaVersion    = "sherlock.kernel-xid-artifact.v1"
	KernelXIDArtifactParserVersion    = "sherlock.kernel-xid.v1"
	KernelXIDArtifactRedactionVersion = "sherlock.kernel-xid-redaction.v1"
	MaxKernelXIDArtifactBytes         = 4096
	MaxKernelXIDArtifactEvents        = 32
)

type KernelXIDArtifactDisposition string

const (
	KernelXIDArtifactBounded     KernelXIDArtifactDisposition = "BOUNDED"
	KernelXIDArtifactNoRows      KernelXIDArtifactDisposition = "NO_ROWS_OBSERVED_BOUNDED"
	KernelXIDArtifactPartial     KernelXIDArtifactDisposition = "PARTIAL"
	KernelXIDArtifactUnavailable KernelXIDArtifactDisposition = "UNAVAILABLE"
)

type KernelXIDArtifactGap string

const (
	KernelXIDArtifactGapTargetUnavailable KernelXIDArtifactGap = "TARGET_UNAVAILABLE"
	KernelXIDArtifactGapTargetFailed      KernelXIDArtifactGap = "TARGET_COMMAND_FAILED"
	KernelXIDArtifactGapTargetTimedOut    KernelXIDArtifactGap = "TARGET_COMMAND_TIMED_OUT"
	KernelXIDArtifactGapTargetRejected    KernelXIDArtifactGap = "TARGET_ACCESS_REJECTED"
	KernelXIDArtifactGapOutputTruncated   KernelXIDArtifactGap = "OUTPUT_TRUNCATED"
	KernelXIDArtifactGapOutputTransformed KernelXIDArtifactGap = "OUTPUT_TRANSFORMED"
	KernelXIDArtifactGapOutputUnknown     KernelXIDArtifactGap = "OUTPUT_TRANSFORMATION_UNKNOWN"
	KernelXIDArtifactGapMalformedRecord   KernelXIDArtifactGap = "MALFORMED_RECORD"
	KernelXIDArtifactGapOutsideWindow     KernelXIDArtifactGap = "OUTSIDE_DECLARED_WINDOW"
	KernelXIDArtifactGapNormalizedLimit   KernelXIDArtifactGap = "NORMALIZED_EVENT_LIMIT"
	KernelXIDArtifactGapLineCap           KernelXIDArtifactGap = "SOURCE_LINE_CAP_REACHED"
	KernelXIDArtifactGapOutputInvalid     KernelXIDArtifactGap = "OUTPUT_NOT_TEXT"
	KernelXIDArtifactGapArtifactLimit     KernelXIDArtifactGap = "ARTIFACT_EVENT_LIMIT"
	KernelXIDArtifactGapScreeningFailure  KernelXIDArtifactGap = "ARTIFACT_SCREENING_FAILED"
	KernelXIDArtifactGapMissing           KernelXIDArtifactGap = "ARTIFACT_MISSING"
	KernelXIDArtifactGapExpired           KernelXIDArtifactGap = "ARTIFACT_EXPIRED"
	KernelXIDArtifactGapDeleted           KernelXIDArtifactGap = "ARTIFACT_DELETED"
	KernelXIDArtifactGapChecksumMismatch  KernelXIDArtifactGap = "ARTIFACT_CHECKSUM_MISMATCH"
	KernelXIDArtifactGapCorrupt           KernelXIDArtifactGap = "ARTIFACT_CORRUPT"
	KernelXIDArtifactGapBindingMismatch   KernelXIDArtifactGap = "ARTIFACT_BINDING_MISMATCH"
)

type KernelXIDArtifactEvent struct {
	ObservedAt time.Time `json:"observed_at"`
	XIDCode    int       `json:"xid_code"`
	// PCIBDF is source context only. It is not an event or GPU identity.
	PCIBDF string `json:"pci_bdf"`
}

// KernelXIDArtifactBinding is provenance, not source output. It binds the
// checksummed body to one signed diagnostic result without retaining journal
// text, a journal hostname, path, label, query, or credential.
type KernelXIDArtifactBinding struct {
	ClusterID          ClusterID              `json:"cluster_id"`
	RunID              DiagnosticRunID        `json:"run_id"`
	WorkID             DiagnosticWorkID       `json:"work_id"`
	Attempt            int                    `json:"attempt"`
	Target             DiagnosticTarget       `json:"target"`
	PackID             string                 `json:"pack_id"`
	PackVersion        string                 `json:"pack_version"`
	DefinitionID       DiagnosticDefinitionID `json:"definition_id"`
	DefinitionVersion  string                 `json:"definition_version"`
	DefinitionDigest   SHA256                 `json:"definition_digest"`
	SourceStdoutSHA256 SHA256                 `json:"source_stdout_sha256"`
}

// KernelXIDArtifact contains exactly the canonical bytes stored by the narrow
// GP-06d store and their checksum. The source diagnostic's raw output is not
// represented by this type.
type KernelXIDArtifact struct {
	bytes       []byte
	checksum    SHA256
	eventCount  int
	truncated   bool
	disposition KernelXIDArtifactDisposition
	gaps        []KernelXIDArtifactGap
	binding     *KernelXIDArtifactBinding
}

func (artifact KernelXIDArtifact) Bytes() []byte   { return slices.Clone(artifact.bytes) }
func (artifact KernelXIDArtifact) SHA256() SHA256  { return artifact.checksum }
func (artifact KernelXIDArtifact) EventCount() int { return artifact.eventCount }
func (artifact KernelXIDArtifact) Truncated() bool { return artifact.truncated }
func (artifact KernelXIDArtifact) Disposition() KernelXIDArtifactDisposition {
	return artifact.disposition
}
func (artifact KernelXIDArtifact) Gaps() []KernelXIDArtifactGap { return slices.Clone(artifact.gaps) }
func (artifact KernelXIDArtifact) HasGap(gap KernelXIDArtifactGap) bool {
	return slices.Contains(artifact.gaps, gap)
}
func (artifact KernelXIDArtifact) Binding() (KernelXIDArtifactBinding, bool) {
	if artifact.binding == nil {
		return KernelXIDArtifactBinding{}, false
	}
	return *artifact.binding, true
}

type KernelXIDArtifactInput struct {
	ObservedFrom   time.Time
	ObservedTo     time.Time
	Disposition    KernelXIDArtifactDisposition
	DeclaredLimits []string
	Gaps           []KernelXIDArtifactGap
	Events         []KernelXIDArtifactEvent
	Binding        *KernelXIDArtifactBinding
}

type kernelXIDArtifactWire struct {
	SchemaVersion    string                        `json:"schema_version"`
	ParserVersion    string                        `json:"parser_version"`
	RedactionVersion string                        `json:"redaction_version"`
	ObservedFrom     time.Time                     `json:"observed_from"`
	ObservedTo       time.Time                     `json:"observed_to"`
	Disposition      KernelXIDArtifactDisposition  `json:"disposition"`
	DeclaredLimits   []string                      `json:"declared_limits"`
	Gaps             []KernelXIDArtifactGap        `json:"gaps"`
	Events           []KernelXIDArtifactEvent      `json:"events"`
	Binding          *kernelXIDArtifactBindingWire `json:"binding,omitempty"`
}

type kernelXIDArtifactBindingWire struct {
	ClusterID          ClusterID              `json:"cluster_id"`
	RunID              DiagnosticRunID        `json:"run_id"`
	WorkID             DiagnosticWorkID       `json:"work_id"`
	Attempt            int                    `json:"attempt"`
	Target             DiagnosticTarget       `json:"target"`
	PackID             string                 `json:"pack_id"`
	PackVersion        string                 `json:"pack_version"`
	DefinitionID       DiagnosticDefinitionID `json:"definition_id"`
	DefinitionVersion  string                 `json:"definition_version"`
	DefinitionDigest   string                 `json:"definition_digest"`
	SourceStdoutSHA256 string                 `json:"source_stdout_sha256"`
}

var kernelXIDPCI = regexp.MustCompile(`^[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}(?:\.[0-7])?$`)

func NewKernelXIDArtifact(input KernelXIDArtifactInput) (KernelXIDArtifact, error) {
	if err := validateKernelXIDArtifactInput(input); err != nil {
		return KernelXIDArtifact{}, err
	}
	wire := kernelXIDArtifactWire{
		SchemaVersion: KernelXIDArtifactSchemaVersion, ParserVersion: KernelXIDArtifactParserVersion,
		RedactionVersion: KernelXIDArtifactRedactionVersion,
		ObservedFrom:     input.ObservedFrom.UTC().Truncate(time.Microsecond),
		ObservedTo:       input.ObservedTo.UTC().Truncate(time.Microsecond),
		Disposition:      input.Disposition,
		DeclaredLimits:   sortedStrings(input.DeclaredLimits), Gaps: sortedArtifactGaps(input.Gaps),
		Events: normalizedArtifactEvents(input.Events), Binding: kernelXIDArtifactBindingWireFrom(input.Binding),
	}
	payload, err := json.Marshal(wire)
	if err != nil {
		return KernelXIDArtifact{}, fmt.Errorf("encode kernel XID artifact: %w", err)
	}
	if len(payload) > MaxKernelXIDArtifactBytes {
		return KernelXIDArtifact{}, fmt.Errorf("kernel XID artifact exceeds %d bytes", MaxKernelXIDArtifactBytes)
	}
	return KernelXIDArtifact{bytes: payload, checksum: ChecksumSHA256(payload), eventCount: len(wire.Events), truncated: slices.Contains(wire.Gaps, KernelXIDArtifactGapArtifactLimit), disposition: wire.Disposition, gaps: slices.Clone(wire.Gaps), binding: cloneKernelXIDArtifactBinding(input.Binding)}, nil
}

// ParseKernelXIDArtifact accepts only exact canonical bytes. Re-marshalling the
// decoded value must reproduce the input, so insignificant JSON variations or
// unreviewed fields cannot enter durable artifact storage.
func ParseKernelXIDArtifact(payload []byte) (KernelXIDArtifact, error) {
	return parseKernelXIDArtifact(payload, true)
}

// BindKernelXIDArtifact creates the only form allowed across the durable
// storage boundary. Its checksum covers both structured event facts and exact
// run/work/attempt/target/definition/source-digest provenance.
func BindKernelXIDArtifact(artifact KernelXIDArtifact, binding KernelXIDArtifactBinding) (KernelXIDArtifact, error) {
	parsed, err := parseKernelXIDArtifact(artifact.Bytes(), false)
	if err != nil {
		return KernelXIDArtifact{}, err
	}
	if prior, bound := parsed.Binding(); bound && !KernelXIDArtifactBindingsEqual(prior, binding) {
		return KernelXIDArtifact{}, fmt.Errorf("kernel XID artifact is already bound to different provenance")
	}
	var wire kernelXIDArtifactWire
	if err := json.Unmarshal(parsed.Bytes(), &wire); err != nil {
		return KernelXIDArtifact{}, fmt.Errorf("decode screened kernel XID artifact: %w", err)
	}
	return NewKernelXIDArtifact(KernelXIDArtifactInput{
		ObservedFrom: wire.ObservedFrom, ObservedTo: wire.ObservedTo, Disposition: wire.Disposition,
		DeclaredLimits: wire.DeclaredLimits, Gaps: wire.Gaps, Events: wire.Events, Binding: &binding,
	})
}

func parseKernelXIDArtifact(payload []byte, requireBinding bool) (KernelXIDArtifact, error) {
	if len(payload) == 0 || len(payload) > MaxKernelXIDArtifactBytes {
		return KernelXIDArtifact{}, fmt.Errorf("kernel XID artifact byte length is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var wire kernelXIDArtifactWire
	if err := decoder.Decode(&wire); err != nil {
		return KernelXIDArtifact{}, fmt.Errorf("decode kernel XID artifact: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return KernelXIDArtifact{}, fmt.Errorf("kernel XID artifact has trailing JSON")
	}
	artifact, err := NewKernelXIDArtifact(KernelXIDArtifactInput{
		ObservedFrom: wire.ObservedFrom, ObservedTo: wire.ObservedTo, Disposition: wire.Disposition,
		DeclaredLimits: wire.DeclaredLimits, Gaps: wire.Gaps, Events: wire.Events, Binding: kernelXIDArtifactBindingFromWire(wire.Binding),
	})
	if err != nil {
		return KernelXIDArtifact{}, err
	}
	if wire.SchemaVersion != KernelXIDArtifactSchemaVersion || wire.ParserVersion != KernelXIDArtifactParserVersion || wire.RedactionVersion != KernelXIDArtifactRedactionVersion || (requireBinding && wire.Binding == nil) || !bytes.Equal(artifact.bytes, payload) {
		return KernelXIDArtifact{}, fmt.Errorf("kernel XID artifact is not canonical")
	}
	return artifact, nil
}

func validateKernelXIDArtifactInput(input KernelXIDArtifactInput) error {
	if input.ObservedFrom.IsZero() || input.ObservedTo.IsZero() || input.ObservedTo.Before(input.ObservedFrom) {
		return fmt.Errorf("kernel XID artifact observation window is invalid")
	}
	switch input.Disposition {
	case KernelXIDArtifactBounded, KernelXIDArtifactNoRows, KernelXIDArtifactPartial, KernelXIDArtifactUnavailable:
	default:
		return fmt.Errorf("kernel XID artifact disposition is invalid")
	}
	if len(input.DeclaredLimits) != 3 || !slices.Equal(sortedStrings(input.DeclaredLimits), []string{"FIXED_WINDOW_7D_NOT_CONTINUOUS", "SOURCE_LINE_CAP_2000", "SOURCE_OUTPUT_CAP_4_MIB"}) {
		return fmt.Errorf("kernel XID artifact declared limits are invalid")
	}
	if len(input.Gaps) > 20 || !uniqueArtifactGaps(input.Gaps) {
		return fmt.Errorf("kernel XID artifact gaps are invalid")
	}
	for _, gap := range input.Gaps {
		if !validKernelXIDArtifactGap(gap) || lifecycleKernelXIDArtifactGap(gap) {
			return fmt.Errorf("kernel XID artifact gap is invalid")
		}
	}
	if len(input.Events) > MaxKernelXIDArtifactEvents {
		return fmt.Errorf("kernel XID artifact event count exceeds %d", MaxKernelXIDArtifactEvents)
	}
	for _, event := range input.Events {
		if event.ObservedAt.IsZero() || event.ObservedAt.Before(input.ObservedFrom) || event.ObservedAt.After(input.ObservedTo) || event.XIDCode < 0 || event.XIDCode > 9999 || !kernelXIDPCI.MatchString(event.PCIBDF) {
			return fmt.Errorf("kernel XID artifact event is invalid")
		}
	}
	if input.Disposition == KernelXIDArtifactBounded && (len(input.Events) == 0 || len(input.Gaps) != 0) {
		return fmt.Errorf("bounded kernel XID artifact requires events and cannot contain gaps")
	}
	if input.Disposition == KernelXIDArtifactNoRows && (len(input.Events) != 0 || len(input.Gaps) != 0) {
		return fmt.Errorf("no-rows kernel XID artifact cannot contain events or gaps")
	}
	if input.Disposition == KernelXIDArtifactPartial && len(input.Gaps) == 0 {
		return fmt.Errorf("partial kernel XID artifact requires a gap")
	}
	if input.Disposition == KernelXIDArtifactUnavailable && (len(input.Events) != 0 || !slices.Contains(input.Gaps, KernelXIDArtifactGapTargetUnavailable)) {
		return fmt.Errorf("unavailable kernel XID artifact requires no events and a target-unavailable gap")
	}
	if slices.Contains(input.Gaps, KernelXIDArtifactGapTargetUnavailable) && len(input.Events) != 0 {
		return fmt.Errorf("target-unavailable kernel XID artifact cannot contain events")
	}
	if input.Binding != nil {
		if err := input.Binding.validate(); err != nil {
			return fmt.Errorf("kernel XID artifact binding: %w", err)
		}
	}
	return nil
}

func (binding KernelXIDArtifactBinding) validate() error {
	if binding.ClusterID == "" || !validKernelXIDArtifactToken(string(binding.RunID)) || !validKernelXIDArtifactToken(string(binding.WorkID)) || !validKernelXIDArtifactToken(string(binding.Target)) || binding.Attempt < 1 || binding.Attempt > 3 || !validKernelXIDArtifactToken(binding.PackID) || !validKernelXIDArtifactToken(binding.PackVersion) || binding.DefinitionID != "node.kernel_xid" || binding.DefinitionVersion != "2.0.0" || binding.DefinitionDigest == (SHA256{}) || binding.SourceStdoutSHA256 == (SHA256{}) {
		return fmt.Errorf("invalid signed diagnostic scope")
	}
	return nil
}

func validKernelXIDArtifactToken(value string) bool {
	if len(value) < 1 || len(value) > 256 {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') && (character < '0' || character > '9') && character != '.' && character != '_' && character != ':' && character != '-' {
			return false
		}
	}
	return true
}

func cloneKernelXIDArtifactBinding(binding *KernelXIDArtifactBinding) *KernelXIDArtifactBinding {
	if binding == nil {
		return nil
	}
	value := *binding
	return &value
}

func kernelXIDArtifactBindingWireFrom(binding *KernelXIDArtifactBinding) *kernelXIDArtifactBindingWire {
	if binding == nil {
		return nil
	}
	return &kernelXIDArtifactBindingWire{
		ClusterID: binding.ClusterID, RunID: binding.RunID, WorkID: binding.WorkID, Attempt: binding.Attempt, Target: binding.Target,
		PackID: binding.PackID, PackVersion: binding.PackVersion, DefinitionID: binding.DefinitionID, DefinitionVersion: binding.DefinitionVersion,
		DefinitionDigest: binding.DefinitionDigest.String(), SourceStdoutSHA256: binding.SourceStdoutSHA256.String(),
	}
}

func kernelXIDArtifactBindingFromWire(binding *kernelXIDArtifactBindingWire) *KernelXIDArtifactBinding {
	if binding == nil {
		return nil
	}
	definitionDigest, definitionErr := ParseSHA256(binding.DefinitionDigest)
	sourceDigest, sourceErr := ParseSHA256(binding.SourceStdoutSHA256)
	if definitionErr != nil || sourceErr != nil {
		return nil
	}
	return &KernelXIDArtifactBinding{
		ClusterID: binding.ClusterID, RunID: binding.RunID, WorkID: binding.WorkID, Attempt: binding.Attempt, Target: binding.Target,
		PackID: binding.PackID, PackVersion: binding.PackVersion, DefinitionID: binding.DefinitionID, DefinitionVersion: binding.DefinitionVersion,
		DefinitionDigest: definitionDigest, SourceStdoutSHA256: sourceDigest,
	}
}

func normalizedArtifactEvents(events []KernelXIDArtifactEvent) []KernelXIDArtifactEvent {
	result := slices.Clone(events)
	for index := range result {
		result[index].ObservedAt = result[index].ObservedAt.UTC().Truncate(time.Microsecond)
		result[index].PCIBDF = strings.ToLower(result[index].PCIBDF)
	}
	return result
}

func sortedStrings(values []string) []string {
	result := slices.Clone(values)
	slices.Sort(result)
	return result
}
func sortedArtifactGaps(values []KernelXIDArtifactGap) []KernelXIDArtifactGap {
	result := slices.Clone(values)
	slices.Sort(result)
	return result
}
func uniqueArtifactGaps(values []KernelXIDArtifactGap) bool {
	return len(values) == len(slices.Compact(sortedArtifactGaps(values)))
}

func validKernelXIDArtifactGap(gap KernelXIDArtifactGap) bool {
	switch gap {
	case KernelXIDArtifactGapTargetUnavailable, KernelXIDArtifactGapTargetFailed, KernelXIDArtifactGapTargetTimedOut, KernelXIDArtifactGapTargetRejected,
		KernelXIDArtifactGapOutputTruncated, KernelXIDArtifactGapOutputTransformed, KernelXIDArtifactGapOutputUnknown, KernelXIDArtifactGapMalformedRecord,
		KernelXIDArtifactGapOutsideWindow, KernelXIDArtifactGapNormalizedLimit, KernelXIDArtifactGapLineCap, KernelXIDArtifactGapOutputInvalid,
		KernelXIDArtifactGapArtifactLimit, KernelXIDArtifactGapScreeningFailure, KernelXIDArtifactGapMissing, KernelXIDArtifactGapExpired,
		KernelXIDArtifactGapDeleted, KernelXIDArtifactGapChecksumMismatch, KernelXIDArtifactGapCorrupt, KernelXIDArtifactGapBindingMismatch:
		return true
	default:
		return false
	}
}

// Lifecycle gaps describe a failed read, not the bounded diagnostic source.
// They must never become part of durable artifact bytes.
func lifecycleKernelXIDArtifactGap(gap KernelXIDArtifactGap) bool {
	switch gap {
	case KernelXIDArtifactGapMissing, KernelXIDArtifactGapExpired, KernelXIDArtifactGapDeleted,
		KernelXIDArtifactGapChecksumMismatch, KernelXIDArtifactGapCorrupt, KernelXIDArtifactGapBindingMismatch:
		return true
	default:
		return false
	}
}

func KernelXIDArtifactBindingsEqual(left, right KernelXIDArtifactBinding) bool {
	leftBytes, leftErr := json.Marshal(kernelXIDArtifactBindingWireFrom(&left))
	rightBytes, rightErr := json.Marshal(kernelXIDArtifactBindingWireFrom(&right))
	return leftErr == nil && rightErr == nil && len(leftBytes) == len(rightBytes) && subtle.ConstantTimeCompare(leftBytes, rightBytes) == 1
}
