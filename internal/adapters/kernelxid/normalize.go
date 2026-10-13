// Package kernelxid normalizes the fixed, signed node.kernel_xid diagnostic.
//
// It intentionally understands only node.kernel_xid@2.0.0. This is not a
// general journal parser and it must not become one: the signed command has a
// fixed seven-day, 2,000-line, 4 MiB window. Its output can provide bounded
// evidence for one bounded diagnostic capture, never an incremental cursor or
// proof that a node has no XID events outside that capture.
package kernelxid

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/verticalcomputer/sherlock/internal/commandpack"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

const (
	ParserVersion     = "sherlock.kernel-xid.v1"
	DefinitionID      = domain.DiagnosticDefinitionID("node.kernel_xid")
	DefinitionVersion = "2.0.0"
	Lookback          = 7 * 24 * time.Hour
	maxRenderedEvents = 32
)

type Disposition string

const (
	DispositionBounded     Disposition = "BOUNDED"
	DispositionNoData      Disposition = "NO_ROWS_OBSERVED_BOUNDED"
	DispositionPartial     Disposition = "PARTIAL"
	DispositionUnavailable Disposition = "UNAVAILABLE"
)

type Gap string

const (
	GapTargetUnavailable Gap = "TARGET_UNAVAILABLE"
	GapTargetFailed      Gap = "TARGET_COMMAND_FAILED"
	GapTargetTimedOut    Gap = "TARGET_COMMAND_TIMED_OUT"
	GapTargetRejected    Gap = "TARGET_ACCESS_REJECTED"
	GapOutputTruncated   Gap = "OUTPUT_TRUNCATED"
	GapOutputTransformed Gap = "OUTPUT_TRANSFORMED"
	GapOutputUnknown     Gap = "OUTPUT_TRANSFORMATION_UNKNOWN"
	GapMalformedRecord   Gap = "MALFORMED_RECORD"
	GapOutsideWindow     Gap = "OUTSIDE_DECLARED_WINDOW"
	GapEventLimit        Gap = "NORMALIZED_EVENT_LIMIT"
	GapLineCapReached    Gap = "SOURCE_LINE_CAP_REACHED"
	GapOutputInvalid     Gap = "OUTPUT_NOT_TEXT"
)

// DeclaredLimit identifies a fixed property of the signed diagnostic. Limits
// are not observations of a particular execution, but they prevent a bounded
// result from being mistaken for complete or continuous history.
type DeclaredLimit string

const (
	LimitFixedWindow DeclaredLimit = "FIXED_WINDOW_7D_NOT_CONTINUOUS"
	LimitLineCap     DeclaredLimit = "SOURCE_LINE_CAP_2000"
	LimitOutputCap   DeclaredLimit = "SOURCE_OUTPUT_CAP_4_MIB"
)

// Event is intentionally not an event identity. Equal values remain separate
// elements in source order because signed journal text and journald do not
// establish a stable unique identity for an XID event.
type Event struct {
	ObservedAt time.Time `json:"observed_at"`
	XIDCode    int       `json:"xid_code"`
	// PCIBDF is normalized source context only. It is neither stable GPU nor
	// event identity, and cannot justify deduplication.
	PCIBDF string `json:"pci_bdf"`
}

type TargetEvidence struct {
	ParserVersion           string          `json:"parser_version"`
	SourceDefinition        string          `json:"source_definition"`
	SourceDefinitionVersion string          `json:"source_definition_version"`
	Target                  string          `json:"target"`
	ObservedFrom            time.Time       `json:"observed_from"`
	ObservedTo              time.Time       `json:"observed_to"`
	DeclaredLimits          []DeclaredLimit `json:"declared_limits"`
	Disposition             Disposition     `json:"disposition"`
	Events                  []Event         `json:"events"`
	Gaps                    []Gap           `json:"gaps"`
	// SourceOutputUnmodified reports only the runner's transformation
	// provenance. It is not event identity and does not establish full source
	// coverage.
	SourceOutputUnmodified bool `json:"source_output_unmodified"`
}

type Result struct {
	ObservedFrom time.Time
	ObservedTo   time.Time
	Targets      []TargetEvidence
}

// SourceTarget holds complete screened runner bytes before generic excerpt
// sampling. It deliberately does not use DiagnosticTargetResult.StdoutExcerpt.
type SourceTarget struct {
	Target                    domain.DiagnosticTarget
	Status                    domain.DiagnosticTargetStatus
	Stdout                    []byte
	StdoutTruncated           bool
	StdoutTransformationState domain.StdoutTransformationState
}

// The documented short-ISO record shape is anchored completely. The trailing
// driver message is intentionally discarded rather than partially interpreted.
var xidLine = regexp.MustCompile(`^([^[:space:]]+) [^[:space:]]+ kernel: NVRM: Xid \(PCI:([0-9A-Fa-f]{4}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}(?:\.[0-7])?)\): ([0-9]+),[^\r\n]*$`)

// VerifiedDefinition fences parser selection to the locally verified catalog
// definition and matching request/result digests, not ID/version alone.
func VerifiedDefinition(catalog *commandpack.Catalog, request domain.DiagnosticRequest, resultID, resultVersion, resultDigest string) bool {
	if catalog == nil || request.Definition.DefinitionID != DefinitionID || request.Definition.DefinitionVersion != DefinitionVersion || resultID != string(DefinitionID) || resultVersion != DefinitionVersion {
		return false
	}
	packID, packVersion := catalog.PackIdentity()
	if packID != request.Definition.PackID || packVersion != request.Definition.PackVersion {
		return false
	}
	definition, digest, found := catalog.Lookup(string(DefinitionID), DefinitionVersion)
	if !found || digest != request.Definition.DefinitionDigest.String() || digest != resultDigest {
		return false
	}
	if definition.OutputSchema != "kernel.xid.v1" || definition.RequiresPrivilege || len(definition.Parameters) != 0 || definition.Limits.TimeoutSeconds != 30 || definition.Limits.MaximumOutputBytes != 4<<20 || definition.Limits.MaximumConcurrency != 8 {
		return false
	}
	want := []string{"--dmesg", "--utc", "--no-pager", "--output=short-iso", "--grep=NVRM: Xid", "--since=-7 days", "--lines=2000"}
	if len(definition.Arguments) != len(want) {
		return false
	}
	for index, value := range want {
		if definition.Arguments[index].Literal != value || definition.Arguments[index].Parameter != "" {
			return false
		}
	}
	return true
}

// Normalize accepts complete screened runner bytes and produces one typed result
// per requested node. It never includes a journal line, hostname, query,
// credential, source error, or trailing message in normalized output.
func Normalize(request domain.DiagnosticRequest, startedAt, completedAt time.Time, targets []SourceTarget) (Result, error) {
	if err := request.Validate(); err != nil {
		return Result{}, fmt.Errorf("kernel XID request is invalid: %w", err)
	}
	if request.Definition.DefinitionID != DefinitionID || request.Definition.DefinitionVersion != DefinitionVersion {
		return Result{}, fmt.Errorf("kernel XID normalizer only accepts %s@%s", DefinitionID, DefinitionVersion)
	}
	if startedAt.IsZero() || completedAt.Before(startedAt) || len(targets) != len(request.Targets) {
		return Result{}, fmt.Errorf("kernel XID source timing or coverage is invalid")
	}
	result := Result{ObservedFrom: startedAt.Add(-Lookback).UTC(), ObservedTo: completedAt.UTC(), Targets: make([]TargetEvidence, 0, len(targets))}
	for index, target := range targets {
		if target.Target != request.Targets[index] {
			return Result{}, fmt.Errorf("kernel XID source target scope is invalid")
		}
		result.Targets = append(result.Targets, normalizeTarget(target, result.ObservedFrom, result.ObservedTo))
	}
	return result, nil
}

func normalizeTarget(target SourceTarget, observedFrom, observedTo time.Time) TargetEvidence {
	result := TargetEvidence{
		ParserVersion: ParserVersion, SourceDefinition: string(DefinitionID), SourceDefinitionVersion: DefinitionVersion,
		Target: string(target.Target), ObservedFrom: observedFrom, ObservedTo: observedTo,
		DeclaredLimits:         []DeclaredLimit{LimitFixedWindow, LimitLineCap, LimitOutputCap},
		SourceOutputUnmodified: target.StdoutTransformationState == domain.StdoutTransformationUnmodified,
	}
	if target.Status != domain.DiagnosticTargetSucceeded {
		result.Disposition = DispositionUnavailable
		return unavailableTarget(result, target.Status)
	}
	if target.StdoutTruncated {
		result = withGap(result, GapOutputTruncated)
	}
	switch target.StdoutTransformationState {
	case domain.StdoutTransformationUnmodified:
	case domain.StdoutTransformationTransformed:
		result = withGap(result, GapOutputTransformed)
	default:
		result = withGap(result, GapOutputUnknown)
	}

	if !utf8.Valid(target.Stdout) || bytes.IndexByte(target.Stdout, 0) >= 0 {
		return finishTarget(withGap(result, GapOutputInvalid))
	}
	nonempty := 0
	for _, line := range strings.Split(string(target.Stdout), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		nonempty++
		at, code, pci, ok := parseLine(line)
		if !ok {
			result = withGap(result, GapMalformedRecord)
			continue
		}
		if at.Before(observedFrom) || at.After(observedTo) {
			result = withGap(result, GapOutsideWindow)
			continue
		}
		result.Events = append(result.Events, Event{ObservedAt: at, XIDCode: code, PCIBDF: pci})
	}
	if nonempty >= 2000 {
		result = withGap(result, GapLineCapReached)
	}
	return finishTarget(result)
}

func finishTarget(result TargetEvidence) TargetEvidence {
	switch {
	case len(result.Events) == 0 && len(result.Gaps) == 0:
		result.Disposition = DispositionNoData
	case len(result.Gaps) == 0:
		result.Disposition = DispositionBounded
	default:
		result.Disposition = DispositionPartial
	}
	return result
}

func unavailableTarget(result TargetEvidence, status domain.DiagnosticTargetStatus) TargetEvidence {
	result = withGap(result, GapTargetUnavailable)
	switch status {
	case domain.DiagnosticTargetFailed:
		return withGap(result, GapTargetFailed)
	case domain.DiagnosticTargetTimedOut:
		return withGap(result, GapTargetTimedOut)
	case domain.DiagnosticTargetRejected:
		return withGap(result, GapTargetRejected)
	default:
		return result
	}
}

func parseLine(line string) (time.Time, int, string, bool) {
	match := xidLine.FindStringSubmatch(line)
	if len(match) != 4 {
		return time.Time{}, 0, "", false
	}
	at, err := parseTimestamp(match[1])
	if err != nil {
		return time.Time{}, 0, "", false
	}
	code, err := strconv.Atoi(match[3])
	if err != nil || code < 0 || code > 9999 {
		return time.Time{}, 0, "", false
	}
	return at, code, strings.ToLower(match[2]), true
}

func parseTimestamp(value string) (time.Time, error) {
	for _, layout := range []string{"2006-01-02T15:04:05.999999-0700", "2006-01-02T15:04:05-0700"} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("invalid short-iso timestamp")
}

func withGap(result TargetEvidence, gap Gap) TargetEvidence {
	if !slices.Contains(result.Gaps, gap) {
		result.Gaps = append(result.Gaps, gap)
	}
	return result
}

// RenderTarget serializes only bounded, typed values for the diagnostic excerpt
// store. If the normalized representation would exceed its inherited excerpt
// limit, it removes only trailing events and records that loss explicitly.
func RenderTarget(target TargetEvidence) (string, error) {
	result := target
	for {
		encoded, err := json.Marshal(result)
		if err != nil {
			return "", fmt.Errorf("encode kernel XID evidence: %w", err)
		}
		if len(encoded) <= domain.MaxDiagnosticStdoutExcerptBytes {
			return string(encoded), nil
		}
		if len(result.Events) == 0 {
			return "", fmt.Errorf("kernel XID normalized evidence exceeds excerpt bound")
		}
		if len(result.Events) > maxRenderedEvents {
			result.Events = slices.Clone(result.Events[:maxRenderedEvents])
		} else {
			result.Events = slices.Clone(result.Events[:len(result.Events)-1])
		}
		result = withGap(result, GapEventLimit)
		result.Disposition = DispositionPartial
	}
}
