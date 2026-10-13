package loki

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/verticalcomputer/sherlock/internal/adapters/source"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

const (
	// ForwardPageSchemaVersion is the serializable, adapter-local cursor
	// contract. It is not a collector protocol cursor and has no persistence
	// authority in this packet.
	ForwardPageSchemaVersion = "sherlock.loki.forward-page.v1"
	maxPageOverlap           = time.Hour
	maxNormalizedLabelBytes  = 128
	maxNormalizedLabels      = 32
)

// PageDisposition says whether this response exposed more chronological rows,
// exhausted the queried range, or stopped at a timestamp tie. TERMINAL_* only
// describes this bounded response; it never proves that the requested historic
// range was retained or atomically queryable by Loki.
type PageDisposition string

const (
	PageMore              PageDisposition = "MORE"
	PageTerminalExhausted PageDisposition = "TERMINAL_EXHAUSTED"
	PageTerminalEmpty     PageDisposition = "TERMINAL_EMPTY"
	PageAmbiguousTie      PageDisposition = "AMBIGUOUS_TIMESTAMP_TIE"
	PageOverlapSaturated  PageDisposition = "OVERLAP_SATURATED"
)

// PageGap records loss or uncertainty that a durable ingestion packet must
// preserve. Returned events are deliberately never deduplicated here.
type PageGap string

const (
	PageGapRetention        PageGap = "RETENTION_GAP"
	PageGapCursorExpired    PageGap = "CURSOR_EXPIRED"
	PageGapTimestampTie     PageGap = "TIMESTAMP_TIE_AMBIGUOUS"
	PageGapOverlapSaturated PageGap = "OVERLAP_SATURATED_NO_PROGRESS"
)

type PageWindow struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// Continuation contains only bounded scope, a digest of the rendered
// allow-listed query, timestamps, and no source labels or log content. Its
// safe-through timestamp is inclusive: the next page starts with overlap at
// or before it and labels those returned rows as replay.
type Continuation struct {
	SchemaVersion    string     `json:"schema_version"`
	ClusterID        string     `json:"cluster_id"`
	SourceID         string     `json:"source_id"`
	TemplateID       string     `json:"template_id"`
	Node             string     `json:"node,omitempty"`
	SourceGeneration string     `json:"source_generation"`
	QueryDigest      string     `json:"query_digest"`
	RequestedWindow  PageWindow `json:"requested_window"`
	SafeThrough      *time.Time `json:"safe_through,omitempty"`
}

type PageRequest struct {
	ClusterID, SourceID, TemplateID, Node string
	// SourceGeneration is a required SHA-256 configuration or source-instance
	// fingerprint. It fences a cursor when a configured Loki source is
	// recreated or materially changed under the same source ID.
	SourceGeneration string
	Start, End       time.Time
	Limit            int
	Overlap          time.Duration
	Continuation     *Continuation
	// RetentionStart is an externally established, inclusive earliest
	// timestamp currently readable from this source. Loki query_range does not
	// return a retention proof; callers leave this nil when it is unknown.
	RetentionStart *time.Time
}

// PageEntry retains reviewed labels and records that its free-form log line
// was omitted. EvidenceUnmodified describes only the retained label values;
// it is never an event-identity claim.
type PageEntry struct {
	Timestamp          time.Time      `json:"timestamp"`
	Labels             []domain.Label `json:"labels"`
	LineOmitted        bool           `json:"line_omitted"`
	Replay             bool           `json:"replay"`
	EvidenceUnmodified bool           `json:"evidence_unmodified"`
	Redactions         int            `json:"redactions"`
}

type PageResult struct {
	Entries         []PageEntry     `json:"entries"`
	RequestedWindow PageWindow      `json:"requested_window"`
	EffectiveWindow PageWindow      `json:"effective_window"`
	Disposition     PageDisposition `json:"disposition"`
	Gaps            []PageGap       `json:"gaps,omitempty"`
	Continuation    Continuation    `json:"continuation"`
	BytesRead       int64           `json:"bytes_read"`
	StreamsReturned int             `json:"streams_returned"`
	ReplayedEntries int             `json:"replayed_entries"`
}

// ForwardPage reads one bounded chronological page. It requests one extra
// entry as a lookahead: when it shares the page boundary timestamp, the source
// has not supplied a tie-break identity and the continuation does not advance.
func (c *Client) ForwardPage(ctx context.Context, input PageRequest) (PageResult, error) {
	query, continuation, requested, effective, gaps, err := c.preparePage(input)
	if err != nil {
		return PageResult{}, err
	}
	// Keep one line of headroom for the tie lookahead while retaining the
	// adapter's configured byte and line ceilings.
	result, err := c.queryRange(ctx, query, effective.Start, effective.End, input.Limit+1, "FORWARD")
	if err != nil {
		return PageResult{}, err
	}
	if err := validatePageSourceWindow(result.Entries, effective); err != nil {
		return PageResult{}, err
	}
	page := PageResult{
		RequestedWindow: requested,
		EffectiveWindow: effective,
		Gaps:            gaps,
		Continuation:    continuation,
		BytesRead:       result.BytesRead,
		StreamsReturned: result.StreamsReturned,
	}
	entries := result.Entries
	if len(entries) > input.Limit {
		entries = entries[:input.Limit]
	}
	for _, entry := range entries {
		normalized := c.normalizePageEntry(entry, continuation.SafeThrough)
		if normalized.Replay {
			page.ReplayedEntries++
		}
		page.Entries = append(page.Entries, normalized)
	}
	if len(result.Entries) > input.Limit && len(entries) > 0 && result.Entries[input.Limit].Timestamp.Equal(entries[len(entries)-1].Timestamp) {
		page.Disposition = PageAmbiguousTie
		page.Gaps = append(page.Gaps, PageGapTimestampTie)
		if err := c.validateNormalizedPage(page); err != nil {
			return PageResult{}, err
		}
		return page, nil
	}
	if len(result.Entries) > input.Limit && len(page.Entries) > 0 && page.ReplayedEntries == len(page.Entries) {
		page.Disposition = PageOverlapSaturated
		page.Gaps = append(page.Gaps, PageGapOverlapSaturated)
		if err := c.validateNormalizedPage(page); err != nil {
			return PageResult{}, err
		}
		return page, nil
	}
	if len(entries) > 0 {
		safe := entries[len(entries)-1].Timestamp.UTC()
		if page.Continuation.SafeThrough == nil || safe.After(*page.Continuation.SafeThrough) {
			page.Continuation.SafeThrough = &safe
		}
	}
	switch {
	case len(result.Entries) == 0:
		page.Disposition = PageTerminalEmpty
	case len(result.Entries) <= input.Limit:
		page.Disposition = PageTerminalExhausted
	default:
		page.Disposition = PageMore
	}
	if err := c.validateNormalizedPage(page); err != nil {
		return PageResult{}, err
	}
	return page, nil
}

func (c *Client) preparePage(input PageRequest) (string, Continuation, PageWindow, PageWindow, []PageGap, error) {
	query, ok := c.templates[input.TemplateID]
	if !ok || !nodePattern.MatchString(input.ClusterID) || !nodePattern.MatchString(input.SourceID) || !validSourceGeneration(input.SourceGeneration) {
		return "", Continuation{}, PageWindow{}, PageWindow{}, nil, source.InvalidArgument("invalid Loki forward-page scope")
	}
	if input.Node != "" {
		if !nodePattern.MatchString(input.Node) || !strings.Contains(query, "{{node}}") {
			return "", Continuation{}, PageWindow{}, PageWindow{}, nil, source.InvalidArgument("invalid Loki forward-page node scope")
		}
		query = strings.ReplaceAll(query, "{{node}}", input.Node)
	} else if strings.Contains(query, "{{node}}") {
		return "", Continuation{}, PageWindow{}, PageWindow{}, nil, source.InvalidArgument("Loki forward-page node scope is required")
	}
	if input.Start.IsZero() || input.End.IsZero() || !input.End.After(input.Start) || input.End.Sub(input.Start) > maxWindow || input.Limit < 1 || input.Limit >= c.maxLines || input.Overlap < 0 || input.Overlap > maxPageOverlap {
		return "", Continuation{}, PageWindow{}, PageWindow{}, nil, source.InvalidArgument("invalid Loki forward-page bounds")
	}
	requested := PageWindow{Start: input.Start.UTC(), End: input.End.UTC()}
	digest := queryDigest(query)
	continuation := Continuation{SchemaVersion: ForwardPageSchemaVersion, ClusterID: input.ClusterID, SourceID: input.SourceID, TemplateID: input.TemplateID, Node: input.Node, SourceGeneration: input.SourceGeneration, QueryDigest: digest, RequestedWindow: requested}
	if input.Continuation != nil {
		if err := validateContinuation(*input.Continuation); err != nil || !sameContinuationScope(*input.Continuation, continuation) {
			return "", Continuation{}, PageWindow{}, PageWindow{}, nil, source.InvalidArgument("Loki forward-page continuation is invalid for this scope")
		}
		continuation.SafeThrough = cloneTime(input.Continuation.SafeThrough)
	}
	effective := requested
	var gaps []PageGap
	if input.RetentionStart != nil {
		retention := input.RetentionStart.UTC()
		if retention.IsZero() || !retention.Before(requested.End) {
			return "", Continuation{}, PageWindow{}, PageWindow{}, nil, source.InvalidArgument("invalid Loki retention boundary")
		}
		if retention.After(effective.Start) {
			effective.Start = retention
			gaps = append(gaps, PageGapRetention)
		}
		if continuation.SafeThrough != nil && retention.After(*continuation.SafeThrough) {
			gaps = append(gaps, PageGapCursorExpired)
		}
	}
	if continuation.SafeThrough != nil {
		start := continuation.SafeThrough.Add(-input.Overlap)
		if start.After(effective.Start) {
			effective.Start = start
		}
	}
	if !effective.End.After(effective.Start) {
		return "", Continuation{}, PageWindow{}, PageWindow{}, nil, source.InvalidArgument("invalid Loki effective forward-page window")
	}
	return query, continuation, requested, effective, gaps, nil
}

func validateContinuation(value Continuation) error {
	if value.SchemaVersion != ForwardPageSchemaVersion || !nodePattern.MatchString(value.ClusterID) || !nodePattern.MatchString(value.SourceID) || !nodePattern.MatchString(value.TemplateID) || (value.Node != "" && !nodePattern.MatchString(value.Node)) || !validSourceGeneration(value.SourceGeneration) || len(value.QueryDigest) != sha256.Size*2 {
		return fmt.Errorf("invalid continuation scope")
	}
	if _, err := hex.DecodeString(value.QueryDigest); err != nil || value.RequestedWindow.Start.IsZero() || value.RequestedWindow.End.IsZero() || !value.RequestedWindow.End.After(value.RequestedWindow.Start) || value.RequestedWindow.End.Sub(value.RequestedWindow.Start) > maxWindow {
		return fmt.Errorf("invalid continuation bounds")
	}
	if value.SafeThrough != nil && (value.SafeThrough.Before(value.RequestedWindow.Start) || !value.SafeThrough.Before(value.RequestedWindow.End)) {
		return fmt.Errorf("invalid continuation checkpoint")
	}
	return nil
}

func sameContinuationScope(left, right Continuation) bool {
	return left.SchemaVersion == right.SchemaVersion && left.ClusterID == right.ClusterID && left.SourceID == right.SourceID && left.TemplateID == right.TemplateID && left.Node == right.Node && left.SourceGeneration == right.SourceGeneration && left.QueryDigest == right.QueryDigest && left.RequestedWindow.Start.Equal(right.RequestedWindow.Start) && left.RequestedWindow.End.Equal(right.RequestedWindow.End)
}

func validSourceGeneration(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func validatePageSourceWindow(entries []Entry, window PageWindow) error {
	for _, entry := range entries {
		if entry.Timestamp.Before(window.Start) || !entry.Timestamp.Before(window.End) {
			return source.NewError(domain.FailureMalformedResponse, false, "Loki returned an entry outside the effective forward-page window", nil)
		}
	}
	return nil
}

func cloneTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	cloned := value.UTC()
	return &cloned
}

func queryDigest(query string) string {
	digest := sha256.Sum256([]byte(query))
	return hex.EncodeToString(digest[:])
}

func (c *Client) validateNormalizedPage(page PageResult) error {
	encoded, err := json.Marshal(page)
	if err != nil || int64(len(encoded)) > c.maxBytes {
		return source.NewError(domain.FailureResultLimit, false, "Loki normalized page exceeds byte limit", nil)
	}
	return nil
}

var (
	pageLabelPattern  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)
	pageSensitiveName = regexp.MustCompile(`(?i)(authorization|cookie|credential|pass(word|wd)?|secret|token|api[_-]?key|bearer)`)
	pageSecretValue   = regexp.MustCompile(`(?i)(bearer\s+|(?:authorization|cookie|credential|pass(?:word|wd)?|secret|token|api[_-]?key)\s*[:=]\s*)[^\s,;]+`)
	pageURLUserInfo   = regexp.MustCompile(`([A-Za-z][A-Za-z0-9+.-]*://)[^\s/@:]+:[^\s/@]+@`)
)

func (c *Client) normalizePageEntry(entry Entry, replayThrough *time.Time) PageEntry {
	labels, redactions := normalizePageLabels(entry.Labels, c.pageLabelAllowlist, c.pageRedactionValues())
	// Loki log lines are unconstrained free-form source data. This adapter does
	// not retain them until a later packet establishes a reviewed structured
	// extraction/redaction contract. Keeping a count-preserving entry still
	// proves a repeated line was returned without treating it as an identity.
	return PageEntry{
		Timestamp:          entry.Timestamp.UTC(),
		Labels:             labels,
		LineOmitted:        true,
		Replay:             replayThrough != nil && !entry.Timestamp.After(*replayThrough),
		EvidenceUnmodified: redactions == 0,
		Redactions:         redactions,
	}
}

func (c *Client) pageRedactionValues() []string {
	values := make([]string, 0, 2)
	if c.auth.BearerToken != "" {
		values = append(values, c.auth.BearerToken)
	}
	if c.auth.Password != "" {
		values = append(values, c.auth.Password)
	}
	return values
}

func normalizePageLabels(labels []domain.Label, allowlist map[string]bool, secrets []string) ([]domain.Label, int) {
	result := make([]domain.Label, 0, len(labels))
	redactions := 0
	for _, label := range labels {
		if len(result) == maxNormalizedLabels || !pageLabelPattern.MatchString(label.Name) || pageSensitiveName.MatchString(label.Name) || !allowlist[label.Name] {
			redactions++
			continue
		}
		value, count := sanitizePageText(label.Value, maxNormalizedLabelBytes, secrets)
		result = append(result, domain.Label{Name: label.Name, Value: value})
		redactions += count
	}
	return result, redactions
}

func sanitizePageText(value string, limit int, secrets []string) (string, int) {
	count := 0
	for _, secret := range secrets {
		if secret != "" && strings.Contains(value, secret) {
			value = strings.ReplaceAll(value, secret, "[REDACTED]")
			count++
		}
	}
	value = pageSecretValue.ReplaceAllStringFunc(value, func(string) string { count++; return "[REDACTED]" })
	value = pageURLUserInfo.ReplaceAllStringFunc(value, func(prefix string) string {
		count++
		return prefix[:strings.Index(prefix, "://")+3] + "[REDACTED]@"
	})
	var builder strings.Builder
	for _, r := range value {
		if unicode.IsControl(r) {
			count++
			continue
		}
		builder.WriteRune(r)
	}
	value = strings.TrimSpace(strings.Join(strings.Fields(builder.String()), " "))
	if len(value) > limit {
		cut := limit
		for cut > 0 && cut < len(value) && (value[cut]&0xC0) == 0x80 {
			cut--
		}
		if cut == 0 || !utf8.ValidString(value[:cut]) {
			value = ""
		} else {
			value = value[:cut]
		}
		count++
	}
	return value, count
}
