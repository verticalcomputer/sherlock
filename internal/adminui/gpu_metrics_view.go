package adminui

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

// GP-06a admin projection. The view layer formats committed evidence only. A
// field with no fresh supported observation renders as an explicit badge; it
// never renders as a number, and never as zero. See docs/GP06A_DCGM_METRICS.md.

// GPUMetricsRowLimit mirrors the projection's own row cap so the page states
// truncation instead of silently showing a partial fleet as complete.
const GPUMetricsRowLimit = 1024

// GPUMetricsProvider is optional: a deployment whose private API does not
// serve the expanded-DCGM projection keeps the tab explicitly disabled rather
// than showing an empty, healthy-looking table.
type GPUMetricsProvider interface {
	GetClusterGPUMetrics(context.Context, string) (GPUMetrics, error)
}

type GPUMetrics struct {
	ClusterID        string
	GeneratedAt      time.Time
	Sources          []GPUMetricsSource
	Fields           []GPUMetricsField
	GPUs             []GPUMetricsRow
	Inventory        GPUMetricsInventory
	OtherSources     []GPUMetricsOtherSource
	Truncated        bool
	SourcesTruncated bool
	// Presentation.
	GoverningSource string
	OtherSourceNote string
	BoundsNote      string
}

// GPUMetricsOtherSource is a Prometheus source outside the governing expected
// revision. The per-GPU table follows one source only, so these sources are
// named with their observed target counts rather than silently omitted.
type GPUMetricsOtherSource struct {
	SourceID, DisplayName       string
	ObservedNodes, ObservedGPUs int
}

type GPUMetricsField struct {
	Name, Unit, Semantics, Operation string
	// UnitSymbol and Counter are filled by presentation.
	UnitSymbol string
	Counter    bool
}

type GPUMetricsSource struct {
	SourceID, DisplayName string
	Primary               bool
	Operations            []GPUMetricsOperation
}

type GPUMetricsOperation struct {
	OperationID, QueryKind string
	Enrolled, Enabled      bool
	Mode                   string
	IntervalSeconds        int64
	Revision               int64
	HasRun                 bool
	RunID, RunStatus       string
	ScheduledFor           time.Time
	CompletedAt            time.Time
	CoverageComplete       bool
	Freshness              string
	FreshWindowSeconds     int64
	Fields                 []GPUMetricsFieldSummary
	// Presentation.
	EnrollmentLabel, EnrollmentClass string
	FreshnessBadge, FreshnessClass   string
	FreshnessDetail                  string
	IntervalLabel                    string
}

type GPUMetricsFieldSummary struct {
	Field, Unit, Semantics           string
	Supported, NotSupported, Unknown int
	Assessed, Expected               int
	UnassessedExpected               int
	Dominant                         string
	// Presentation.
	CountsLabel, DenominatorLabel string
	DominantBadge, DominantClass  string
}

type GPUMetricsRow struct {
	SourceID, NodeID, GPUUUID string
	MIGIdentity               string
	Expected, Observed        bool
	ObservedAt                *time.Time
	ObservedState             string
	Values                    map[string]GPUMetricsCell
	Conditions                []domain.HealthSignal
	// Presentation.
	ShortUUID      string
	ObservedAge    string
	ObservedBadge  string
	ObservedClass  string
	MIG            bool
	Cells          []GPUMetricsCell
	ConditionViews []GPUMetricsCondition
}

// GPUMetricsCondition only formats the shared server projection; it never
// compares field values or calculates thresholds in the dashboard.
type GPUMetricsCondition struct {
	Label, Class, Detail string
}

// GPUMetricsCell keeps the committed state and the display text apart. Value
// text is produced only for the SUPPORTED state, so no template path can turn
// an absent, unsupported, unknown or stale field into a number.
type GPUMetricsCell struct {
	Field, Unit, Semantics string
	State                  string
	Value                  *float64
	ObservedAt             *time.Time
	ResetObserved          bool
	// Presentation.
	Supported bool
	Counter   bool
	Display   string
	Age       string
	Badge     string
	Class     string
	Title     string
}

type GPUMetricsEntityRef struct {
	NodeID, GPUUUID string
	Stale           bool
	Unknown         bool
	ObservedAt      *time.Time
	// Presentation.
	Label      string
	Badge      string
	BadgeClass string
}

type GPUMetricsInventory struct {
	SourceID                          string
	HasExpectedRevision               bool
	RevisionID                        string
	EffectiveAt, SourceAt, ObservedAt *time.Time
	ExpectedNodes, ExpectedGPUs       int
	MIGCount                          int
	ObservedNodes, ObservedGPUs       int
	FreshObservedNodes                int
	FreshObservedGPUs                 int
	StaleObservedGPUs                 int
	CoveredNodes, CoveredGPUs         int
	CoverageComplete                  bool
	ObservationWindowSeconds          int64
	ExpectedNotObserved               []GPUMetricsEntityRef
	ObservedNotExpected               []GPUMetricsEntityRef
	Truncated                         bool
	// Presentation.
	CoverageLabel, CoverageClass string
	WindowLabel                  string
}

type gpuMetricsPageData struct {
	pageBase
	Record      ClusterRecord
	Metrics     GPUMetrics
	Available   bool
	Error       string
	Tab         string
	TabTitle    string
	RowLimit    int
	GeneratedAt time.Time
}

// clusterGPUMetricsPage is a sibling of the cluster detail tabs. It shares the
// same Cloudflare Access requirement, audit record and layout, but performs
// its own bounded read instead of widening the detail page's single load.
func (server *Server) clusterGPUMetricsPage(writer http.ResponseWriter, request *http.Request) {
	key, csrfToken, ok := server.requireAccess(writer, request)
	if !ok {
		return
	}
	id := strings.TrimSpace(request.PathValue("id"))
	record, err := server.provider.GetCluster(request.Context(), id)
	if err != nil || id == "" {
		http.Error(writer, "cluster not found", http.StatusNotFound)
		return
	}
	now := server.clock.Now().UTC()
	page := gpuMetricsPageData{
		pageBase: pageBase{Page: "clusters", CSRFToken: csrfToken},
		Record:   record, Tab: "gpu-metrics", TabTitle: "GPU metrics",
		RowLimit: GPUMetricsRowLimit, GeneratedAt: now,
	}
	if server.gpuMetricsProvider == nil {
		page.Error = "The expanded DCGM projection is not configured for this deployment. Absent field evidence is not a health claim."
	} else if metrics, loadErr := server.gpuMetricsProvider.GetClusterGPUMetrics(request.Context(), id); loadErr != nil {
		page.Error = "GPU metric evidence is temporarily unavailable. Missing data is not interpreted as healthy."
	} else {
		page.Metrics, page.Available = presentGPUMetrics(metrics, now), true
	}
	if !server.auditView(writer, request, key, "cluster_gpu_metrics") {
		return
	}
	server.renderTemplate(writer, server.gpuMetricsTemplate, "cluster-gpu-metrics.html", page)
}

// presentGPUMetrics formats the projection for display. It makes no state
// decision of its own: every state was already committed upstream.
func presentGPUMetrics(metrics GPUMetrics, now time.Time) GPUMetrics {
	for index := range metrics.Fields {
		field := &metrics.Fields[index]
		field.UnitSymbol = gpuMetricUnitSymbol(field.Unit)
		field.Counter = field.Semantics == "counter"
	}
	for sourceIndex := range metrics.Sources {
		for operationIndex := range metrics.Sources[sourceIndex].Operations {
			presentGPUMetricsOperation(&metrics.Sources[sourceIndex].Operations[operationIndex])
		}
	}
	for rowIndex := range metrics.GPUs {
		row := &metrics.GPUs[rowIndex]
		row.ShortUUID = shortGPUUUID(row.GPUUUID)
		row.MIG = row.MIGIdentity != ""
		row.ObservedAge = formatGPUMetricAge(now, row.ObservedAt)
		row.ObservedBadge, row.ObservedClass = gpuMetricsObservedBadge(row.ObservedState, now, row.ObservedAt)
		row.ConditionViews = make([]GPUMetricsCondition, 0, len(row.Conditions))
		for _, condition := range row.Conditions {
			class := "no-data"
			switch {
			case condition.Severity == domain.HealthSeverityCritical:
				class = "unavailable"
			case condition.Severity == domain.HealthSeverityWarning || condition.Type == domain.HealthSignalStale:
				class = "stale"
			case condition.Type == domain.HealthSignalNormal && condition.Freshness == domain.FreshnessFresh:
				class = "healthy"
			}
			label := string(condition.Type)
			if condition.Category != "" && condition.Category != condition.Type {
				label = string(condition.Category) + " · " + label
			}
			if condition.Severity == domain.HealthSeverityWarning || condition.Severity == domain.HealthSeverityCritical {
				label += " · " + string(condition.Severity)
			}
			row.ConditionViews = append(row.ConditionViews, GPUMetricsCondition{Label: label, Class: class, Detail: condition.Metric + " · " + condition.Reason})
		}
		row.Cells = make([]GPUMetricsCell, 0, len(metrics.Fields))
		for _, field := range metrics.Fields {
			cell, ok := row.Values[field.Name]
			if !ok {
				cell = GPUMetricsCell{Field: field.Name, Unit: field.Unit, Semantics: field.Semantics, State: "NO_DATA"}
			}
			row.Cells = append(row.Cells, presentGPUMetricsCell(cell, field, now))
		}
	}
	presentGPUMetricsRefs(metrics.Inventory.ExpectedNotObserved)
	presentGPUMetricsRefs(metrics.Inventory.ObservedNotExpected)
	presentGPUMetricsInventory(&metrics.Inventory)
	metrics.GoverningSource = gpuMetricsGoverningSource(metrics)
	metrics.OtherSourceNote = gpuMetricsOtherSourceNote(metrics.OtherSources)
	metrics.BoundsNote = gpuMetricsBoundsNote(metrics)
	return metrics
}

// gpuMetricsGoverningSource names the one source whose expected revision the
// GPU table and the inventory section follow, so neither can be read as a
// cluster-wide claim.
func gpuMetricsGoverningSource(metrics GPUMetrics) string {
	if metrics.Inventory.SourceID != "" {
		return metrics.Inventory.SourceID
	}
	for _, source := range metrics.Sources {
		if source.Primary {
			return source.SourceID
		}
	}
	return ""
}

func gpuMetricsOtherSourceNote(others []GPUMetricsOtherSource) string {
	if len(others) == 0 {
		return ""
	}
	parts := make([]string, 0, len(others))
	for _, other := range others {
		parts = append(parts, fmt.Sprintf("%s (%d observed GPUs, %d observed nodes)", other.SourceID, other.ObservedGPUs, other.ObservedNodes))
	}
	return "The table below follows one source only. These other Prometheus sources are not in it: " +
		strings.Join(parts, "; ") + ". Their GPUs are not assessed here and their absence is not a health claim."
}

// gpuMetricsBoundsNote states every bound that actually dropped records, so a
// truncated page is never read as a complete one.
func gpuMetricsBoundsNote(metrics GPUMetrics) string {
	reasons := []string{}
	if metrics.Truncated {
		reasons = append(reasons, fmt.Sprintf("the GPU table is bounded to %d rows", GPUMetricsRowLimit))
	}
	if metrics.Inventory.Truncated {
		reasons = append(reasons, fmt.Sprintf("the inventory lists are bounded to %d entries", GPUMetricsRowLimit))
	}
	if metrics.SourcesTruncated {
		reasons = append(reasons, "the Prometheus source list is bounded")
	}
	if len(reasons) == 0 {
		return ""
	}
	return strings.ToUpper(reasons[0][:1]) + reasons[0][1:] + gpuMetricsJoinRest(reasons[1:]) +
		". Records beyond a bound are not shown and are not assessed."
}

func gpuMetricsJoinRest(reasons []string) string {
	if len(reasons) == 0 {
		return ""
	}
	return ", and " + strings.Join(reasons, ", and ")
}

// presentGPUMetricsInventory states coverage from fresh observations only. A
// never-pruned target record is not coverage, so the label counts covered
// entities rather than present ones.
func presentGPUMetricsInventory(inventory *GPUMetricsInventory) {
	inventory.WindowLabel = fmt.Sprintf("observation window %ds", inventory.ObservationWindowSeconds)
	switch {
	case !inventory.HasExpectedRevision:
		inventory.CoverageLabel, inventory.CoverageClass = "COVERAGE UNKNOWN", "no-data"
	case inventory.CoverageComplete:
		inventory.CoverageLabel, inventory.CoverageClass = fmt.Sprintf("COVERED %d / %d EXPECTED GPUs", inventory.CoveredGPUs, inventory.ExpectedGPUs), "healthy"
	default:
		inventory.CoverageLabel, inventory.CoverageClass = fmt.Sprintf("COVERAGE INCOMPLETE · %d / %d EXPECTED GPUs", inventory.CoveredGPUs, inventory.ExpectedGPUs), "stale"
	}
}

// gpuMetricsObservedBadge never renders a healthy badge for a target whose
// newest observation is older than the window: the target cache is never
// pruned, so presence alone would read as health it does not establish.
func gpuMetricsObservedBadge(state string, now time.Time, observed *time.Time) (string, string) {
	switch strings.ToUpper(strings.TrimSpace(state)) {
	case "OBSERVED":
		return "OBSERVED", "healthy"
	case "OBSERVED_STALE":
		age := formatGPUMetricAgeShort(now, observed)
		if age == "" {
			return "OBSERVED · STALE", "stale"
		}
		return "OBSERVED · STALE " + age, "stale"
	case "OBSERVED_UNKNOWN":
		return "OBSERVED · CLOCK UNKNOWN", "no-data"
	default:
		return "NOT OBSERVED", "unavailable"
	}
}

func presentGPUMetricsOperation(operation *GPUMetricsOperation) {
	switch {
	case operation.Enrolled && operation.Enabled:
		operation.EnrollmentLabel, operation.EnrollmentClass = "ENROLLED · ENABLED", "healthy"
	case operation.Enrolled:
		operation.EnrollmentLabel, operation.EnrollmentClass = "ENROLLED · DISABLED", "stale"
	default:
		operation.EnrollmentLabel, operation.EnrollmentClass = "NOT ENROLLED", "no-data"
	}
	operation.FreshnessBadge, operation.FreshnessClass = gpuMetricStateBadge(operation.Freshness), gpuMetricStateClass(operation.Freshness)
	if operation.HasRun {
		operation.FreshnessDetail = "newest run " + operation.RunStatus
	} else {
		operation.FreshnessDetail = "no committed run"
	}
	if operation.Enrolled && operation.IntervalSeconds > 0 {
		operation.IntervalLabel = fmt.Sprintf("every %ds", operation.IntervalSeconds)
	} else {
		operation.IntervalLabel = "no schedule"
	}
	for index := range operation.Fields {
		field := &operation.Fields[index]
		field.CountsLabel = fmt.Sprintf("SUPPORTED %d / NOT SUPPORTED %d / UNKNOWN %d", field.Supported, field.NotSupported, field.Unknown)
		field.DenominatorLabel = fmt.Sprintf("assessed %d of %d expected", field.Assessed, field.Expected)
		field.DominantBadge, field.DominantClass = gpuMetricStateBadge(field.Dominant), gpuMetricStateClass(field.Dominant)
	}
}

func presentGPUMetricsCell(cell GPUMetricsCell, field GPUMetricsField, now time.Time) GPUMetricsCell {
	cell.Field, cell.Counter = field.Name, field.Semantics == "counter"
	if cell.Unit == "" {
		cell.Unit = field.Unit
	}
	cell.Class = gpuMetricStateClass(cell.State)
	// A non-finite sample has no printable form, so it is treated exactly like
	// an absent one: a badge, never an empty value element.
	cell.Supported = cell.State == "SUPPORTED" && cell.Value != nil &&
		cell.ObservedAt != nil && !cell.ObservedAt.IsZero() &&
		!math.IsNaN(*cell.Value) && !math.IsInf(*cell.Value, 0)
	if !cell.Supported {
		// A non-supported cell never carries value text, even if a stale value
		// reached this process.
		cell.Badge, cell.Display, cell.Value = gpuMetricStateBadge(cell.State), "", nil
		if cell.State == "SUPPORTED" {
			// The value could not be rendered, so the cell states the only
			// honest thing left about it.
			cell.Badge, cell.Class = "UNKNOWN", "no-data"
		}
		if cell.ObservedAt != nil {
			cell.Title = "last observation " + cell.ObservedAt.UTC().Format(time.RFC3339)
		} else {
			cell.Title = "no current projection for this field"
		}
		return cell
	}
	cell.Display = formatGPUMetricValue(*cell.Value, cell.Unit)
	cell.Age = formatGPUMetricAge(now, cell.ObservedAt)
	cell.Title = fmt.Sprintf("%s %s · observed %s", cell.Field, cell.Unit, cell.ObservedAt.UTC().Format(time.RFC3339))
	return cell
}

func presentGPUMetricsRefs(refs []GPUMetricsEntityRef) {
	for index := range refs {
		if refs[index].GPUUUID == "" {
			refs[index].Label = "node " + refs[index].NodeID
		} else {
			refs[index].Label = refs[index].GPUUUID + " on " + refs[index].NodeID
		}
		// A stale gap is a present but unrefreshed target record; naming it
		// keeps it out of the "never seen" reading without making it healthy.
		if refs[index].Unknown {
			refs[index].Badge, refs[index].BadgeClass = "OBSERVATION CLOCK UNKNOWN", "no-data"
			continue
		}
		if refs[index].Stale {
			refs[index].Badge, refs[index].BadgeClass = "OBSERVATION STALE", "stale"
			continue
		}
		refs[index].Badge, refs[index].BadgeClass = "NEVER OBSERVED", "unavailable"
	}
}

func gpuMetricStateClass(state string) string {
	switch strings.ToUpper(strings.TrimSpace(state)) {
	case "SUPPORTED", "FRESH", "OBSERVED":
		return "healthy"
	case "NOT_SUPPORTED", "FAILING":
		return "unavailable"
	case "STALE", "OBSERVED_STALE", "CLOCK_SKEW":
		return "stale"
	default:
		return "no-data"
	}
}

func gpuMetricStateBadge(state string) string {
	badge := strings.ReplaceAll(strings.ToUpper(strings.TrimSpace(state)), "_", " ")
	if badge == "" {
		return "NO DATA"
	}
	return badge
}

// shortGPUUUID keeps the table scannable; the template carries the exact UUID
// in a title attribute so the identity is never lost.
func shortGPUUUID(uuid string) string {
	if len(uuid) <= 18 {
		return uuid
	}
	return uuid[:10] + "…" + uuid[len(uuid)-4:]
}

// formatGPUMetricAge states a future instant as "in 2 h" rather than clamping
// it to zero: a record ahead of the reader's clock is a clock disagreement, and
// hiding it would make a skewed record look freshly observed.
func formatGPUMetricAge(now time.Time, observed *time.Time) string {
	magnitude := formatGPUMetricAgeShort(now, observed)
	if magnitude == "" {
		return ""
	}
	if now.UTC().Sub(observed.UTC()) < 0 {
		return "in " + magnitude
	}
	return magnitude + " ago"
}

// formatGPUMetricAgeShort is the unsigned magnitude of an age, for badges that
// already state the direction.
func formatGPUMetricAgeShort(now time.Time, observed *time.Time) string {
	if observed == nil || observed.IsZero() {
		return ""
	}
	age := now.UTC().Sub(observed.UTC())
	if age < 0 {
		age = -age
	}
	switch {
	case age < time.Minute:
		return fmt.Sprintf("%d s", int(age.Seconds()))
	case age < time.Hour:
		return fmt.Sprintf("%d min", int(age.Minutes()))
	case age < 48*time.Hour:
		return fmt.Sprintf("%d h", int(age.Hours()))
	default:
		return fmt.Sprintf("%d d", int(age.Hours()/24))
	}
}

// formatGPUMetricValue prints the exact absolute value with its reviewed unit.
// Counters keep their absolute value; no rate or delta is inferred here.
func formatGPUMetricValue(value float64, unit string) string {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return ""
	}
	text := fmt.Sprintf("%.1f", value)
	if value == math.Trunc(value) && math.Abs(value) < 1e15 {
		text = formatCount(int64(value))
	}
	if symbol := gpuMetricUnitSymbol(unit); symbol != "" {
		return text + " " + symbol
	}
	return text
}

func gpuMetricUnitSymbol(unit string) string {
	switch unit {
	case "celsius":
		return "°C"
	case "watts":
		return "W"
	case "mebibytes":
		return "MiB"
	case "count":
		return ""
	default:
		return unit
	}
}
