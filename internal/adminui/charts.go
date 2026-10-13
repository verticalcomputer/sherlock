package adminui

import (
	"context"
	"fmt"
	"github.com/verticalcomputer/sherlock/internal/application"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Charts are rendered on the server as inline SVG. Templates cannot do
// arithmetic and the CSP forbids inline styles, so geometry is computed here
// and carried by SVG presentation attributes while stylesheet classes carry
// color. Every chart states its window and unit; missing data stays explicit.

const (
	activityDays = 14
	// clusterSummaryLimit bounds the per-cluster summary requests one overview
	// or cluster-list render makes to the private API.
	clusterSummaryLimit = 24
	// privateAPIOperationsLimit mirrors the private API's operations page
	// bound. A full page may not reach back across the whole chart window.
	privateAPIOperationsLimit = 200
	plotTop                   = 16.0
	plotHeight                = 120.0
	minimumColumnHeight       = 2.0
)

type barPart struct {
	Class, Label string
	Count        int64
}

type barSegment struct {
	Class, Label, X, Width string
	Count                  int64
}

type stackedBar struct {
	Total    int64
	Segments []barSegment
}

// newStackedBar lays parts end to end. A positive scale sizes the bar against
// a shared maximum so rows in one list stay comparable; otherwise the bar is a
// share of its own total.
func newStackedBar(parts []barPart, scale int64) stackedBar {
	bar := stackedBar{Segments: make([]barSegment, 0, len(parts))}
	for _, part := range parts {
		bar.Total += max(part.Count, 0)
	}
	if scale <= 0 {
		scale = bar.Total
	}
	var offset int64
	for _, part := range parts {
		count := max(part.Count, 0)
		segment := barSegment{Class: part.Class, Label: part.Label, Count: count, X: "0%", Width: "0%"}
		if scale > 0 && count > 0 {
			segment.X = percentAttr(float64(offset) * 100 / float64(scale))
			segment.Width = percentAttr(float64(count) * 100 / float64(scale))
		}
		offset += count
		bar.Segments = append(bar.Segments, segment)
	}
	return bar
}

type columnSegment struct{ Class, Y, Height string }

type chartColumn struct {
	X, Width, Center, Label, Title string
	// Narrow columns drop their day label on small screens; the most recent
	// day always keeps its label.
	Narrow   bool
	Segments []columnSegment
}

type columnChart struct {
	AriaLabel, MaxLabel, MidLabel, EmptyText string
	Empty                                    bool
	Columns                                  []chartColumn
	Legend                                   stackedBar
}

type activityWindow struct {
	Runs, Spend  columnChart
	RunCount     int
	Tokens, Cost int64
	Start        time.Time
}

var investigationOutcomes = []barPart{
	{Class: "healthy", Label: "completed"},
	{Class: "degraded", Label: "partial or blocked"},
	{Class: "unavailable", Label: "failed or cancelled"},
	{Class: "neutral", Label: "in progress"},
}

func investigationOutcomeIndex(status string) int {
	switch strings.ToUpper(strings.TrimSpace(status)) {
	case "COMPLETED":
		return 0
	case "PARTIAL", "BLOCKED":
		return 1
	case "FAILED", "CANCELLED":
		return 2
	default:
		return 3
	}
}

func activityWindowBounds(now time.Time) (time.Time, time.Time) {
	end := now.UTC().Truncate(24*time.Hour).AddDate(0, 0, 1)
	return end.AddDate(0, 0, -activityDays), end
}

// buildActivityWindow buckets runs by the UTC day of their last update over
// the trailing activityDays days, today included.
func buildActivityWindow(investigations []Investigation, now time.Time) activityWindow {
	start, end := activityWindowBounds(now)
	window := activityWindow{Start: start}
	runs := make([][]int64, activityDays)
	for day := range runs {
		runs[day] = make([]int64, len(investigationOutcomes))
	}
	costs := make([]int64, activityDays)
	tokens := make([]int64, activityDays)
	for _, investigation := range investigations {
		updated := investigation.UpdatedAt.UTC()
		if updated.Before(start) || !updated.Before(end) {
			continue
		}
		day := int(updated.Sub(start) / (24 * time.Hour))
		runs[day][investigationOutcomeIndex(investigation.Status)]++
		costs[day] += investigation.AuditedCostMicrounits
		tokens[day] += investigation.AuditedTokens
		window.RunCount++
		window.Cost += investigation.AuditedCostMicrounits
		window.Tokens += investigation.AuditedTokens
	}

	legend := append([]barPart(nil), investigationOutcomes...)
	var runMax, costMax int64
	for day := range runs {
		var total int64
		for index, count := range runs[day] {
			total += count
			legend[index].Count += count
		}
		runMax = max(runMax, total)
		costMax = max(costMax, costs[day])
	}
	runScale, costScale := niceCeiling(runMax), niceCeiling(costMax)
	window.Runs = columnChart{
		AriaLabel: fmt.Sprintf("Investigation runs per UTC day over the last %d days: %s in total", activityDays, countLabel(window.RunCount, "run", "runs")),
		MaxLabel:  strconv.FormatInt(runScale, 10), MidLabel: strconv.FormatInt(runScale/2, 10),
		Empty: window.RunCount == 0, EmptyText: fmt.Sprintf("No investigation run was updated in the last %d days.", activityDays),
		Legend: newStackedBar(legend, 0),
	}
	window.Spend = columnChart{
		AriaLabel: fmt.Sprintf("Audited model spend per UTC day over the last %d days: %s in total", activityDays, formatCost(window.Cost)),
		MaxLabel:  formatTickCost(costScale), MidLabel: formatTickCost(costScale / 2),
		Empty: window.Cost <= 0, EmptyText: fmt.Sprintf("No audited model spend in the last %d days.", activityDays),
	}

	step := 100.0 / activityDays
	for day := range activityDays {
		date := start.AddDate(0, 0, day)
		column := chartColumn{
			X: percentAttr(float64(day)*step + step*0.18), Width: percentAttr(step * 0.64),
			Center: percentAttr(float64(day)*step + step/2), Label: date.Format("02"),
			Narrow: (activityDays-1-day)%2 == 1,
		}
		runColumn, spendColumn := column, column
		var total int64
		stack := 0.0
		for index, count := range runs[day] {
			if count == 0 {
				continue
			}
			total += count
			height := max(float64(count)/float64(runScale)*plotHeight, minimumColumnHeight)
			stack += height
			runColumn.Segments = append(runColumn.Segments, columnSegment{Class: investigationOutcomes[index].Class, Y: pixelAttr(plotTop + plotHeight - stack), Height: pixelAttr(height)})
		}
		runColumn.Title = date.Format("02 Jan") + " · " + countLabel(int(total), "run", "runs")
		if costs[day] > 0 {
			height := max(float64(costs[day])/float64(costScale)*plotHeight, minimumColumnHeight)
			spendColumn.Segments = []columnSegment{{Class: "accent", Y: pixelAttr(plotTop + plotHeight - height), Height: pixelAttr(height)}}
		}
		spendColumn.Title = fmt.Sprintf("%s · %s · %s tokens", date.Format("02 Jan"), formatCost(costs[day]), formatCount(tokens[day]))
		window.Runs.Columns = append(window.Runs.Columns, runColumn)
		window.Spend.Columns = append(window.Spend.Columns, spendColumn)
	}
	return window
}

// investigationsMayBeTruncated reports a full API page that never reaches the
// start of the window, where the earliest days may be undercounted.
func investigationsMayBeTruncated(investigations []Investigation, windowStart time.Time) bool {
	if len(investigations) < privateAPIOperationsLimit {
		return false
	}
	for _, investigation := range investigations {
		if investigation.UpdatedAt.Before(windowStart) {
			return false
		}
	}
	return true
}

// niceCeiling rounds an axis maximum up to an even step so the midpoint tick
// stays a whole number.
func niceCeiling(value int64) int64 {
	if value <= 0 {
		return 2
	}
	magnitude := int64(1)
	for magnitude*10 < value {
		magnitude *= 10
	}
	for _, step := range []int64{2, 4, 6, 8, 10} {
		if step*magnitude >= value {
			return step * magnitude
		}
	}
	return 10 * magnitude
}

func formatTickCost(microunits int64) string {
	if microunits < 10_000 {
		return fmt.Sprintf("$%.4f", float64(microunits)/1_000_000)
	}
	return fmt.Sprintf("$%.2f", float64(microunits)/1_000_000)
}

func percentAttr(value float64) string {
	return strconv.FormatFloat(value, 'f', 3, 64) + "%"
}

func pixelAttr(value float64) string {
	return strconv.FormatFloat(value, 'f', 2, 64)
}

// percentWidth is an SVG width for a utilization reading; nil stays empty so
// the template can show "No data" instead of an empty meter.
func percentWidth(value *float64) string {
	if value == nil {
		return ""
	}
	return percentAttr(min(max(*value, 0), 100))
}

func evidenceStreamBar(streams []EvidenceStreamHealth) stackedBar {
	parts := []barPart{{Class: "healthy", Label: "complete"}, {Class: "degraded", Label: "partial or stale"}, {Class: "no-data", Label: "no data"}, {Class: "unavailable", Label: "unavailable"}}
	for _, stream := range streams {
		switch normalizeState(stream.State) {
		case StateHealthy:
			parts[0].Count++
		case StateNoData:
			parts[2].Count++
		case StateUnavailable:
			parts[3].Count++
		default:
			parts[1].Count++
		}
	}
	return newStackedBar(parts, 0)
}

func evidenceHistoryBar(history EvidenceHistory) stackedBar {
	return newStackedBar([]barPart{
		{Class: "healthy", Label: "complete", Count: history.Complete},
		{Class: "degraded", Label: "partial", Count: history.Partial},
		{Class: "no-data", Label: "no data", Count: history.NoData},
		{Class: "unavailable", Label: "unavailable", Count: history.Unavailable},
	}, 0)
}

// clusterHealthRow is one cluster as the overview and cluster list present
// it. The registered record is the fallback; a current summary, when it loads,
// supplies the state, contact time, evidence, and resources.
type clusterHealthRow struct {
	Health                application.ClusterHealthView
	CanConfigure          bool
	ID, Name, Description string
	State                 OperationalState
	CreatedAt, LastSeenAt time.Time
	RemovedAt             *time.Time
	HasSummary            bool
	Evidence              stackedBar
	EvidenceComplete      int64
	GPU                   *float64
	GPUWidth              string
	Nodes, GPUs           int64
	HasOperations         bool
	Incidents, Runs       int
	Spend                 int64
}

func (server *Server) loadClusterHealthRows(ctx context.Context, records []ClusterRecord) ([]clusterHealthRow, int) {
	rows := make([]clusterHealthRow, len(records))
	var wait sync.WaitGroup
	requested, omitted := 0, 0
	for index, record := range records {
		rows[index] = clusterHealthRow{
			ID: record.ID, Name: record.DisplayName, Description: record.Description,
			State: normalizeState(record.State), CreatedAt: record.CreatedAt,
			LastSeenAt: record.LastSeenAt, RemovedAt: record.RemovedAt,
		}
		if record.RemovedAt != nil {
			continue
		}
		if requested == clusterSummaryLimit {
			omitted++
			continue
		}
		requested++
		wait.Add(1)
		go func(row *clusterHealthRow) {
			defer wait.Done()
			if summary, err := server.provider.GetClusterSummary(ctx, row.ID); err == nil {
				row.applySummary(summary)
			}
		}(&rows[index])
	}
	wait.Wait()
	sort.SliceStable(rows, func(left, right int) bool {
		a, b := rows[left], rows[right]
		if (a.RemovedAt == nil) != (b.RemovedAt == nil) {
			return a.RemovedAt == nil
		}
		if stateRank(a.State) != stateRank(b.State) {
			return stateRank(a.State) > stateRank(b.State)
		}
		return strings.ToLower(a.Name) < strings.ToLower(b.Name)
	})
	return rows, omitted
}

func (row *clusterHealthRow) applySummary(summary Cluster) {
	row.HasSummary = true
	row.Health = summary.Health
	row.State = normalizeState(summary.State)
	if summary.LastSeenAt.After(row.LastSeenAt) {
		row.LastSeenAt = summary.LastSeenAt
	}
	row.Evidence = evidenceStreamBar(summary.EvidenceStreams)
	row.EvidenceComplete = row.Evidence.Segments[0].Count
	row.GPU = summary.Resources.GPUUtilizationPercent
	row.GPUWidth = percentWidth(row.GPU)
	row.Nodes, row.GPUs = summary.Resources.ObservedNodes, summary.Resources.ObservedGPUs
}

// applyClusterOperations counts live incidents and in-window runs per cluster.
// Tickets must already be consolidated.
func applyClusterOperations(rows []clusterHealthRow, operations Operations, windowStart time.Time) {
	byID := make(map[string]*clusterHealthRow, len(rows))
	for index := range rows {
		rows[index].HasOperations = true
		byID[rows[index].ID] = &rows[index]
	}
	for _, ticket := range operations.Tickets {
		if row := byID[ticket.ClusterID]; row != nil {
			row.Incidents++
		}
	}
	for _, investigation := range operations.Investigations {
		if row := byID[investigation.ClusterID]; row != nil && !investigation.UpdatedAt.Before(windowStart) {
			row.Runs++
			row.Spend += investigation.AuditedCostMicrounits
		}
	}
}

func fleetStateBar(rows []clusterHealthRow) stackedBar {
	parts := []barPart{{Class: "healthy", Label: "healthy"}, {Class: "degraded", Label: "degraded"}, {Class: "unavailable", Label: "unavailable"}, {Class: "no-data", Label: "no data"}}
	for _, row := range rows {
		if row.RemovedAt != nil {
			continue
		}
		switch stateClass(row.State) {
		case "healthy":
			parts[0].Count++
		case "unavailable":
			parts[2].Count++
		case "no-data":
			parts[3].Count++
		default:
			parts[1].Count++
		}
	}
	return newStackedBar(parts, 0)
}

type labeledBar struct {
	Label, Href, Value string
	Bar                stackedBar
}

type overviewData struct {
	InventoryAvailable                 bool
	Rows                               []clusterHealthRow
	ActiveClusters, Attention, Omitted int
	FleetBar                           stackedBar
	Activity                           activityWindow
	InvestigationsCapped               bool
	HighIncidents                      int
	IncidentRows, RepairRows           []labeledBar
	IncidentLegend                     stackedBar
}

func (server *Server) buildOverview(ctx context.Context, operations Operations, now time.Time) overviewData {
	overview := overviewData{Activity: buildActivityWindow(operations.Investigations, now)}
	overview.InvestigationsCapped = investigationsMayBeTruncated(operations.Investigations, overview.Activity.Start)
	names := make(map[string]string)
	if records, err := server.provider.ListClusters(ctx); err == nil {
		overview.InventoryAvailable = true
		rows, omitted := server.loadClusterHealthRows(ctx, records)
		applyClusterOperations(rows, operations, overview.Activity.Start)
		for _, row := range rows {
			names[row.ID] = row.Name
			if row.RemovedAt != nil {
				continue
			}
			overview.Rows = append(overview.Rows, row)
			if row.State != StateHealthy {
				overview.Attention++
			}
		}
		overview.ActiveClusters, overview.Omitted = len(overview.Rows), omitted
		overview.FleetBar = fleetStateBar(overview.Rows)
	}
	overview.IncidentRows, overview.IncidentLegend, overview.HighIncidents = incidentBars(operations.Tickets, names)
	overview.RepairRows = repairBars(operations.Repairs)
	return overview
}

func incidentBars(tickets []Ticket, names map[string]string) ([]labeledBar, stackedBar, int) {
	newParts := func() []barPart {
		return []barPart{{Class: "unavailable", Label: "critical or high"}, {Class: "degraded", Label: "medium or warning"}, {Class: "neutral", Label: "other"}}
	}
	type clusterIncidents struct {
		id    string
		parts []barPart
		total int64
	}
	byCluster := make(map[string]*clusterIncidents)
	order := make([]*clusterIncidents, 0)
	legend, high := newParts(), 0
	for _, ticket := range tickets {
		entry := byCluster[ticket.ClusterID]
		if entry == nil {
			entry = &clusterIncidents{id: ticket.ClusterID, parts: newParts()}
			byCluster[ticket.ClusterID] = entry
			order = append(order, entry)
		}
		index := 2
		switch severityClass(ticket.Severity) {
		case "unavailable":
			index = 0
			high++
		case "degraded":
			index = 1
		}
		entry.parts[index].Count++
		entry.total++
		legend[index].Count++
	}
	sort.SliceStable(order, func(left, right int) bool { return order[left].total > order[right].total })
	rows := make([]labeledBar, 0, len(order))
	for _, entry := range order {
		label := names[entry.id]
		if label == "" {
			label = entry.id
		}
		rows = append(rows, labeledBar{
			Label: label, Href: "/admin/clusters/" + url.PathEscape(entry.id),
			Value: strconv.FormatInt(entry.total, 10), Bar: newStackedBar(entry.parts, order[0].total),
		})
	}
	return rows, newStackedBar(legend, 0), high
}

func repairBars(repairs RepairOverview) []labeledBar {
	if !repairs.Available {
		return nil
	}
	parts := []barPart{
		{Class: "healthy", Label: "Verified recoveries", Count: repairs.Succeeded},
		{Class: "neutral", Label: "Awaiting verification", Count: repairs.PendingVerification},
		{Class: "accent", Label: "Active requests", Count: repairs.ActiveRequests},
		{Class: "unavailable", Label: "Contained, failed, or expired", Count: repairs.Contained},
		{Class: "degraded", Label: "Rolled back", Count: repairs.RolledBack},
		{Class: "muted", Label: "Cancelled", Count: repairs.Cancelled},
	}
	scale := int64(1)
	for _, part := range parts {
		scale = max(scale, part.Count)
	}
	rows := make([]labeledBar, 0, len(parts))
	for _, part := range parts {
		rows = append(rows, labeledBar{Label: part.Label, Value: strconv.FormatInt(part.Count, 10), Bar: newStackedBar([]barPart{part}, scale)})
	}
	return rows
}
