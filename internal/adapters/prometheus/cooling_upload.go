package prometheus

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

// CoolingInstant reads raw range vectors from the instant endpoint. An
// evaluated instant vector or /query_range assigns evaluation times to its
// output; the raw selector's tuples retain Prometheus's scrape timestamps.
func (c *Client) CoolingInstant(ctx context.Context, profile domain.CoolingUploadProfile, query domain.QueryKind, slot time.Time) (QueryResult, error) {
	field, ok := domain.CoolingUploadField(query)
	if err := profile.Validate(); err != nil || !ok || !slot.Equal(slot.Truncate(domain.CoolingUploadInterval)) ||
		!profile.ActiveAt(slot) {
		return QueryResult{}, &Error{Code: domain.FailureInvalidArgument, Message: "invalid cooling upload query or scope"}
	}
	// One absolute deadline covers all selectors; it is not reset per HTTP call.
	ctx, cancel := context.WithDeadline(ctx, slot.Add(domain.CoolingUploadSourceTimeout))
	defer cancel()
	allowed := make(map[domain.CoolingUploadAsset]bool, len(profile.Assets))
	for _, asset := range profile.Assets {
		allowed[asset] = true
	}
	var result QueryResult
	endpoint := c.baseURL.ResolveReference(&url.URL{Path: "/api/v1/query"})
	params := endpoint.Query()
	params.Set("time", formatTimestamp(slot))
	for _, selector := range coolingSelectors(profile, field.Name) {
		params.Set("query", selector)
		endpoint.RawQuery = params.Encode()
		bounded := *c
		bounded.maxBytes -= result.BytesRead
		body, bytesRead, err := bounded.get(ctx, endpoint)
		if err != nil {
			return result, err
		}
		result.BytesRead += bytesRead
		parsed, err := parseCoolingMatrix(body, c.maxSeries-result.SeriesReturned)
		if err != nil {
			return result, err
		}
		// A fleet selector bounds both label sets, but their cross product is not
		// authority. Validate each exact node+UUID pair and reject ambiguous aliases.
		if profile.Version == domain.CoolingUploadProductionVersion {
			for _, sample := range parsed.Samples {
				node, gpu, valid := domain.DCGMIdentity(domain.SortedLabels(sample.Metric), profile.Task(query, slot))
				if !valid || !allowed[domain.CoolingUploadAsset{NodeID: domain.StableNodeID(node), GPUUUID: domain.PhysicalGPUUUID(gpu)}] {
					return result, &Error{Code: domain.FailureMalformedResponse, Message: "cooling source returned an unauthorized or ambiguous GPU identity"}
				}
			}
		}
		result.SeriesReturned += parsed.SeriesReturned
		result.WarningCount += parsed.WarningCount
		result.Samples = append(result.Samples, parsed.Samples...)
	}

	return result, nil
}

// V2 preserves its existing per-node selectors. V3 uses exactly four disjoint
// alias selectors per metric, regardless of fleet size; response identity is
// still checked against the exact approved pairs before observations are built.
func coolingSelectors(profile domain.CoolingUploadProfile, metric string) []string {
	groups := make(map[domain.StableNodeID][]string)
	var nodes []domain.StableNodeID
	for _, asset := range profile.Assets {
		if _, ok := groups[asset.NodeID]; !ok {
			nodes = append(nodes, asset.NodeID)
		}
		groups[asset.NodeID] = append(groups[asset.NodeID], regexp.QuoteMeta(string(asset.GPUUUID)))
	}
	type group struct {
		node  string
		gpus  []string
		regex bool
	}
	var selected []group
	if profile.Version == domain.CoolingUploadProductionVersion {
		var hosts, gpus []string
		for _, node := range nodes {
			hosts = append(hosts, regexp.QuoteMeta(string(node)))
			gpus = append(gpus, groups[node]...)
		}
		selected = []group{{strings.Join(hosts, "|"), gpus, true}}
	} else {
		for _, node := range nodes {
			selected = append(selected, group{string(node), groups[node], false})
		}
	}
	var result []string
	for _, g := range selected {
		for _, hostLabel := range []string{"Hostname", "hostname"} {
			op := "="
			if g.regex {
				op = "=~"
			}
			host := hostLabel + op + strconv.Quote(g.node)
			if hostLabel == "hostname" {
				host += `,Hostname=""`
			}
			for _, gpuLabel := range []string{"UUID", "uuid"} {
				gpu := gpuLabel + "=~" + strconv.Quote(strings.Join(g.gpus, "|"))
				if gpuLabel == "uuid" {
					gpu += `,UUID=""`
				}
				result = append(result, fmt.Sprintf("%s{%s,%s}[%ds]", metric, host, gpu, domain.CoolingUploadInterval/time.Second))
			}
		}
	}
	return result
}

func parseCoolingMatrix(body []byte, maxSeries int) (QueryResult, error) {
	response, err := decodeResponse(body, "matrix")
	if err != nil {
		return QueryResult{}, err
	}
	var seriesValues []apiMatrixSeries
	if err := json.Unmarshal(response.Data.Result, &seriesValues); err != nil {
		return QueryResult{}, &Error{Code: domain.FailureMalformedResponse, Message: "Prometheus cooling result is malformed", Cause: err}
	}
	if len(seriesValues) > maxSeries {
		return QueryResult{}, &Error{Code: domain.FailureResultLimit, Message: "Prometheus cooling response exceeds series limit"}
	}
	result := QueryResult{Samples: make([]Sample, 0, len(seriesValues)), SeriesReturned: len(seriesValues), WarningCount: len(response.Warnings)}
	for _, series := range seriesValues {
		if len(series.Values) == 0 {
			return QueryResult{}, &Error{Code: domain.FailureMalformedResponse, Message: "Prometheus cooling response contains an empty series"}
		}
		// The raw range-vector API returns each series in timestamp order.
		sample, err := parseSample(series.Metric, series.Values[len(series.Values)-1])
		if err != nil {
			return QueryResult{}, err
		}
		result.Samples = append(result.Samples, sample)
	}
	return result, nil
}
