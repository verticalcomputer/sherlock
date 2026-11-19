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
	groups := make(map[domain.StableNodeID][]string, domain.CoolingUploadMaxNodes)
	var nodes []domain.StableNodeID
	for _, asset := range profile.Assets {
		if _, found := groups[asset.NodeID]; !found {
			nodes = append(nodes, asset.NodeID)
		}
		groups[asset.NodeID] = append(groups[asset.NodeID], regexp.QuoteMeta(string(asset.GPUUUID)))
	}

	var result QueryResult
	endpoint := c.baseURL.ResolveReference(&url.URL{Path: "/api/v1/query"})
	params := endpoint.Query()
	params.Set("time", formatTimestamp(slot))
	for _, node := range nodes {
		gpus := strconv.Quote(strings.Join(groups[node], "|"))
		// Lower-case spellings have an absent upper-case alias. These selectors
		// are disjoint even when an exporter supplies both label spellings.
		for _, hostLabel := range []string{"Hostname", "hostname"} {
			host := hostLabel + "=" + strconv.Quote(string(node))
			if hostLabel == "hostname" {
				host += `,Hostname=""`
			}
			for _, gpuLabel := range []string{"UUID", "uuid"} {
				gpu := gpuLabel + "=~" + gpus
				if gpuLabel == "uuid" {
					gpu += `,UUID=""`
				}
				query := fmt.Sprintf("%s{%s,%s}[%ds]", field.Name, host, gpu, domain.CoolingUploadInterval/time.Second)
				params.Set("query", query)
				endpoint.RawQuery = params.Encode()
				bounded := *c
				bounded.maxBytes -= result.BytesRead
				body, bytesRead, err := bounded.get(ctx, endpoint)
				if err != nil {
					return result, err
				}
				result.BytesRead += bytesRead
				remaining := c.maxSeries - result.SeriesReturned
				parsed, err := parseCoolingMatrix(body, remaining)
				if err != nil {
					return result, err
				}
				result.SeriesReturned += parsed.SeriesReturned
				result.WarningCount += parsed.WarningCount
				result.Samples = append(result.Samples, parsed.Samples...)
			}
		}
	}
	return result, nil
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
