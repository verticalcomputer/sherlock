// Command sherlock-api-acceptance runs a bounded, read-only consumer and load
// acceptance check against a deployed Sherlock public API.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	maxRequests    = 10000
	maxConcurrency = 64
	maxBodyBytes   = 4 << 20
)

type configuration struct {
	BaseURL        string
	APIKey         string
	ClusterID      string
	Requests       int
	Concurrency    int
	RequestTimeout time.Duration
	P95Limit       time.Duration
	MaxErrorRate   float64
	AllowHTTP      bool
}

type result struct {
	SchemaVersion string         `json:"schema_version"`
	StartedAt     time.Time      `json:"started_at"`
	CompletedAt   time.Time      `json:"completed_at"`
	Requests      int            `json:"requests"`
	Succeeded     int            `json:"succeeded"`
	Failed        int            `json:"failed"`
	ErrorRate     float64        `json:"error_rate"`
	P95Millis     int64          `json:"p95_millis"`
	MaximumMillis int64          `json:"maximum_millis"`
	StatusCounts  map[string]int `json:"status_counts"`
	Passed        bool           `json:"passed"`
}

type sample struct {
	duration time.Duration
	status   int
	err      error
}

func main() {
	cfg, err := parseFlags()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	report := run(context.Background(), cfg, http.DefaultClient)
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		fmt.Fprintln(os.Stderr, "encode acceptance report")
		os.Exit(2)
	}
	if !report.Passed {
		os.Exit(1)
	}
}

func parseFlags() (configuration, error) {
	var cfg configuration
	var keyEnvironment string
	flag.StringVar(&cfg.BaseURL, "base-url", "", "Sherlock API base URL ending in /api/v1")
	flag.StringVar(&cfg.ClusterID, "cluster-id", "", "authorized cluster identifier")
	flag.StringVar(&keyEnvironment, "api-key-env", "SHERLOCK_API_KEY", "environment variable containing the API key")
	flag.IntVar(&cfg.Requests, "requests", 200, "total read requests (4-10000)")
	flag.IntVar(&cfg.Concurrency, "concurrency", 8, "concurrent requests (1-64)")
	flag.DurationVar(&cfg.RequestTimeout, "request-timeout", 5*time.Second, "timeout for each request")
	flag.DurationVar(&cfg.P95Limit, "p95-limit", 750*time.Millisecond, "maximum accepted p95 latency")
	flag.Float64Var(&cfg.MaxErrorRate, "max-error-rate", 0.01, "maximum accepted error rate from 0 through 1")
	flag.BoolVar(&cfg.AllowHTTP, "allow-http", false, "permit cleartext HTTP for an isolated local test only")
	flag.Parse()
	cfg.APIKey = os.Getenv(keyEnvironment)
	if err := cfg.validate(); err != nil {
		return configuration{}, err
	}
	return cfg, nil
}

func (cfg configuration) validate() error {
	parsed, err := url.Parse(cfg.BaseURL)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "https" && !(cfg.AllowHTTP && parsed.Scheme == "http")) {
		return errors.New("base URL must be absolute HTTPS (or HTTP with -allow-http for an isolated local test)")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" || strings.TrimSuffix(parsed.Path, "/") != "/api/v1" {
		return errors.New("base URL must end in /api/v1 and contain no query or fragment")
	}
	if cfg.APIKey == "" || cfg.ClusterID == "" || strings.ContainsAny(cfg.ClusterID, "/?#") {
		return errors.New("API key environment variable and a safe cluster identifier are required")
	}
	if cfg.Requests < 4 || cfg.Requests > maxRequests || cfg.Concurrency < 1 || cfg.Concurrency > maxConcurrency || cfg.Concurrency > cfg.Requests {
		return errors.New("requests or concurrency are outside bounded limits")
	}
	if cfg.RequestTimeout <= 0 || cfg.RequestTimeout > time.Minute || cfg.P95Limit <= 0 || cfg.P95Limit > time.Minute || cfg.MaxErrorRate < 0 || cfg.MaxErrorRate > 1 {
		return errors.New("timeout or SLO thresholds are outside bounded limits")
	}
	return nil
}

func run(ctx context.Context, cfg configuration, client *http.Client) result {
	started := time.Now().UTC()
	jobs := make(chan int)
	samples := make(chan sample, cfg.Requests)
	var workers sync.WaitGroup
	for worker := 0; worker < cfg.Concurrency; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for index := range jobs {
				samples <- execute(ctx, cfg, client, index)
			}
		}()
	}
	go func() {
		for index := 0; index < cfg.Requests; index++ {
			jobs <- index
		}
		close(jobs)
		workers.Wait()
		close(samples)
	}()

	report := result{SchemaVersion: "sherlock.api-acceptance/v1", StartedAt: started, Requests: cfg.Requests, StatusCounts: make(map[string]int)}
	durations := make([]time.Duration, 0, cfg.Requests)
	for measured := range samples {
		durations = append(durations, measured.duration)
		report.StatusCounts[fmt.Sprint(measured.status)]++
		if measured.err == nil {
			report.Succeeded++
		} else {
			report.Failed++
		}
	}
	sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
	var p95 time.Duration
	if len(durations) > 0 {
		p95 = durations[(len(durations)*95-1)/100]
		report.P95Millis = p95.Milliseconds()
		report.MaximumMillis = durations[len(durations)-1].Milliseconds()
	}
	report.ErrorRate = float64(report.Failed) / float64(report.Requests)
	report.CompletedAt = time.Now().UTC()
	report.Passed = report.ErrorRate <= cfg.MaxErrorRate && p95 <= cfg.P95Limit
	return report
}

func execute(parent context.Context, cfg configuration, client *http.Client, index int) sample {
	paths := []string{
		"/clusters?page_size=25",
		"/clusters/" + url.PathEscape(cfg.ClusterID),
		"/clusters/" + url.PathEscape(cfg.ClusterID) + "/health",
		"/clusters/" + url.PathEscape(cfg.ClusterID) + "/sources?page_size=25",
	}
	ctx, cancel := context.WithTimeout(parent, cfg.RequestTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(cfg.BaseURL, "/")+paths[index%len(paths)], nil)
	if err != nil {
		return sample{err: err}
	}
	request.Header.Set("Authorization", "Bearer "+cfg.APIKey)
	request.Header.Set("Accept", "application/json")
	started := time.Now()
	response, err := client.Do(request)
	measured := sample{duration: time.Since(started)}
	if err != nil {
		measured.err = err
		return measured
	}
	defer response.Body.Close()
	measured.status = response.StatusCode
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxBodyBytes))
		measured.err = fmt.Errorf("unexpected HTTP status %d", response.StatusCode)
		return measured
	}
	if response.Header.Get("X-Request-ID") == "" || !strings.HasPrefix(response.Header.Get("Content-Type"), "application/json") {
		measured.err = errors.New("response lacks required request ID or JSON content type")
		return measured
	}
	payload, err := io.ReadAll(io.LimitReader(response.Body, maxBodyBytes+1))
	if err != nil || len(payload) > maxBodyBytes {
		measured.err = errors.New("response exceeds the body limit")
		return measured
	}
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	var document map[string]any
	if err := decoder.Decode(&document); err != nil || len(document) == 0 {
		measured.err = errors.New("response is not a bounded non-empty JSON object")
		return measured
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		measured.err = errors.New("response contains trailing JSON data")
	}
	return measured
}
