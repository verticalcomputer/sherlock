package loki

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/adapters/source"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

func TestSearchRendersOnlyAllowListedTemplateAndNormalizes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("query"); got != `{job="kernel",node="comp007"} |= "NVRM: Xid"` {
			t.Errorf("query = %q", got)
		}
		if r.URL.Query().Get("limit") != "2" || r.URL.Query().Get("direction") != "BACKWARD" {
			t.Errorf("bounds = %s", r.URL.RawQuery)
		}
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"streams","result":[{"stream":{"node":"comp007"},"values":[["1787133600000000000","NVRM: Xid 79"]]}]}}`))
	}))
	defer server.Close()
	client, err := NewClient(Config{BaseURL: server.URL, Timeout: time.Second, Templates: map[string]string{"kernel-xid": `{job="kernel",node="{{node}}"} |= "NVRM: Xid"`}})
	if err != nil {
		t.Fatal(err)
	}
	end := time.Date(2026, 8, 20, 11, 0, 0, 0, time.UTC)
	result, err := client.Search(context.Background(), SearchRequest{TemplateID: "kernel-xid", Node: "comp007", Start: end.Add(-time.Hour), End: end, Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Entries) != 1 || result.Entries[0].Line != "NVRM: Xid 79" || !result.Entries[0].Timestamp.Equal(time.Unix(0, 1787133600000000000)) {
		t.Fatalf("result = %#v", result)
	}
}

func TestForwardPageFixtureUsesForwardLookaheadAndOverlapReplay(t *testing.T) {
	fixture, err := os.ReadFile("testdata/forward-page-grafana-http-api-2026-09-22.json")
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Fixture struct {
			Source            string `json:"source"`
			VersionAssumption string `json:"version_assumption"`
		} `json:"fixture"`
		Response json.RawMessage `json:"response"`
	}
	if err := json.Unmarshal(fixture, &document); err != nil {
		t.Fatal(err)
	}
	if document.Fixture.Source != "Grafana Loki HTTP API" || document.Fixture.VersionAssumption != "documentation retrieved 2026-09-22" {
		t.Fatalf("fixture assumptions = %#v", document.Fixture)
	}
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("direction"); got != "FORWARD" {
			t.Errorf("direction = %q", got)
		}
		if got := r.URL.Query().Get("limit"); got != "3" {
			t.Errorf("lookahead limit = %q", got)
		}
		if calls.Add(1) == 1 {
			_, _ = w.Write(document.Response)
			return
		}
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"streams","result":[{"stream":{"job":"kernel","node":"comp002"},"values":[["2000000000","second"],["3000000000","third"]]}]}}`))
	}))
	defer server.Close()
	client := mustLokiClient(t, server.URL, 8)
	start := time.Unix(0, 0).UTC()
	end := start.Add(10 * time.Second)
	request := pageRequest(start, 2)
	request.End = end
	first, err := client.ForwardPage(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if first.Disposition != PageMore || len(first.Entries) != 2 || !first.Entries[0].LineOmitted || !first.Entries[1].LineOmitted || first.Continuation.SafeThrough == nil || !first.Continuation.SafeThrough.Equal(time.Unix(0, 2_000_000_000)) {
		t.Fatalf("first page = %#v", first)
	}
	request.Continuation = &first.Continuation
	second, err := client.ForwardPage(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if second.Disposition != PageTerminalExhausted || len(second.Entries) != 2 || !second.Entries[0].Replay || second.Entries[1].Replay || second.ReplayedEntries != 1 {
		t.Fatalf("overlap replay page = %#v", second)
	}
}

func TestForwardPageDoesNotAdvanceAcrossEqualTimestampTieOrCollapseRepeatedLines(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"streams","result":[{"stream":{"job":"kernel"},"values":[["1000000000","same"],["1000000000","same"],["1000000000","same again"]]}]}}`))
	}))
	defer server.Close()
	client := mustLokiClient(t, server.URL, 8)
	page, err := client.ForwardPage(context.Background(), pageRequest(time.Unix(0, 0), 2))
	if err != nil {
		t.Fatal(err)
	}
	if page.Disposition != PageAmbiguousTie || page.Continuation.SafeThrough != nil || len(page.Entries) != 2 || !page.Entries[0].LineOmitted || !page.Entries[1].LineOmitted || !hasPageGap(page.Gaps, PageGapTimestampTie) {
		t.Fatalf("ambiguous equal timestamp page = %#v", page)
	}
}

func TestForwardPageContinuationSerializesAndRejectsForeignOrChangedSourceScope(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"streams","result":[{"stream":{"job":"kernel"},"values":[["1000000000","one"],["2000000000","two"],["3000000000","three"]]}]}}`))
	}))
	defer server.Close()
	client := mustLokiClient(t, server.URL, 8)
	request := pageRequest(time.Unix(0, 0), 2)
	first, err := client.ForwardPage(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(first.Continuation)
	if err != nil || strings.Contains(string(encoded), "one") || strings.Contains(string(encoded), "job") {
		t.Fatalf("unsafe serialized continuation %q, err=%v", encoded, err)
	}
	var restarted Continuation
	if err := json.Unmarshal(encoded, &restarted); err != nil {
		t.Fatal(err)
	}
	request.Continuation = &restarted
	if _, err := client.ForwardPage(context.Background(), request); err != nil {
		t.Fatalf("serialized continuation restart: %v", err)
	}
	foreign := restarted
	foreign.ClusterID = "cluster-b"
	request.Continuation = &foreign
	assertInvalidPage(t, client, request)
	foreign = restarted
	foreign.SourceID = "loki-b"
	request.Continuation = &foreign
	assertInvalidPage(t, client, request)
	foreign = restarted
	foreign.SourceGeneration = strings.Repeat("b", 64)
	request.Continuation = &foreign
	assertInvalidPage(t, client, request)
	foreign = restarted
	atEnd := request.End.UTC()
	foreign.SafeThrough = &atEnd
	request.Continuation = &foreign
	assertInvalidPage(t, client, request)
	changedTemplate := mustLokiClient(t, server.URL, 8)
	changedTemplate.templates["kernel"] = `{job="another"}`
	request.Continuation = &restarted
	assertInvalidPage(t, changedTemplate, request)
	if got := calls.Load(); got != 2 {
		t.Fatalf("foreign/changing scope reached source %d times", got)
	}
}

func TestForwardPageMarksRetentionAndExpiredCursorWithoutCallingItComplete(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("start"); got != "2000000000" {
			t.Errorf("effective retention start = %q", got)
		}
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"streams","result":[]}}`))
	}))
	defer server.Close()
	client := mustLokiClient(t, server.URL, 8)
	request := pageRequest(time.Unix(0, 0), 2)
	checkpoint := time.Unix(0, 1_000_000_000).UTC()
	request.Continuation = &Continuation{SchemaVersion: ForwardPageSchemaVersion, ClusterID: request.ClusterID, SourceID: request.SourceID, TemplateID: request.TemplateID, SourceGeneration: request.SourceGeneration, QueryDigest: queryDigest(`{job="kernel"}`), RequestedWindow: PageWindow{Start: request.Start.UTC(), End: request.End.UTC()}, SafeThrough: &checkpoint}
	retention := time.Unix(0, 2_000_000_000).UTC()
	request.RetentionStart = &retention
	page, err := client.ForwardPage(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if page.Disposition != PageTerminalEmpty || !hasPageGap(page.Gaps, PageGapRetention) || !hasPageGap(page.Gaps, PageGapCursorExpired) {
		t.Fatalf("retention loss page = %#v", page)
	}
}

func TestForwardPageRedactsNormalizedEvidenceAndBoundsFailures(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"streams","result":[{"stream":{"job":"kernel","token":"source-secret","context":"hunter2"},"values":[["1000000000","password=log-secret bearer abcdefghijklmnop hunter2"]]}]}}`))
	}))
	defer server.Close()
	client, err := NewClient(Config{BaseURL: server.URL, Timeout: time.Second, MaxLines: 8, Templates: map[string]string{"kernel": `{job="kernel"}`}, PageLabelAllowlist: []string{"job", "context"}, Auth: Auth{BearerToken: "hunter2"}})
	if err != nil {
		t.Fatal(err)
	}
	page, err := client.ForwardPage(context.Background(), pageRequest(time.Unix(0, 0), 2))
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(page)
	if strings.Contains(string(encoded), "source-secret") || strings.Contains(string(encoded), "log-secret") || strings.Contains(string(encoded), "abcdefghijklmnop") || strings.Contains(string(encoded), "hunter2") || page.Entries[0].EvidenceUnmodified || page.Entries[0].Redactions == 0 || !page.Entries[0].LineOmitted || page.Entries[0].Labels[0].Name != "context" || page.Entries[0].Labels[0].Value != "[REDACTED]" {
		t.Fatalf("normalized evidence leaked or claimed identity: %s", encoded)
	}
	malformed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"status":"success"`)) }))
	defer malformed.Close()
	_, err = mustLokiClient(t, malformed.URL, 8).ForwardPage(context.Background(), pageRequest(time.Unix(0, 0), 2))
	var typed *source.Error
	if !errors.As(err, &typed) || typed.Code != domain.FailureMalformedResponse || strings.Contains(err.Error(), "secret") {
		t.Fatalf("malformed forward page error = %#v", err)
	}
}

func TestForwardPageStopsWhenOverlapFillsPageWithoutProgress(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"streams","result":[{"stream":{"job":"kernel"},"values":[["1000000000","old replay"],["2000000000","safe replay"],["3000000000","later unseen"]]}]}}`))
	}))
	defer server.Close()
	client := mustLokiClient(t, server.URL, 8)
	request := pageRequest(time.Unix(0, 0), 2)
	safe := time.Unix(0, 2_000_000_000).UTC()
	request.Continuation = &Continuation{SchemaVersion: ForwardPageSchemaVersion, ClusterID: request.ClusterID, SourceID: request.SourceID, TemplateID: request.TemplateID, SourceGeneration: request.SourceGeneration, QueryDigest: queryDigest(`{job="kernel"}`), RequestedWindow: PageWindow{Start: request.Start, End: request.End}, SafeThrough: &safe}
	page, err := client.ForwardPage(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if page.Disposition != PageOverlapSaturated || !hasPageGap(page.Gaps, PageGapOverlapSaturated) || page.Continuation.SafeThrough == nil || !page.Continuation.SafeThrough.Equal(safe) || page.ReplayedEntries != 2 {
		t.Fatalf("overlap saturation page = %#v", page)
	}
}

func TestForwardPageRejectsSourceRowsOutsideEffectiveHalfOpenWindow(t *testing.T) {
	for _, value := range []string{"-1", "10000000000"} {
		t.Run(value, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"streams","result":[{"stream":{"job":"kernel"},"values":[["` + value + `","outside"]]}]}}`))
			}))
			defer server.Close()
			_, err := mustLokiClient(t, server.URL, 8).ForwardPage(context.Background(), pageRequest(time.Unix(0, 0), 2))
			var typed *source.Error
			if !errors.As(err, &typed) || typed.Code != domain.FailureMalformedResponse {
				t.Fatalf("outside-window error = %#v", err)
			}
		})
	}
}

func TestForwardPageEnforcesReservedLineByteAndTimeLimits(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"streams","result":[{"stream":{},"values":[["1","this response is deliberately larger than the configured byte limit"]}]}}`))
	}))
	defer server.Close()
	client, err := NewClient(Config{BaseURL: server.URL, Timeout: time.Second, MaxBytes: 32, MaxLines: 3, Templates: map[string]string{"kernel": `{job="kernel"}`}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.ForwardPage(context.Background(), pageRequest(time.Unix(0, 0), 2))
	var typed *source.Error
	if !errors.As(err, &typed) || typed.Code != domain.FailureResultLimit {
		t.Fatalf("byte limit error = %#v", err)
	}
	_, err = client.ForwardPage(context.Background(), pageRequest(time.Unix(0, 0), 3))
	if !errors.As(err, &typed) || typed.Code != domain.FailureInvalidArgument {
		t.Fatalf("reserved lookahead line error = %#v", err)
	}
	timeout := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { time.Sleep(50 * time.Millisecond) }))
	defer timeout.Close()
	timed, err := NewClient(Config{BaseURL: timeout.URL, Timeout: time.Millisecond, MaxLines: 3, Templates: map[string]string{"kernel": `{job="kernel"}`}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = timed.ForwardPage(context.Background(), pageRequest(time.Unix(0, 0), 2))
	if !errors.As(err, &typed) || typed.Code != domain.FailureDeadlineExceeded {
		t.Fatalf("timeout error = %#v", err)
	}
}

func mustLokiClient(t *testing.T, baseURL string, maxLines int) *Client {
	t.Helper()
	client, err := NewClient(Config{BaseURL: baseURL, Timeout: time.Second, MaxLines: maxLines, Templates: map[string]string{"kernel": `{job="kernel"}`}, PageLabelAllowlist: []string{"job", "node"}})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func pageRequest(start time.Time, limit int) PageRequest {
	return PageRequest{ClusterID: "cluster-a", SourceID: "loki-a", TemplateID: "kernel", SourceGeneration: strings.Repeat("a", 64), Start: start.UTC(), End: start.UTC().Add(10 * time.Second), Limit: limit, Overlap: time.Second}
}

func hasPageGap(gaps []PageGap, want PageGap) bool {
	for _, gap := range gaps {
		if gap == want {
			return true
		}
	}
	return false
}

func assertInvalidPage(t *testing.T, client *Client, request PageRequest) {
	t.Helper()
	_, err := client.ForwardPage(context.Background(), request)
	var typed *source.Error
	if !errors.As(err, &typed) || typed.Code != domain.FailureInvalidArgument {
		t.Fatalf("invalid page error = %#v", err)
	}
}

func TestSearchRejectsInjectionAndUnboundedWindow(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests++ }))
	defer server.Close()
	client, _ := NewClient(Config{BaseURL: server.URL, Timeout: time.Second, Templates: map[string]string{"kernel": `{node="{{node}}"}`}})
	end := time.Now().UTC()
	for _, input := range []SearchRequest{{TemplateID: "kernel", Node: `x"} |= "secret`, Start: end.Add(-time.Hour), End: end, Limit: 1}, {TemplateID: "kernel", Node: "comp001", Start: end.Add(-25 * time.Hour), End: end, Limit: 1}, {TemplateID: "unknown", Node: "comp001", Start: end.Add(-time.Hour), End: end, Limit: 1}} {
		_, err := client.Search(context.Background(), input)
		var typed *source.Error
		if !errors.As(err, &typed) || typed.Code != domain.FailureInvalidArgument {
			t.Fatalf("error = %#v", err)
		}
	}
	if requests != 0 {
		t.Fatalf("made %d rejected requests", requests)
	}
}

func TestSearchEnforcesLineLimitFromUpstream(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"streams","result":[{"stream":{},"values":[["1","a"],["2","b"]]}]}}`))
	}))
	defer server.Close()
	client, _ := NewClient(Config{BaseURL: server.URL, Timeout: time.Second, Templates: map[string]string{"all": "{job=\"kernel\"}"}})
	end := time.Now().UTC()
	_, err := client.Search(context.Background(), SearchRequest{TemplateID: "all", Start: end.Add(-time.Minute), End: end, Limit: 1})
	var typed *source.Error
	if !errors.As(err, &typed) || typed.Code != domain.FailureResultLimit {
		t.Fatalf("error = %#v", err)
	}
}

func TestNewClientRequiresTLSOutsideLoopback(t *testing.T) {
	_, err := NewClient(Config{BaseURL: "http://loki.example", Timeout: time.Second, Templates: map[string]string{"all": `{job="kernel"}`}})
	if err == nil {
		t.Fatal("non-loopback HTTP Loki origin accepted")
	}
}

func TestNewClientRejectsUnsafeForwardPageLabelAllowlist(t *testing.T) {
	for _, allowlist := range [][]string{{"token"}, {"job", "job"}, {"not-a-label"}} {
		_, err := NewClient(Config{BaseURL: "http://127.0.0.1", Timeout: time.Second, Templates: map[string]string{"all": `{job="kernel"}`}, PageLabelAllowlist: allowlist})
		if err == nil {
			t.Fatalf("unsafe page label allowlist accepted: %#v", allowlist)
		}
	}
}

func TestSearchDoesNotForwardCredentialsAcrossRedirect(t *testing.T) {
	var destinationCalls atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		destinationCalls.Add(1)
		if request.Header.Get("Authorization") != "" {
			t.Error("Loki credential reached redirect destination")
		}
	}))
	defer destination.Close()
	sourceServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, destination.URL, http.StatusTemporaryRedirect)
	}))
	defer sourceServer.Close()
	client, err := NewClient(Config{BaseURL: sourceServer.URL, Timeout: time.Second, Templates: map[string]string{"all": `{job="kernel"}`}, Auth: Auth{BearerToken: "runtime-secret"}})
	if err != nil {
		t.Fatal(err)
	}
	end := time.Now().UTC()
	_, err = client.Search(context.Background(), SearchRequest{TemplateID: "all", Start: end.Add(-time.Minute), End: end, Limit: 1})
	var typed *source.Error
	if !errors.As(err, &typed) || destinationCalls.Load() != 0 {
		t.Fatalf("error=%v destination calls=%d", err, destinationCalls.Load())
	}
}
