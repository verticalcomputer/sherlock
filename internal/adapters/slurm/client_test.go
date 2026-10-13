package slurm

import (
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/adapters/source"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

type call struct {
	command string
	args    []string
}
type fixtureRunner struct {
	body  []byte
	err   error
	calls []call
	max   int
}

func (r *fixtureRunner) Run(_ context.Context, maxBytes int, command string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, call{command, append([]string(nil), args...)})
	r.max = maxBytes
	return r.body, r.err
}

func TestNodesUsesExactBoundedArgvAndNormalizes(t *testing.T) {
	runner := &fixtureRunner{body: []byte(`{"nodes":[{"name":"comp007","state":"ALLOCATED","cpus":128,"last_busy":1787133600}]}`)}
	client, err := NewClient(Config{Timeout: time.Second, Runner: runner})
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.Nodes(context.Background(), []string{"comp007"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(runner.calls, []call{{command: "scontrol", args: []string{"show", "nodes", "--json", "comp007"}}}) {
		t.Fatalf("calls = %#v", runner.calls)
	}
	if runner.max != defaultMaxBytes {
		t.Fatalf("runner limit = %d", runner.max)
	}
	if len(result.Records) != 1 || result.Records[0].ID != "comp007" || result.Records[0].State != "ALLOCATED" || !result.Records[0].ObservedAt.Equal(time.Unix(1787133600, 0)) {
		t.Fatalf("result = %#v", result)
	}
}

func TestExecRunnerStopsReadingAtOutputLimit(t *testing.T) {
	runner := execRunner{timeout: time.Second}
	body, err := runner.Run(context.Background(), 32, os.Args[0], "-test.run=TestExecRunnerProcess", "--", "oversize")
	if !errors.Is(err, errOutputLimit) || body != nil {
		t.Fatalf("body=%q error=%v", body, err)
	}
}

func TestExecRunnerPropagatesCancellation(t *testing.T) {
	runner := execRunner{timeout: 2 * time.Second}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, err := runner.Run(ctx, 32, os.Args[0], "-test.run=TestExecRunnerProcess", "--", "wait")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v", err)
	}
}

func TestExecRunnerProcess(t *testing.T) {
	separator := -1
	for index, argument := range os.Args {
		if argument == "--" {
			separator = index
			break
		}
	}
	if separator < 0 || separator+1 >= len(os.Args) {
		return
	}
	switch os.Args[separator+1] {
	case "oversize":
		_, _ = fmt.Fprint(os.Stdout, strings.Repeat("x", 1<<20))
	case "wait":
		time.Sleep(10 * time.Second)
	}
}

func TestAccountingRejectsUnsafeScopeBeforeExecution(t *testing.T) {
	runner := &fixtureRunner{}
	client, _ := NewClient(Config{Timeout: time.Second, Runner: runner})
	end := time.Now().UTC()
	for _, input := range [][]string{{"1;rm"}, {"1", "1"}} {
		if _, err := client.Accounting(context.Background(), end.Add(-time.Hour), end, input); err == nil {
			t.Fatalf("scope %#v accepted", input)
		}
	}
	if _, err := client.Accounting(context.Background(), end.Add(-8*24*time.Hour), end, nil); err == nil {
		t.Fatal("unbounded window accepted")
	}
	if len(runner.calls) != 0 {
		t.Fatalf("executed rejected query: %#v", runner.calls)
	}
}

func TestAccountingAllocationsUsesExactClusterAndOverlapIdentityFlags(t *testing.T) {
	runner := &fixtureRunner{body: []byte(`{"jobs":[]}`)}
	client, _ := NewClient(Config{Timeout: time.Second, Runner: runner})
	start := time.Date(2026, 9, 19, 1, 2, 3, 0, time.FixedZone("offset", 5*60*60+30*60))
	end := start.Add(time.Hour)
	if _, err := client.AccountingAllocations(context.Background(), start, end, "cluster-a", []string{"41"}); err != nil {
		t.Fatal(err)
	}
	want := []call{{command: "sacct", args: []string{"--json", "--starttime=2026-09-18T19:32:03", "--endtime=2026-09-18T20:32:03", "--allocations", "--duplicates", "--clusters=cluster-a", "--jobs=41"}}}
	if !reflect.DeepEqual(runner.calls, want) {
		t.Fatalf("calls = %#v", runner.calls)
	}
	if _, err := client.AccountingAllocations(context.Background(), start, end, "cluster-a,other", nil); err == nil {
		t.Fatal("unsafe accounting cluster accepted")
	}
}

func TestMalformedAndRecordLimitAreClassified(t *testing.T) {
	for _, test := range []struct {
		name string
		body string
		max  int
		code domain.FailureCode
	}{{"malformed", `{`, 10, domain.FailureMalformedResponse}, {"limit", `{"jobs":[{"job_id":1},{"job_id":2}]}`, 1, domain.FailureResultLimit}} {
		t.Run(test.name, func(t *testing.T) {
			runner := &fixtureRunner{body: []byte(test.body)}
			client, _ := NewClient(Config{Timeout: time.Second, MaxRecords: test.max, Runner: runner})
			_, err := client.Jobs(context.Background(), nil)
			var typed *source.Error
			if !errors.As(err, &typed) || typed.Code != test.code {
				t.Fatalf("error = %#v", err)
			}
		})
	}
}

func TestDiagnosticEnvelopeMustBeAbsentNullOrArray(t *testing.T) {
	for _, test := range []struct {
		name    string
		body    string
		wantErr bool
	}{
		{name: "absent", body: `{"jobs":[]}`},
		{name: "null", body: `{"errors":null,"warnings":null,"jobs":[]}`},
		{name: "empty-arrays", body: `{"errors":[],"warnings":[],"jobs":[]}`},
		{name: "object-error", body: `{"errors":{"error":"query failed"},"jobs":[]}`, wantErr: true},
		{name: "string-warning", body: `{"warnings":"partial result","jobs":[]}`, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, err := NewClient(Config{Timeout: time.Second, Runner: &fixtureRunner{body: []byte(test.body)}})
			if err != nil {
				t.Fatal(err)
			}
			result, err := client.Jobs(t.Context(), nil)
			if !test.wantErr {
				if err != nil || len(result.Records) != 0 || result.ReportedErrors != 0 || result.ReportedWarnings != 0 {
					t.Fatalf("result=%#v err=%v", result, err)
				}
				return
			}
			var classified *source.Error
			if !errors.As(err, &classified) || classified.Code != domain.FailureMalformedResponse {
				t.Fatalf("error = %#v", err)
			}
		})
	}
}

func FuzzNormalizeFailsClosed(f *testing.F) {
	f.Add([]byte(`{"jobs":[{"job_id":42,"job_state":"RUNNING"}]}`))
	f.Fuzz(func(t *testing.T, body []byte) {
		records, _, err := normalize("job", body, 32)
		if err == nil {
			if len(records) > 32 {
				t.Fatal("record limit bypass")
			}
			for _, record := range records {
				if record.ID == "" {
					t.Fatal("empty identity accepted")
				}
			}
		}
	})
}
