package prometheus

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

func TestInstantTimestampCausalBoundary(t *testing.T) {
	boundary := time.Date(2026, 9, 11, 7, 32, 19, 493095000, time.UTC)
	for _, at := range []time.Time{boundary, boundary.Truncate(time.Millisecond), time.Date(2026, 9, 11, 7, 32, 19, 999999999, time.UTC)} {
		t.Run(at.Format(time.RFC3339Nano), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				evaluation, err := time.Parse(time.RFC3339Nano, r.URL.Query().Get("time"))
				if err != nil {
					t.Error(err)
					w.WriteHeader(400)
					return
				}
				if evaluation.Before(at) || evaluation.Sub(at) >= time.Millisecond || evaluation.Nanosecond()%1000000 != 0 {
					t.Errorf("evaluation %s violates boundary %s", evaluation, at)
				}
				// Real Prometheus returns decimal Unix seconds at millisecond resolution.
				fmt.Fprintf(w, `{"status":"success","data":{"resultType":"vector","result":[{"metric":{},"value":[%d.%03d,"42"]}]}}`, evaluation.Unix(), evaluation.Nanosecond()/1000000)
			}))
			defer server.Close()
			client, err := NewClient(Config{BaseURL: server.URL, Timeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			result, err := client.Instant(context.Background(), domain.QueryGPUUtilization, "", at)
			if err != nil {
				t.Fatal(err)
			}
			observed := result.Samples[0].ObservedAt
			if observed.Before(at) || observed.Sub(at) >= time.Millisecond {
				t.Fatalf("returned timestamp %s violates strict boundary %s", observed, at)
			}
		})
	}
}

func TestSampleTimestampExactAndFailClosed(t *testing.T) {
	for _, tc := range []struct{ raw, want string }{
		{"1789111939.493", "2026-09-11T07:32:19.493Z"},
		{"1789111939.494", "2026-09-11T07:32:19.494Z"},
		{"1.789111939493e9", "2026-09-11T07:32:19.493Z"},
		{"-0.001", "1969-12-31T23:59:59.999Z"},
		{"1789111939.493095", "2026-09-11T07:32:19.493095Z"},
	} {
		t.Run(tc.raw, func(t *testing.T) {
			result, err := parseVectorResponse([]byte(fmt.Sprintf(`{"status":"success","data":{"resultType":"vector","result":[{"metric":{},"value":[%s,"1"]}]}}`, tc.raw)), 1)
			if err != nil {
				t.Fatal(err)
			}
			if got := result.Samples[0].ObservedAt.Format(time.RFC3339Nano); got != tc.want {
				t.Fatalf("got %s want %s", got, tc.want)
			}
		})
	}
	for _, raw := range []string{`"1789111939.493"`, "null", "true", "1e100000000", "1e-100000000", "9223372037", "0.0000000001"} {
		t.Run(raw, func(t *testing.T) {
			_, err := parseVectorResponse([]byte(fmt.Sprintf(`{"status":"success","data":{"resultType":"vector","result":[{"metric":{},"value":[%s,"1"]}]}}`, raw)), 1)
			if err == nil {
				t.Fatal("invalid timestamp accepted")
			}
		})
	}
}
