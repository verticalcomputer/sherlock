package alertdelivery

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testWebhook = "https://hooks.slack.com/services/T123/B456/secret-canary-789"

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func response(status int, body string, headers http.Header) *http.Response {
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: headers}
}

func TestWebhookFileRejectsExposedOrForgedSecrets(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hook")
	if err := os.WriteFile(path, []byte(testWebhook+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := LoadWebhookFile(path)
	if err != nil || got != testWebhook {
		t.Fatalf("load result=%q err=%v", got, err)
	}
	if err := os.Chmod(path, 0640); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadWebhookFile(path); err != nil {
		t.Fatalf("service-group-readable file rejected: %v", err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadWebhookFile(path); err == nil {
		t.Fatal("world-readable secret accepted")
	}
	if err := os.Symlink(path, filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadWebhookFile(filepath.Join(dir, "link")); err == nil {
		t.Fatal("symlink accepted")
	}
	for _, value := range []string{
		"http://hooks.slack.com/services/T/B/X", "https://hooks.slack.com.evil.test/services/T/B/X",
		"https://hooks.slack.com:444/services/T/B/X", "https://hooks.slack.com/services/T/B/X?token=y",
		"https://hooks.slack.com/services/T/B/X\nmalicious", "https://hooks.slack.com/services/T/B/X/more",
	} {
		if ValidSlackWebhook(value) {
			t.Fatalf("forged webhook accepted: %q", value)
		}
	}
}

func TestSlackSendClassifiesWithoutSecretLeakage(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		retry  string
		want   Outcome
		code   string
	}{
		{"accepted", 200, "ok", "", Accepted, "SLACK_ACCEPTED"},
		{"rate limited", 429, "secret-canary-789", "7", RetryableFailure, "RECEIVER_RETRYABLE"},
		{"server error", 503, "secret-canary-789", "", RetryableFailure, "RECEIVER_RETRYABLE"},
		{"revoked", 403, "secret-canary-789", "", PermanentFailure, "RECEIVER_REJECTED"},
		{"unexpected success", 200, "secret-canary-789", "", RetryableFailure, "UNEXPECTED_RESPONSE"},
		{"redirect", 302, "redirect", "", PermanentFailure, "RECEIVER_REJECTED"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			called := 0
			client := &http.Client{Transport: transportFunc(func(request *http.Request) (*http.Response, error) {
				called++
				if request.Method != http.MethodPost || request.URL.String() != testWebhook || request.Header.Get("Content-Type") != "application/json" {
					t.Fatalf("wrong request")
				}
				data, err := io.ReadAll(request.Body)
				if err != nil || string(data) != `{"text":"GP-09 test"}` {
					t.Fatalf("body=%q err=%v", data, err)
				}
				h := http.Header{}
				if tc.retry != "" {
					h.Set("Retry-After", tc.retry)
				}
				return response(tc.status, tc.body, h), nil
			}), CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			result := (Sender{Client: client}).Send(context.Background(), testWebhook, "GP-09 test")
			if called != 1 || result.Outcome != tc.want || result.Code != tc.code || strings.Contains(result.Describe(), "secret-canary") {
				t.Fatalf("result=%+v called=%d", result, called)
			}
			if tc.status == 429 && result.RetryAfter != 7*time.Second {
				t.Fatalf("retry-after=%v", result.RetryAfter)
			}
		})
	}
}

func TestSlackSendRejectsInvalidInputAndBoundsTransport(t *testing.T) {
	called := false
	sender := Sender{Client: &http.Client{Transport: transportFunc(func(*http.Request) (*http.Response, error) {
		called = true
		<-time.After(100 * time.Millisecond)
		return nil, context.DeadlineExceeded
	})}}
	for _, input := range []struct{ hook, message string }{{"https://example.com/secret", "test"}, {testWebhook, ""}, {testWebhook, strings.Repeat("x", MaxMessageBytes+1)}} {
		result := sender.Send(context.Background(), input.hook, input.message)
		if result.Outcome != PermanentFailure || called {
			t.Fatalf("invalid input reached transport: %+v", result)
		}
	}
	result := sender.Send(context.Background(), testWebhook, "test")
	if result.Outcome != RetryableFailure || result.Code != "TRANSPORT_FAILURE" || strings.Contains(result.Describe(), "secret") {
		t.Fatalf("unsafe transport error: %+v", result)
	}
}
