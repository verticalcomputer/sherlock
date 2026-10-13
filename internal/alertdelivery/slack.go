// Package alertdelivery sends bounded notifications without exposing receiver
// secrets in returned errors or logs. Durable scheduling is owned by a caller.
package alertdelivery

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const MaxWebhookBytes = 2048
const MaxMessageBytes = 3000
const RequestTimeout = 5 * time.Second

var ErrInvalidWebhook = errors.New("invalid Slack webhook configuration")
var ErrInvalidMessage = errors.New("invalid Slack message")

// LoadWebhookFile accepts only Slack's HTTPS incoming-webhook origins. The
// secret is held in memory for the duration of delivery and never returned by
// an error. File permissions are verified to catch an accidental public file.
func LoadWebhookFile(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0037 != 0 || info.Size() < 32 || info.Size() > MaxWebhookBytes {
		return "", ErrInvalidWebhook
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", ErrInvalidWebhook
	}
	value := strings.TrimSuffix(string(data), "\n")
	if !ValidSlackWebhook(value) {
		return "", ErrInvalidWebhook
	}
	return value, nil
}

func ValidSlackWebhook(value string) bool {
	if len(value) < 32 || len(value) > MaxWebhookBytes || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\r\n\t ") {
		return false
	}
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || u.Port() != "" {
		return false
	}
	if u.Host != "hooks.slack.com" && u.Host != "hooks.slack-gov.com" {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
	return len(parts) == 4 && parts[0] == "services" && parts[1] != "" && parts[2] != "" && parts[3] != "" && u.RawPath == ""
}

type Outcome string

const (
	Accepted         Outcome = "ACCEPTED"
	RetryableFailure Outcome = "RETRYABLE_FAILURE"
	PermanentFailure Outcome = "PERMANENT_FAILURE"
)

type Result struct {
	Outcome    Outcome
	HTTPStatus int
	RetryAfter time.Duration
	Code       string
}

type Sender struct{ Client *http.Client }

// Send issues exactly one HTTPS POST. A caller must durably record its result
// and decide whether to retry; a lost HTTP response can cause a duplicate
// Slack message on retry, so transport acceptance is not exactly-once proof.
func (sender Sender) Send(ctx context.Context, webhook, message string) Result {
	if !ValidSlackWebhook(webhook) || len(message) == 0 || len(message) > MaxMessageBytes || strings.TrimSpace(message) == "" {
		return Result{Outcome: PermanentFailure, Code: "INVALID_INPUT"}
	}
	client := sender.Client
	if client == nil {
		client = &http.Client{Timeout: RequestTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	bounded, cancel := context.WithTimeout(ctx, RequestTimeout)
	defer cancel()
	body, err := json.Marshal(struct {
		Text string `json:"text"`
	}{Text: message})
	if err != nil {
		return Result{Outcome: PermanentFailure, Code: "INVALID_INPUT"}
	}
	request, err := http.NewRequestWithContext(bounded, http.MethodPost, webhook, bytes.NewReader(body))
	if err != nil {
		return Result{Outcome: PermanentFailure, Code: "INVALID_INPUT"}
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return Result{Outcome: RetryableFailure, Code: "TRANSPORT_FAILURE"}
	}
	defer response.Body.Close()
	result := Result{HTTPStatus: response.StatusCode}
	if response.StatusCode == http.StatusOK {
		data, readErr := io.ReadAll(io.LimitReader(response.Body, 16))
		if readErr == nil && strings.TrimSpace(string(data)) == "ok" {
			result.Outcome, result.Code = Accepted, "SLACK_ACCEPTED"
			return result
		}
		result.Outcome, result.Code = RetryableFailure, "UNEXPECTED_RESPONSE"
		return result
	}
	if response.StatusCode == http.StatusTooManyRequests || response.StatusCode >= 500 {
		result.Outcome, result.Code = RetryableFailure, "RECEIVER_RETRYABLE"
		if seconds, parseErr := strconv.Atoi(response.Header.Get("Retry-After")); parseErr == nil && seconds >= 0 && seconds <= 300 {
			result.RetryAfter = time.Duration(seconds) * time.Second
		}
		return result
	}
	result.Outcome, result.Code = PermanentFailure, "RECEIVER_REJECTED"
	return result
}

// Describe contains only safe status metadata; it never formats the webhook
// or the response body, which may echo secrets or other untrusted content.
func (result Result) Describe() string {
	return fmt.Sprintf("outcome=%s code=%s http_status=%d retry_after=%s", result.Outcome, result.Code, result.HTTPStatus, result.RetryAfter)
}
