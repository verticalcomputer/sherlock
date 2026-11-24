package openrouter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/verticalcomputer/sherlock/internal/modelprovider"
)

const endpoint = "https://openrouter.ai/api/alpha/decisions"
const model = "liquid/d1.2-ultra"
const sizeLimit = 64 << 10

type Provider struct {
	key    string
	client *http.Client
}

func New(key string) (*Provider, error) {
	if strings.TrimSpace(key) == "" {
		return nil, errors.New("warming triage requires OPENROUTER_API_KEY")
	}
	return &Provider{key: key, client: &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func (p *Provider) TriageWarming(ctx context.Context, state json.RawMessage) (string, string, error) {
	state = bytes.TrimSpace(state)
	if len(state) == 0 || len(state) > sizeLimit || state[0] != '{' || !json.Valid(state) {
		return "", "", errors.New("invalid warming evidence")
	}
	body, err := json.Marshal(map[string]any{"model": model, "state": state, "questions": map[string]any{"action": map[string]any{
		"type": "choice", "instructions": warmingInstructions, "criteria": map[string]string{"WATCH": "Continue observation and reassess.", "NOTIFY": "Notify the hardware team now for investigation."},
	}}})
	if err != nil {
		return "", "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Authorization", "Bearer "+p.key)
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return "", "", errors.New("warming decision request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", errors.New("warming decision request rejected")
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, sizeLimit+1))
	if err != nil || len(data) > sizeLimit {
		return "", "", errors.New("invalid warming decision response")
	}
	choice, err := modelprovider.DecodeWarmingChoice(data, model)
	if err != nil {
		return "", "", err
	}
	if choice == "NOTIFY" {
		return choice, "Warming persisted above the confirmation thresholds. The decision model selected hardware investigation.", nil
	}
	return choice, "The decision model selected continued observation.", nil
}
