package azureopenai

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/verticalcomputer/sherlock/internal/modelprovider"
)

func TestWarmingTriageUsesReviewedPromptAndStrictOutput(t *testing.T) {
	evidence := json.RawMessage(`{"rows":[[-15,60,500,null],[0,66,500,null]]}`)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request responseRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
		}
		if r.URL.Path != "/openai/v1/responses" || request.Store || request.MaxOutputTokens != 1200 ||
			len(request.Input) != 1 || request.Input[0].Content != string(evidence) ||
			request.Text.Format.Name != "sherlock_warming_v1" || !request.Text.Format.Strict {
			t.Error("unexpected cooling triage request")
		}
		if got := fmt.Sprintf("%x", sha256.Sum256([]byte(request.Instructions))); got != "a1f8c4be69d5f223d86986ab2ecd260a8f7f864279f76e78a5c2931262043d92" {
			t.Error("warming instructions differ from offline qualification")
		}
		writeResponse(t, w, `{"action":"NOTIFY","reason":"Temperature rose again while load remained stable."}`, 20, 10)
	}))
	defer server.Close()
	action, reason, err := testProvider(t, server.URL).TriageWarming(context.Background(), evidence)
	if err != nil || action != "NOTIFY" || !strings.Contains(reason, "stable") {
		t.Fatalf("unexpected decision %q %q, err=%v", action, reason, err)
	}
}

func TestWarmingTriageRefusalCannotPage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"status":"completed","output":[{"type":"message","content":[{"type":"refusal","refusal":"no"}]}]}`)
	}))
	defer server.Close()
	provider := testProvider(t, server.URL)
	for _, input := range []string{`{"rows":[]}`, "null", "[]", "{", strings.Repeat("x", 65537)} {
		if action, reason, err := provider.TriageWarming(context.Background(), []byte(input)); err == nil || action != "" || reason != "" {
			t.Fatalf("unexpected successful decision %q %q", action, reason)
		}
	}
}

func TestWarmingDecisionSchema(t *testing.T) {
	if action, _, err := modelprovider.DecodeWarmingDecision([]byte(`{"action":"WATCH","reason":"The current load explains the temperature."}`)); err != nil || action != "WATCH" {
		t.Fatal("WATCH rejected")
	}
	for _, output := range []string{
		`{"action":"ALERT","reason":"Rising."}`, `{"action":"NOTIFY"}`, `{"action":"NOTIFY","reason":" "}`,
		`{"action":"NOTIFY","reason":"Rising.","unused":true}`, `{"action":"WATCH","action":"NOTIFY","reason":"Rising."}`,
		`{"ACTION":"NOTIFY","reason":"Rising."}`, `{"action":"NOTIFY","reason":"line\nline"}`,
		`{"action":"WATCH","reason":"Normal."}{}`,
	} {
		if action, _, err := modelprovider.DecodeWarmingDecision([]byte(output)); err == nil || action != "" {
			t.Errorf("accepted invalid output %q", output)
		}
	}
}
