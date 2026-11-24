package openrouter

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestDecisionContract(t *testing.T) {
	if _, err := New(""); err == nil {
		t.Fatal("accepted empty credential")
	}
	p, err := New("test")
	if err != nil {
		t.Fatal(err)
	}
	const input = `{"rows":[[0,66,500,null]]}`
	for _, tc := range []struct{ name, reply, want string }{
		{"notify", `{"model":"liquid/d1.2-ultra-20261116","answers":{"action":{"type":"choice","choice":"NOTIFY","confidence":0.5}}}`, "NOTIFY"},
		{"watch", `{"model":"liquid/d1.2-ultra","answers":{"action":{"type":"choice","choice":"WATCH"}}}`, "WATCH"},
		{"wrong model", `{"model":"other","answers":{"action":{"type":"choice","choice":"NOTIFY"}}}`, ""},
		{"duplicate", `{"model":"liquid/d1.2-ultra","answers":{"action":{"type":"choice","choice":"WATCH","choice":"NOTIFY"}}}`, ""},
		{"invalid choice", `{"model":"liquid/d1.2-ultra","answers":{"action":{"type":"choice","choice":"YES"}}}`, ""},
		{"error", `{"error":{"message":"failed"}}`, ""},
		{"too large", strings.Repeat(" ", sizeLimit+1), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p.client.Transport = transportFunc(func(r *http.Request) (*http.Response, error) {
				if r.URL.String() != endpoint || r.Method != "POST" || r.Header.Get("Authorization") != "Bearer test" {
					t.Fatal("incorrect request destination or authorization")
				}
				var req struct {
					Model     string
					State     json.RawMessage
					Questions map[string]struct {
						Type, Instructions string
						Criteria           map[string]string
					}
				}
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					t.Fatal(err)
				}
				action := req.Questions["action"]
				if req.Model != model || string(req.State) != input || action.Type != "choice" || action.Instructions != warmingInstructions || len(action.Criteria) != 2 || action.Criteria["WATCH"] == "" || action.Criteria["NOTIFY"] == "" {
					t.Fatal("incorrect decision contract")
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(tc.reply))}, nil
			})
			got, reason, err := p.TriageWarming(context.Background(), []byte(input))
			if got != tc.want || (err == nil) != (tc.want != "") || (reason != "") != (tc.want != "") {
				t.Fatalf("unexpected decision %q, error %v", got, err)
			}
		})
	}
}

func TestRedirectCannotForwardCredential(t *testing.T) {
	p, _ := New("test")
	calls := 0
	p.client.Transport = transportFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		h := make(http.Header)
		h.Set("Location", "https://example.com/elsewhere")
		return &http.Response{StatusCode: 307, Header: h, Body: http.NoBody}, nil
	})
	action, _, err := p.TriageWarming(context.Background(), []byte(`{}`))
	if err == nil || action != "" || calls != 1 {
		t.Fatal("redirect must fail closed")
	}
}
