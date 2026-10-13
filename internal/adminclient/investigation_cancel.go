package adminclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/verticalcomputer/sherlock/internal/adminui"
	"net/http"
	"net/url"
)

func (client *Client) CancelInvestigation(ctx context.Context, id string, version int, reason string, mutation adminui.MutationContext) error {
	if !validClusterID(id) || version < 1 {
		return errors.New("invalid investigation reference")
	}
	body, err := json.Marshal(struct {
		ExpectedVersion    int    `json:"expected_version"`
		Reason             string `json:"reason"`
		SessionFingerprint []byte `json:"session_fingerprint"`
		RequestID          string `json:"request_id"`
	}{version, reason, mutation.SessionFingerprint[:], mutation.RequestID})
	if err != nil {
		return errors.New("encode investigation cancellation")
	}
	request, err := client.request(ctx, http.MethodPost, "/internal/admin/v1/investigations/"+url.PathEscape(id)+"/cancel", bytes.NewReader(body))
	if err != nil {
		return err
	}
	_, err = client.do(request)
	return err
}
