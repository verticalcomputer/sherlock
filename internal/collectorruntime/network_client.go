package collectorruntime

import (
	"context"
	"errors"
	"net/http"

	"github.com/verticalcomputer/sherlock/internal/networkmonitor"
)

func (c *HTTPClient) SubmitNetworkCycle(ctx context.Context, cycle networkmonitor.Cycle) error {
	var response struct {
		Accepted bool `json:"accepted"`
	}
	_, err := c.doV2(ctx, http.MethodPost, "/collector/v2/network/polls", cycle, &response, 200)
	if err == nil && !response.Accepted {
		return errors.New("network cycle was not accepted")
	}
	return err
}
