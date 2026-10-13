package adminclient

import (
	"context"
	"errors"
	"io"
	"net/http"

	"github.com/verticalcomputer/sherlock/internal/adminui"
)

func (client *Client) LoadHumanAccess(ctx context.Context) ([]adminui.ClusterAccess, error) {
	request, err := client.request(ctx, http.MethodGet, "/internal/admin/v1/human-access", nil)
	if err != nil {
		return nil, err
	}
	response, err := client.http.Do(request)
	if err != nil {
		return nil, errors.New("human authorization unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusForbidden {
		return nil, adminui.ErrHumanAccessDenied
	}
	if response.StatusCode != http.StatusOK {
		return nil, errors.New("human authorization unavailable")
	}
	payload, err := io.ReadAll(io.LimitReader(response.Body, 32769))
	if err != nil || len(payload) > 32768 {
		return nil, errors.New("human authorization response invalid")
	}
	var result struct {
		Clusters []adminui.ClusterAccess `json:"clusters"`
	}
	if decodeStrict(payload, &result) != nil || len(result.Clusters) < 1 || len(result.Clusters) > 64 {
		return nil, errors.New("human authorization response invalid")
	}
	seen := map[string]bool{}
	for _, row := range result.Clusters {
		if !validClusterID(row.ClusterID) || seen[row.ClusterID] || (row.Role != "CLUSTER_ADMIN" && row.Role != "CLUSTER_VIEWER") ||
			row.Role == "CLUSTER_VIEWER" && (row.CanConfigure || row.CanInvestigate || row.CanManageCredentials || row.CanManagePolicy || row.CanRemove) ||
			(row.CanManageCredentials || row.CanManagePolicy || row.CanRemove) && !row.CanConfigure {
			return nil, errors.New("human authorization response invalid")
		}
		seen[row.ClusterID] = true
	}
	return result.Clusters, nil
}
