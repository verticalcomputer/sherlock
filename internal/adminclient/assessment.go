package adminclient

import (
	"context"
	"errors"
	"github.com/verticalcomputer/sherlock/internal/alertdelivery"
	"net/http"
	"net/url"
	"strconv"
)

func (client *Client) GetAssessmentHistory(ctx context.Context, cluster, enrollment, occurrence string, after, audit int64) (alertdelivery.ProductionNotificationHistory, error) {
	var h alertdelivery.ProductionNotificationHistory
	if !validClusterID(cluster) || !validClusterID(enrollment) || !validClusterID(occurrence) || after < 0 || audit < 0 {
		return h, errors.New("invalid assessment history scope")
	}
	path := "/internal/admin/v1/clusters/" + url.PathEscape(cluster) + "/assessment/" + url.PathEscape(enrollment) + "/" + url.PathEscape(occurrence)
	req, err := client.requestQuery(ctx, http.MethodGet, path, url.Values{"after": {strconv.FormatInt(after, 10)}, "after_audit": {strconv.FormatInt(audit, 10)}}, nil)
	if err != nil {
		return h, err
	}
	b, err := client.do(req)
	if err != nil {
		return h, err
	}
	if err = decodeStrict(b, &h); err != nil {
		return h, errors.New("invalid assessment history response")
	}
	if h.Occurrence.ClusterID != cluster || h.Occurrence.EnrollmentID != enrollment || h.Occurrence.ID != occurrence {
		return alertdelivery.ProductionNotificationHistory{}, errors.New("assessment history scope mismatch")
	}
	return h, nil
}
