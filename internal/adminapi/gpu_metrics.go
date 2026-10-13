package adminapi

import (
	"context"
	"net/http"

	"github.com/verticalcomputer/sherlock/internal/adminview"
)

// GPUMetricsProvider is a separate narrow boundary from SnapshotProvider: the
// expanded-DCGM projection is a different bounded read with its own evaluation
// instant, and widening the dashboard provider would couple them. A deployment
// without this provider serves an explicit unavailable answer rather than an
// empty one, so a missing projection is never read as "no GPU problems".
type GPUMetricsProvider interface {
	GPUMetrics(context.Context, adminview.GPUMetricsQuery) (adminview.GPUMetricsSnapshot, error)
}

// clusterGPUMetrics serves the persisted per-GPU field evidence for one
// cluster. It carries the same bearer authentication, query rejection,
// security headers, and redacted backend errors as the other cluster reads.
func (server *Server) clusterGPUMetrics(writer http.ResponseWriter, request *http.Request) {
	if rejectQuery(writer, request) {
		return
	}
	if server.gpuMetrics == nil {
		writeProblem(writer, http.StatusServiceUnavailable, "GPU_METRICS_DISABLED", "the GPU metric projection is not configured")
		return
	}
	id := request.PathValue("cluster_id")
	if !validClusterIDPath(id) {
		writeProblem(writer, http.StatusBadRequest, "INVALID_ARGUMENT", "the cluster ID is invalid")
		return
	}
	snapshot, err := server.gpuMetrics.GPUMetrics(request.Context(), adminview.GPUMetricsQuery{
		ClusterID: id, Now: server.clock.Now().UTC(),
	})
	if err != nil {
		writeProblem(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "the GPU metric projection is temporarily unavailable")
		return
	}
	writeJSON(writer, http.StatusOK, snapshot)
}
