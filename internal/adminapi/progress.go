package adminapi

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/verticalcomputer/sherlock/internal/application"
	"github.com/verticalcomputer/sherlock/internal/domain"
)

type ProgressProvider interface {
	Evaluate(context.Context, application.ProgressQuery) (application.ProgressWindowResult, error)
}

func (server *Server) clusterProgress(writer http.ResponseWriter, request *http.Request) {
	if server.progress == nil {
		writeProblem(writer, http.StatusServiceUnavailable, "PROGRESS_DISABLED", "the progress projection is not configured")
		return
	}
	clusterID := request.PathValue("cluster_id")
	if !validClusterIDPath(clusterID) {
		writeProblem(writer, http.StatusBadRequest, "INVALID_ARGUMENT", "the cluster ID is invalid")
		return
	}
	query := request.URL.Query()
	fields := []string{"source_id", "allocation_source_id", "inventory_source_id", "scheduler_namespace", "job_id", "submit_at", "attempt", "start", "end", "max_gap_seconds"}
	if len(query) != len(fields) {
		writeProblem(writer, http.StatusBadRequest, "INVALID_ARGUMENT", "an exact progress query is required")
		return
	}
	for _, field := range fields {
		if len(query[field]) != 1 || query.Get(field) == "" {
			writeProblem(writer, http.StatusBadRequest, "INVALID_ARGUMENT", "an exact progress query is required")
			return
		}
	}
	start, startErr := time.Parse(time.RFC3339Nano, query.Get("start"))
	end, endErr := time.Parse(time.RFC3339Nano, query.Get("end"))
	submitAt, submitErr := time.Parse(time.RFC3339Nano, query.Get("submit_at"))
	attempt, attemptErr := strconv.Atoi(query.Get("attempt"))
	maxGapSeconds, gapErr := strconv.Atoi(query.Get("max_gap_seconds"))
	if startErr != nil || endErr != nil || submitErr != nil || attemptErr != nil || gapErr != nil ||
		maxGapSeconds < 1 || maxGapSeconds > 3600 || len(query.Get("source_id")) > 256 || len(query.Get("allocation_source_id")) > 256 || len(query.Get("inventory_source_id")) > 256 {
		writeProblem(writer, http.StatusBadRequest, "INVALID_ARGUMENT", "the progress query is invalid")
		return
	}
	input := application.ProgressQuery{ClusterID: domain.ClusterID(clusterID), SourceID: domain.SourceID(query.Get("source_id")),
		AllocationSourceID: domain.SourceID(query.Get("allocation_source_id")),
		InventorySourceID:  domain.SourceID(query.Get("inventory_source_id")),
		Job: domain.JobIdentity{SchedulerNamespace: domain.SchedulerNamespace(query.Get("scheduler_namespace")),
			JobID: domain.SchedulerJobID(query.Get("job_id")), SubmitAt: submitAt, Attempt: attempt},
		Start: start, End: end, MaxGap: time.Duration(maxGapSeconds) * time.Second}
	if !validClusterIDPath(query.Get("source_id")) || !validClusterIDPath(query.Get("allocation_source_id")) || !validClusterIDPath(query.Get("inventory_source_id")) ||
		!end.After(start) || end.Sub(start) > 24*time.Hour {
		writeProblem(writer, http.StatusBadRequest, "INVALID_ARGUMENT", "the progress query is invalid")
		return
	}
	if _, err := domain.CreateJobIdentity(input.Job); err != nil {
		writeProblem(writer, http.StatusBadRequest, "INVALID_ARGUMENT", "the progress job identity is invalid")
		return
	}
	result, err := server.progress.Evaluate(request.Context(), input)
	if err != nil {
		writeProblem(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "the progress projection is temporarily unavailable")
		return
	}
	writeJSON(writer, http.StatusOK, result)
}
