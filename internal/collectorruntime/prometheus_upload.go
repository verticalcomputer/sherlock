package collectorruntime

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

const prometheusSpoolMaxEntries = 112

type prometheusExecutor interface {
	Execute(context.Context, domain.CollectionTask) domain.CollectionResult
}

// ProbePrometheusUpload submits an intentionally invalid report. The exact
// application error proves the request passed authentication and scope
// checks, without persisting a collection result.
func (c *HTTPClient) ProbePrometheusUpload(ctx context.Context) error {
	bounded, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	var problem struct {
		Type          string `json:"type"`
		Title         string `json:"title"`
		Status        int    `json:"status"`
		Code          string `json:"code"`
		CorrelationID string `json:"correlation_id"`
	}
	_, err := c.do(bounded, http.MethodPost, domain.PrometheusUploadPath, struct{}{}, &problem, http.StatusBadRequest)
	if err != nil {
		return err
	}
	if problem.Type != "urn:sherlock:collector:error:invalid_argument" || problem.Title != "scheduled report is invalid" ||
		problem.Status != http.StatusBadRequest || problem.Code != "INVALID_ARGUMENT" || problem.CorrelationID == "" {
		return fmt.Errorf("scheduled upload route returned an unexpected readiness response")
	}
	return nil
}

func (c *HTTPClient) uploadPrometheusReport(ctx context.Context, raw json.RawMessage) (bool, error) {
	bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	status, err := c.do(bounded, http.MethodPost, domain.PrometheusUploadPath, raw, nil,
		http.StatusNoContent, http.StatusBadRequest, http.StatusRequestEntityTooLarge, http.StatusConflict)
	return status != http.StatusNoContent && err == nil, err
}

// RunPrometheusUpload evaluates the fixed profile on minute boundaries. Missed
// evaluations are skipped. Already evaluated reports are durably retried from
// a private spool without asking the server for work.
func RunPrometheusUpload(ctx context.Context, executor prometheusExecutor, client *HTTPClient, logger *slog.Logger,
	dir string, cluster domain.ClusterID, source domain.SourceID) error {
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return fmt.Errorf("scheduled report spool must be an existing private 0700 directory")
	}
	lock, err := acquireJournalLock(filepath.Join(dir, ".lock"))
	if err != nil {
		return err
	}
	defer lock.release()
	s := prometheusSpool{dir: dir, client: client, logger: logger}
	if err := s.flush(ctx, time.Now()); err != nil {
		return err
	}
	for ctx.Err() == nil {
		slot := time.Now().UTC().Truncate(domain.PrometheusUploadInterval).Add(domain.PrometheusUploadInterval)
		timer := time.NewTimer(time.Until(slot))
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
		if err := s.collect(ctx, executor, cluster, source, slot); err != nil {
			return err
		}
		if err := s.flush(ctx, time.Now()); err != nil {
			return err
		}
	}
	return ctx.Err()
}

type prometheusSpool struct {
	dir    string
	client *HTTPClient
	logger *slog.Logger
}

func (s prometheusSpool) collect(ctx context.Context, executor prometheusExecutor,
	cluster domain.ClusterID, source domain.SourceID, slot time.Time) error {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return err
	}
	// Reserve room for one profile cycle. Expired files are swept after
	// collection and this hard limit also applies across clock regressions.
	queries := domain.PrometheusUploadQueries()
	if len(entries)+len(queries) > prometheusSpoolMaxEntries+1 {
		s.logger.Warn("collector.prometheus_spool_full")
		return nil
	}
	for index, query := range queries {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		task := domain.PrometheusUploadTask(cluster, source, query, slot)
		if time.Until(task.Deadline) < time.Second {
			break
		}
		result := executor.Execute(ctx, task)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		// Keep only the physical identity and optional numeric projection index.
		// Reject ambiguous UUID/MIG labels before dropping exporter metadata.
		samples := result.Observations[:0]
		for _, o := range result.Observations {
			node, gpu, valid := domain.DCGMIdentity(o.Labels, task)
			if !valid {
				result.Status = domain.ResultPartial
				result.Coverage.Complete = false
				result.Failures = []domain.CollectionFailure{{Code: domain.FailurePartialData, Message: "Prometheus returned an ambiguous physical GPU identity"}}
				continue
			}
			labels := map[string]string{"Hostname": node, "UUID": gpu}
			for _, label := range o.Labels {
				if label.Name == "gpu" && len(label.Value) > 0 && len(label.Value) <= 8 && strings.Trim(label.Value, "0123456789") == "" {
					labels["gpu"] = label.Value
				}
			}
			o.Labels = domain.SortedLabels(labels)
			samples = append(samples, o)
		}
		result.Observations = samples
		report := domain.PrometheusReport{Version: domain.PrometheusUploadVersion, Result: result}
		raw, err := json.Marshal(report)
		if err != nil || len(raw) > domain.PrometheusUploadMaxBytes || report.Validate(cluster, source, time.Now()) != nil {
			s.logger.Warn("collector.prometheus_report_invalid", "query", query)
			continue
		}
		name := fmt.Sprintf("%012d-%d.json", slot.Unix(), index)
		if err := s.save(name, raw); err != nil {
			return err
		}
	}
	return nil
}

func (s prometheusSpool) save(name string, raw []byte) error {
	tmp := filepath.Join(s.dir, ".report.tmp")
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer os.Remove(tmp)
	_, writeErr := f.Write(raw)
	if writeErr == nil {
		writeErr = f.Sync()
	}
	closeErr := f.Close()
	if writeErr != nil {
		return writeErr
	}
	if closeErr != nil {
		return closeErr
	}
	// Linking prevents a second evaluation of the same slot from replacing an
	// unacknowledged report after a clock adjustment or interrupted restart.
	if err := os.Link(tmp, filepath.Join(s.dir, name)); err != nil {
		if os.IsExist(err) {
			return nil
		}
		return err
	}
	return s.sync()
}

func (s prometheusSpool) flush(ctx context.Context, now time.Time) error {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return err
	}
	remaining := 2 * len(domain.PrometheusUploadQueries())
	changed := false
	for _, entry := range entries {
		name := entry.Name()
		if name == ".lock" {
			continue
		}
		path := filepath.Join(s.dir, name)
		if !entry.Type().IsRegular() {
			return fmt.Errorf("invalid scheduled report spool entry")
		}
		if name == ".report.tmp" {
			// A crash can leave a temporary file before or after linking.
			if err := os.Remove(path); err != nil {
				return err
			}
			changed = true
			continue
		}
		seconds, suffix, ok := strings.Cut(name, "-")
		stamp, err := strconv.ParseInt(seconds, 10, 64)
		index, indexErr := strconv.Atoi(strings.TrimSuffix(suffix, ".json"))
		if !ok || err != nil || len(seconds) != 12 || indexErr != nil ||
			index < 0 || index >= len(domain.PrometheusUploadQueries()) || suffix != fmt.Sprintf("%d.json", index) {
			return fmt.Errorf("invalid scheduled report spool filename")
		}
		slot := time.Unix(stamp, 0)
		if slot.Before(now.Add(-domain.PrometheusUploadRetention)) {
			s.logger.Warn("collector.prometheus_report_expired", "slot", slot)
		} else {
			if remaining == 0 || slot.After(now) || ctx.Err() != nil {
				continue
			}
			raw, err := readSpoolReport(path)
			if err != nil {
				return err
			}
			remaining--
			rejected, err := s.client.uploadPrometheusReport(ctx, raw)
			if err != nil {
				s.logger.Warn("collector.prometheus_upload_deferred", "slot", slot)
				remaining = 0
				continue
			}
			if rejected {
				s.logger.Warn("collector.prometheus_upload_rejected", "slot", slot)
			}
		}
		if err := os.Remove(path); err != nil {
			return err
		}
		changed = true
	}
	if changed {
		return s.sync()
	}
	return nil
}

func readSpoolReport(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, domain.PrometheusUploadMaxBytes+1))
	if err != nil || len(raw) > domain.PrometheusUploadMaxBytes {
		return nil, fmt.Errorf("scheduled report spool payload is unreadable or too large")
	}
	return raw, nil
}

func (s prometheusSpool) sync() error {
	dir, err := os.Open(s.dir)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
