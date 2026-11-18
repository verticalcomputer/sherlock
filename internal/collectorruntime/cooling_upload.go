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
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

const (
	coolingSpoolMaxReports = 122
	coolingReplayBatch     = 4
	coolingReplayInterval  = 5 * time.Second
)

type coolingExecutor interface {
	ExecuteCooling(context.Context, domain.CoolingUploadProfile, domain.CollectionTask) domain.CollectionResult
}

type coolingSpool struct {
	prometheusSpool
	profile domain.CoolingUploadProfile
	hash    string
}

type coolingUploadProblem struct {
	Type          string `json:"type"`
	Title         string `json:"title"`
	Status        int    `json:"status"`
	Code          string `json:"code"`
	CorrelationID string `json:"correlation_id"`
}

// ProbeCoolingUpload proves that authentication and configured source scope
// passed by checking the rejection of an intentionally invalid report.
func (c *HTTPClient) ProbeCoolingUpload(ctx context.Context) error {
	bounded, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	var problem coolingUploadProblem
	_, err := c.doV2(bounded, http.MethodPost, domain.CoolingUploadPath, struct{}{}, &problem, http.StatusBadRequest)
	if err != nil {
		return err
	}
	if problem.Type != "urn:sherlock:collector:error:invalid_argument" || problem.Title != "cooling report is invalid" ||
		problem.Status != http.StatusBadRequest || problem.Code != "INVALID_ARGUMENT" || problem.CorrelationID == "" {
		return fmt.Errorf("cooling upload route returned an unexpected readiness response")
	}
	return nil
}

func (c *HTTPClient) uploadCoolingReport(ctx context.Context, raw []byte) (int, error) {
	correlation := correlationID()
	headers := map[string]string{protocolHeader: strconv.Itoa(domain.CoolingUploadVersion), correlationHeader: correlation}
	var problem coolingUploadProblem
	status, err := c.doWithHeaders(ctx, http.MethodPost, domain.CoolingUploadPath, json.RawMessage(raw), &problem, headers,
		http.StatusNoContent, http.StatusBadRequest, http.StatusRequestEntityTooLarge, http.StatusConflict, http.StatusForbidden)
	switch status {
	case http.StatusBadRequest, http.StatusRequestEntityTooLarge, http.StatusConflict:
		// These terminal responses do not require a problem body.
		return status, nil
	case http.StatusForbidden:
		// A preregistration slot can never be admitted. Only the specified
		// response from the intake is terminal; proxy and auth denials retry.
		if err == nil && problem.Type == "urn:sherlock:collector:error:forbidden" &&
			problem.Title == "cooling report lacks active enrollment" && problem.Status == status &&
			problem.Code == "FORBIDDEN" && problem.CorrelationID == correlation {
			return status, nil
		}
		return status, fmt.Errorf("cooling upload returned an unconfirmed enrollment rejection")
	default:
		return status, err
	}
}

// RunCoolingUpload samples only active 15-second slots. Durable handoff runs
// independently so a slow upload cannot displace a scheduled source read.
func RunCoolingUpload(ctx context.Context, executor coolingExecutor, client *HTTPClient, logger *slog.Logger,
	dir string, profile domain.CoolingUploadProfile, hash string) error {
	if err := profile.Validate(); err != nil {
		return err
	}
	digest, err := domain.ParseSHA256(hash)
	if err != nil || digest.String() != hash {
		return fmt.Errorf("invalid cooling upload profile hash")
	}
	info, err := os.Lstat(dir)
	if err != nil || !filepath.IsAbs(dir) || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return fmt.Errorf("cooling report spool must be an existing private 0700 directory")
	}
	lock, err := acquireJournalLock(filepath.Join(dir, ".lock"))
	if err != nil {
		return err
	}
	defer lock.release()

	s := coolingSpool{prometheusSpool: prometheusSpool{dir: dir, client: client, logger: logger}, profile: profile, hash: hash}
	// Clear a crash remnant before starting the independent writer and reader.
	temp := filepath.Join(dir, ".report.tmp")
	if info, err := os.Lstat(temp); err == nil {
		if !info.Mode().IsRegular() {
			return fmt.Errorf("invalid cooling report spool temporary entry")
		}
		if err := os.Remove(temp); err != nil {
			return err
		}
		if err := s.sync(); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}

	wake := make(chan struct{}, 1)
	g, runCtx := errgroup.WithContext(ctx)
	g.Go(func() error {
		for runCtx.Err() == nil {
			slot := time.Now().UTC().Truncate(domain.CoolingUploadInterval).Add(domain.CoolingUploadInterval)
			if slot.Before(profile.StartsAt) {
				slot = profile.StartsAt
			}
			if !slot.Before(profile.EndsAt) {
				return nil
			}
			timer := time.NewTimer(time.Until(slot))
			select {
			case <-runCtx.Done():
				timer.Stop()
				return runCtx.Err()
			case <-timer.C:
			}
			now := time.Now()
			if now.Before(slot) || slot.Add(domain.CoolingUploadSourceTimeout).Sub(now) < time.Second {
				continue
			}
			if err := s.collect(runCtx, executor, slot); err != nil {
				return err
			}
			select {
			case wake <- struct{}{}:
			default:
			}
		}
		return runCtx.Err()
	})
	g.Go(func() error {
		ticker := time.NewTicker(coolingReplayInterval)
		defer ticker.Stop()
		expiry := profile.EndsAt.Add(domain.CoolingUploadRetention)
		timer := time.NewTimer(time.Until(expiry))
		defer timer.Stop()
		for {
			now := time.Now()
			if err := s.flush(runCtx, now); err != nil {
				return err
			}
			if !now.Before(expiry) {
				return nil
			}
			select {
			case <-runCtx.Done():
				return runCtx.Err()
			case <-ticker.C:
			case <-timer.C:
			case <-wake:
			}
		}
	})
	return g.Wait()
}

func (s coolingSpool) collect(ctx context.Context, executor coolingExecutor, slot time.Time) error {
	entries, err := s.entries()
	if err != nil {
		return err
	}
	queries := domain.CoolingUploadQueries()
	if len(entries)+len(queries) > coolingSpoolMaxReports {
		s.logger.Warn("collector.cooling_spool_full")
		return nil
	}
	results := make([]domain.CollectionResult, len(queries))
	var collects sync.WaitGroup
	for index, query := range queries {
		collects.Go(func() {
			results[index] = executor.ExecuteCooling(ctx, s.profile, s.profile.Task(query, slot))
		})
	}
	collects.Wait()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	for index, result := range results {
		report := domain.CoolingUploadReport{
			Version: domain.CoolingUploadVersion, ProfileID: s.profile.ProfileID, ProfileRevision: s.profile.Revision,
			ProfileHash: s.hash, Result: result,
		}
		raw, err := json.Marshal(report)
		if err != nil || len(raw) > domain.CoolingUploadMaxBytes || report.Validate(s.profile, s.hash, time.Now()) != nil {
			s.logger.Warn("collector.cooling_report_invalid", "query", result.Task.Query)
			continue
		}
		if err := s.save(coolingSpoolFilename(slot.Unix(), index, s.hash), raw); err != nil {
			return err
		}
	}
	return nil
}

func (s coolingSpool) entries() ([]os.DirEntry, error) {
	dir, err := os.Open(s.dir)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	entries, err := dir.ReadDir(coolingSpoolMaxReports + 3)
	if err != nil && err != io.EOF {
		return nil, err
	}
	// The process lock and transient file are outside the report budget.
	reports := entries[:0]
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			return nil, fmt.Errorf("invalid cooling report spool entry")
		}
		if entry.Name() != ".lock" && entry.Name() != ".report.tmp" {
			reports = append(reports, entry)
		}
	}
	if len(reports) > coolingSpoolMaxReports {
		return nil, fmt.Errorf("cooling report spool exceeds its entry limit")
	}
	slices.SortFunc(reports, func(a, b os.DirEntry) int { return strings.Compare(a.Name(), b.Name()) })
	return reports, nil
}

func coolingSpoolFilename(slot int64, query int, hash string) string {
	return fmt.Sprintf("%012d-%d-%s.json", slot, query, hash)
}

func parseCoolingSpoolFilename(name string) (time.Time, string, error) {
	parts := strings.Split(strings.TrimSuffix(name, ".json"), "-")
	if len(parts) != 3 {
		return time.Time{}, "", fmt.Errorf("invalid cooling report spool filename")
	}
	seconds, err := strconv.ParseInt(parts[0], 10, 64)
	index, indexErr := strconv.Atoi(parts[1])
	hash, hashErr := domain.ParseSHA256(parts[2])
	slot := time.Unix(seconds, 0).UTC()
	if err != nil || indexErr != nil || hashErr != nil || index < 0 || index >= len(domain.CoolingUploadQueries()) ||
		!slot.Equal(slot.Truncate(domain.CoolingUploadInterval)) || name != coolingSpoolFilename(seconds, index, hash.String()) {
		return time.Time{}, "", fmt.Errorf("invalid cooling report spool filename")
	}
	return slot, hash.String(), nil
}

func (s coolingSpool) flush(ctx context.Context, now time.Time) error {
	entries, err := s.entries()
	if err != nil {
		return err
	}
	remaining := coolingReplayBatch
	changed := false
	started := time.Now()
	for _, entry := range entries {
		slot, hash, err := parseCoolingSpoolFilename(entry.Name())
		if err != nil {
			return err
		}
		path := filepath.Join(s.dir, entry.Name())
		current := now.Add(time.Since(started))
		replayFor := slot.Add(domain.CoolingUploadRetention).Sub(current)
		if replayFor <= 0 {
			s.logger.Warn("collector.cooling_report_expired", "slot", slot)
		} else {
			// A different profile may resume during its replay window. Keep its
			// pending bytes but send only under the current local enrollment.
			if hash != s.hash || slot.After(now) || remaining == 0 || ctx.Err() != nil {
				continue
			}
			raw, err := readSpoolReport(path)
			if err != nil {
				return err
			}
			remaining--
			bounded, cancel := context.WithTimeout(ctx, min(replayFor, 3*time.Second))
			status, err := s.client.uploadCoolingReport(bounded, raw)
			cancel()
			if err != nil {
				s.logger.Warn("collector.cooling_upload_deferred", "slot", slot)
				remaining = 0
				continue
			}
			if status != http.StatusNoContent {
				s.logger.Warn("collector.cooling_upload_rejected", "slot", slot, "status", status)
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
