// Package coolingprofile reads precomputed, enrollment-scoped temperature profiles.
// The warming worker calls it after local confirmation, outside database transactions.
package coolingprofile

import (
	"encoding/json"
	"io"
	"math"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/verticalcomputer/sherlock/internal/alertassessment/cooling"
)

const maxFileSize = 8 << 20
const day = 24 * time.Hour

type band struct {
	CenterW int       `json:"center_w"`
	MedianC *float64  `json:"median_c"`
	P95C    *float64  `json:"p95_c"`
	Samples int       `json:"samples"`
	Periods int       `json:"periods"`
	Days    int       `json:"days"`
	Last    time.Time `json:"last_at"`
}

type snapshot struct {
	Schema     int               `json:"schema"`
	Cluster    string            `json:"cluster_id"`
	Source     string            `json:"source_id"`
	Enrollment string            `json:"enrollment_id"`
	Cutoff     time.Time         `json:"cutoff"`
	Published  time.Time         `json:"published_at"`
	Assets     map[string][]band `json:"assets"`
}

type Reader struct {
	dir, cluster, source, enrollment string
	mu                               sync.Mutex
	cached                           [3]*snapshot
}

func NewReader(dir, cluster, source, enrollment string) *Reader {
	return &Reader{dir: dir, cluster: cluster, source: source, enrollment: enrollment}
}

func (r *Reader) read(cutoff time.Time) *snapshot {
	for _, cached := range r.cached {
		if cached != nil && cached.Cutoff.Equal(cutoff) {
			return cached
		}
	}
	f, err := os.OpenFile(filepath.Join(r.dir, cutoff.Format("2006-01-02")+".json"), os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxFileSize {
		return nil
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxFileSize+1))
	if err != nil || len(raw) > maxFileSize {
		return nil
	}
	var s snapshot
	if json.Unmarshal(raw, &s) != nil || s.Schema != 1 || s.Cluster != r.cluster || s.Source != r.source || s.Enrollment != r.enrollment || !s.Cutoff.Equal(cutoff) || s.Published.Before(cutoff) || s.Assets == nil {
		return nil
	}
	copy(r.cached[1:], r.cached[:2])
	r.cached[0] = &s
	return &s
}

// Lookup freezes the knowledge cutoff at candidate entry. Daily files are
// published atomically and immutable. Look back two days across publication delays.
func (r *Reader) Lookup(asset string, anchor time.Time, c cooling.WarmingContext) *cooling.HistoricalProfile {
	out := &cooling.HistoricalProfile{Status: "unavailable"}
	if c.ComparableLoad == nil || anchor.IsZero() {
		return out
	}
	watts := c.ComparableLoad.PowerW
	if math.IsNaN(watts) || math.IsInf(watts, 0) || watts <= 0 || watts > 2000 {
		return out
	}
	out.CenterW = int(math.Round(watts/25)) * 25
	cutoff := anchor.UTC().Truncate(day)
	r.mu.Lock()
	defer r.mu.Unlock()
	for offset := 0; offset <= 2; offset++ {
		s := r.read(cutoff.Add(-time.Duration(offset) * day))
		if s == nil || s.Published.After(anchor) {
			continue
		}
		out.CutoffAgeDays = anchor.Sub(s.Cutoff).Hours() / 24
		out.Status = "no_matching_band"
		for _, b := range s.Assets[asset] {
			if b.CenterW != out.CenterW {
				continue
			}
			if out.Samples != 0 || b.MedianC == nil || b.P95C == nil || *b.MedianC < 0 || *b.P95C < *b.MedianC || *b.P95C > 150 || b.Days < 1 || b.Days > 24 || b.Periods < 1 || b.Samples < b.Periods || b.Samples < b.Days || b.Last.Before(s.Cutoff.Add(-24*day)) || !b.Last.Before(s.Cutoff) {
				return &cooling.HistoricalProfile{Status: "invalid", CenterW: out.CenterW}
			}
			out.Status = "qualified"
			out.Days, out.Periods, out.Samples = b.Days, b.Periods, b.Samples
			out.LastAgeDays = anchor.Sub(b.Last).Hours() / 24
			if b.Periods < 3 || b.Days < 3 {
				out.Status = "sparse"
			} else if out.LastAgeDays > 7 {
				out.Status = "stale"
			} else {
				median, upper := *b.MedianC, *b.P95C
				out.MedianC, out.P95C = &median, &upper
			}
		}
		return out
	}
	return out
}
