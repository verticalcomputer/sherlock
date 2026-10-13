package gpuprocess

import (
	"encoding/csv"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"

	"github.com/verticalcomputer/sherlock/internal/domain"
)

// HostStat is parsed only from gpu.host_stats@1.0.0's fixed four-column CSV.
// Unsupported NVIDIA values remain nil; raw fields and hostnames are dropped.
type HostStat struct {
	GPUUUID      domain.PhysicalGPUUUID
	TemperatureC *float64
	PowerWatts   *float64
	MemoryMiB    *float64
}

func ParseHostStats(csvText string, limit int) ([]HostStat, []Gap, error) {
	if limit < 1 || len(csvText) > MaxBytes {
		return nil, nil, fmt.Errorf("host stats bounds are invalid")
	}
	reader := csv.NewReader(strings.NewReader(csvText))
	reader.FieldsPerRecord = 4
	reader.TrimLeadingSpace = true
	seen := map[domain.PhysicalGPUUUID]bool{}
	stats := make([]HostStat, 0)
	gaps := []Gap(nil)
	for {
		row, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, []Gap{Malformed}, nil
		}
		if len(stats) == limit {
			return stats, []Gap{OutputLimit}, nil
		}
		uuid := domain.PhysicalGPUUUID(strings.TrimSpace(row[0]))
		if !uuidPattern.MatchString(string(uuid)) || seen[uuid] {
			return nil, []Gap{Malformed}, nil
		}
		seen[uuid] = true
		temp, tempOK := hostNumber(row[1])
		power, powerOK := hostNumber(row[2])
		memory, memoryOK := hostNumber(row[3])
		if !tempOK || !powerOK || !memoryOK || temp == nil || power == nil || memory == nil {
			gaps = appendUnique(gaps, Unsupported)
		}
		if temp == nil && power == nil && memory == nil {
			gaps = appendUnique(gaps, Unsupported)
		}
		stats = append(stats, HostStat{GPUUUID: uuid, TemperatureC: temp, PowerWatts: power, MemoryMiB: memory})
	}
	return stats, gaps, nil
}

func hostNumber(value string) (*float64, bool) {
	value = strings.TrimSpace(value)
	if value == "N/A" || value == "[N/A]" {
		return nil, true
	}
	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil || parsed < 0 || math.IsNaN(parsed) || math.IsInf(parsed, 0) {
		return nil, false
	}
	return &parsed, true
}
