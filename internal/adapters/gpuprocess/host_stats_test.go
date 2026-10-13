package gpuprocess

import "testing"

func TestParseHostStatsRetainsReviewedFieldsAndGapsUnsupported(t *testing.T) {
	stats, gaps, err := ParseHostStats("GPU-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee, 61, N/A, 1024\n", 4)
	if err != nil || len(stats) != 1 || stats[0].TemperatureC == nil || stats[0].PowerWatts != nil || stats[0].MemoryMiB == nil || len(gaps) != 1 || gaps[0] != Unsupported {
		t.Fatalf("stats=%+v gaps=%v err=%v", stats, gaps, err)
	}
}

func TestParseHostStatsRejectsNonFiniteValues(t *testing.T) {
	for _, value := range []string{"NaN", "+Inf", "-Inf"} {
		stats, gaps, err := ParseHostStats("GPU-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee,"+value+", 1, 2\n", 4)
		if err != nil || len(stats) != 1 || stats[0].TemperatureC != nil || len(gaps) != 1 || gaps[0] != Unsupported {
			t.Fatalf("value %q stats=%+v gaps=%v err=%v", value, stats, gaps, err)
		}
	}
}
