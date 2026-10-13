package contextbudget

import "testing"

func TestCalibrationUsesNearestRankP95WithSafetyMultiplier(t *testing.T) {
	ratios := make([]int64, 20)
	for index := range ratios {
		ratios[index] = 1_000_000 + int64(index)*10_000
	}
	// nearest-rank p95 is the nineteenth sorted sample (1.18), then 5% safety.
	if got, want := CalibrationFactor(ratios, 1_600_000), int64(1_239_000); got != want {
		t.Fatalf("factor=%d want=%d", got, want)
	}
	if got := CalibrationFactor(ratios[:19], 1_600_000); got != 1_600_000 {
		t.Fatalf("fallback=%d", got)
	}
	if got := CalibrationFactor([]int64{2_000_000}, 1_600_000); got != 2_100_000 {
		t.Fatalf("underrun factor=%d", got)
	}
	ratios[19] = 9_000_000
	ratios[18] = 9_000_000
	if got := CalibrationFactor(ratios, 1_600_000); got != 3_000_000 {
		t.Fatalf("clamped factor=%d", got)
	}
}
