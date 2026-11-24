package cooling

// HistoricalProfile is evidence for an already confirmed local rise. Only
// numerical context and bounded status values reach the decision provider.
type HistoricalProfile struct {
	Status        string   `json:"status"`
	CenterW       int      `json:"center_w"`
	MedianC       *float64 `json:"median_c,omitempty"`
	P95C          *float64 `json:"p95_c,omitempty"`
	Days          int      `json:"days"`
	Periods       int      `json:"periods"`
	Samples       int      `json:"samples"`
	LastAgeDays   float64  `json:"last_age_days,omitempty"`
	CutoffAgeDays float64  `json:"cutoff_age_days,omitempty"`
}
