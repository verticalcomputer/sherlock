package cooling

// PeerContext contains only numeric summaries from comparable, enrolled GPUs.
// Each row gives one vote to each distinct peer at the target sample's time.
type PeerContext struct {
	Status        string           `json:"status"`
	DistinctPeers int              `json:"distinct_peers"`
	Rows          []PeerComparison `json:"rows,omitempty"`
}

type PeerComparison struct {
	SecondsBeforeOpen float64 `json:"seconds_before_open"`
	TargetC           float64 `json:"target_c"`
	TargetW           float64 `json:"target_w"`
	Peers             int     `json:"peers"`
	MedianC           float64 `json:"peer_median_c"`
	MaxC              float64 `json:"peer_max_c"`
}
