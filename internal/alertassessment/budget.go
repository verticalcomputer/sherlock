package alertassessment

import "time"

// ShadowGPUBudget bounds all cooperative work for one GPU across its arms.
// ShadowRefreshBudget also bounds source loading and persistence for a serial
// refresh. Neither budget changes a candidate's observation deadline.
const (
	ShadowGPUBudget     = 250 * time.Millisecond
	ShadowRefreshBudget = 2 * time.Second
)
