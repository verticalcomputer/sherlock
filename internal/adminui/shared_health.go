package adminui

import (
	"github.com/verticalcomputer/sherlock/internal/application"
	"strconv"
)

// Unknown capacity is never presented as zero or inferred from metric series.
func healthCount(value *int64) string {
	if value == nil {
		return "UNKNOWN"
	}
	return strconv.FormatInt(*value, 10)
}

// Only the reviewed shared schema is rendered. Other versions stay unavailable.
func sharedHealthAvailable(health application.ClusterHealthView) bool {
	return health.SchemaVersion == 1 && health.ClusterID != "" && !health.GeneratedAt.IsZero()
}
