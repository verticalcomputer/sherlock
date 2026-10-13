package adminui

func repairDecisionLabel(code string) string {
	switch code {
	case "SCHEDULE_DISPATCH_GAP":
		return "Collection scheduling gap"
	case "SCHEDULE_FACTS_UNKNOWN":
		return "Scheduling evidence unavailable"
	case "STREAM_DISABLED":
		return "Collection stream disabled"
	case "COLLECTION_ACTIVE":
		return "Collection already active"
	case "SOURCE_UNAVAILABLE":
		return "Source unavailable"
	case "COLLECTOR_UNAVAILABLE":
		return "Collector unavailable"
	case "INVENTORY_MISSING":
		return "Inventory missing"
	case "COVERAGE_INCOMPLETE":
		return "Evidence coverage incomplete"
	case "COLLECTION_FAILED":
		return "Previous collection failed"
	case "STREAM_FRESH":
		return "Evidence was fresh"
	case "NORMAL_SCHEDULER_DUE":
		return "Ordinary collection due"
	default:
		return "Other assessment"
	}
}
