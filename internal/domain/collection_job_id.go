package domain

import "strings"

// ValidCollectionJobID accepts opaque, slash-separated scheduler identifiers.
// It never normalizes identifiers or treats them as filesystem paths.
func ValidCollectionJobID(value string) bool {
	return validNamespacedID(value, 128)
}

func validNamespacedID(value string, maximum int) bool {
	if len(value) == 0 || len(value) > maximum {
		return false
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "." || segment == ".." || !validDiagnosticToken(segment) {
			return false
		}
	}
	return true
}

// ValidRemediationTarget accepts scheduler targets without widening command,
// actor, recipe, diagnostic-node or other security-token validation.
func ValidRemediationTarget(value string) bool { return ValidCollectionJobID(value) }

// ValidCollectorWorkID includes repair work IDs embedding a namespaced job.
func ValidCollectorWorkID(value string) bool {
	return validControlID(value) || (strings.HasPrefix(value, "repair-work-") && strings.Contains(value, "/") && validNamespacedID(value, 256))
}
