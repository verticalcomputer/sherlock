package application

// RedactSharedNarrative applies the same token-pattern policy as model IO to
// the synthesized report. Raw model IO is excluded separately by the API.
func RedactSharedNarrative(value string) string {
	text, _ := redactModelString(value)
	return text
}
