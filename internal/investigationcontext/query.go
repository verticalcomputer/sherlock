package investigationcontext

import (
	"strings"
	"unicode"
)

const (
	maxQueryBytes       = 8192
	maxQueryTerms       = 64
	maxQueryTermBytes   = 128
	maxSearchFieldBytes = 8192
)

// queryTerms is a bounded, deterministic lexical hint. Matching text never
// confers citation authority, proves a hypothesis or bypasses scope filters.
func queryTerms(text string) map[string]struct{} {
	terms := make(map[string]struct{})
	text, _ = truncateUTF8(text, maxQueryBytes)
	for _, term := range lexicalTerms(text) {
		if len(term) > maxQueryTermBytes || commonQueryWord(term) {
			continue
		}
		terms[term] = struct{}{}
		if len(terms) == maxQueryTerms {
			break
		}
	}
	return terms
}

func lexicalTerms(text string) []string {
	return strings.FieldsFunc(strings.ToLower(text), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsNumber(r)
	})
}

func commonQueryWord(term string) bool {
	switch term {
	case "a", "an", "and", "are", "as", "at", "be", "by", "can", "do", "does", "for", "from", "how", "in", "is", "it", "of", "on", "or", "that", "the", "this", "to", "was", "were", "what", "when", "where", "which", "why", "with":
		return true
	}
	return false
}

// queryMatchScore adds at most 1,000 points, below the existing full scope,
// time, class and mandatory bonuses. Each distinct query term counts once,
// regardless of repetition or which field matched. Opaque IDs are not searched.
func queryMatchScore(value EvidenceInput, query RetrievalQuery, terms map[string]struct{}) int64 {
	if len(terms) == 0 {
		return 0
	}
	matched := make(map[string]struct{}, len(terms))
	fields := []struct {
		text  string
		limit int
	}{{value.Summary, query.MaxSummaryBytes}, {value.Excerpt, query.MaxExcerptBytes}}
	for _, field := range fields {
		limit := maxSearchFieldBytes
		if field.limit > 0 {
			limit = min(limit, field.limit)
		}
		text, _ := truncateUTF8(field.text, limit)
		for _, term := range lexicalTerms(text) {
			if _, ok := terms[term]; ok {
				matched[term] = struct{}{}
			}
		}
	}
	return int64(1000 * len(matched) / len(terms))
}
