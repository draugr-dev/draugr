package scanners

import (
	"strings"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

// ratingWord reads one of the LOW, MEDIUM and HIGH a scanner rates with, in upper case, and reports
// whether v was one of them.
//
// Anything else is not a rating Draugr has a row for. A value a rule author made up, or one of a
// type a rule's metadata allows and the scanner never writes, leaves the finding on its level
// rather than on a guess at what the author meant.
func ratingWord(v any) (string, bool) {
	s, ok := v.(string)
	if !ok {
		return "", false
	}
	switch word := strings.ToUpper(strings.TrimSpace(s)); word {
	case "LOW", "MEDIUM", "HIGH":
		return word, true
	}
	return "", false
}

// ratingText is a field's value as the scanner wrote it, a list joined with ", ", or "" for a value
// that is neither a string nor a list of strings.
func ratingText(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case []any:
		parts := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, ", ")
	}
	return ""
}

// ratingFields keeps the named fields of a scanner's rating as the scanner wrote them, leaving out
// those it did not write.
func ratingFields(from map[string]any, keys ...string) map[string]string {
	out := map[string]string{}
	for _, k := range keys {
		if s := ratingText(from[k]); s != "" {
			out[k] = s
		}
	}
	return out
}

// newRating is a rating of severity, the detail joined the way every list of facts on a report is.
func newRating(severity sarif.Severity, fields map[string]string, detail ...string) *sarif.Rating {
	return &sarif.Rating{Severity: severity, Detail: strings.Join(detail, " · "), Fields: fields}
}
