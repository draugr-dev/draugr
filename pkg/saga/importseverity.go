package saga

import (
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

// SeverityOf is the severity the mapping gives a value the tool wrote, and whether it names one.
//
// Matched regardless of case and surrounding space, because tools are not consistent about either
// across versions, and a number matches however it is written, so `3` names a value the file writes
// as `3.0`.
func (s ImportSeverity) SeverityOf(value string) (sarif.Severity, bool) {
	want := foldRatingValue(value)
	for k, word := range s.Values {
		if foldRatingValue(k) == want {
			return sarif.Severity(word), true
		}
	}
	return "", false
}

// foldRatingValue is a value as SeverityOf compares it.
func foldRatingValue(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if f, err := strconv.ParseFloat(v, 64); err == nil {
		return strconv.FormatFloat(f, 'f', -1, 64)
	}
	return v
}

// validateImportSeverity refuses a mapping that cannot rate as written: no property, no values, a
// value mapped to a word that is not a severity, or two values SeverityOf cannot tell apart.
//
// A word that is not a severity is an error rather than a default. A mapping that quietly rated
// `Major` low because `severe` was misspelled would rank the findings it exists to raise below the
// level the file already gave them.
func validateImportSeverity(s ImportSeverity, at string) []error {
	var errs []error
	if strings.TrimSpace(s.Property) == "" {
		errs = append(errs, fmt.Errorf("%s.property is required, the result property holding the tool's rating", at))
	}
	if len(s.Values) == 0 {
		errs = append(errs, fmt.Errorf("%s.values is required, each value the tool writes and the severity it means", at))
	}
	folded := map[string]string{}
	for _, value := range slices.Sorted(maps.Keys(s.Values)) {
		key := foldRatingValue(value)
		switch first, seen := folded[key]; {
		case key == "":
			errs = append(errs, fmt.Errorf("%s.values: an empty value names nothing the tool writes", at))
		case seen:
			errs = append(errs, fmt.Errorf("%s.values: %q and %q name the same value, since values match regardless "+
				"of case and numbers by value", at, first, value))
		default:
			folded[key] = value
		}
		if word := s.Values[value]; !slices.Contains(sarif.Severities, word) {
			errs = append(errs, fmt.Errorf("%s.values[%q]: %q is not a severity: use %s", at, value, word,
				strings.Join(sarif.Severities, ", ")))
		}
	}
	return errs
}
