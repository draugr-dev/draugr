package feeds

import (
	"fmt"
	"time"

	"github.com/draugr-dev/draugr/internal/english"
)

// HumanAge renders a duration the way someone reads a staleness report: the largest unit that
// still says something useful, and never more precision than the answer deserves.
func HumanAge(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "just now"
	// Rounded rather than truncated: a feed fetched 119 minutes ago is two hours old to
	// everyone except integer division.
	case d < time.Hour:
		return english.Count(int(d.Round(time.Minute).Minutes()), "minute")
	case d < 48*time.Hour:
		return english.Count(int(d.Round(time.Hour).Hours()), "hour")
	default:
		return english.Count(int(d.Round(time.Hour).Hours())/24, "day")
	}
}

// HumanBytes renders a size in the largest unit that keeps it under four digits.
func HumanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGT"[exp])
}
