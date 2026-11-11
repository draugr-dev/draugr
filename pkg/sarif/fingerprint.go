package sarif

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
)

// LineHashKey is the partial-fingerprint name for a finding's content hash.
//
// GitHub code scanning's own name, deliberately. It is what GitHub reads to decide that an alert
// in this run is the same alert as one in the last, so emitting it under any other name would mean
// computing the right thing and having nobody consume it. Versioned by GitHub's convention: the
// suffix changes if the algorithm does, and consumers compare like with like.
const LineHashKey = "primaryLocationLineHash/v1"

// fingerprintContext is how many lines either side of the finding go into the hash.
//
// Two. Zero would make every occurrence of a common line, a bare `}`, an import, collide, and a
// large window would make the fingerprint change whenever anything nearby did, which is the churn
// this exists to avoid.
const fingerprintContext = 2

// LineHash is a content fingerprint for a finding at a line.
//
// The point is identity across runs, which the ordinary Fingerprint deliberately does not provide:
// that one hashes the line *number*, so adding an import at the top of a file makes every finding
// below it look new. This hashes what the code says rather than where it sits, so a finding
// survives edits elsewhere in the file.
//
// Normalized per line, leading and trailing whitespace removed. So reformatting and reindenting do
// not churn it either. Returns "" when there is nothing to hash, which is honest: absent means "no
// content-based identity", and a fabricated one would be worse than none.
//
// **What it does not survive: an edit inside the context window.** Nearby lines are part of the
// identity, so inserting a line immediately above a finding changes it. That is inherent rather
// than a shortcoming to fix, without context, every bare `}` in a repository would share one
// fingerprint. And it is the same trade CodeQL makes. The case that matters is an edit elsewhere
// in the file, which is the common one and the one that used to invalidate everything below it.
//
// A finding on the first lines of a file is more exposed to this, because there is nothing above
// it to include and anything inserted there lands inside the window.
func LineHash(lines []string, startLine int) string {
	if startLine < 1 || startLine > len(lines) {
		return ""
	}
	from := max(startLine-1-fingerprintContext, 0)
	to := min(startLine+fingerprintContext, len(lines))

	window := make([]string, 0, to-from)
	for _, line := range lines[from:to] {
		window = append(window, strings.TrimSpace(line))
	}
	// A window of nothing but blank lines identifies nothing, and hashing it would hand out a
	// fingerprint that collides with every other blank region in the repository.
	if strings.TrimSpace(strings.Join(window, "")) == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(strings.Join(window, "\n")))
	return hex.EncodeToString(sum[:])
}

// StampLineHash records a content fingerprint on a result, if there is one to record.
func (r *Result) StampLineHash(lines []string) {
	hash := LineHash(lines, r.Location.StartLine)
	if hash == "" {
		return
	}
	if r.PartialFingerprints == nil {
		r.PartialFingerprints = map[string]string{}
	}
	r.PartialFingerprints[LineHashKey] = hash
}

// NumberRepeatedLineHashes tells apart results whose content fingerprints are the same, as GitHub's
// own primaryLocationLineHash does: in line order, the second result sharing a component,
// repository, rule, file and fingerprint has ":2" appended to its fingerprint, the third ":3".
//
// The fingerprint is the text around a line, so two lines that read alike with neighbors that read
// alike hash alike: the same `if` in two copies of a function, the same `uses:` step in two jobs.
// Anything that takes the fingerprint, with the rule and the file, as a finding's identity across
// runs would store those as one finding and lose the rest. The first keeps the value it has always
// had, so a finding that has no repeat, and the first of those that do, keep their identity across
// this change.
//
// Over every result of a run at once, after its findings are final, because a repeat may come from
// another scanner's report of the same rule. Results without a fingerprint are left alone.
func NumberRepeatedLineHashes(results []*Result) {
	groups := map[string][]*Result{}
	var keys []string
	for _, r := range results {
		hash := r.PartialFingerprints[LineHashKey]
		if hash == "" {
			continue
		}
		k := strings.Join([]string{r.Component, RepositoryIdentity(r.Repository), r.RuleID, r.Location.URI, hash}, "\x00")
		if _, ok := groups[k]; !ok {
			keys = append(keys, k)
		}
		groups[k] = append(groups[k], r)
	}
	for _, k := range keys {
		group := groups[k]
		if len(group) < 2 {
			continue
		}
		sort.SliceStable(group, func(a, b int) bool {
			return group[a].Location.StartLine < group[b].Location.StartLine
		})
		for i, r := range group[1:] {
			r.PartialFingerprints[LineHashKey] += ":" + strconv.Itoa(i+2)
		}
	}
}
