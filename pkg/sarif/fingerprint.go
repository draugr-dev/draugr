package sarif

import (
	"crypto/sha256"
	"encoding/hex"
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
// Two. Zero would make every occurrence of a common line — a bare `}`, an import — collide, and a
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
// Normalized per line — leading and trailing whitespace removed — so reformatting and reindenting
// do not churn it either. Returns "" when there is nothing to hash, which is honest: absent means
// "no content-based identity", and a fabricated one would be worse than none.
//
// **What it does not survive: an edit inside the context window.** Nearby lines are part of the
// identity, so inserting a line immediately above a finding changes it. That is inherent rather
// than a shortcoming to fix — without context, every bare `}` in a repository would share one
// fingerprint — and it is the same trade CodeQL makes. The case that matters is an edit elsewhere
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
