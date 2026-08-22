package scanners

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

// maxFingerprintFile bounds what is read to fingerprint a finding.
//
// A finding can point at a minified bundle or a checked-in binary, and reading one of those to
// hash five lines of it would cost more than the identity is worth. Past this the finding simply
// carries no content fingerprint, which is the honest answer.
const maxFingerprintFile = 4 << 20

// stampLineHashes records a content fingerprint on every finding that has a file and a line.
//
// Done here because this is where the checkout still exists. The plane that consumes a report has
// the findings and not the repository, so a fingerprint computed from file content can only be
// computed at scan time — and without one, a finding that moved down a file reads as a finding
// that was fixed and a new one that appeared.
//
// Best-effort by design. A file that cannot be read leaves the finding without a fingerprint
// rather than failing the scan: identity across runs is worth having and never worth losing a
// scan over.
func stampLineHashes(results []sarif.Result, dir string) {
	// One read per file, not one per finding. A SAST run over a large file can produce dozens of
	// findings in it, and reading it dozens of times is the kind of cost nobody notices until the
	// repository is big.
	cache := map[string][]string{}

	for i := range results {
		res := &results[i]
		if res.Location.URI == "" || res.Location.StartLine < 1 {
			// A finding about a dependency rather than a line. Its identity is its package, which
			// is already on the finding.
			continue
		}
		lines, ok := cache[res.Location.URI]
		if !ok {
			lines = readSourceLines(dir, res.Location.URI)
			cache[res.Location.URI] = lines
		}
		if lines == nil {
			continue
		}
		res.StampLineHash(lines)
	}
}

// readSourceLines reads a repository-relative source file, or returns nil.
func readSourceLines(dir, rel string) []string {
	// Rejected rather than cleaned. Paths here come from a scanner's output, and a scanner that
	// reports something outside the tree it was pointed at is a scanner to distrust rather than to
	// second-guess — reading the file it named would be following that lead.
	if filepath.IsAbs(rel) || strings.Contains(rel, "..") {
		return nil
	}
	path := filepath.Join(dir, filepath.FromSlash(rel))

	info, err := os.Stat(path)
	if err != nil || info.IsDir() || info.Size() > maxFingerprintFile {
		return nil
	}
	// #nosec G304 -- path is joined onto the checkout directory this scanner just created, from a
	// relative path checked above. It is the file the scanner reported a finding in.
	content, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	// A NUL byte is the cheap, reliable signal that this is not source. Hashing five "lines" of a
	// binary produces a fingerprint that means nothing and changes whenever the binary does.
	if strings.ContainsRune(string(content), 0) {
		return nil
	}
	return strings.Split(strings.ReplaceAll(string(content), "\r\n", "\n"), "\n")
}
