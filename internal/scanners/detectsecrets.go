package scanners

import (
	"bytes"
	"path"
	"regexp"
	"strings"

	"github.com/draugr-dev/draugr/pkg/sarif"
)

// A project using detect-secrets commits a `.secrets.baseline`, a JSON file listing what the tool
// found, each as the SHA-1 of the value in a `hashed_secret` field. Gitleaks's generic-api-key rule
// matches that field, so every entry would be reported as a credential to rotate, when it is a
// digest of one.
//
// So a generic-api-key finding on such a line is marked, and the secrets control's
// detectSecretsBaselines decides whether it counts. The mark is as narrow as the file format: that
// one rule, a file named `.secrets.baseline`, and a line holding nothing but the field and exactly
// 40 lowercase hex characters. Another rule's finding in the same file, and the same field in any
// other file, are left as they are.
//
// The shape is the limit of what can be told from the file: a real token of 40 lowercase hex
// characters written into that field of that file would be marked too.

// detectSecretsBaselineFile is the name detect-secrets gives its baseline.
const detectSecretsBaselineFile = ".secrets.baseline"

// detectSecretsHashLine is a baseline line recording one hash, and nothing else.
var detectSecretsHashLine = regexp.MustCompile(`^\s*"hashed_secret"\s*:\s*"[0-9a-f]{40}"\s*,?\s*$`)

// markDetectSecretsBaselines marks each Gitleaks generic-api-key finding on a line of a
// detect-secrets baseline that records a hash. A finding from the repository's history is left
// unmarked: the line it names is the one the file held in that commit, which the checkout does not
// hold. A file that cannot be read marks nothing.
//
// Every repository scanner's findings pass through, after their paths are repository-relative and
// while the checkout still exists, as markOwnPackages's do.
func markDetectSecretsBaselines(results []sarif.Result, dir string) {
	files := map[string][][]byte{}
	for i := range results {
		res := &results[i]
		if res.DetectSecretsBaseline || res.Historical || !strings.EqualFold(res.Tool, "gitleaks") ||
			res.RuleID != "generic-api-key" || path.Base(res.Location.URI) != detectSecretsBaselineFile ||
			res.Location.StartLine < 1 {
			continue
		}
		lines, read := files[res.Location.URI]
		if !read {
			if content, err := checkoutReader(dir)(res.Location.URI); err == nil {
				lines = bytes.Split(content, []byte("\n"))
			}
			files[res.Location.URI] = lines
		}
		if res.Location.StartLine <= len(lines) && detectSecretsHashLine.Match(lines[res.Location.StartLine-1]) {
			res.DetectSecretsBaseline = true
		}
	}
}
