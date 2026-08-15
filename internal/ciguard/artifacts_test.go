package ciguard

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// trackedFiles lists what git has under version control, which is the only list that matters here:
// a file present in a working tree is somebody's business, and a file committed is everybody's.
func trackedFiles(t *testing.T) []string {
	t.Helper()
	out, err := exec.Command("git", "-C", "../..", "ls-files").Output()
	if err != nil {
		t.Skipf("git ls-files is unavailable, so this cannot check what is tracked: %v", err)
	}
	return strings.Split(strings.TrimSpace(string(out)), "\n")
}

// TestScanOutputIsNotCommitted keeps a scan's own output out of the repository.
//
// The directory is where the self-scan writes and what `examples/reporting.saga.yaml` names, so it
// turns up in a working tree as a matter of course, and `*.out` in .gitignore does not match a
// directory called `draugr-out`.
//
// What it costs is not clutter. A committed CycloneDX document is read by other people's tooling
// as this project's dependency manifest — OpenSSF Scorecard runs OSV over the repository, and a
// scan report of a Debian-based container contributes its operating-system packages as though they
// were ours. The result is a public security score reporting vulnerabilities in software this
// project does not ship, which is the opposite of what a security tool wants to be saying about
// itself and is invisible from the inside.
func TestScanOutputIsNotCommitted(t *testing.T) {
	t.Parallel()

	for _, path := range trackedFiles(t) {
		if path == "" {
			continue
		}
		top, _, _ := strings.Cut(filepath.ToSlash(path), "/")
		if top == "draugr-out" || top == ".draugr-out" {
			t.Errorf("%s is a scan's own output and is committed — add the directory to "+
				".gitignore and `git rm -r --cached` it", path)
		}
	}
}

// TestNoSBOMIsCommittedOutsideFixtures is the general form of the same problem.
//
// An SBOM in a repository is taken by other tools to describe that repository. A report produced
// by scanning something else — a container image, another project — describes something else, and
// nothing about the file says which it is. Fixtures are exempt because a parser needs something to
// parse, and their location says plainly that they are inputs.
func TestNoSBOMIsCommittedOutsideFixtures(t *testing.T) {
	t.Parallel()

	suffixes := []string{".cdx.json", ".spdx.json", ".cdx.xml"}
	for _, path := range trackedFiles(t) {
		slash := filepath.ToSlash(path)
		if strings.Contains(slash, "/testdata/") || strings.HasPrefix(slash, "testdata/") {
			continue
		}
		for _, suffix := range suffixes {
			if strings.HasSuffix(slash, suffix) {
				t.Errorf("%s is a bill of materials committed outside a fixture directory, so "+
					"anything scanning this repository will read it as a description of this "+
					"repository", path)
			}
		}
	}
}
