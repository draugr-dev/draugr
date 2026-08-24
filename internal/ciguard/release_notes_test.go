package ciguard

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// changelogScript runs ./scripts/changelog.sh against a CHANGELOG this test wrote.
func changelogScript(t *testing.T, changelog string, args ...string) (string, error) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "CHANGELOG.md")
	if err := os.WriteFile(path, []byte(changelog), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("../../scripts/changelog.sh", args...) // #nosec G204 -- arguments are this test's
	cmd.Env = append(os.Environ(), "CHANGELOG_FILE="+path)
	out, err := cmd.Output()
	return strings.TrimSpace(string(out)), err
}

// The tag message is derived from the notes, and the notes are written by hand in whichever shape
// reads best. Both shapes occur.
//
// A version whose summary cannot be derived does not fail: the step substitutes a fallback. What
// it must never do is exit non-zero, because that step is the one that pushes the tag — and it
// runs after the release has already been merged, so failing there leaves a promoted CHANGELOG
// with no tag and no release.
func TestATagMessageCanBeDerivedFromEitherNoteShape(t *testing.T) {
	const header = "# Changelog\n\n"
	for name, tc := range map[string]struct {
		changelog string
		want      string
	}{
		"list items": {
			header + "## [1.2.3] - 2026-01-01\n\n### Added\n\n" +
				"- **Something happened.** And here is the detail of it.\n",
			"Something happened. And here is the detail of it",
		},
		"paragraphs": {
			header + "## [1.2.3] - 2026-01-01\n\n### Added\n\n" +
				"**Something happened.** And here is the detail of it.\n",
			"Something happened. And here is the detail of it",
		},
		"code in the lead": {
			header + "## [1.2.3] - 2026-01-01\n\n### Added\n\n" +
				"**`results.sarif` says why.** A finding carries its reason.\n",
			"results.sarif says why. A finding carries its reason",
		},
		"nothing to summarize": {
			header + "## [1.2.3] - 2026-01-01\n\n### Added\n\n",
			"",
		},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := changelogScript(t, tc.changelog, "summary", "1.2.3")
			if err != nil {
				t.Fatalf("summary exited non-zero, which would leave a release untagged: %v", err)
			}
			if got != tc.want {
				t.Errorf("summary = %q, want %q", got, tc.want)
			}
		})
	}
}

// The workflow must ask the script rather than deriving the summary itself. A pipeline in a
// workflow file is not reachable by any test, and this one is on the path that pushes the tag.
func TestTheTagWorkflowDerivesItsSummaryFromTheScript(t *testing.T) {
	data, err := os.ReadFile("../../.github/workflows/release-tag.yml")
	if err != nil {
		t.Fatal(err)
	}
	body := string(data)
	if !strings.Contains(body, `changelog.sh summary "$version"`) {
		t.Error("the tag message is no longer derived by changelog.sh summary — a pipeline here " +
			"cannot be tested, and it runs after the release is merged")
	}
	// Any grep in a `pipefail` step is a step that fails when its pattern does not match, which
	// on this path means a promoted CHANGELOG with no tag and nothing said about why.
	for _, line := range strings.Split(body, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.Contains(trimmed, "| grep ") || strings.Contains(trimmed, "|grep ") {
			t.Errorf("a grep in a pipeline on the tagging path: %s", trimmed)
		}
	}
}
