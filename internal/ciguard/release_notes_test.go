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
// it must never do is exit non-zero, because that step is the one that pushes the tag. And it
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
		t.Error("the tag message is no longer derived by changelog.sh summary, a pipeline here " +
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

// The placeholder marking an empty [Unreleased] must not travel into the release.
//
// `promote` writes it back over the section it just emptied, and an entry added afterwards lands
// above it rather than replacing it, so without this the notes a tag publishes end with a line
// saying nothing is here, underneath the list of things that are.
func TestPromoteDropsThePlaceholderForAnEmptySection(t *testing.T) {
	const changelog = `# Changelog

## [Unreleased]

### Added

- Something that landed after the last release.

_Nothing yet._

## [0.1.0] - 2026-01-01

### Added

- The first one.

[Unreleased]: https://github.com/draugr-dev/draugr/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.1.0
`
	dir := t.TempDir()
	path := filepath.Join(dir, "CHANGELOG.md")
	if err := os.WriteFile(path, []byte(changelog), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("../../scripts/changelog.sh", "promote", "0.2.0") // #nosec G204 -- literal
	cmd.Env = append(os.Environ(), "CHANGELOG_FILE="+path, "CHANGELOG_FRAGMENTS="+filepath.Join(dir, "none"))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("promote: %v\n%s", err, out)
	}
	after, err := os.ReadFile(path) // #nosec G304 -- this test's own file
	if err != nil {
		t.Fatal(err)
	}
	released := string(after)[strings.Index(string(after), "## [0.2.0]"):]
	released = released[:strings.Index(released, "## [0.1.0]")]
	if strings.Contains(released, "_Nothing yet._") {
		t.Errorf("the release carries the empty-section placeholder:\n%s", released)
	}
	if !strings.Contains(released, "Something that landed") {
		t.Errorf("the entry did not travel into the release:\n%s", released)
	}
	// And the emptied section keeps its own placeholder, which is what says there is nothing
	// waiting rather than leaving a heading with a blank under it.
	unreleased := string(after)[strings.Index(string(after), "## [Unreleased]"):strings.Index(string(after), "## [0.2.0]")]
	if !strings.Contains(unreleased, "_Nothing yet._") {
		t.Errorf("[Unreleased] lost its placeholder:\n%s", unreleased)
	}
}

// changelogWith runs the script against a CHANGELOG and a fragment directory this test wrote.
func changelogWith(t *testing.T, changelog string, fragments map[string]string, args ...string) (string, error) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "CHANGELOG.md")
	if err := os.WriteFile(path, []byte(changelog), 0o600); err != nil {
		t.Fatal(err)
	}
	frags := filepath.Join(dir, "changelog.d")
	if err := os.MkdirAll(frags, 0o750); err != nil {
		t.Fatal(err)
	}
	for name, body := range fragments {
		if err := os.WriteFile(filepath.Join(frags, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("./scripts/changelog.sh", args...) // #nosec G204 -- arguments are this test's
	cmd.Dir = filepath.Join("..", "..")                    // the check runs the guard beside it by relative path
	cmd.Env = append(os.Environ(), "CHANGELOG_FILE="+path, "CHANGELOG_FRAGMENTS="+frags)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

const withInlineEntries = `# Changelog

## [Unreleased]

### Added

- **Written into the file.** Directly.

### Fixed

- **Also written into the file.** Directly.

## [0.1.0] - 2026-01-01

### Added

- The first one.

[Unreleased]: https://github.com/draugr-dev/draugr/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/draugr-dev/draugr/releases/tag/v0.1.0
`

// Entries written into [Unreleased] and entries waiting as fragments publish under one heading per
// section. Appended, a release carries two of each heading and reads as two releases run together.
func TestTheNotesHaveOneHeadingPerSection(t *testing.T) {
	notes, err := changelogWith(t, withInlineEntries, map[string]string{
		"b.added.md": "- **A fragment.** Waiting.\n",
		"c.fixed.md": "- **A fixed fragment.** Waiting.\n",
	}, "show")
	if err != nil {
		t.Fatalf("show: %v\n%s", err, notes)
	}
	for _, h := range []string{"### Added", "### Fixed"} {
		if n := strings.Count(notes, h); n != 1 {
			t.Errorf("%q appears %d times:\n%s", h, n, notes)
		}
	}
	for _, want := range []string{"Written into the file", "A fragment", "Also written", "A fixed fragment"} {
		if !strings.Contains(notes, want) {
			t.Errorf("the notes lost %q:\n%s", want, notes)
		}
	}
	if strings.Index(notes, "### Added") > strings.Index(notes, "### Fixed") {
		t.Errorf("sections out of order:\n%s", notes)
	}
}

// An entry written into the file directly, and a fragment that is not a bullet, are both refused
// by the check, which is what CI runs.
func TestTheCheckRefusesAnEntryOutsideAFragment(t *testing.T) {
	out, err := changelogWith(t, withInlineEntries, nil, "check")
	if err == nil || !strings.Contains(out, "written into") {
		t.Errorf("check passed an entry written into [Unreleased]: %v\n%s", err, out)
	}

	empty := strings.Replace(withInlineEntries,
		withInlineEntries[strings.Index(withInlineEntries, "### Added"):strings.Index(withInlineEntries, "## [0.1.0]")],
		"_Nothing yet._\n\n", 1)
	out, err = changelogWith(t, empty, map[string]string{"p.fixed.md": "A paragraph, not a bullet.\n"}, "check")
	if err == nil || !strings.Contains(out, "one '- ' bullet") {
		t.Errorf("check passed a fragment that is not a bullet: %v\n%s", err, out)
	}
	// The guard that follows compares this file's released section with the real tag of that
	// name, so the run as a whole may fail; what is asserted is that the structure passed.
	out, _ = changelogWith(t, empty, map[string]string{"p.fixed.md": "- **A bullet.** Fine.\n"}, "check")
	if strings.Contains(out, "structural problems") {
		t.Errorf("check refused a well-formed fragment:\n%s", out)
	}
}

// An entry is short enough to read as an item in a list. The link's URL is not words anybody
// reads, so it does not count toward the limit.
func TestTheCheckRefusesAnEntryTooLongToRead(t *testing.T) {
	empty := strings.Replace(withInlineEntries,
		withInlineEntries[strings.Index(withInlineEntries, "### Added"):strings.Index(withInlineEntries, "## [0.1.0]")],
		"_Nothing yet._\n\n", 1)
	entry := func(words int) string {
		return "- **Lead.** " + strings.Repeat("word ", words-2) +
			"([#1](https://github.com/draugr-dev/draugr/issues/1/with/a/long/path/that/is/not/prose))\n"
	}

	out, _ := changelogWith(t, empty, map[string]string{"long.fixed.md": entry(61)}, "check")
	if !strings.Contains(out, "61 words, over 60") {
		t.Errorf("check passed a 61-word entry:\n%s", out)
	}
	out, _ = changelogWith(t, empty, map[string]string{"fits.fixed.md": entry(60)}, "check")
	if strings.Contains(out, "structural problems") {
		t.Errorf("check refused a 60-word entry, or counted the link's URL:\n%s", out)
	}
}
