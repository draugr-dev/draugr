package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/draugr-dev/draugr/pkg/saga"
)

// fillExcludeEntry is the entry TRY prints with its placeholders filled as a reader fills them: the
// rule id and the file as a finding's row prints them, the file without its line.
func fillExcludeEntry(id, file, reason, expires string) string {
	entry := strings.Join(excludeEntry, "\n")
	for placeholder, value := range map[string]string{
		"<full rule id>":        id,
		"<file without :line>":  file,
		"<why it is set aside>": reason,
		"<YYYY-MM-DD>":          expires,
	} {
		if !strings.Contains(entry, placeholder) {
			panic("the printed entry has no " + placeholder)
		}
		entry = strings.ReplaceAll(entry, placeholder, value)
	}
	return entry
}

// parseExclude reads entry as it sits under config.exclude in a descriptor.
func parseExclude(t *testing.T, entry string) saga.ExcludeRule {
	t.Helper()
	var doc struct {
		Config struct {
			Exclude []saga.ExcludeRule `yaml:"exclude"`
		} `yaml:"config"`
	}
	if err := yaml.Unmarshal([]byte("config:\n  exclude:\n"+indent(entry, "  ")), &doc); err != nil {
		t.Fatalf("the printed entry is not valid YAML once filled: %v\n%s", err, entry)
	}
	if len(doc.Config.Exclude) != 1 {
		t.Fatalf("parsed %d entries, want one:\n%s", len(doc.Config.Exclude), entry)
	}
	return doc.Config.Exclude[0]
}

// The config.exclude entry TRY prints is the entry a reader pastes under the key. Filled from a
// finding, a full rule id, its file and a reason holding a comma, it parses as the descriptor's own
// type and sets that finding aside, and not another finding of the same rule in a different file.
func TestThePrintedExcludeEntrySetsAsideOneFindingNotTheRule(t *testing.T) {
	const id = "KSV-0041"
	rule := parseExclude(t, fillExcludeEntry(id, "deploy/a/rbac.yaml", "read-only cluster, accepted for now", "2027-01-31"))
	if rule.Reason != "read-only cluster, accepted for now" {
		t.Errorf("reason = %q, want the whole reason, comma included", rule.Reason)
	}
	if rule.Expires != "2027-01-31" {
		t.Errorf("expires = %q, want the date", rule.Expires)
	}
	if !rule.Matches("deploy/a/rbac.yaml", id) {
		t.Errorf("the filled entry does not set aside the %s finding in its file", id)
	}
	if rule.Matches("deploy/b/rbac.yaml", id) {
		t.Errorf("the filled entry sets aside a %s finding in another file too", id)
	}
	if rule.Matches("deploy/a/rbac.yaml", "KSV-0046") {
		t.Errorf("the filled entry sets aside another rule's finding in its file")
	}
	for _, line := range excludeEntry {
		if n := len([]rune(line)); n > 80 {
			t.Errorf("%d columns: %q", n, line)
		}
	}
}

// The file a reader writes into paths is the one config.exclude's own check accepts, and the
// location as a row prints it, with the line, is the one it refuses.
func TestThePrintedExcludeEntryPassesTheLineCheck(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "deploy", "a"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "deploy", "a", "rbac.yaml"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	check := func(file string) []error {
		rule := parseExclude(t, fillExcludeEntry("KSV-0041", file, "accepted", "2027-01-31"))
		return (&saga.Model{Config: saga.Config{Exclude: []saga.ExcludeRule{rule}}}).ExcludeLineErrors([]string{root})
	}
	if errs := check("deploy/a/rbac.yaml"); len(errs) != 0 {
		t.Errorf("the entry filled with the file is refused: %v", errs)
	}
	if errs := check("deploy/a/rbac.yaml:18"); len(errs) != 1 {
		t.Errorf("the entry filled with the location and its line: errors = %v, want one", errs)
	}
}

// Pasted without filling it in, the entry is refused rather than taken as an exclusion, because its
// date placeholder is no date.
func TestTheUnfilledExcludeEntryIsRefused(t *testing.T) {
	doc := "config:\n  exclude:\n" + indent(strings.Join(excludeEntry, "\n"), "  ")
	if _, err := saga.LoadFragment([]byte(doc), "team.saga-fragment.yaml"); err == nil ||
		!strings.Contains(err.Error(), "expires must be a date") {
		t.Errorf("err = %v, want the unfilled date refused", err)
	}
}

// indent prefixes every line of s.
func indent(s, prefix string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = prefix + l
	}
	return strings.Join(lines, "\n") + "\n"
}
