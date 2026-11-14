package report

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/draugr-dev/draugr/pkg/saga"
)

// The config.exclude entry TRY prints is the entry a reader pastes under the key. With its
// placeholders filled, a full rule id and a reason holding a comma, it parses as the descriptor's
// own type and sets the finding aside.
func TestThePrintedExcludeEntryParsesAndMatches(t *testing.T) {
	const id = "python.lang.security.dangerous-system-call.dangerous-system-call"
	entry := strings.Join(excludeEntry, "\n")
	entry = strings.ReplaceAll(entry, "<full rule id>", id)
	entry = strings.ReplaceAll(entry, "<why it does not apply>", "fixtures only, never shipped")
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
	rule := doc.Config.Exclude[0]
	if rule.Reason != "fixtures only, never shipped" {
		t.Errorf("reason = %q, want the whole reason, comma included", rule.Reason)
	}
	if !rule.Matches("app/run.py", id) {
		t.Errorf("the filled entry does not set aside a finding of %s", id)
	}
	for _, line := range excludeEntry {
		if n := len([]rune(line)); n > 80 {
			t.Errorf("%d columns: %q", n, line)
		}
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
