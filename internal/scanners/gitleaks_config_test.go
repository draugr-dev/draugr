package scanners

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
)

// The rule has to match a real token and nothing that merely talks about one. A pattern that fires
// on prose is a pattern people turn off, and then it catches nothing at all.
func TestTheIngestTokenPatternMatchesATokenAndNotAMention(t *testing.T) {
	// Lifted from the ruleset rather than restated, so the test cannot pass against a regex the
	// scanner does not use.
	line := ""
	for _, l := range strings.Split(gitleaksRules, "\n") {
		if strings.HasPrefix(l, "regex = ") {
			line = l
			break
		}
	}
	if line == "" {
		t.Fatal("no regex in the ruleset — its format changed and this is testing nothing")
	}
	pattern := strings.Trim(strings.TrimPrefix(line, "regex = "), "'")
	re, err := regexp.Compile(pattern)
	if err != nil {
		t.Fatalf("the shipped pattern does not compile: %v", err)
	}

	const planted = "drgr_ci_CznR3oGTaBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789_"
	for name, tc := range map[string]struct {
		in   string
		want bool
	}{
		"a token in a file":      {"DRAUGR_API_TOKEN=" + planted[:51], true},
		"the prefix in prose":    {"Every ingest token begins with drgr_ci_ followed by 43 characters.", false},
		"the hint from a report": {"drgr_ci_oQyo", false},
		"a prefix and too few":   {"drgr_ci_short", false},
		"nothing at all":         {"nothing here", false},
	} {
		t.Run(name, func(t *testing.T) {
			if got := re.MatchString(tc.in); got != tc.want {
				t.Errorf("match(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// A hint is what the product shows a person so they can tell two credentials apart in a list. If
// the pattern matched it, every screenshot of the settings page would be a leak report.
func TestTheHintIsNotLongEnoughToMatch(t *testing.T) {
	if !strings.Contains(gitleaksRules, "{43}") {
		t.Error("the pattern no longer anchors the length — a hint or a prose mention will match it")
	}
}

// Draugr's rule is added whether or not the descriptor named a configuration. Ignoring ours when
// somebody has their own would leave the token undetected in exactly the repositories that have
// been configured most carefully.
func TestOurRuleSurvivesTheUsersOwnConfig(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	plain, err := gitleaksConfigFor("")
	if err != nil {
		t.Fatal(err)
	}
	body := read(t, plain)
	if !strings.Contains(body, "useDefault = true") {
		t.Error("without a user config, Gitleaks' own ruleset must still be in play")
	}
	if !strings.Contains(body, "draugr-ingest-token") {
		t.Error("the rule is missing")
	}

	theirs := filepath.Join(t.TempDir(), "mine.toml")
	if err := os.WriteFile(theirs, []byte("title = \"mine\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	composed, err := gitleaksConfigFor(theirs)
	if err != nil {
		t.Fatal(err)
	}
	body = read(t, composed)
	if !strings.Contains(body, "draugr-ingest-token") {
		t.Error("the rule was dropped when the descriptor named a configuration")
	}
	if !strings.Contains(body, theirs) {
		t.Errorf("the user's ruleset is not extended:\n%s", body)
	}
	if strings.Contains(body, "useDefault") {
		t.Error("extending both the defaults and a named file would make the named one's own " +
			"choice about the defaults moot")
	}
	if plain == composed {
		t.Error("two different configurations were written to one path")
	}
}

// Gitleaks resolves a relative --config path against its own working directory, not ours, so a
// relative path would silently extend nothing.
func TestTheExtendedPathIsAbsolute(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()
	theirs := filepath.Join(dir, "mine.toml")
	if err := os.WriteFile(theirs, []byte("title = \"mine\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	defer func() { _ = os.Chdir(cwd) }()

	composed, err := gitleaksConfigFor("mine.toml")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(read(t, composed), theirs) {
		t.Error("a relative config was not resolved to an absolute path")
	}
}

// The scan must carry a configuration on every path, because that is what carries the rule.
func TestEveryGitleaksInvocationCarriesTheRuleset(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	for name, argv := range map[string][]string{
		"tree":    gitleaksArgs("/repo", plugin.Config{}),
		"history": gitleaksHistoryArgs("/repo", plugin.Config{"history": true}),
	} {
		t.Run(name, func(t *testing.T) {
			if len(argv) == 0 {
				t.Fatal("no argv")
			}
			var config string
			for i, a := range argv {
				if a == "--config" && i+1 < len(argv) {
					config = argv[i+1]
				}
			}
			if config == "" {
				t.Fatalf("no --config in %v", argv)
			}
			if !strings.Contains(read(t, config), "draugr-ingest-token") {
				t.Error("the configuration it points at does not carry the rule")
			}
		})
	}
}

// A machine with no writable home must still scan. One rule is worth losing; the secrets control
// is not.
func TestAnUnwritableHomeStillScans(t *testing.T) {
	t.Setenv("HOME", "/proc/nonexistent-and-unwritable")
	argv := gitleaksArgs("/repo", plugin.Config{})
	if len(argv) == 0 || argv[0] != "gitleaks" {
		t.Fatalf("the scan did not survive an unwritable home: %v", argv)
	}
}

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path) // #nosec G304 -- a path this test produced
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
