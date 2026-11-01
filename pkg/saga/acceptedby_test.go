package saga

import (
	"strings"
	"testing"
)

// An exclusion that still sets acceptedBy is refused, in a descriptor and in a fragment it names,
// and the error says what records who wrote the exclusion instead.
func TestAcceptedByIsRefusedWithWhatReplacedIt(t *testing.T) {
	dir := t.TempDir()
	root := write(t, dir, "draugr.saga.yaml", rootHeader+`components: [{ name: web, repositories: [{ url: "." }] }]
config:
  exclude:
    - rules: ["A"]
      reason: "named"
      acceptedBy: someone@example.com
`)
	_, err := ResolveFile(root, nil)
	assertAcceptedByRefused(t, "descriptor", err)

	frag := write(t, dir, "team.saga-fragment.yaml", "config:\n  exclude:\n    - rules: [C]\n      acceptedBy: team\n      reason: team\n")
	_, err = LoadFragment([]byte("config:\n  exclude:\n    - rules: [C]\n      acceptedBy: team\n      reason: team\n"), frag)
	assertAcceptedByRefused(t, "fragment", err)

	named := write(t, dir, "with-fragment.saga.yaml", rootHeader+`components: [{ name: web, repositories: [{ url: "." }] }]
fragments:
  - path: "team.saga-fragment.yaml"
`)
	_, err = ResolveFile(named, nil)
	assertAcceptedByRefused(t, "fragment a descriptor names", err)
}

func assertAcceptedByRefused(t *testing.T, what string, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: an exclusion setting acceptedBy loaded", what)
	}
	for _, want := range []string{"config.exclude.acceptedBy was removed", "delete the line",
		"git blame", "descriptor.exclusions[].gitHistory"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("%s: error %q does not say %q", what, err, want)
		}
	}
	if strings.Contains(err.Error(), "unknown field") {
		t.Errorf("%s: a removed key is reported as a typo: %v", what, err)
	}
}
