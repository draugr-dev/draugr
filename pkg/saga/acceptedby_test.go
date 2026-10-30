package saga

import (
	"strings"
	"testing"
)

// Each acceptedBy is named by the file and line the key is on, which is the line to delete, and
// points at the exclusion's git history as the record of who wrote it.
func TestAcceptedByWarningsNameTheLine(t *testing.T) {
	dir := t.TempDir()
	root := write(t, dir, "draugr.saga.yaml", rootHeader+`components: [{ name: web, repositories: [{ url: "." }] }]
config:
  exclude:
    - rules: ["A"]
      reason: "named"
      acceptedBy: someone@example.com
    - rules: ["B"]
      reason: "not named"
fragments:
  - path: "team.saga-fragment.yaml"
`)
	write(t, dir, "team.saga-fragment.yaml", "config:\n  exclude:\n    - rules: [C]\n      acceptedBy: team\n      reason: team\n")

	res, err := ResolveFile(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := AcceptedByWarnings(res.Model.Config.Exclude)
	if len(got) != 2 {
		t.Fatalf("warnings = %q, want one per acceptedBy", got)
	}
	want := root + ":8: acceptedBy is deprecated and no longer read as who accepted the finding, and " +
		AcceptedByRemovedIn + " removes it. Delete the line; git history records who wrote the exclusion " +
		"(git blame -L 6,6 " + root + ")"
	if got[0] != want {
		t.Errorf("warning\n got %q\nwant %q", got[0], want)
	}
	if !strings.HasPrefix(got[1], dir+"/team.saga-fragment.yaml:4: ") || !strings.Contains(got[1], "git blame -L 3,3 ") {
		t.Errorf("fragment warning = %q", got[1])
	}
	if strings.Contains(strings.Join(got, "\n"), "someone@example.com") {
		t.Error("a warning repeats the name it says nothing verifies")
	}
}

// A fragment fetched from another repository is read from a checkout that is removed once the
// descriptor is resolved, so the warning names the line and offers no command to run against it.
// A rule built in code has no line to name.
func TestAcceptedByWarningsWithoutALocalFile(t *testing.T) {
	got := AcceptedByWarnings([]ExcludeRule{
		{Reason: "r", AcceptedBy: "x", Source: "https://example.com/p.git@v1 policy.saga-fragment.yaml",
			File: "/tmp/draugr-repo-1/policy.saga-fragment.yaml", Line: 3, acceptedByLine: 5},
		{Reason: "r", AcceptedBy: "x"},
		{Reason: "r", AcceptedBy: "x", Source: "draugr.saga.yaml"},
	})
	if len(got) != 3 {
		t.Fatalf("warnings = %q", got)
	}
	if !strings.HasPrefix(got[0], "https://example.com/p.git@v1 policy.saga-fragment.yaml:5: ") || strings.Contains(got[0], "git blame") {
		t.Errorf("remote fragment warning = %q", got[0])
	}
	if !strings.HasPrefix(got[1], "config.exclude: ") || strings.Contains(got[1], "git blame") {
		t.Errorf("rule built in code = %q", got[1])
	}
	if !strings.HasPrefix(got[2], "draugr.saga.yaml: ") {
		t.Errorf("rule with a file and no line = %q", got[2])
	}
}
