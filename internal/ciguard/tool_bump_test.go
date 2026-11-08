package ciguard

import (
	"strings"
	"testing"
)

// A bump of a Go-built tool has two pins. The bump workflow's text about one comes from pinbump, which
// knows which of them moved, and the assembly passes the Go its proof ran. A line written in the
// workflow reads a Go-only bump as a version moving to itself, and an assembly that leaves the Go out
// asks go.dev again and can put a Go in the pull request that no proof ran.
func TestToolBumpDescribesAndAppliesTheGoItProved(t *testing.T) {
	t.Parallel()
	workflow := readRepoFile(t, ".github/workflows/tool-bump.yml")
	for _, want := range []string{
		`pinbump "$tool" "$to" "$to_go"`,
		`pinbump entry "$TOOL" "$from" "$from_go" "$version" "$to_go"`,
		`pinbump entry "$tool" "$from" "$from_go" "$to" "$to_go"`,
		`pinbump heading "$TOOL" "$FROM" "$FROM_GO" "$VERSION" "$TO_GO"`,
		`fromGo: $fromGo, toGo: $toGo`,
	} {
		if !strings.Contains(workflow, want) {
			t.Errorf("tool-bump.yml does not hold %s", want)
		}
	}
	for _, refused := range []string{"which was pinned at", "built with", `pinbump "$tool" "$to" |`} {
		if strings.Contains(workflow, refused) {
			t.Errorf("tool-bump.yml holds %q, which pinbump's forms are for", refused)
		}
	}
}
