package ciguard

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var (
	goVersionPin = regexp.MustCompile(`(?m)^\s*GO_VERSION:\s*"([^"]+)"`)
	setupGo      = regexp.MustCompile(`(?m)^\s*go-version:\s*(.+)$`)
)

// TestEveryWorkflowBuildsOnThePinnedGo holds each setup-go step to the GO_VERSION its workflow
// declares, and each declaration to the patch ci.yml pins.
//
// A literal "1.26" resolves to whatever patch setup-go's manifest lists that day, so a job written
// that way builds on a different toolchain from the pull requests, and govulncheck's verdict on the
// standard library can differ between the two. A literal patch is the same problem a bump later,
// when the pin moves and the copy does not.
func TestEveryWorkflowBuildsOnThePinnedGo(t *testing.T) {
	t.Parallel()

	ci, err := os.ReadFile("../../.github/workflows/ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	m := goVersionPin.FindSubmatch(ci)
	if m == nil {
		t.Fatal("ci.yml declares no GO_VERSION")
	}
	pin := string(m[1])

	paths, err := filepath.Glob("../../.github/workflows/*.yml")
	if err != nil || len(paths) == 0 {
		t.Fatalf("no workflows found: %v", err)
	}
	for _, path := range paths {
		body, err := os.ReadFile(path) // #nosec G304 -- a checked-in workflow
		if err != nil {
			t.Fatal(err)
		}
		name := filepath.Base(path)
		uses := setupGo.FindAllSubmatch(body, -1)
		if len(uses) == 0 {
			continue
		}
		for _, u := range uses {
			if got := strings.TrimSpace(string(u[1])); got != "${{ env.GO_VERSION }}" {
				t.Errorf("%s: go-version: %s, want ${{ env.GO_VERSION }}", name, got)
			}
		}
		decl := goVersionPin.FindSubmatch(body)
		switch {
		case decl == nil:
			t.Errorf("%s runs setup-go and declares no GO_VERSION", name)
		case string(decl[1]) != pin:
			t.Errorf("%s pins Go %s, and ci.yml pins %s", name, decl[1], pin)
		}
	}
}
