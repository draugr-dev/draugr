package cli

import (
	"bytes"
	"context"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// lineSaga is a descriptor whose two components each name a repository, excluding paths.
func lineSaga(first, second string, paths ...string) string {
	quoted := make([]string, len(paths))
	for i, p := range paths {
		quoted[i] = `"` + p + `"`
	}
	return `project: shop
release:
  version: "1.0"
components:
  - name: api
    repositories: [{url: "` + first + `"}]
  - name: deploy
    repositories: [{url: "` + second + `"}]
config:
  controls:
    secrets: {}
  exclude:
    - rules: [KSV-0041]
      paths: [` + strings.Join(quoted, ", ") + `]
      reason: the controller needs every verb on its own resources
`
}

// validate refuses an exclusion path carrying a finding's line, where the file is in one of the
// descriptor's repositories, and accepts the file it names. Checked against the second repository
// too: an exclusion matches a finding from any of them.
func TestValidateRefusesAnExclusionPathThatNamesALine(t *testing.T) {
	first := gitRepo(t, "app")
	second := gitRepo(t, "deploy/x")

	var out bytes.Buffer
	err := runValidate([]string{writeSaga(t, lineSaga(first, second, "deploy/x/f.txt:18"))}, &out)
	const want = `config.exclude[0]: paths[0] "deploy/x/f.txt:18" names a line, and paths match files. ` +
		`Write "deploy/x/f.txt", which covers every KSV-0041 finding in that file`
	if err == nil || err.Error() != want {
		t.Errorf("err = %v, want %q", err, want)
	}

	out.Reset()
	if err := runValidate([]string{writeSaga(t, lineSaga(first, second, "deploy/x/f.txt"))}, &out); err != nil {
		t.Errorf("the file the refusal names is refused too: %v", err)
	}
}

// A descriptor whose repositories are remote has no tree on this machine to check against, and
// validates as it did before.
func TestValidateAcceptsALineWhereNoRepositoryIsLocal(t *testing.T) {
	var out bytes.Buffer
	descriptor := writeSaga(t, lineSaga("https://github.com/acme/api", "https://github.com/acme/deploy", "deploy/x/f.txt:18"))
	if err := runValidate([]string{descriptor}, &out); err != nil {
		t.Errorf("runValidate: %v", err)
	}
}

// The scan refuses the same entry before anything runs, so no finding is counted that its author
// believes is set aside.
func TestScanRefusesAnExclusionPathThatNamesALineBeforeRunning(t *testing.T) {
	first := gitRepo(t, "app")
	second := gitRepo(t, "deploy/x")
	rec := &targetRecorder{}
	reg := engine.NewRegistry()
	reg.RegisterController(rec)
	reg.RegisterScanner(recorderScanner{rec})

	err := runScan(context.Background(), writeSaga(t, lineSaga(first, second, "app/f.txt:3")),
		scanOptions{format: "json", noGate: true}, reg, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), `Write "app/f.txt", which covers every KSV-0041 finding in that file`) {
		t.Errorf("err = %v, want the refusal naming app/f.txt", err)
	}
	if len(rec.targets) != 0 {
		t.Errorf("the scan ran %d jobs before refusing", len(rec.targets))
	}
}

// The trees are each local repository's work-tree root, once, since a finding's path is relative
// to it; a remote adds none.
func TestExclusionTreesAreTheLocalRepositoryRoots(t *testing.T) {
	root := gitRepo(t, "services/payments", "services/web")
	other := gitRepo(t, "lib")
	plain := t.TempDir() // a directory in no work tree, which the scan refuses later in its own words
	m := &saga.Model{Components: []saga.Component{
		{Name: "payments", Repositories: []saga.Repository{{URL: filepath.Join(root, "services/payments")}}},
		{Name: "web", Repositories: []saga.Repository{{URL: filepath.Join(root, "services/web")}, {URL: other}}},
		{Name: "upstream", Repositories: []saga.Repository{{URL: "https://github.com/acme/lib"}}},
		{Name: "loose", Repositories: []saga.Repository{{URL: plain}}},
	}}
	if got, want := exclusionTrees(context.Background(), m), []string{root, other, plain}; !slices.Equal(got, want) {
		t.Errorf("trees = %v, want %v", got, want)
	}
}
