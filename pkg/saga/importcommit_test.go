package saga

import (
	"os"
	"strings"
	"testing"
)

// importWithCommit is a descriptor of two components, one importing a file with the given commit and
// the other carrying release.version, so a test can tell an import's commit from every other value.
func importWithCommit(commit string) string {
	return `
project: x
release:
  version: "1.0"
components:
  - name: api
    repositories: [{ url: "." }, { url: "https://github.com/acme/web" }]
    imports:
      - control: sast
        file: reports/bandit.sarif
        commit: "` + commit + `"
`
}

// unsetEnv unsets name for the test and restores whatever the environment held afterwards. In CI
// GITHUB_SHA is set, so a test of the unset case has to clear it.
func unsetEnv(t *testing.T, name string) {
	t.Helper()
	t.Setenv(name, "")
	_ = os.Unsetenv(name)
}

// An import's commit substitutes as any value does where the variable is set.
func TestAnImportsCommitIsSubstituted(t *testing.T) {
	t.Setenv("GITHUB_SHA", "0123456789abcdef0123456789abcdef01234567")
	m, err := Load([]byte(importWithCommit("${{ GITHUB_SHA }}")))
	if err != nil {
		t.Fatal(err)
	}
	imp := m.Components[0].Imports[0]
	if imp.Commit != "0123456789abcdef0123456789abcdef01234567" || imp.CommitUnset() != "" {
		t.Errorf("commit = %q, unset %q, want the variable's value", imp.Commit, imp.CommitUnset())
	}
}

// Where the variable is unset, the descriptor still loads and the import names the variable, so the
// file is read unbound. Anywhere else an unset variable still fails the load, and an import's commit
// still refuses a variable the descriptor may not substitute.
func TestAnUnsetVariableLeavesAnImportUnbound(t *testing.T) {
	unsetEnv(t, "GITHUB_SHA")
	t.Setenv(SagaEnvsVar, "")
	m, err := Load([]byte(importWithCommit("${{ GITHUB_SHA }}")))
	if err != nil {
		t.Fatalf("an unset commit variable failed the load: %v", err)
	}
	if got := m.Components[0].Imports[0].CommitUnset(); got != "GITHUB_SHA" {
		t.Errorf("CommitUnset = %q, want GITHUB_SHA", got)
	}

	elsewhere := strings.Replace(importWithCommit("${{ GITHUB_SHA }}"), `version: "1.0"`, `version: "${{ GITHUB_SHA }}"`, 1)
	if _, err := Load([]byte(elsewhere)); err == nil || !strings.Contains(err.Error(), "which the environment does not set") {
		t.Errorf("an unset variable outside an import's commit loaded: %v", err)
	}
	if _, err := Load([]byte(importWithCommit("${{ AWS_SECRET_ACCESS_KEY }}"))); err == nil ||
		!strings.Contains(err.Error(), "does not list") {
		t.Errorf("an unlisted variable in an import's commit was not refused: %v", err)
	}
	// Text around the reference makes it no commit and no reference, so validation refuses it.
	if _, err := Load([]byte(importWithCommit("v${{ GITHUB_SHA }}"))); err == nil || !strings.Contains(err.Error(), "imports[0].commit is") {
		t.Errorf("a commit with text around an unset reference loaded: %v", err)
	}
}

// A commit is a commit id, whole or abbreviated, SHA-1 or SHA-256; a branch name or a revision git
// would have to resolve is refused, because the file was written for a commit and not a branch.
func TestValidateImportCommit(t *testing.T) {
	for _, commit := range []string{"", "0123456", "0123456789AB", "0123456789abcdef0123456789abcdef01234567",
		strings.Repeat("a", 64), "${{ GITHUB_SHA }}"} {
		imp := Import{Control: "sast", File: "a.sarif", Commit: commit}
		if errs := validateImportCommit(imp, "imports[0]"); len(errs) > 0 {
			t.Errorf("%q was refused: %v", commit, errs)
		}
	}
	for _, commit := range []string{"main", "012345", "HEAD~1", strings.Repeat("a", 65), "v1.2.3"} {
		imp := Import{Control: "sast", File: "a.sarif", Commit: commit}
		errs := validateImportCommit(imp, "imports[0]")
		if len(errs) != 1 || !strings.Contains(errs[0].Error(), "imports[0].commit is \""+commit+"\", but a commit is 7 to 64 hexadecimal characters") {
			t.Errorf("%q: errs = %v, want it refused", commit, errs)
		}
	}
}
