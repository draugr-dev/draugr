package saga

import (
	"fmt"
	"regexp"
)

// commitID is the shape of a commit as git names it: a SHA-1 or SHA-256 object name, whole or
// abbreviated to the seven characters git abbreviates to by default.
var commitID = regexp.MustCompile(`^[0-9a-fA-F]{7,64}$`)

// soleReference matches a value that is one ${{ VAR }} reference and nothing else.
var soleReference = regexp.MustCompile(`^\s*` + envPattern.String() + `\s*$`)

// CommitUnset is the variable Commit references where the environment does not set it, and "" where
// Commit is a commit or empty.
//
// The load leaves an import's commit reference in place where every other unset reference fails it,
// because the variable is one CI sets and a laptop does not: `${{ GITHUB_SHA }}` would otherwise
// make the descriptor unusable anywhere but the pipeline. The file is then read unbound, which the
// report lists as a caveat, and is never held to a commit nobody named.
func (i Import) CommitUnset() string {
	if m := soleReference.FindStringSubmatch(i.Commit); m != nil {
		return m[1]
	}
	return ""
}

// validateImportCommit refuses a commit that is not one, such as a branch name: the file would be
// held to a commit this run reads, and a branch is not what a file was written for.
func validateImportCommit(imp Import, at string) []error {
	if imp.Commit == "" || imp.CommitUnset() != "" || commitID.MatchString(imp.Commit) {
		return nil
	}
	return []error{fmt.Errorf("%s.commit is %q, but a commit is 7 to 64 hexadecimal characters, as git rev-parse HEAD "+
		"prints. Write the commit the file describes, or ${{ GITHUB_SHA }} in GitHub Actions", at, imp.Commit)}
}
