package ciguard

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// identityRe finds the cosign certificate-identity regex a file asserts.
var identityRe = regexp.MustCompile(`release\\?\.yml@refs/(tags|heads)/[^'"\s]*`)

// normalize strips what only differs because of where the string is written: install.sh escapes
// the regex's trailing `$` for the shell, and comparing that against a YAML copy would report
// drift on every run while both say the same thing.
func normalize(s string) string {
	return strings.TrimSuffix(strings.TrimSuffix(s, `\$`), "$")
}

// TestEverythingVerifiesTheSameSigningIdentity keeps the claim and the check from drifting apart.
//
// A release is signed keylessly, so the certificate records the workflow and the ref it ran on,
// and that string is the whole of what a verifier checks. install.sh refusing to install and
// action.yml refusing to run are the same assertion written twice, and the docs write it a third
// time — three copies of one string, none of which fails when another changes.
func TestEverythingVerifiesTheSameSigningIdentity(t *testing.T) {
	files := []string{
		"../../install.sh",
		"../../action.yml",
		"../../docs/trust-and-operations/verifying-releases.md",
	}
	want := ""
	for _, f := range files {
		data, err := os.ReadFile(f) // #nosec G304 -- this repository's own files
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		got := normalize(identityRe.FindString(string(data)))
		if got == "" {
			t.Errorf("%s asserts no signing identity — a verifier that checks nothing passes "+
				"anything", f)
			continue
		}
		if want == "" {
			want = got
			continue
		}
		if got != want {
			t.Errorf("%s verifies %q, but an earlier file verifies %q — one of them will reject a "+
				"release the other accepts", f, got, want)
		}
	}
	if !strings.Contains(want, "refs/tags/") {
		t.Errorf("the verified identity is %q; it must be a tag, or any run on any branch could "+
			"produce artifacts that verify", want)
	}
}

// TestReleaseIsNotCallable is the other half, and the one no reading of release.yml can catch.
//
// A reusable workflow runs under the **caller's** ref, so calling release.yml from a workflow on
// main signs artifacts as `release.yml@refs/heads/main`. Everything above verifies
// `refs/tags/v*`, so such a release publishes and then refuses to install. The file that causes
// this is the caller; release.yml itself can be entirely correct throughout, which is why the
// check lives here rather than in a reading of its contents.
//
// A tag push or a dispatch against the tag both put the tag in the certificate. A call cannot.
func TestReleaseIsNotCallable(t *testing.T) {
	data, err := os.ReadFile("../../.github/workflows/release.yml") // #nosec G304 -- our own workflow
	if err != nil {
		t.Fatalf("read release.yml: %v", err)
	}
	if regexp.MustCompile(`(?m)^\s{0,4}workflow_call:`).Match(data) {
		t.Error("release.yml declares workflow_call: a called run signs with the caller's ref, so " +
			"the artifacts would carry refs/heads/<branch> while install.sh verifies refs/tags/v*")
	}
	for _, workflow := range []string{"release-tag.yml", "release-prepare.yml"} {
		wf, err := os.ReadFile("../../.github/workflows/" + workflow) // #nosec G304 -- our own workflow
		if err != nil {
			t.Fatalf("read %s: %v", workflow, err)
		}
		if strings.Contains(string(wf), "workflows/release.yml") {
			t.Errorf("%s calls release.yml, which would publish artifacts signed with %s's ref",
				workflow, workflow)
		}
	}
}

// TestTheTagIsPushedWithACredentialThatTriggers guards the one line the whole release depends on.
//
// GitHub raises no workflow-starting event for anything the built-in GITHUB_TOKEN did. A checkout
// that falls back to it pushes a tag nobody acts on: the workflow is green, the tag is real, and
// no release exists — and because the tag *is* there, the next run finds the version already
// tagged and does nothing either. Nothing anywhere reports a problem.
//
// The same token is what lets `gh pr create` work without granting Actions the right to approve
// pull requests, so both release workflows are checked.
func TestTheTagIsPushedWithACredentialThatTriggers(t *testing.T) {
	for _, name := range []string{"release-tag.yml", "release-prepare.yml"} {
		data, err := os.ReadFile("../../.github/workflows/" + name) // #nosec G304 -- our own workflow
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		wf := string(data)
		if !strings.Contains(wf, "create-github-app-token") {
			t.Errorf("%s mints no installation token, so it acts as GITHUB_TOKEN: its pushes "+
				"start no workflow and it cannot open a pull request", name)
			continue
		}
		if !strings.Contains(wf, "token: ${{ steps.app.outputs.token }}") {
			t.Errorf("%s mints a token but its checkout does not use it, so pushes still go out "+
				"as GITHUB_TOKEN and trigger nothing", name)
		}
		if strings.Contains(wf, "GH_TOKEN: ${{ github.token }}") {
			t.Errorf("%s runs gh as GITHUB_TOKEN, which cannot create a pull request unless the "+
				"repository also lets Actions approve them", name)
		}
	}
}
