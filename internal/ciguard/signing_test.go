package ciguard

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// identityRe finds the cosign certificate-identity regex a file asserts.
var identityRe = regexp.MustCompile(`release\\?\.yml@refs/(tags|heads)/[^'"\s]*`)

// normalise strips what only differs because of where the string is written: install.sh escapes
// the regex's trailing `$` for the shell, and comparing that against a YAML copy would report
// drift on every run while both say the same thing.
func normalise(s string) string {
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
		got := normalise(identityRe.FindString(string(data)))
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

// TestReleaseIsNotCallable is the other half, and the one that was learned the hard way round.
//
// A reusable workflow runs under the **caller's** ref, so calling release.yml from a workflow on
// main signs artifacts as `release.yml@refs/heads/main`. Everything above verifies
// `refs/tags/v*`, so the release publishes and then refuses to install — which no test of
// release.yml's own contents would notice, because release.yml would be entirely correct.
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
