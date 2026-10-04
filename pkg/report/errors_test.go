package report

import (
	"fmt"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/norn"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

func TestShortReasonKeepsWhatWentWrong(t *testing.T) {
	for _, c := range []struct{ detail, want string }{
		// The last clause repeats the address, so the one before it says what happened.
		{"trivy-fs: git clone: exit status 128: remote: Repository not found.\nfatal: repository 'https://github.com/acme/x/' not found",
			"Repository not found"},
		{`trivy image ghcr.io/acme/billing:4.1: GET https://ghcr.io/v2/acme/billing/manifests/4.1: MANIFEST_UNKNOWN: manifest unknown`,
			"manifest unknown"},
		{"draugr-headers: Get \"https://shop.invalid\": dial tcp: lookup shop.invalid: no such host", "no such host"},
		{"a single clause.", "a single clause"},
		// git's `fatal` says only that it failed, so the last clause speaks, without the address.
		{"gitleaks: git clone: exit status 128: fatal: repository '/home/u/shop/app' does not exist",
			"repository does not exist"},
		{"draugr-k8s-policies: " + strings.Repeat("x", 120), strings.Repeat("x", whyWidth-1) + "…"},
	} {
		if got := shortReason(c.detail, whyWidth); got != c.want {
			t.Errorf("shortReason(%q) = %q, want %q", c.detail, got, c.want)
		}
	}
}

// failedRepository is a repository every scanner failed to clone, as the engine accounts for it.
func failedRepository(url string, components ...string) engine.TargetOutcome {
	return engine.TargetOutcome{Kind: "repository", Target: url + "@main", Status: engine.TargetFailed,
		Detail: "trivy-fs: git clone " + url + ": exit status 128: remote: Repository not found.", Components: components}
}

// Two repositories on one component, one of them shared with a second component and read, the
// other not: the errors block names the one not read, once, with the component it leaves
// unscanned, and the control's own row no longer repeats the scanner's message.
func TestErrorsNameEachTargetOnce(t *testing.T) {
	const archive = "https://github.com/acme/api-archive"
	msg := "trivy-fs: git clone " + archive + ": exit status 128: remote: Repository not found."
	d := Data{
		Run: engine.Result{
			Controls:   map[string]plugin.ControlResult{"sca": {Report: sarif.Report{}}},
			ScanErrors: map[string][]string{"sca": {msg, "trivy-fs: database download failed"}, "secrets": {msg}},
			Stats: engine.Stats{Failures: []engine.Unscanned{
				{Control: "sca", Kind: "repository", Target: archive, Detail: msg},
				{Control: "secrets", Kind: "repository", Target: archive, Detail: msg},
			}},
			Targets: []engine.TargetOutcome{
				{Kind: "repository", Target: "https://github.com/acme/api@main", Status: engine.TargetReached, Components: []string{"api", "web"}},
				failedRepository(archive, "api"),
			},
		},
		Verdict: norn.Result{Verdict: norn.Fail, Controls: []norn.ControlOutcome{{Control: "sca", Verdict: norn.Pass}}},
		Components: []ComponentVerdict{
			{Name: "api", Verdict: norn.Pass, Unscanned: []engine.Unscanned{{Control: "sca", Kind: "repository", Target: archive}}},
			{Name: "web", Verdict: norn.Pass},
		},
	}
	out := renderWith(t, consoleReporter{}, d)
	for _, want := range []string{
		"ERRORS  1 of 2 targets not reached",
		"repository " + archive + "@main  api         Repository not found",
		"api  ERROR  no findings",
		"web  pass   no findings",
		// An error that is not a target's stays under its control.
		"trivy-fs: database download failed",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
	if n := strings.Count(out, "api-archive"); n != 1 {
		t.Errorf("the repository is named %d times, want once:\n%s", n, out)
	}
	if strings.Contains(out, "acme/api@main") {
		t.Errorf("a repository that was read is listed as an error:\n%s", out)
	}
}

// A target two components declare leaves both unscanned.
func TestErrorsListEveryComponentATargetLeavesUnscanned(t *testing.T) {
	d := Data{Run: engine.Result{Targets: []engine.TargetOutcome{failedRepository("https://github.com/acme/lib", "api", "web")}}}
	if out := renderWith(t, consoleReporter{}, d); !strings.Contains(out, "repository https://github.com/acme/lib@main  api, web") {
		t.Errorf("the second component is missing:\n%s", out)
	}
}

// Capped as the findings are, so a run against a registry that is down does not bury the verdict
// under a row per image, and --top 0 names every one.
func TestErrorsAreCappedUnlessTopZero(t *testing.T) {
	var targets []engine.TargetOutcome
	for i := range errorRowsShown + 3 {
		targets = append(targets, failedRepository(fmt.Sprintf("https://github.com/acme/r%02d", i), "api"))
	}
	d := Data{Run: engine.Result{Targets: targets}}
	last := fmt.Sprintf("acme/r%02d", errorRowsShown+2)
	out := renderWith(t, consoleReporter{}, d)
	if strings.Contains(out, last) || !strings.Contains(out, "… and 3 more · --top 0 lists every one") {
		t.Errorf("the default view named the last target or left it uncounted:\n%s", out)
	}
	d.TopN = -1
	if out := renderWith(t, consoleReporter{}, d); !strings.Contains(out, last) || strings.Contains(out, "more · --top 0") {
		t.Errorf("--top 0 left a target unnamed:\n%s", out)
	}
}

// A run that accepted its errors says so beside the verdict, with how much it did not reach where
// that is known.
func TestAcceptedErrorsMarkTheVerdictPartial(t *testing.T) {
	d := Data{
		AcceptedErrors: true,
		Verdict:        norn.Result{Verdict: norn.Pass},
		Run: engine.Result{Targets: []engine.TargetOutcome{
			failedRepository("https://github.com/acme/a", "api"),
			{Kind: "image", Target: "ghcr.io/acme/api:1", Status: engine.TargetReached},
		}},
	}
	if out := renderWith(t, consoleReporter{}, d); !strings.Contains(out, "PASS  partial · 1 of 2 targets not reached") {
		t.Errorf("the header does not say the pass is partial:\n%s", out)
	}
	d.Run.Targets = d.Run.Targets[1:]
	if out := renderWith(t, consoleReporter{}, d); !strings.Contains(out, "PASS  partial · scan errors accepted") {
		t.Errorf("errors accepted with every target reached must still mark the pass:\n%s", out)
	}
	d.AcceptedErrors = false
	if out := renderWith(t, consoleReporter{}, d); strings.Contains(out, "partial") {
		t.Errorf("a run that accepted nothing is marked partial:\n%s", out)
	}
}

// What was declared and never looked at, what a scanner could not measure and what was not read
// are one block, by component, each saying which of the three it is.
func TestCaveatsGatherEveryShortfallThatDoesNotFail(t *testing.T) {
	d := Data{
		Uncovered: []Gap{{Component: "web", Surface: "hosts", Controls: []string{"dast", "headers", "tls"}}},
		Run: engine.Result{
			Skipped: []engine.SkippedJob{{Control: "kubernetes", Scanner: "kube-bench-job", Component: "payments",
				Reason: "audits the whole cluster and cannot be narrowed to namespace payments"}},
			Inputs: []engine.InputCoverage{{Component: "api", Control: "sca", Unread: []engine.UnreadInput{
				{Repository: "https://github.com/acme/api", Path: "go.mod", Reason: "no packages read"}}}},
			UnreadChecks: []engine.UnreadChecks{{Component: "platform", Control: "cloud", Group: "compute",
				Checks: []string{"compute_firewall_ssh_access_from_the_internet_allowed", "compute_instance_public_ip"},
				Reason: "denied compute.instances.list"}},
		},
	}
	out := renderWith(t, consoleReporter{}, d)
	for _, want := range []string{
		"CAVEATS  do not fail the run",
		"api        go.mod          unread        no packages read (sca)",
		"payments   kube-bench-job  not measured  audits the whole cluster and cannot be narrowed to namespace payments",
		"platform   compute         unread        2 checks · denied compute.instances.list",
		"web        hosts           not checked   dast, headers, tls off",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "ERRORS") {
		t.Errorf("a caveat is listed as an error:\n%s", out)
	}
}

// One repository two components share fails once per component's job, with one message. It is
// still said once, by target, and not again under the control with a count of the jobs.
func TestATargetTwoComponentsShareIsNotRepeatedUnderItsControl(t *testing.T) {
	const lib = "https://github.com/acme/lib"
	msg := "trivy-fs: git clone " + lib + ": exit status 128: remote: Repository not found."
	d := Data{
		Run: engine.Result{
			Controls:   map[string]plugin.ControlResult{"sca": {Report: sarif.Report{}}},
			ScanErrors: map[string][]string{"sca": {msg, msg}},
			Stats: engine.Stats{Failures: []engine.Unscanned{
				{Control: "sca", Component: "api", Kind: "repository", Target: lib, Detail: msg},
				{Control: "sca", Component: "web", Kind: "repository", Target: lib, Detail: msg},
			}},
			Targets: []engine.TargetOutcome{failedRepository(lib, "api", "web")},
		},
		Verdict: norn.Result{Verdict: norn.Fail, Controls: []norn.ControlOutcome{{Control: "sca", Verdict: norn.Pass}}},
	}
	out := renderWith(t, consoleReporter{}, d)
	if strings.Contains(out, "(2 jobs)") || strings.Count(out, "acme/lib") != 1 {
		t.Errorf("the shared repository is repeated:\n%s", out)
	}
}
