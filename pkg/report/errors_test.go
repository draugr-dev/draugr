package report

import (
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/norn"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
	"github.com/draugr-dev/draugr/pkg/skald"
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
		// A tool the kernel killed says so in one clause, so the reason is the whole of it.
		{"run gitleaks: was killed by SIGKILL, usually because memory ran out",
			"was killed by SIGKILL, usually because memory ran out"},
		// git's `fatal` says only that it failed, so the last clause speaks, without the address.
		{"gitleaks: git clone: exit status 128: fatal: repository '/home/u/shop/app' does not exist",
			"repository does not exist"},
		{"draugr-k8s-policies: " + strings.Repeat("x", 120), strings.Repeat("x", whyWidth-1) + "…"},
		// An imported SARIF file that cannot be read for this run says why, the file being the target.
		{"sarif-import: reports/bandit.sarif: written for commit 4f2a9c1e7b3d, and this run reads 123509aace3d",
			"written for commit 4f2a9c1e7b3d, and this run reads 123509aace3d"},
		{"sarif-import: reports/bandit.sarif: names repository draugr-demo, which component api does not declare",
			"names repository draugr-demo, which component api does not declare"},
		// A registry's request id is not a reason; the clause before it is.
		{"run trivy: exit status 1: … UNAUTHORIZED: authentication required, visit https://aka.ms/acr/authorization for more information. CorrelationId: 5bf38f62-783a-4cad-a09e-5262470783fa",
			"authentication required"},
		// The Kubernetes API server's refusal opens with the identity the scan ran as. The reason is
		// what the credential lacks: the verb, the resource, its API group and where.
		{`draugr-k8s-policies: list clusterrolebindings: clusterrolebindings.rbac.authorization.k8s.io is forbidden: User "system:serviceaccount:ft-rbac:ft-view" cannot list resource "clusterrolebindings" in API group "rbac.authorization.k8s.io" at the cluster scope`,
			"cannot list clusterrolebindings (rbac.authorization.k8s.io) at the cluster scope"},
		// In a namespace, from the core API group, whose empty name is left out.
		{`draugr-k8s-policies: list pods: namespace "team-a": pods is forbidden: User "system:serviceaccount:team-a:scanner" cannot list resource "pods" in API group "" in the namespace "team-a"`,
			`cannot list pods in the namespace "team-a"`},
		// An authorizer's own note after the refusal, and an identity with an escaped quote in it.
		{`draugr-k8s-policies: list roles: roles.rbac.authorization.k8s.io is forbidden: User "o\"brien@example.com" cannot list resource "roles" in API group "rbac.authorization.k8s.io" at the cluster scope: RBAC: clusterrole.rbac.authorization.k8s.io "auditor" not found`,
			"cannot list roles (rbac.authorization.k8s.io) at the cluster scope"},
		// A refusal still too long for the width keeps its start, the verb and the resource.
		{`list x: User "u" cannot list resource "verylongresourcenamesthatgoonandon" in API group "some.very.long.group.example.com" in the namespace "a-namespace-with-a-long-name"`,
			`cannot list verylongresourcenamesthatgoonandon (some.very.long.group.example.co…`},
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

// A run that accepted its errors says so on the line under the verdict, with how much it did not
// reach where that is known, and the title line keeps the verdict alone.
func TestAcceptedErrorsMarkTheVerdictPartial(t *testing.T) {
	d := Data{
		AcceptedErrors: true,
		Verdict:        norn.Result{Verdict: norn.Pass},
		Run: engine.Result{Targets: []engine.TargetOutcome{
			failedRepository("https://github.com/acme/a", "api"),
			{Kind: "image", Target: "ghcr.io/acme/api:1", Status: engine.TargetReached},
		}},
	}
	out := renderWith(t, consoleReporter{}, d)
	if first, rest, _ := strings.Cut(out, "\n"); strings.Contains(first, "artial") ||
		!strings.HasPrefix(strings.TrimLeft(rest, "\n"), " Partial: 1 of 2 targets not reached, and the run accepted it.") {
		t.Errorf("the line under the verdict does not say the pass is partial, or the title does:\n%s", out)
	}
	d.Run.Targets = d.Run.Targets[1:]
	if out := renderWith(t, consoleReporter{}, d); !strings.Contains(out, " Partial: the run accepted its scan errors.") {
		t.Errorf("errors accepted with every target reached must still mark the pass:\n%s", out)
	}
	d.AcceptedErrors = false
	if out := renderWith(t, consoleReporter{}, d); strings.Contains(out, "artial") {
		t.Errorf("a run that accepted nothing is marked partial:\n%s", out)
	}
}

// consoleCaveatGroup is a heading of the console's caveats block, whether it carries the mark, and
// the rows under it with their runs of spaces closed up.
type consoleCaveatGroup struct {
	heading string
	marked  bool
	rows    []string
}

// consoleCaveats reads the console's caveats block back into its header, its groups, and the line
// counting what it left out, which is empty where it left nothing out. A row not indented past its
// heading fails the test, because without color the indent is all that puts it under the heading.
func consoleCaveats(t *testing.T, out string) (header string, groups []consoleCaveatGroup, more string) {
	t.Helper()
	_, block, ok := strings.Cut(out, "\nCAVEATS  ")
	if !ok {
		t.Fatalf("no CAVEATS block:\n%s", out)
	}
	block, _, _ = strings.Cut(block, "\n\n")
	lines := strings.Split(block, "\n")
	header = "CAVEATS  " + lines[0]
	indent := -1
	for _, l := range lines[1:] {
		marked := strings.HasPrefix(l, "  ✗ ")
		plain := l
		if marked {
			plain = "    " + strings.TrimPrefix(l, "  ✗ ")
		}
		text := strings.TrimLeft(plain, " ")
		n := len(plain) - len(text)
		switch {
		case strings.HasPrefix(text, "… and "):
			more = text
		case indent < 0 || n == indent:
			indent = n
			groups = append(groups, consoleCaveatGroup{heading: text, marked: marked})
		case n < indent+2:
			t.Errorf("row %q is not indented under its heading:\n%s", l, out)
		default:
			g := &groups[len(groups)-1]
			g.rows = append(g.rows, strings.Join(strings.Fields(text), " "))
		}
	}
	return header, groups, more
}

// What was declared and never looked at, what a scanner could not measure and what was not read
// are one block, grouped by kind, controls and component, each heading saying which it is.
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
	header, groups, more := consoleCaveats(t, out)
	if want := "CAVEATS  do not fail the run · config.gate.failOnCaveats lists the kinds that do"; header != want {
		t.Errorf("header = %q, want %q", header, want)
	}
	want := []consoleCaveatGroup{
		{heading: "not-checked · web", rows: []string{"hosts controls off: dast, headers, tls"}},
		{heading: "not-measured · payments", rows: []string{"kube-bench-job audits the whole cluster and cannot be narrowed to namespace payments"}},
		{heading: "unread-files · sca · api", rows: []string{"go.mod no packages read"}},
		{heading: "unread-checks · platform", rows: []string{"compute 2 checks unread · denied compute.instances.list"}},
	}
	if !reflect.DeepEqual(groups, want) || more != "" {
		t.Errorf("groups = %+v, more %q\nwant %+v:\n%s", groups, more, want, out)
	}
	if strings.Contains(out, "ERRORS") {
		t.Errorf("a caveat is listed as an error:\n%s", out)
	}
}

// A service's row counts the checks with no result and those read in part apart, and leaves out a
// count of none.
func TestAnUnreadChecksRowCountsThePartlyRead(t *testing.T) {
	for _, c := range []struct {
		unread, partly []string
		want           string
	}{
		{[]string{"a", "b"}, nil, "2 checks unread · denied iam:GetRole"},
		{[]string{"a"}, []string{"b", "c"}, "1 check unread · 2 checks partly read · denied iam:GetRole"},
		{nil, []string{"b"}, "1 check partly read · denied iam:GetRole"},
	} {
		g := engine.UnreadChecks{Group: "iam", Checks: c.unread, PartlyRead: c.partly, Reason: "denied iam:GetRole"}
		if got := unreadDetail(g); got != c.want {
			t.Errorf("%v, %v = %q, want %q", c.unread, c.partly, got, c.want)
		}
	}
}

// Caveats sharing a kind, controls and component sit under one heading, the kinds in the order the
// setting lists them, then by controls and component. Two components and two sets of controls, so
// neither can be folded into the other's group, and a run past the cap draws no heading whose rows
// all fall beyond it. --top 0 draws every row and heading.
func TestCaveatsGroupByKindControlsAndComponent(t *testing.T) {
	unread := func(component, control string, paths ...string) engine.InputCoverage {
		in := engine.InputCoverage{Component: component, Control: control}
		for _, p := range paths {
			in.Unread = append(in.Unread, engine.UnreadInput{Repository: component, Path: p, Reason: "no lockfile"})
		}
		return in
	}
	d := Data{
		Uncovered: []Gap{{Component: "web", Surface: "hosts", Controls: []string{"dast"}}},
		Run: engine.Result{Inputs: []engine.InputCoverage{
			unread("web", "sca", "a/package.json", "b/package.json"),
			unread("api", "sca", "c/package.json"),
			unread("api", "licenses", "d/pyproject.toml", "e/pyproject.toml", "f/pyproject.toml", "g/pyproject.toml",
				"h/pyproject.toml", "i/pyproject.toml"),
			unread("worker", "sca", "j/package.json", "k/package.json"),
		}},
	}
	out := renderWith(t, consoleReporter{}, d)
	_, groups, more := consoleCaveats(t, out)
	want := []consoleCaveatGroup{
		{heading: "not-checked · web", rows: []string{"hosts controls off: dast"}},
		{heading: "unread-files · licenses · api", rows: []string{
			"d/pyproject.toml no lockfile", "e/pyproject.toml no lockfile", "f/pyproject.toml no lockfile",
			"g/pyproject.toml no lockfile", "h/pyproject.toml no lockfile", "i/pyproject.toml no lockfile"}},
		{heading: "unread-files · sca · api", rows: []string{"c/package.json no lockfile"}},
		{heading: "unread-files · sca · web", rows: []string{"a/package.json no lockfile", "b/package.json no lockfile"}},
	}
	if !reflect.DeepEqual(groups, want) || more != "… and 2 more · --top 0 lists every one" {
		t.Errorf("groups = %+v, more %q\nwant %+v:\n%s", groups, more, want, out)
	}
	if strings.Contains(out, "worker") {
		t.Errorf("a heading is drawn for rows past the cap:\n%s", out)
	}

	d.TopN = -1
	out = renderWith(t, consoleReporter{}, d)
	_, groups, more = consoleCaveats(t, out)
	want = append(want, consoleCaveatGroup{heading: "unread-files · sca · worker",
		rows: []string{"j/package.json no lockfile", "k/package.json no lockfile"}})
	if !reflect.DeepEqual(groups, want) || more != "" {
		t.Errorf("--top 0: groups = %+v, more %q\nwant %+v:\n%s", groups, more, want, out)
	}
}

// tryRows is the console's TRY block, a row each with its runs of spaces closed up, and nil where
// the console has no such block.
func tryRows(out string) []string {
	_, block, ok := strings.Cut(out, "\nTRY\n")
	if !ok {
		return nil
	}
	var rows []string
	for _, l := range strings.Split(strings.TrimRight(block, "\n"), "\n") {
		if !strings.HasPrefix(l, "  ") {
			break
		}
		rows = append(rows, strings.Join(strings.Fields(l), " "))
	}
	return rows
}

// TRY offers the HTML report wherever the console cut a block short and the run writes no HTML
// report: the caveats past their ten rows, the targets not reached past theirs, or the findings
// past the list's. In every view, compact included. Nothing cut, or an HTML report already written,
// and it is not offered. A run that wrote no reports is offered the formats explain and --base read
// as well, in the directory explain looks in. Two components, each with its own caveats, so the cut
// is counted across them.
func TestTheHTMLReportIsOfferedWhereTheConsoleCutABlock(t *testing.T) {
	unread := func(component string, n int) engine.InputCoverage {
		in := engine.InputCoverage{Component: component, Control: "sca"}
		for i := range n {
			in.Unread = append(in.Unread, engine.UnreadInput{Repository: component, Path: fmt.Sprintf("m%02d/go.mod", i), Reason: "no packages read"})
		}
		return in
	}
	cutCaveats := Data{Run: engine.Result{Inputs: []engine.InputCoverage{unread("api", 6), unread("web", 6)}}}
	var targets []engine.TargetOutcome
	for i := range errorRowsShown + 1 {
		targets = append(targets, failedRepository(fmt.Sprintf("https://github.com/acme/r%02d", i), "api", "web"))
	}
	cutErrors := Data{Run: engine.Result{Targets: targets}}
	whole := Data{Run: engine.Result{Inputs: []engine.InputCoverage{unread("api", 5), unread("web", 5)}}}

	const why = reportRowSays
	for _, c := range []struct {
		name string
		d    Data
		want []string
	}{
		{"caveats cut, no reports", cutCaveats, []string{"--report json,sarif,html -o .draugr/out " + why}},
		{"targets cut, no reports", cutErrors, []string{"--report json,sarif,html -o .draugr/out " + why}},
		{"caveats cut, json and sarif written", withReports(cutCaveats, "out", "json", "sarif"), []string{"--report json,sarif,html " + why}},
		{"caveats cut, an HTML report written", withReports(cutCaveats, "out", "html"), nil},
		{"nothing cut", whole, nil},
		{"caveats cut, compact", withView(cutCaveats, ViewCompact), []string{"--report json,sarif,html -o .draugr/out " + why}},
	} {
		if got := tryRows(renderWith(t, consoleReporter{}, c.d)); !slices.Equal(got, c.want) {
			t.Errorf("%s: TRY = %q, want %q", c.name, got, c.want)
		}
	}
	// --top 0 draws every row, so nothing is cut.
	all := cutCaveats
	all.TopN = -1
	if got := tryRows(renderWith(t, consoleReporter{}, all)); got != nil {
		t.Errorf("--top 0: TRY = %q, want none", got)
	}
}

func withReports(d Data, dir string, formats ...string) Data {
	d.ReportsDir, d.Reports = dir, formats
	return d
}

func withView(d Data, v View) Data {
	d.View = v
	return d
}

// A caveat row standing for several files sends a reader to --evidence for their names, from TRY,
// unless the run is under --evidence already or the row falls past the cut.
func TestAFoldedCaveatRowOffersEvidence(t *testing.T) {
	cargo := func(component string) engine.InputCoverage {
		return engine.InputCoverage{Component: component, Control: "licenses", Unread: []engine.UnreadInput{
			{Repository: component, Path: "a/Cargo.lock", Reason: "records no licenses for 2 packages", Kind: "cargo"},
			{Repository: component, Path: "b/Cargo.lock", Reason: "records no licenses for 3 packages", Kind: "cargo"},
		}}
	}
	d := Data{Run: engine.Result{Inputs: []engine.InputCoverage{cargo("api"), cargo("web")}}}
	want := []string{"--evidence each file behind a caveat row such as Cargo.lock ×2"}
	if got := tryRows(renderWith(t, consoleReporter{}, d)); !slices.Equal(got, want) {
		t.Errorf("TRY = %q, want %q", got, want)
	}
	d.Evidence = true
	if got := tryRows(renderWith(t, consoleReporter{}, d)); got != nil {
		t.Errorf("under --evidence, TRY = %q, want none", got)
	}

	// Ten rows of another kind ahead of it, so the folded row is past the cut.
	d.Evidence = false
	for i := range errorRowsShown {
		d.Uncovered = append(d.Uncovered, Gap{Component: fmt.Sprintf("c%02d", i), Surface: "hosts", Controls: []string{"tls"}})
	}
	if got := tryRows(renderWith(t, consoleReporter{}, d)); slices.ContainsFunc(got, func(r string) bool { return strings.HasPrefix(r, "--evidence") }) {
		t.Errorf("a folded row past the cut is offered --evidence: %q", got)
	}
}

// The block's header fits in a hundred columns whatever the gate says, and no longer points at
// --evidence, which TRY offers where a row stands for several files.
func TestCaveatsHeaderFitsAHundredColumns(t *testing.T) {
	for name, d := range map[string]Data{"nothing fails": {Uncovered: failingCaveatData().Uncovered}, "failing": failingCaveatData()} {
		header, _, _ := consoleCaveats(t, renderWith(t, consoleReporter{}, d))
		if n := utf8.RuneCountInString(header); n > 100 || strings.Contains(header, "--evidence") {
			t.Errorf("%s: header is %d columns: %q", name, n, header)
		}
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

// failingCaveatData is the run TestCaveatsGatherEveryShortfallThatDoesNotFail reads, with a gate
// that fails on both kinds of unread.
func failingCaveatData() Data {
	return Data{
		FailOnCaveats:     []saga.CaveatKind{saga.CaveatUnreadChecks, saga.CaveatUnreadFiles},
		FailOnCaveatsFrom: "config.gate.failOnCaveats",
		Uncovered:         []Gap{{Component: "web", Surface: "hosts", Controls: []string{"dast", "headers", "tls"}}},
		Run: engine.Result{
			Skipped: []engine.SkippedJob{{Control: "kubernetes", Scanner: "kube-bench-job", Component: "payments",
				Reason: "audits the whole cluster and cannot be narrowed to namespace payments"}},
			Inputs: []engine.InputCoverage{{Component: "api", Control: "sca", Unread: []engine.UnreadInput{
				{Repository: "https://github.com/acme/api", Path: "go.mod", Reason: "no packages read"}}}},
			UnreadChecks: []engine.UnreadChecks{{Component: "platform", Control: "cloud", Group: "compute",
				Checks: []string{"compute_instance_public_ip"}, Reason: "denied compute.instances.list"}},
		},
	}
}

// The caveats the gate fails on stay in the one block, marked where they sit, and the heading says
// how many and under which setting. The others line up under them unmarked.
func TestCaveatsTheGateFailsOnAreMarkedWhereTheySit(t *testing.T) {
	out := renderWith(t, consoleReporter{}, failingCaveatData())
	header, groups, _ := consoleCaveats(t, out)
	if want := "CAVEATS  2 fail the run · config.gate.failOnCaveats: unread-checks, unread-files"; header != want {
		t.Errorf("header = %q, want %q", header, want)
	}
	want := []consoleCaveatGroup{
		{heading: "not-checked · web", rows: []string{"hosts controls off: dast, headers, tls"}},
		{heading: "not-measured · payments", rows: []string{"kube-bench-job audits the whole cluster and cannot be narrowed to namespace payments"}},
		{heading: "unread-files · sca · api", marked: true, rows: []string{"go.mod no packages read"}},
		{heading: "unread-checks · platform", marked: true, rows: []string{"compute 1 check unread · denied compute.instances.list"}},
	}
	if !reflect.DeepEqual(groups, want) {
		t.Errorf("groups = %+v\nwant %+v:\n%s", groups, want, out)
	}
	// The unmarked headings keep the mark's two columns, so every kind starts in one column.
	for _, line := range []string{"\n    not-checked · web\n", "\n  ✗ unread-files · sca · api\n", "\n      go.mod  no packages read\n"} {
		if !strings.Contains(out, line) {
			t.Errorf("missing the line %q:\n%s", line, out)
		}
	}
	if strings.Contains(out, "ERRORS") {
		t.Errorf("a caveat moved into the errors:\n%s", out)
	}

	one := failingCaveatData()
	one.FailOnCaveats, one.FailOnCaveatsFrom = []saga.CaveatKind{saga.CaveatNotChecked}, "--fail-on-caveats"
	if out := renderWith(t, consoleReporter{}, one); !strings.Contains(out, "CAVEATS  1 fails the run · --fail-on-caveats: not-checked") {
		t.Errorf("one failing caveat, named by the flag:\n%s", out)
	}

	accepted := failingCaveatData()
	accepted.AcceptedErrors = true
	if out := renderWith(t, consoleReporter{}, accepted); !strings.Contains(out, "CAVEATS  2 accepted by --allow-scan-errors · config.gate.failOnCaveats") {
		t.Errorf("accepted caveats:\n%s", out)
	}

	// A gate listing a kind the run has none of reads as a run with nothing failing.
	none := failingCaveatData()
	none.FailOnCaveats = []saga.CaveatKind{saga.CaveatNotMeasured}
	none.Run.Skipped = nil
	if out := renderWith(t, consoleReporter{}, none); !strings.Contains(out, "CAVEATS  do not fail the run") || strings.Contains(out, "✗") {
		t.Errorf("nothing failing should read as it always did:\n%s", out)
	}
}

func TestFailedCaveatsAreTheKindsTheGateLists(t *testing.T) {
	got := FailedCaveats(failingCaveatData())
	if len(got) != 2 || got[0].Component != "api" || got[0].Kind != saga.CaveatUnreadFiles ||
		got[1].Component != "platform" || got[1].Kind != saga.CaveatUnreadChecks {
		t.Errorf("FailedCaveats = %+v, want api's file and platform's checks", got)
	}
	if got := FailedCaveats(Data{Uncovered: failingCaveatData().Uncovered}); len(got) != 0 {
		t.Errorf("with no setting, FailedCaveats = %+v, want none", got)
	}
}

// A component with a caveat the gate fails on reads ERROR in every format. Its row says nothing more:
// the Caveats section lists the caveats, and a row naming each unread file grows with the tree.
func TestAComponentWithAFailingCaveatReadsError(t *testing.T) {
	d := failingCaveatData()
	d.Components = []ComponentVerdict{
		{Name: "api", FailedCaveats: FailedCaveats(d)[:1]},
		{Name: "web"},
	}
	console := renderWith(t, consoleReporter{}, d)
	if !strings.Contains(console, "api  ERROR") || !strings.Contains(console, "web  pass") {
		t.Errorf("console:\n%s", console)
	}
	md := renderWith(t, markdownReporter{}, d)
	if !strings.Contains(md, "**ERROR**") || strings.Contains(md, "| unread-files go.mod") {
		t.Errorf("markdown:\n%s", md)
	}
	html := renderWith(t, htmlReporter{}, d)
	if strings.Contains(html, `class="gap" href="#caveats"`) || !strings.Contains(html, `<td class="outcome"><span class="err">ERROR</span></td>`) {
		t.Errorf("html: the row should read ERROR and say nothing more about the caveat")
	}
	if got := joinNotes("", "b"); got != "b" {
		t.Errorf("joinNotes = %q", got)
	}
	if got := joinNotes("a", ""); got != "a" {
		t.Errorf("joinNotes = %q", got)
	}
	if got := joinNotes("a", "b"); got != "a · b" {
		t.Errorf("joinNotes = %q", got)
	}
}

// report.json carries the setting on the gate and the caveats it failed.
func TestReportJSONCarriesFailedCaveats(t *testing.T) {
	out := renderWith(t, jsonReporter{}, failingCaveatData())
	for _, want := range []string{`"failOnCaveats": [`, `"unread-checks"`, `"failedCaveats": [`, `"what": "go.mod"`, `"kind": "unread-files"`} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %s in report.json:\n%s", want, out)
		}
	}
}

// report.json, written by the json reporter as a publisher writes it, carries the gate on new
// findings and the comparison the run made, from the same settings the command resolved.
func TestReportJSONCarriesTheGateOnNewFindings(t *testing.T) {
	d := failingCaveatData()
	d.Gate.FailOnNew = "P2"
	d.Gate.New = &skald.NewFindings{
		Base:       []sarif.RepositoryRef{{URL: "https://example.com/api.git", Revision: "3f2a9c1"}},
		Introduced: []sarif.Result{{RuleID: "CVE-1", Priority: "P2"}},
		Tripped:    []sarif.Result{{RuleID: "CVE-1", Priority: "P2"}},
	}
	out := renderWith(t, jsonReporter{}, d)
	for _, want := range []string{`"failOnNew": "P2"`, `"commit": "3f2a9c1"`, `"p2": 1`, `"verdict": "fail"`} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %s in report.json:\n%s", want, out)
		}
	}
}

// An imported file that states no commit is a caveat, once however many controls read it; a bound
// file and another scanner's provenance are not.
func TestAnUnboundImportIsACaveat(t *testing.T) {
	imported := func(file, commit string) sarif.Provenance {
		return sarif.Provenance{Tool: plugin.ImportScanner, Fields: []sarif.Field{
			{Key: "file", Value: file}, {Key: "commit", Value: commit}, {Key: "component", Value: "web"}}}
	}
	unbound := imported("reports/codeql.sarif", "not stated")
	d := Data{
		FailOnCaveats:     []saga.CaveatKind{saga.CaveatUnboundImports},
		FailOnCaveatsFrom: "config.gate.failOnCaveats",
		Run: engine.Result{Controls: map[string]plugin.ControlResult{
			"sast": {Report: sarif.Report{Provenance: []sarif.Provenance{
				unbound, imported("reports/semgrep.sarif", "0123456789ab"),
				{Tool: "gosec", Fields: []sarif.Field{{Key: "commit", Value: "not stated"}}}}}},
			"sca": {Report: sarif.Report{Provenance: []sarif.Provenance{unbound}}},
		}},
	}
	got := FailedCaveats(d)
	if len(got) != 1 || got[0].Component != "web" || got[0].Kind != saga.CaveatUnboundImports {
		t.Fatalf("FailedCaveats = %+v, want web's one unbound import", got)
	}
	out := renderWith(t, consoleReporter{}, d)
	if !strings.Contains(out, "reports/codeql.sarif") || strings.Contains(out, "reports/semgrep.sarif") {
		t.Errorf("want the unbound file listed and the bound one not:\n%s", out)
	}
}
