package report

import (
	"bytes"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/draugr-dev/draugr/pkg/sarif"
	"github.com/draugr-dev/draugr/pkg/skald"
	"github.com/draugr-dev/draugr/pkg/tui"
)

// demoRepository is where every finding below was found, as a scan of a checkout records it.
const demoRepository = "https://github.com/draugr-dev/draugr-demo.git"

// codeFinding is a SAST finding at a line, with the scanner and the message it reported.
func codeFinding(tool, rule, prio string, level sarif.Level, loc, msg string) finding {
	sev := sarif.SeverityMedium
	if level == sarif.LevelError {
		sev = sarif.SeverityHigh
	}
	return finding{control: "sast", tool: tool, ruleID: rule, priority: prio, level: level, severity: sev,
		component: "api", repository: demoRepository, location: loc, message: msg,
		fingerprint: tool + "|" + rule + "|" + loc}
}

// rated is f with the severity the scanner's own rating gave it.
func rated(f finding, sev sarif.Severity) finding {
	f.severity = sev
	return f
}

// appPy is what Bandit and Semgrep report on draugr-demo's app/app.py, messages as they wrote them
// and each at the band and severity a scan gives it: one shell command on line 23 that four rules
// flag, an eval on line 30 that three do, and a rule that flags line 30 and one more line.
func appPy() []finding {
	return []finding{
		// issue_severity HIGH, issue_confidence HIGH.
		rated(codeFinding("Bandit", "B602", "P1", sarif.LevelError, "app/app.py:23",
			"subprocess call with shell=True identified, security issue."), sarif.SeverityHigh),
		// impact MEDIUM, likelihood HIGH.
		rated(codeFinding("Semgrep OSS", "python.flask.security.injection.subprocess-injection.subprocess-injection", "P1",
			sarif.LevelError, "app/app.py:23",
			"Detected user input entering a `subprocess` call unsafely. This could result in a command injection vulnerability."),
			sarif.SeverityHigh),
		// impact HIGH, likelihood MEDIUM.
		rated(codeFinding("Semgrep OSS", "python.lang.security.dangerous-subprocess-use.dangerous-subprocess-use", "P1",
			sarif.LevelError, "app/app.py:23",
			"Detected subprocess function 'check_output' with user controlled data. A malicious actor could leverage this to perform command injection."),
			sarif.SeverityHigh),
		// impact LOW, likelihood HIGH.
		rated(codeFinding("Semgrep OSS", "python.lang.security.audit.subprocess-shell-true.subprocess-shell-true", "P2",
			sarif.LevelError, "app/app.py:23",
			"Found 'subprocess' function 'check_output' with 'shell=True'. This is dangerous because this call will spawn the command using a shell process."),
			sarif.SeverityMedium),
		// impact MEDIUM, likelihood MEDIUM.
		rated(codeFinding("Semgrep OSS", "python.flask.security.injection.user-eval.eval-injection", "P2",
			sarif.LevelError, "app/app.py:30",
			"Detected user data flowing into eval. This is code injection and should be avoided."), sarif.SeverityMedium),
		// impact HIGH, likelihood LOW, confidence LOW, subcategory audit.
		rated(codeFinding("Semgrep OSS", "python.lang.security.audit.eval-detected.eval-detected", "P3",
			sarif.LevelWarning, "app/app.py:30",
			"Detected the use of eval(). eval() can be dangerous if used to evaluate dynamic content."), sarif.SeverityLow),
		// issue_severity MEDIUM, issue_confidence HIGH.
		rated(codeFinding("Bandit", "B307", "P2", sarif.LevelWarning, "app/app.py:30",
			"Use of possibly insecure function - consider using safer ast.literal_eval."), sarif.SeverityMedium),
		rated(codeFinding("Semgrep OSS", "python.lang.security.audit.eval-detected.eval-detected", "P3",
			sarif.LevelWarning, "app/util.py:12",
			"Detected the use of eval(). eval() can be dangerous if used to evaluate dynamic content."), sarif.SeverityLow),
	}
}

// byLocation indexes actions by the one place each is at.
func byLocation(t *testing.T, actions []action) map[string]action {
	t.Helper()
	out := map[string]action{}
	for _, a := range actions {
		locs := a.locations()
		if len(locs) != 1 {
			t.Fatalf("an action for a line should be at one place, %q is at %+v", a.title, locs)
		}
		out[locs[0].Repository+" "+a.component+" "+a.findings[0].location] = a
	}
	return out
}

// One flaw that several rules recognize is one edit, and the fix list says so: the four rules on
// line 23 are one action clearing four findings, not four actions clearing one each. A rule that
// flags two lines is still two actions, because each line is its own edit.
func TestOneLineOfCodeIsOneAction(t *testing.T) {
	in := appPy()
	sortFindings(in)
	got, _ := groupActions(in, nil)
	if len(got) != 3 {
		t.Fatalf("want an action per line, 3, got %d: %q", len(got), titles(got))
	}
	at := byLocation(t, got)
	line23 := at[demoRepository+" api app/app.py:23"]
	if line23.count() != 4 || line23.priority != "P1" || line23.kind != skald.KindCode {
		t.Errorf("line 23 = %d findings at %s, kind %s; want 4 at P1, code", line23.count(), line23.priority, line23.kind)
	}
	if line23.summary != "" {
		t.Errorf("the title says what is wrong, so there is no summary: %q", line23.summary)
	}
	if n := at[demoRepository+" api app/app.py:30"].count(); n != 3 {
		t.Errorf("line 30 clears %d findings, want 3", n)
	}
	if n := at[demoRepository+" api app/util.py:12"].count(); n != 1 {
		t.Errorf("the rule's other line is its own action with 1 finding, got %d", n)
	}

	// Every rule the line clears, by scanner, the one the title quotes first. Each scanner by its
	// own name, without the edition beside it.
	want := []string{
		"Bandit: B602",
		"Semgrep: subprocess-injection, dangerous-subprocess-use, subprocess-shell-true",
	}
	if got := ruleGroups(line23); !reflect.DeepEqual(got, want) {
		t.Errorf("rules = %q, want %q", got, want)
	}
}

// ruleGroups renders an action's rules as "tool: rule, rule", one entry per scanner.
func ruleGroups(a action) []string {
	var out []string
	for _, g := range a.rulesByTool() {
		names := make([]string, 0, len(g.rules))
		for _, f := range g.rules {
			names = append(names, shortRuleName(f.ruleID))
		}
		out = append(out, g.tool+": "+strings.Join(names, ", "))
	}
	return out
}

func titles(actions []action) []string {
	out := make([]string, 0, len(actions))
	for _, a := range actions {
		out = append(out, a.title)
	}
	return out
}

// The title says what the flaw is in a scanner's own words, chosen by rule, so it is the same
// whichever order the scanners finished in, and never the rule that sorts first.
func TestALineIsTitledByWhatItsRulesFound(t *testing.T) {
	in := appPy()
	sortFindings(in)
	first, _ := groupActions(in, nil)

	reversed := appPy()
	for i, j := 0, len(reversed)-1; i < j; i, j = i+1, j-1 {
		reversed[i], reversed[j] = reversed[j], reversed[i]
	}
	sortFindings(reversed)
	again, _ := groupActions(reversed, nil)
	if !reflect.DeepEqual(titles(first), titles(again)) {
		t.Errorf("titles moved with the input order: %q, then %q", titles(first), titles(again))
	}

	at := byLocation(t, first)
	for loc, want := range map[string]string{
		// TestTheTitleOfAppPy23IsDecidedByLength says which tier decides it.
		"app/app.py:23": "Fix “subprocess call with shell=True identified, security issue”",
		// Two at the worst band, P2, and Bandit's description runs past the title.
		"app/app.py:30":  "Fix “Detected user data flowing into eval”",
		"app/util.py:12": "Fix “Detected the use of eval()”",
	} {
		if got := at[demoRepository+" api "+loc].title; got != want {
			t.Errorf("%s: title = %q, want %q", loc, got, want)
		}
	}
}

// The four rules on app.py:23 are titled by length. The band leaves out subprocess-shell-true, a
// P2. Severity and score do not separate the other three: each is high, and none is scored.
// dangerous-subprocess-use does not fit the title whole. Of the two that do, Bandit's description
// is one character longer than subprocess-injection's, so it titles the line, and a longer one from
// subprocess-injection that still fits would title it instead.
func TestTheTitleOfAppPy23IsDecidedByLength(t *testing.T) {
	var line []finding
	for _, f := range appPy() {
		if f.location == "app/app.py:23" {
			line = append(line, f)
		}
	}
	byRule := map[string]finding{}
	for _, f := range line {
		byRule[shortRuleName(f.ruleID)] = f
	}
	b602, injection := byRule["B602"], byRule["subprocess-injection"]
	dangerous, shell := byRule["dangerous-subprocess-use"], byRule["subprocess-shell-true"]

	if !titlesBetter(b602, shell) || shell.priority == b602.priority {
		t.Errorf("subprocess-shell-true should lose on the band: %s against %s", shell.priority, b602.priority)
	}
	for _, f := range []finding{injection, dangerous} {
		if f.priority != b602.priority || f.severity != b602.severity || f.score != b602.score {
			t.Errorf("%s should rank alike with B602: %s %s %v", f.ruleID, f.priority, f.severity, f.score)
		}
	}
	if fitsTitle(dangerous, describe(dangerous)) || !fitsTitle(b602, describe(b602)) || !fitsTitle(injection, describe(injection)) {
		t.Error("only dangerous-subprocess-use should run past the title")
	}
	if lb, li := utf8.RuneCountInString(describe(b602)), utf8.RuneCountInString(describe(injection)); lb != li+1 {
		t.Errorf("descriptions are %d and %d characters, want B602's one longer", lb, li)
	}
	if got := titleFinding(line).ruleID; got != "B602" {
		t.Errorf("titled by %q, want B602", got)
	}

	longer := injection
	longer.message = "Detected user input entering a `subprocess` call unsafely here. This could result in injection."
	if got := titleFinding([]finding{b602, longer, dangerous, shell}).ruleID; got != injection.ruleID {
		t.Errorf("a longer description that still fits should title the line, got %q", got)
	}
}

// Each step of the titling rule, alone: band, severity, score, a description that fits, length,
// and the rule id last.
func TestTheTitlingRuleTakesItsStepsInOrder(t *testing.T) {
	short := "Short description."
	long := "A rather longer description of the same flaw."
	cut := "A description long enough that a title quoting it cannot hold it whole, which is too long."
	base := func(rule, prio string, sev sarif.Severity, msg string) finding {
		return finding{control: "sast", ruleID: rule, priority: prio, severity: sev, location: "a.py:1", message: msg}
	}
	scored := base("scored", "P2", sarif.SeverityHigh, short)
	scored.score, scored.hasScore = 8.1, true
	for _, c := range []struct {
		name    string
		a, b    finding
		winning string
	}{
		{"the worse band", base("p1", "P1", sarif.SeverityLow, short), base("p2", "P2", sarif.SeverityHigh, long), "p1"},
		{"then the higher severity", base("high", "P2", sarif.SeverityHigh, short), base("medium", "P2", sarif.SeverityMedium, long), "high"},
		{"then the higher score", scored, base("unscored", "P2", sarif.SeverityHigh, long), "scored"},
		{"then a description that fits", base("fits", "P2", sarif.SeverityHigh, short), base("cut", "P2", sarif.SeverityHigh, cut), "fits"},
		{"then the longer description", base("short", "P2", sarif.SeverityHigh, short), base("long", "P2", sarif.SeverityHigh, long), "long"},
		{"then the rule id", base("b-rule", "P2", sarif.SeverityHigh, short), base("a-rule", "P2", sarif.SeverityHigh, short), "a-rule"},
	} {
		for _, order := range [][]finding{{c.a, c.b}, {c.b, c.a}} {
			if got := titleFinding(order).ruleID; got != c.winning {
				t.Errorf("%s: titled by %q, want %q", c.name, got, c.winning)
			}
		}
	}
}

// A line whose findings carry no description is still titled by something a reader can act on: the
// rule's name, and the place where there is not even that.
func TestALineWithoutADescriptionIsStillTitled(t *testing.T) {
	for _, c := range []struct {
		f    finding
		want string
	}{
		{finding{control: "sast", ruleID: "G204", location: "main.go:12"}, "Fix G204"},
		{finding{control: "sast", location: "main.go:12"}, "Fix main.go:12"},
		// A finding that reports a fact is reviewed, on a line as anywhere.
		{finding{control: "sast", ruleID: "x", location: "main.go:12", message: "Uses MD5.", score: 1, hasScore: true},
			"Review “Uses MD5”"},
	} {
		if got, _ := lineTitle([]finding{c.f}); got != c.want {
			t.Errorf("lineTitle(%+v) = %q, want %q", c.f, got, c.want)
		}
	}
}

// A lone rule whose description would be cut is titled by the rule's name, with the description
// whole on the line under it, as every action named for a rule is. One whose description fits is
// quoted. Where several rules flag the line and none fits, the title quotes one of them, cut, and
// still closes its quotation.
func TestATitleThatWouldBeCutNamesItsRuleOrClosesItsQuote(t *testing.T) {
	long := "In Kubernetes, each pod runs in its own isolated environment with its own set of security policies."
	escalation := codeFinding("Semgrep OSS",
		"yaml.kubernetes.security.allow-privilege-escalation-true.allow-privilege-escalation-true",
		"P2", sarif.LevelWarning, "deploy/pod.yaml:13", long)
	title, summary := lineTitle([]finding{escalation})
	if title != "Fix allow-privilege-escalation-true" || summary != strings.TrimSuffix(long, ".") {
		t.Errorf("a lone rule cut short: title %q, summary %q", title, summary)
	}

	privileged := codeFinding("Semgrep OSS", "yaml.kubernetes.security.privileged-container.privileged-container",
		"P2", sarif.LevelWarning, "deploy/pod.yaml:11",
		"Container or pod is running in privileged mode. This grants the container the equivalent of root capabilities.")
	title, summary = lineTitle([]finding{privileged})
	if title != "Fix “Container or pod is running in privileged mode”" || summary != "" {
		t.Errorf("a lone rule that fits: title %q, summary %q", title, summary)
	}

	other := escalation
	other.tool, other.ruleID = "Checkov", "CKV_K8S_20"
	title, summary = lineTitle([]finding{escalation, other})
	if !strings.HasPrefix(title, "Fix “In Kubernetes, each pod") || !strings.HasSuffix(title, "…”") ||
		utf8.RuneCountInString(title) > actionTitleWidth || summary != "" {
		t.Errorf("several rules, none fitting: title %q (%d runes), summary %q",
			title, utf8.RuneCountInString(title), summary)
	}
}

// A title quoting a scanner keeps its closing mark when it is cut, whether it is cut when written or
// fitted into a narrow terminal. The quoted words give way.
func TestACutQuotationStaysClosed(t *testing.T) {
	cve := finding{control: "sca", ruleID: "CVE-2019-20477",
		message: "PyYAML: command execution through python/object/apply constructor in FullLoader"}
	if got, want := titleFor(cve), "Fix CVE-2019-20477 “PyYAML: command execution through python/object/ap…”"; got != want {
		t.Errorf("titleFor = %q, want %q", got, want)
	}
	for _, c := range []struct {
		title string
		width int
		want  string
	}{
		{"Fix “Detected user data flowing into eval”", 80, "Fix “Detected user data flowing into eval”"},
		{"Fix “Detected user data flowing into eval”", 30, "Fix “Detected user data flow…”"},
		{"Fix CVE-1 “A flaw that runs long”", 20, "Fix CVE-1 “A flaw…”"},
		{"Fix tainted-sql-string", 12, "Fix…"},
		{"Fix “x”", 6, "Fix “…"},
	} {
		if got := elideTitle(c.title, c.width); got != c.want {
			t.Errorf("elideTitle(%q, %d) = %q, want %q", c.title, c.width, got, c.want)
		}
	}
}

// A scanner is named as it names itself, without the edition beside it, unless the edition is what
// tells two scanners on one line apart.
func TestARuleLineNamesEachScannerOnce(t *testing.T) {
	at := func(tool, rule string) finding {
		return codeFinding(tool, rule, "P1", sarif.LevelError, "app/app.py:23", "subprocess call with shell=True.")
	}
	one, _ := groupActions([]finding{at("Semgrep OSS", "a.b.shell-true"), at("Bandit", "B602")}, nil)
	if got, want := ruleGroups(one[0]), []string{"Bandit: B602", "Semgrep: shell-true"}; !reflect.DeepEqual(got, want) {
		t.Errorf("rules = %q, want %q", got, want)
	}
	two, _ := groupActions([]finding{at("Semgrep OSS", "a.b.shell-true"), at("Semgrep", "c.d.injection")}, nil)
	if got, want := ruleGroups(two[0]), []string{"Semgrep OSS: shell-true", "Semgrep: injection"}; !reflect.DeepEqual(got, want) {
		t.Errorf("rules = %q, want %q", got, want)
	}
}

// Paths are repository-relative and a component is an owner, so the same line in two repositories,
// or in two components sharing one, is two actions. Each names its repository once the list spans
// more than one, or the two rows would read alike.
func TestTheSameLineInTwoRepositoriesIsTwoActions(t *testing.T) {
	at := func(component, repo, rule string) finding {
		f := codeFinding("gosec", rule, "P1", sarif.LevelError, "main.go:12", "Subprocess launched with variable.")
		f.component, f.repository = component, repo
		f.fingerprint += "|" + component + "|" + repo
		return f
	}
	const web, worker = "https://github.com/acme/web", "https://github.com/acme/worker"
	in := []finding{
		at("api", web, "G204"), at("api", web, "G304"),
		at("api", worker, "G204"),
		at("admin", web, "G204"),
	}
	sortFindings(in)
	got, _ := groupActions(in, nil)
	if len(got) != 3 {
		t.Fatalf("one line in two repositories and two components is 3 actions, got %d: %+v", len(got), got)
	}
	actions := byLocation(t, got)
	if a := actions[web+" api main.go:12"]; a.count() != 2 || a.component != "api" {
		t.Errorf("api's main.go:12 in acme/web = %d findings in %q, want both rules in api", a.count(), a.component)
	}
	if a := actions[worker+" api main.go:12"]; a.count() != 1 {
		t.Errorf("api's main.go:12 in acme/worker = %d findings, want its own 1", a.count())
	}
	if a := actions[web+" admin main.go:12"]; a.count() != 1 || a.component != "admin" {
		t.Errorf("admin's main.go:12 = %d findings in %q, want its own 1", a.count(), a.component)
	}
	var where []string
	for _, a := range got {
		where = append(where, a.where(2)...)
	}
	want := []string{"acme/web main.go:12", "acme/web main.go:12", "acme/worker main.go:12"}
	if !reflect.DeepEqual(where, want) {
		t.Errorf("where = %q, want each place named with its repository: %q", where, want)
	}

	// One repository names none, as everywhere else.
	got, _ = groupActions([]finding{at("api", web, "G204"), at("api", web, "G304")}, nil)
	if w := got[0].where(2); !reflect.DeepEqual(w, []string{"main.go:12"}) {
		t.Errorf("a single repository should not prefix its location: %q", w)
	}
}

// A SARIF file another tool wrote names paths and no repository. Its finding at a line joins the
// action for that line in the one repository the rest of its component was scanned in, and stays
// apart where the component spans two, because then nothing says which file it is.
func TestAnImportedFindingJoinsTheLineItIsOn(t *testing.T) {
	imported := codeFinding("Bandit", "B602", "P1", sarif.LevelError, "app/app.py:23",
		"subprocess call with shell=True identified, security issue.")
	imported.repository = ""
	scanned := codeFinding("Semgrep OSS", "python.lang.security.audit.subprocess-shell-true.subprocess-shell-true", "P1",
		sarif.LevelError, "app/app.py:23", "Found 'subprocess' function 'check_output' with 'shell=True'.")

	got, _ := groupActions([]finding{imported, scanned}, nil)
	if len(got) != 1 || got[0].count() != 2 {
		t.Fatalf("an imported finding on a scanned line should join it, got %q", titles(got))
	}
	if locs := got[0].locations(); len(locs) != 1 || locs[0].Repository != demoRepository {
		t.Errorf("one place, in the component's repository: %+v", locs)
	}

	elsewhere := scanned
	elsewhere.repository, elsewhere.location = "https://github.com/acme/other", "lib.py:1"
	got, _ = groupActions([]finding{imported, scanned, elsewhere}, nil)
	if len(got) != 3 {
		t.Errorf("a component spanning two repositories cannot place a path, want 3 actions, got %q", titles(got))
	}
}

// A SAST finding with no line is about a whole file, and keeps the grouping on its rule.
func TestASASTFindingWithoutALineGroupsByRule(t *testing.T) {
	got, _ := groupActions([]finding{
		{control: "sast", ruleID: "x.missing-license-header", priority: "P4", location: "a.py", message: "No header."},
		{control: "sast", ruleID: "x.missing-license-header", priority: "P4", location: "b.py", message: "No header."},
	}, nil)
	if len(got) != 1 || got[0].atOneLine() || got[0].title != "Fix missing-license-header" {
		t.Errorf("want one action for the rule, got %+v", got)
	}
}

// The line of rules fits its room by naming fewer and counting the rest.
func TestTheRuleLineFitsItsRoom(t *testing.T) {
	in := appPy()[:4]
	sortFindings(in)
	got, _ := groupActions(in, nil)
	for _, c := range []struct {
		room int
		want string
	}{
		{120, "Bandit: B602 · Semgrep: subprocess-injection, dangerous-subprocess-use, subprocess-shell-true"},
		{93, "Bandit: B602 · Semgrep: subprocess-injection, dangerous-subprocess-use, subprocess-shell-true"},
		{92, "Bandit: B602 · Semgrep: subprocess-injection, dangerous-subprocess-use · and 1 more"},
		{60, "Bandit: B602 · Semgrep: subprocess-injection · and 2 more"},
		{40, "Bandit: B602 · and 3 more"},
		{20, "Bandit: B602"},
		{8, "Bandit:…"},
	} {
		if line := ruleLine(tui.Plain(), got[0], c.room); line != c.want {
			t.Errorf("room %d: %q, want %q", c.room, line, c.want)
		}
	}
	if line := ruleLine(tui.Plain(), action{key: lineKey, findings: []finding{{location: "a.py:1"}}}, 40); line != "" {
		t.Errorf("findings without a rule list none: %q", line)
	}
}

// The console prints the rules under the title, and the line under them carries no rule reference,
// which would name one of them a second time.
func TestTheConsoleListsALinesRules(t *testing.T) {
	in := appPy()
	sortFindings(in)
	actions, _ := groupActions(in, nil)
	var b bytes.Buffer
	renderActions(&b, tui.Plain(), actions, false)
	want := "" +
		"  P1  Fix “subprocess call with shell=True identified, security issue”\n" +
		"      Bandit: B602 · Semgrep: subprocess-injection, dangerous-subprocess-use, subprocess-shell-true\n" +
		"      control sast · 4 findings · app/app.py:23\n"
	if !strings.HasPrefix(b.String(), want) {
		t.Errorf("got:\n%s\nwant it to open with:\n%s", b.String(), want)
	}
}

// report.json and the MCP server read a merged results.sarif, and get the same actions: one per
// line, naming every rule it clears and the one place it is, one change rather than one per rule.
func TestAnExportedLineActionNamesItsRulesAndItsPlace(t *testing.T) {
	var merged sarif.Report
	for _, f := range appPy() {
		path, n, _ := strings.Cut(f.location, ":")
		line, err := strconv.Atoi(n)
		if err != nil {
			t.Fatal(err)
		}
		merged.Results = append(merged.Results, sarif.Result{
			Control: "sast", Tool: f.tool, RuleID: f.ruleID, Priority: f.priority, Level: f.level,
			Component: f.component, Repository: f.repository, Message: f.message,
			Location: sarif.Location{URI: path, StartLine: line}, Rating: &sarif.Rating{Severity: f.severity},
		})
	}
	data, err := merged.MarshalSARIF()
	if err != nil {
		t.Fatal(err)
	}
	read, err := sarif.FromSARIF(data)
	if err != nil {
		t.Fatal(err)
	}
	got := ActionsFor(map[string]sarif.Report{"": read})
	if len(got) != 3 {
		t.Fatalf("want an action per line, 3, got %d", len(got))
	}
	a := got[0]
	if a.Clears != 4 || a.Control != "sast" || a.Kind != skald.KindCode || !a.OneChange || a.Summary != "" {
		t.Errorf("line 23 = %+v", a)
	}
	// The rule the title quotes first, then the order the console lists them in.
	wantRules := []string{
		"B602",
		"python.flask.security.injection.subprocess-injection.subprocess-injection",
		"python.lang.security.dangerous-subprocess-use.dangerous-subprocess-use",
		"python.lang.security.audit.subprocess-shell-true.subprocess-shell-true",
	}
	if !reflect.DeepEqual(a.RuleIDs, wantRules) {
		t.Errorf("ruleIds = %q, want %q", a.RuleIDs, wantRules)
	}
	wantLoc := []ActionLocation{{Repository: demoRepository, Path: "app/app.py", Line: 23, Kind: skald.LocationFile}}
	if !reflect.DeepEqual(a.Locations, wantLoc) || !reflect.DeepEqual(a.Where, []string{"app/app.py:23"}) {
		t.Errorf("locations = %+v, where = %q", a.Locations, a.Where)
	}
	if len(a.Findings) != 4 || len(a.Fingerprints) != 4 {
		t.Errorf("each finding is still its own record: %d findings, %d fingerprints", len(a.Findings), len(a.Fingerprints))
	}
	if Cleared(got) != len(merged.Results) {
		t.Errorf("the actions clear %d findings between them, want every one of %d", Cleared(got), len(merged.Results))
	}
}
