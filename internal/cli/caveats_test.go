package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/builtins"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/report"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// caveatSaga declares two components over one repository each, and a host on web that no enabled
// control looks at: one not-checked caveat, on web and not on api.
func caveatSaga(t *testing.T, gate string) string {
	t.Helper()
	root := gitRepo(t, "web", "api")
	return writeSaga(t, `
project: shop
config:
`+gate+`
  controls:
    secrets: {}
components:
  - name: api
    repositories: [{url: "`+filepath.Join(root, "api")+`"}]
  - name: web
    repositories: [{url: "`+filepath.Join(root, "web")+`"}]
    hosts: [{url: "https://example.com"}]
`)
}

func caveatRegistry() *engine.Registry {
	rec := &targetRecorder{}
	reg := engine.NewRegistry()
	reg.RegisterController(rec)
	reg.RegisterScanner(recorderScanner{rec})
	return reg
}

const failOnNotChecked = `  gate:
    failOnCaveats: [not-checked]`

// A caveat of a kind the gate lists fails the run as an error does: the exit says so and names the
// setting, report.json names the caveat and the setting, and only the component it belongs to
// reads ERROR.
func TestACaveatTheGateListsFailsTheRun(t *testing.T) {
	path := caveatSaga(t, failOnNotChecked)
	var buf bytes.Buffer
	err := runScan(context.Background(), path, scanOptions{format: "json"}, caveatRegistry(), &buf)
	if err == nil || !strings.Contains(err.Error(), "scan incomplete: 1 caveat fails it under config.gate.failOnCaveats") {
		t.Fatalf("err = %v, want the run failed by its caveat", err)
	}
	var doc struct {
		Verdict string `json:"verdict"`
		Gate    struct {
			FailOnCaveats []string `json:"failOnCaveats"`
		} `json:"gate"`
		FailedCaveats []report.FailedCaveat `json:"failedCaveats"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Verdict != "fail" || len(doc.Gate.FailOnCaveats) != 1 || doc.Gate.FailOnCaveats[0] != "not-checked" {
		t.Errorf("verdict %q, gate %v: want fail under not-checked", doc.Verdict, doc.Gate.FailOnCaveats)
	}
	if len(doc.FailedCaveats) != 1 || doc.FailedCaveats[0].Component != "web" ||
		doc.FailedCaveats[0].What != "hosts" || doc.FailedCaveats[0].Kind != saga.CaveatNotChecked {
		t.Errorf("failedCaveats = %+v, want web's hosts, not-checked", doc.FailedCaveats)
	}

	var console bytes.Buffer
	_ = runScan(context.Background(), path, scanOptions{format: "console"}, caveatRegistry(), &console)
	out := console.String()
	for _, want := range []string{
		"CAVEATS  1 fails the run · config.gate.failOnCaveats: not-checked",
		"\n  ✗ not-checked · web\n      hosts  ",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
	if !strings.Contains(out, "web  ERROR") || !strings.Contains(out, "api  pass") {
		t.Errorf("want web ERROR and api pass:\n%s", out)
	}
}

// A run whose caveats the console cuts short is offered the HTML report, with -o where it writes no
// report files and with the formats it already writes where it does, and not offered it where it
// already writes one. Twelve components each declaring a host and an image no enabled control looks
// at: every component keeps a row, and the rest are past the block's ten.
func TestACutCaveatsBlockOffersTheHTMLReport(t *testing.T) {
	root := gitRepo(t, "api")
	body := "project: shop\nconfig:\n  controls:\n    secrets: {}\ncomponents:\n" +
		"  - name: api\n    repositories: [{url: \"" + filepath.Join(root, "api") + "\"}]\n"
	for i := range 12 {
		body += fmt.Sprintf("  - name: web%02d\n    hosts: [{url: \"https://web%02d.example.com\"}]\n"+
			"    images: [{image: \"registry.example.com/web%02d:1\"}]\n", i, i, i)
	}
	path := writeSaga(t, body)
	for _, c := range []struct {
		name string
		opts scanOptions
		want string
	}{
		{"no report files", scanOptions{format: "console"}, "--report json,sarif,html -o .draugr/out"},
		{"the default reports", scanOptions{format: "console", outputDir: t.TempDir()}, "--report json,sarif,html "},
		{"named reports", scanOptions{format: "console", outputDir: t.TempDir(), reports: []string{"junit"}}, "--report junit,html "},
		{"an HTML report", scanOptions{format: "console", outputDir: t.TempDir(), reports: []string{"html"}}, ""},
	} {
		var buf bytes.Buffer
		if err := runScan(context.Background(), path, c.opts, caveatRegistry(), &buf); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		out := buf.String()
		if !strings.Contains(out, "… and 1 more") || !strings.Contains(out, "\n  --top 0 lists every one\n") {
			t.Fatalf("%s: the caveats block was not cut, so this test checks nothing:\n%s", c.name, out)
		}
		offered := strings.Contains(out, "every finding in one searchable page")
		if c.want == "" && offered || c.want != "" && !strings.Contains(out, "\n  "+c.want) {
			t.Errorf("%s: want %q offered:\n%s", c.name, c.want, out)
		}
	}
}

func TestReportFormatsAreWhatDashOWrites(t *testing.T) {
	for _, c := range []struct {
		opts scanOptions
		want []string
	}{
		{scanOptions{}, nil},
		{scanOptions{reports: []string{"html"}}, nil},
		{scanOptions{outputDir: "out"}, []string{"json", "sarif"}},
		{scanOptions{outputDir: "out", reports: []string{"html"}}, []string{"html"}},
	} {
		if got := reportFormats(&c.opts); !slices.Equal(got, c.want) {
			t.Errorf("reportFormats(%+v) = %v, want %v", c.opts, got, c.want)
		}
	}
}

// --allow-scan-errors accepts a failing caveat as it accepts any other error, and the report says
// the pass is partial.
func TestAllowScanErrorsAcceptsAFailingCaveat(t *testing.T) {
	path := caveatSaga(t, failOnNotChecked)
	var buf bytes.Buffer
	if err := runScan(context.Background(), path, scanOptions{format: "console", allowScanErrors: true}, caveatRegistry(), &buf); err != nil {
		t.Fatalf("err = %v, want the caveat accepted", err)
	}
	for _, want := range []string{"PASS", "Partial: the run accepted its scan errors.", "1 accepted by --allow-scan-errors"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("missing %q:\n%s", want, buf.String())
		}
	}
}

// The flag overrides the descriptor for one run, in both directions, and names itself in the exit.
func TestFailOnCaveatsFlagOverridesTheDescriptor(t *testing.T) {
	typed := map[string]bool{"fail-on-caveats": true}

	off := caveatSaga(t, failOnNotChecked)
	if err := runScan(context.Background(), off, scanOptions{format: "json", failOnCaveats: []string{"none"}, setFlags: typed},
		caveatRegistry(), &bytes.Buffer{}); err != nil {
		t.Errorf("--fail-on-caveats none: err = %v, want the descriptor's setting off for this run", err)
	}

	on := caveatSaga(t, "")
	err := runScan(context.Background(), on, scanOptions{format: "json", failOnCaveats: []string{"not-checked"}, setFlags: typed},
		caveatRegistry(), &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "under --fail-on-caveats") {
		t.Errorf("--fail-on-caveats not-checked: err = %v, want the run failed, naming the flag", err)
	}

	// Without the setting anywhere, a caveat does not fail the run.
	if err := runScan(context.Background(), on, scanOptions{format: "json"}, caveatRegistry(), &bytes.Buffer{}); err != nil {
		t.Errorf("no setting: err = %v, want a caveat to be only a caveat", err)
	}
}

func TestResolveFailOnCaveats(t *testing.T) {
	gate := &saga.GateConfig{FailOnCaveats: []saga.CaveatKind{saga.CaveatUnreadChecks}}
	for _, c := range []struct {
		name    string
		flag    []string
		set     bool
		gate    *saga.GateConfig
		want    []saga.CaveatKind
		from    string
		wantErr string
	}{
		{"nothing anywhere", nil, false, nil, nil, "", ""},
		{"the descriptor's", nil, false, gate, gate.FailOnCaveats, "config.gate.failOnCaveats", ""},
		{"the flag wins", []string{"unread-files"}, true, gate, []saga.CaveatKind{saga.CaveatUnreadFiles}, "--fail-on-caveats", ""},
		{"none", []string{"none"}, true, gate, nil, "--fail-on-caveats", ""},
		{"once each", []string{"unread-files", " unread-files"}, true, nil, []saga.CaveatKind{saga.CaveatUnreadFiles}, "--fail-on-caveats", ""},
		{"a kind that is not one", []string{"unread"}, true, nil, nil, "", `"unread" is not a kind of caveat`},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, from, err := resolveFailOnCaveats(c.flag, c.set, c.gate)
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("err = %v, want %q", err, c.wantErr)
				}
				return
			}
			if err != nil || from != c.from || len(got) != len(c.want) {
				t.Fatalf("got %v from %q, err %v; want %v from %q", got, from, err, c.want, c.from)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Errorf("got %v, want %v", got, c.want)
				}
			}
		})
	}
}

func TestCaveatClauseCountsTheCaveats(t *testing.T) {
	one := []report.FailedCaveat{{Component: "web"}}
	if got := caveatClause(one); got != "1 caveat fails it" {
		t.Errorf("caveatClause(1) = %q", got)
	}
	if got := caveatClause(append(one, report.FailedCaveat{Component: "api"})); got != "2 caveats fail it" {
		t.Errorf("caveatClause(2) = %q", got)
	}
}

// doctor reads the descriptor's setting, so the preflight and the scan cannot disagree about a
// declared surface no enabled control looks at.
func TestDoctorFailsWhereTheScanWouldOnNotChecked(t *testing.T) {
	path := writeSaga(t, strings.Replace(doctorSagaUncovered, "config:\n", "config:\n  gate:\n    failOnCaveats: [not-checked]\n", 1))
	var out bytes.Buffer
	err := runDoctor(context.Background(), &out, builtins.Registry(), path, doctorRun{}, fakeDetect("gitleaks", "git"), nil)
	if err == nil || !strings.Contains(out.String(), "config.gate.failOnCaveats lists not-checked") {
		t.Errorf("err = %v, want doctor to fail naming the setting:\n%s", err, out.String())
	}
	if failsOnNotChecked(nil) {
		t.Error("no descriptor fails on nothing")
	}
}

// The reference lists the kinds of caveat twice, beside the flag and under config.gate, both by
// hand. A kind missing from either is one a reader looking there does not know they can fail on.
func TestEveryCaveatKindIsDocumented(t *testing.T) {
	for _, doc := range []struct{ path, line string }{
		{"../../docs/reference/cli.md", "| `--fail-on-caveats` |"},
		{"../../docs/reference/saga-schema.md", ""},
	} {
		raw, err := os.ReadFile(doc.path)
		if err != nil {
			t.Fatal(err)
		}
		text := string(raw)
		if doc.line != "" {
			i := strings.Index(text, doc.line)
			if i < 0 {
				t.Fatalf("%s has no %s row", doc.path, doc.line)
			}
			text, _, _ = strings.Cut(text[i:], "\n")
		}
		for _, k := range saga.CaveatKinds {
			mark := "`" + string(k) + "`"
			if doc.line == "" {
				mark = "| `" + string(k) + "` |"
			}
			if !strings.Contains(text, mark) {
				t.Errorf("%s does not list the caveat kind %s", doc.path, k)
			}
		}
	}
}

// A run whose findings fail the gate and whose caveat fails it too says both, the findings first,
// and offers --allow-scan-errors only where accepting the caveat would let the run pass: the
// findings fail it either way, and --no-gate takes their failure away.
func TestARunFailingOnFindingsAndACaveatSaysBoth(t *testing.T) {
	path := writeSaga(t, `
project: app
config:
  gate:
    failOnCaveats: [not-checked]
  controllers:
    images:
      enabled: true
components:
  - name: c
    images:
      - image: repo/x:1
    hosts: [{url: "https://example.com"}]
`)
	const caveat = "1 caveat fails it under config.gate.failOnCaveats"
	for _, c := range []struct {
		name  string
		level sarif.Level
		opts  scanOptions
		want  string
	}{
		{"both fail", sarif.LevelError, scanOptions{},
			"policy verdict: fail; the scan is also incomplete: " + caveat},
		{"the caveat accepted", sarif.LevelError, scanOptions{allowScanErrors: true},
			"policy verdict: fail"},
		{"no gate", sarif.LevelError, scanOptions{noGate: true},
			"scan incomplete: " + caveat + " (use --allow-scan-errors to accept partial results)"},
		{"the findings pass", sarif.LevelNote, scanOptions{},
			"scan incomplete: " + caveat + " (use --allow-scan-errors to accept partial results)"},
	} {
		c.opts.failOn, c.opts.format = "error", "json"
		err := runScan(context.Background(), path, c.opts, fakeRegistry(c.level), &bytes.Buffer{})
		if err == nil || err.Error() != c.want {
			t.Errorf("%s: err = %v, want %q", c.name, err, c.want)
		}
	}
}

// Where the gate fails too, every kind of incomplete run names the gate first and leaves out the
// flag, which cannot make it pass.
func TestIncompleteErrorLeadsWithAFailingGate(t *testing.T) {
	gate := errors.New("policy verdict: fail")
	caveats := []report.FailedCaveat{{Component: "web"}, {Component: "api"}}
	const setting = "config.gate.failOnCaveats"
	for _, c := range []struct {
		name     string
		gate     error
		unwaived []string
		waived   []string
		caveats  []report.FailedCaveat
		allow    bool
		want     string
	}{
		{"caveats", nil, nil, nil, caveats, false,
			"scan incomplete: 2 caveats fail it under config.gate.failOnCaveats (use --allow-scan-errors to accept partial results)"},
		{"caveats and the gate", gate, nil, nil, caveats, false,
			"policy verdict: fail; the scan is also incomplete: 2 caveats fail it under config.gate.failOnCaveats"},
		{"a scanner", nil, nil, []string{"sca"}, caveats, false,
			"scan incomplete: sca could not run, and 2 caveats fail it under config.gate.failOnCaveats (use --allow-scan-errors to accept partial results)"},
		{"a scanner and the gate", gate, nil, []string{"sca"}, nil, false,
			"policy verdict: fail; the scan is also incomplete: sca could not run"},
		{"no scanner", nil, []string{"sast"}, nil, nil, false,
			"scan incomplete: sast could not run. --allow-scan-errors does not apply: it accepts a failed scanner, and no scanner ran"},
		{"no scanner and the gate", gate, []string{"sast"}, []string{"sca"}, nil, true,
			"policy verdict: fail; the scan is also incomplete: sast could not run"},
	} {
		err := incompleteError(c.gate, c.unwaived, c.waived, c.caveats, setting, c.allow)
		if err.Error() != c.want {
			t.Errorf("%s:\n got %q\nwant %q", c.name, err, c.want)
		}
		if c.gate != nil && !errors.Is(err, c.gate) {
			t.Errorf("%s: the gate's error is not wrapped", c.name)
		}
	}
}
