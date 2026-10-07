package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/builtins"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/report"
	"github.com/draugr-dev/draugr/pkg/saga"
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
		"✗ not checked",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
	if !strings.Contains(out, "web  ERROR") || !strings.Contains(out, "api  pass") {
		t.Errorf("want web ERROR and api pass:\n%s", out)
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
	for _, want := range []string{"PASS", "partial · scan errors accepted", "1 accepted by --allow-scan-errors"} {
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
