package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/builtins"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/report"
)

// secretSARIF is one leaked credential, as Gitleaks writes it, at path.
func secretSARIF(t *testing.T, dir, path string) string {
	t.Helper()
	file := filepath.Join(dir, strings.ReplaceAll(path, "/", "-")+".sarif")
	body := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"gitleaks","version":"8.28.0"}},` +
		`"results":[{"ruleId":"generic-api-key","level":"error",` +
		`"message":{"text":"generic-api-key has detected secret for file ` + path + `."},` +
		`"locations":[{"physicalLocation":{"artifactLocation":{"uri":"` + path + `"},"region":{"startLine":3}}}]}]}]}`
	if err := os.WriteFile(file, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return file
}

// floorSaga declares the components named, each importing one secret into the control given: api
// is public and critical, which the floor cannot raise, and worker is internal, which it can.
func floorSaga(t *testing.T, control string, components ...string) string {
	t.Helper()
	dir := t.TempDir()
	declared := map[string]string{
		"api":    "    exposure: public\n    criticality: critical\n",
		"worker": "    exposure: internal\n    criticality: important\n",
	}
	body := "project: shop\nconfig:\n  controls: {}\ncomponents:\n"
	for _, name := range components {
		body += "  - name: " + name + "\n" + declared[name] +
			"    imports:\n      - control: " + control + "\n        file: \"" +
			secretSARIF(t, dir, name+"/config.env") + "\"\n"
	}
	return writeSaga(t, body)
}

// The floor row counts what the floor raised, and only that. Two components each carrying a secret:
// the public, critical one was already at the tier the floor ranks at, so only the internal one is
// counted. A run with the first alone says "nothing raised", and a run with no floor control has no
// row, so a reader can tell a floor that changed nothing from one that was never applied.
func TestTheFloorRowCountsOnlyWhatTheFloorRaised(t *testing.T) {
	for _, tc := range []struct {
		name string
		saga string
		want string // the floor row, or "" for none
	}{
		{"one public and critical, one internal", floorSaga(t, "secrets", "api", "worker"),
			"floor  1 finding raised by a control's own rule"},
		{"only the public and critical one", floorSaga(t, "secrets", "api"), "floor  nothing raised"},
		{"no control that declares a floor", floorSaga(t, "sast", "api", "worker"), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var console bytes.Buffer
			err := runScan(context.Background(), tc.saga, scanOptions{format: "console"}, builtins.Registry(), &console)
			if err == nil || !strings.Contains(err.Error(), "policy verdict: fail") {
				t.Fatalf("err = %v, want the gate to fail on the secrets", err)
			}
			out := console.String()
			if tc.want == "" {
				if strings.Contains(out, "SIGNALS") {
					t.Errorf("a Signals block with no floor control and no feed:\n%s", out)
				}
				return
			}
			if !strings.Contains(out, "SIGNALS\n  "+tc.want+"\n") {
				t.Errorf("want the Signals block to read %q:\n%s", tc.want, out)
			}
		})
	}
}

// cveSaga ranks the fake scanner's two CVEs against an EPSS file that scores one of them, with
// the threshold line given.
func cveSaga(t *testing.T, threshold string) string {
	t.Helper()
	epss := filepath.Join(t.TempDir(), "epss.csv")
	if err := os.WriteFile(epss, []byte("cve,epss,percentile\nCVE-2021-44228,0.94,0.99\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return writeSaga(t, `
project: app
release:
  version: "1.0"
config:
  controllers:
    images:
      enabled: true
  exploitability:
    epss: "`+epss+`"
`+threshold+`
components:
  - name: api
    images:
      - image: repo/api:1
  - name: worker
    images:
      - image: repo/worker:1
`)
}

// The EPSS row states the threshold the run measured against, whichever of the flag, the
// descriptor and the default set it, never a fixed number.
func TestTheHTMLReportStatesTheEPSSThresholdTheRunUsed(t *testing.T) {
	for _, tc := range []struct {
		name      string
		threshold string
		flag      bool
		want      string
	}{
		{"the default", "", false, "0.5"},
		{"the descriptor", "    epssThreshold: 0.2", false, "0.2"},
		{"the flag over the descriptor", "    epssThreshold: 0.2", true, "0.35"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reg := engine.NewRegistry()
			reg.RegisterController(fakeController{})
			reg.RegisterScanner(cveScanner{})
			dir := t.TempDir()
			opts := scanOptions{format: "json", reports: []string{"html"}, outputDir: dir, failOn: "error",
				epssThreshold: 0.5, setFlags: map[string]bool{}}
			if tc.flag {
				opts.epssThreshold, opts.setFlags["epss-threshold"] = 0.35, true
			}
			if err := runScan(context.Background(), cveSaga(t, tc.threshold), opts, reg, &bytes.Buffer{}); err != nil &&
				!strings.Contains(err.Error(), "verdict") {
				t.Fatal(err)
			}
			page, err := os.ReadFile(filepath.Join(dir, report.Filename("html"))) // #nosec G304 -- the test's own temp dir
			if err != nil {
				t.Fatal(err)
			}
			want := "at or above <code>" + tc.want + "</code>, this run&#39;s threshold"
			if !strings.Contains(string(page), want) {
				t.Errorf("the EPSS row does not say %q", want)
			}
		})
	}
}
