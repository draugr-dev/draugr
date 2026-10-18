package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/builtins"
	"github.com/draugr-dev/draugr/internal/netpolicy"
	"github.com/draugr-dev/draugr/internal/tools"
	"github.com/draugr-dev/draugr/pkg/config"
	"github.com/draugr-dev/draugr/pkg/engine"
)

// notInstalled is a PATH on which the named tools are missing and everything else is found.
func notInstalled(missing ...string) func(string) (string, error) {
	return func(name string) (string, error) {
		for _, m := range missing {
			if m == name {
				return "", errors.New("not found")
			}
		}
		return "/usr/bin/" + name, nil
	}
}

// The zero-config scan's controls, with trivy and semgrep missing: each tool once, with every
// control it would leave unrun, and nothing for a tool that is present.
func TestMissingForScanNamesEachToolWithTheControlsItBlocks(t *testing.T) {
	model := syntheticSaga(t.TempDir())
	got := missingForScan(builtins.Registry(), model, engine.Scope{}, notInstalled("trivy", "semgrep"))
	want := []missingScanner{{tool: "semgrep", controls: []string{"sast"}}, {tool: "trivy", controls: []string{"iac", "sca"}}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("missingForScan = %+v, want %+v", got, want)
	}
	scoped := missingForScan(builtins.Registry(), model, engine.Scope{Controls: []string{"iac"}}, notInstalled("trivy", "semgrep"))
	if want := []missingScanner{{tool: "trivy", controls: []string{"iac"}}}; !reflect.DeepEqual(scoped, want) {
		t.Errorf("with --controls iac: %+v, want %+v", scoped, want)
	}
	if got := missingForScan(builtins.Registry(), model, engine.Scope{}, notInstalled()); len(got) != 0 {
		t.Errorf("offered tools that are installed: %+v", got)
	}
}

// offerWith is an offer at a terminal, answering with the given line.
func offerWith(answer string, missing ...string) (installOffer, *bytes.Buffer, *[]string) {
	var out bytes.Buffer
	var installed []string
	return installOffer{
		in: strings.NewReader(answer), out: &out,
		terminal: func() bool { return true },
		lookPath: notInstalled(missing...),
		install: func(_ context.Context, name, version string) (tools.Installed, error) {
			installed = append(installed, name+"@"+version)
			if name == "broken" {
				return tools.Installed{}, errors.New("download failed")
			}
			return tools.Installed{Name: name, Version: "1.0.0", Path: "/home/you/.draugr/bin/" + name}, nil
		},
		remember: func() (string, string, error) {
			return "/home/you/.draugr/config.yaml", "`draugr config unset --global output.offerInstall`", nil
		},
	}, &out, &installed
}

func runOffer(o installOffer, cfg config.File, scope engine.Scope) {
	o.run(context.Background(), builtins.Registry(), syntheticSaga(os.TempDir()), scope, cfg)
}

func TestTheOfferNamesWhatIsMissingAndInstallsItOnYes(t *testing.T) {
	cfg := config.File{Tools: map[string]config.ToolSettings{"trivy": {Version: "0.69.3"}}}
	for _, yes := range []string{"\n", "y\n", "YES\n"} {
		o, out, installed := offerWith(yes, "trivy", "semgrep")
		runOffer(o, cfg, engine.Scope{})
		for _, want := range []string{
			"semgrep and trivy are not installed, so iac, sast and sca would not run.\n",
			"Install them now with draugr tools install semgrep trivy? [Y/n/never] ",
			"✓ semgrep 1.0.0 → /home/you/.draugr/bin/semgrep",
		} {
			if !strings.Contains(out.String(), want) {
				t.Errorf("answer %q: missing %q in:\n%s", yes, want, out)
			}
		}
		// In name order, and at the version draugr.config.yaml pins, as `tools install` would.
		if want := []string{"semgrep@", "trivy@0.69.3"}; !reflect.DeepEqual(*installed, want) {
			t.Errorf("answer %q: installed %v, want %v", yes, *installed, want)
		}
	}
}

func TestTheOfferForOneToolIsWorded(t *testing.T) {
	o, out, _ := offerWith("n\n", "trivy")
	runOffer(o, config.File{}, engine.Scope{Controls: []string{"iac"}})
	for _, want := range []string{"trivy is not installed, so iac would not run.", "Install it now with draugr tools install trivy?"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestNoAndAnythingElseInstallNothing(t *testing.T) {
	for _, no := range []string{"n\n", "no\n", "maybe\n", ""} {
		o, out, installed := offerWith(no, "trivy")
		runOffer(o, config.File{}, engine.Scope{})
		if len(*installed) != 0 {
			t.Errorf("answer %q installed %v", no, *installed)
		}
		if strings.Contains(out.String(), "Wrote") {
			t.Errorf("answer %q recorded a preference:\n%s", no, out)
		}
	}
}

func TestNeverIsRememberedAndSaysHowToUndoIt(t *testing.T) {
	o, out, installed := offerWith("never\n", "trivy")
	runOffer(o, config.File{}, engine.Scope{})
	if len(*installed) != 0 {
		t.Errorf("never installed %v", *installed)
	}
	want := "Wrote output.offerInstall: false to /home/you/.draugr/config.yaml. " +
		"`draugr config unset --global output.offerInstall` asks again."
	if !strings.Contains(out.String(), want) {
		t.Errorf("missing %q in:\n%s", want, out)
	}

	o, out, _ = offerWith("never\n", "trivy")
	o.remember = func() (string, string, error) { return "", "", errors.New("read-only file system") }
	runOffer(o, config.File{}, engine.Scope{})
	if !strings.Contains(out.String(), "could not write output.offerInstall: false: read-only file system. The scan continues.") {
		t.Errorf("a failed write went unreported:\n%s", out)
	}
}

// A failed install is reported and the rest still install; the scan then says what could not run.
func TestAFailedInstallIsReportedAndTheRestContinue(t *testing.T) {
	o, out, _ := offerWith("y\n", "trivy")
	o.install = func(context.Context, string, string) (tools.Installed, error) {
		return tools.Installed{}, errors.New("download failed")
	}
	runOffer(o, config.File{}, engine.Scope{})
	if !strings.Contains(out.String(), "✗ trivy: download failed") {
		t.Errorf("failure not reported:\n%s", out)
	}
}

// No person, no question: a pipeline, an assistant, --offline, a declined offer, or nothing
// missing all scan as before, without a word.
func TestTheOfferIsMadeOnlyWhenItCanBeAnswered(t *testing.T) {
	no := false
	cases := map[string]func(*installOffer, *config.File){
		"not a terminal":     func(o *installOffer, _ *config.File) { o.terminal = func() bool { return false } },
		"declined in config": func(_ *installOffer, c *config.File) { c.Output.OfferInstall = &no },
		"nothing missing":    func(o *installOffer, _ *config.File) { o.lookPath = notInstalled() },
		"offline":            func(_ *installOffer, _ *config.File) { netpolicy.SetOffline(true) },
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			t.Cleanup(func() { netpolicy.SetOffline(false) })
			o, out, installed := offerWith("y\n", "trivy")
			cfg := config.File{}
			setup(&o, &cfg)
			runOffer(o, cfg, engine.Scope{})
			if out.Len() != 0 || len(*installed) != 0 {
				t.Errorf("offered anyway: %q, installed %v", out, *installed)
			}
		})
	}
}

// "never" goes where the next scan reads it: ~/.draugr/config.yaml, or the file --config names.
// Never the project's draugr.config.yaml, which is committed.
func TestNeverIsWrittenWhereTheNextScanReadsIt(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv(config.EnvVar, "")
	project := t.TempDir()
	t.Chdir(project)

	path, undo, err := rememberNoInstallOffer()
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(home, ".draugr", "config.yaml"); path != want || !strings.Contains(undo, "--global") {
		t.Errorf("wrote %s (undo %s), want %s", path, undo, want)
	}
	res, err := config.Load("", project)
	if err != nil {
		t.Fatal(err)
	}
	if res.File.Output.Offers() {
		t.Error("the next scan would still offer")
	}
	if _, err := os.Stat(filepath.Join(project, config.FileName)); err == nil {
		t.Error("wrote the project's committed config")
	}

	explicit := filepath.Join(t.TempDir(), "ci.yaml")
	withRootConfig(t, explicit)
	path, undo, err = rememberNoInstallOffer()
	if err != nil {
		t.Fatal(err)
	}
	if path != explicit || undo != "`draugr config unset --config "+explicit+" output.offerInstall`" {
		t.Errorf("with --config: wrote %s (undo %s), want %s", path, undo, explicit)
	}
}

// withRootConfig sets --config for one test.
func withRootConfig(t *testing.T, path string) {
	t.Helper()
	old := rootConfigPath
	rootConfigPath = path
	t.Cleanup(func() { rootConfigPath = old })
}
