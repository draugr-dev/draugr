package ciguard

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/draugr-dev/draugr/internal/standin"
)

// stubScan stands in for the binary in the Action's scan step. It advertises the code-scanning report
// unless STUB_OLD is set, records the arguments of its scan in STUB_SCAN_ARGS, prints STUB_STDERR to
// stderr and exits STUB_EXIT, as the real one prints a failure and exits 1.
const stubScan = `#!/usr/bin/env bash
case "$1" in
  version) echo "draugr stub" ;;
  scan)
    if [ "$2" = "--help" ]; then
      [ -n "$STUB_OLD" ] || echo "  --report strings   formats to write into -o (code-scanning, console, json, sarif); default json,sarif"
      exit 0
    fi
    echo "${*:2}" > "$STUB_SCAN_ARGS"
    echo "FAIL  1 finding at or above P1"
    [ -z "$STUB_STDERR" ] || printf '%s\n' "$STUB_STDERR" >&2
    exit "${STUB_EXIT:-0}" ;;
esac
`

// actionStep is the run block of the Action's step with id, exactly as GitHub runs it.
func actionStep(t *testing.T, id string) string {
	t.Helper()
	raw, err := os.ReadFile("../../action.yml")
	if err != nil {
		t.Fatal(err)
	}
	var action struct {
		Runs struct {
			Steps []struct {
				ID  string `yaml:"id"`
				Run string `yaml:"run"`
			} `yaml:"steps"`
		} `yaml:"runs"`
	}
	if err := yaml.Unmarshal(raw, &action); err != nil {
		t.Fatal(err)
	}
	for _, s := range action.Runs.Steps {
		if s.ID == id {
			return s.Run
		}
	}
	t.Fatalf("action.yml has no step with id %s", id)
	return ""
}

// scanRun is what one run of the scan step left behind.
type scanRun struct {
	out, args, outputs string
	exit               int
}

// runActionScan runs the Action's scan step against the stub, with env added to its environment.
func runActionScan(t *testing.T, env ...string) scanRun {
	t.Helper()
	root := t.TempDir()
	bin := filepath.Join(root, "bin")
	if err := os.MkdirAll(bin, 0o750); err != nil {
		t.Fatal(err)
	}
	// #nosec G306 -- the stub has to be executable to stand in for the binary
	standin.Write(t, filepath.Join(bin, "draugr"), []byte(stubScan), 0o700)
	args, outputs := filepath.Join(root, "args"), filepath.Join(root, "github-output")
	// #nosec G204 -- the Action's own checked-in script, run as GitHub runs it
	cmd := exec.Command("bash", "-c", actionStep(t, "scan"))
	cmd.Dir = root
	cmd.Env = append(os.Environ(),
		"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"STUB_SCAN_ARGS="+args, "GITHUB_OUTPUT="+outputs, "GITHUB_TOKEN=t",
		"INPUT_SAGA=draugr.saga.yaml", "INPUT_OUTPUT=draugr-out", "OUTPUT_PATH=app/draugr-out",
		"INPUT_FAIL_ON=", "INPUT_FAIL_ON_PRIORITY=", "INPUT_MIN_PRIORITY=",
		"INPUT_CODE_SCANNING_MIN_PRIORITY=", "INPUT_CACHE_DIR=", "CACHE_READ_ONLY=", "INPUT_ARGS=")
	cmd.Env = append(cmd.Env, env...)
	b, err := cmd.CombinedOutput()
	run := scanRun{out: string(b)}
	var exit *exec.ExitError
	switch {
	case errors.As(err, &exit):
		run.exit = exit.ExitCode()
	case err != nil:
		t.Fatal(err)
	}
	a, _ := os.ReadFile(args)    // #nosec G304 -- written by the stub under t.TempDir()
	o, _ := os.ReadFile(outputs) // #nosec G304 -- written by the step under t.TempDir()
	run.args, run.outputs = string(a), string(o)
	return run
}

const refused = `publisher "github": github code scanning could not process the upload: unrecognized SARIF location URI scheme "python"`

// A publish that failed is an error annotation on the run, whatever else the step did. A workflow that
// lets the scan step continue on error shows a green job, and code scanning keeps the alerts of the
// last upload it accepted, so the log line alone is a failure nobody sees.
func TestTheActionAnnotatesAFailedPublish(t *testing.T) {
	for name, stderr := range map[string]string{
		"with the gate":  "draugr: gate failed: 1 finding at or above P1 (publishing also failed: " + refused + ")",
		"alone":          "draugr: " + refused,
		"two publishers": "draugr: " + refused + "\npublisher \"draugr-api\": 401 Unauthorized",
	} {
		t.Run(name, func(t *testing.T) {
			run := runActionScan(t, "STUB_STDERR="+stderr, "STUB_EXIT=1")
			if run.exit != 1 {
				t.Errorf("exit = %d, want the scan's 1", run.exit)
			}
			if !strings.Contains(run.out, `::error title=Draugr could not publish::`+refused) {
				t.Errorf("no annotation naming the publisher and why:\n%s", run.out)
			}
			if name == "two publishers" && !strings.Contains(run.out, `::error title=Draugr could not publish::publisher "draugr-api": 401 Unauthorized`) {
				t.Errorf("the second publisher is not annotated:\n%s", run.out)
			}
			// The scan's own output still reaches the log.
			if !strings.Contains(run.out, "FAIL  1 finding") || !strings.Contains(run.out, stderr[:20]) {
				t.Errorf("the scan's output is missing:\n%s", run.out)
			}
		})
	}
}

// Only a publisher is annotated: a gate that trips is the step's outcome, and the step exits with the
// scan's own status whichever it was.
func TestTheActionKeepsTheScansExitAndAnnotatesNoGate(t *testing.T) {
	run := runActionScan(t, "STUB_STDERR=draugr: gate failed: 1 finding at or above P1", "STUB_EXIT=3")
	if run.exit != 3 {
		t.Errorf("exit = %d, want the scan's 3", run.exit)
	}
	if strings.Contains(run.out, "::error") {
		t.Errorf("a gate failure was annotated as a publish failure:\n%s", run.out)
	}
	if ok := runActionScan(t); ok.exit != 0 || strings.Contains(ok.out, "::error") {
		t.Errorf("a clean scan: exit %d\n%s", ok.exit, ok.out)
	}
}

// An annotation's message is a workflow command, where % starts an escape.
func TestTheActionEscapesThePublishFailure(t *testing.T) {
	run := runActionScan(t, `STUB_STDERR=draugr: publisher "file": 100% full`, "STUB_EXIT=1")
	if !strings.Contains(run.out, `::error title=Draugr could not publish::publisher "file": 100%25 full`) {
		t.Errorf("the message is not escaped:\n%s", run.out)
	}
}

// The `sarif` output on a push is code-scanning.sarif, which code scanning accepts, where the release
// writes it; a release that predates it, or an `args` naming the reports, keeps results.sarif.
func TestTheActionUploadsTheCodeScanningReport(t *testing.T) {
	run := runActionScan(t)
	if !strings.Contains(run.args, "--report json,sarif,code-scanning") {
		t.Errorf("the scan was not asked for the code-scanning report: %s", run.args)
	}
	if !strings.Contains(run.outputs, "sarif=app/draugr-out/code-scanning.sarif\n") {
		t.Errorf("outputs = %q, want sarif naming code-scanning.sarif under the working directory", run.outputs)
	}
	// Written before the scan, so a gate that fails the step leaves it set for an always() upload.
	if failed := runActionScan(t, "STUB_EXIT=1"); !strings.Contains(failed.outputs, "code-scanning.sarif") {
		t.Errorf("a failed scan left outputs = %q", failed.outputs)
	}

	for name, env := range map[string]string{
		"an older release":     "STUB_OLD=1",
		"args naming a report": "INPUT_ARGS=--report html,sarif",
	} {
		run := runActionScan(t, env)
		if strings.Contains(run.args, "code-scanning") || strings.Contains(run.outputs, "sarif=") {
			t.Errorf("%s: args %q, outputs %q; want neither touched", name, run.args, run.outputs)
		}
	}
}

// A pull request whose workflow sets code-scanning: all uploads the complete scan, as
// code-scanning.sarif; with code-scanning: new it uploads the diff's new findings, and only that.
func TestTheActionDiffUploadsTheCodeScanningReportForAll(t *testing.T) {
	for _, tc := range []struct{ setting, want, not string }{
		{"all", "/code-scanning.sarif\n", "results-new.sarif"},
		{"new", "/results-new.sarif\n", "code-scanning.sarif"},
	} {
		t.Run(tc.setting, func(t *testing.T) {
			r := newDiffRepo(t)
			base := r.commit([]string{"draugr.saga.yaml"})
			r.commit([]string{"draugr.saga.yaml", "main.go"})
			args := filepath.Join(r.root, "scan-args")
			_, _, ok := r.run(base, "INPUT_FAIL_ON_NEW=", "INPUT_CODE_SCANNING="+tc.setting, "STUB_SCAN_ARGS="+args)
			if !ok {
				t.Fatal("the diff step failed")
			}
			outputs, _ := os.ReadFile(filepath.Join(r.root, "github-output")) // #nosec G304 -- written by the step under t.TempDir()
			if strings.Count(string(outputs), "sarif=") != 1 || !strings.Contains(string(outputs), tc.want) || strings.Contains(string(outputs), tc.not) {
				t.Errorf("outputs = %q, want one sarif ending %q", outputs, tc.want)
			}
			scans, _ := os.ReadFile(args) // #nosec G304 -- written by the stub under t.TempDir()
			head, _, _ := strings.Cut(string(scans), "\n")
			if !strings.Contains(head, "--report json,sarif,code-scanning") {
				t.Errorf("the head scan was asked for %q, want the code-scanning report beside results.sarif", head)
			}
		})
	}
}
