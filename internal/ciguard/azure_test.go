package ciguard

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/draugr-dev/draugr/internal/standin"
)

const azureTemplate = "../../azure-pipelines/draugr.yml"

// azureSteps returns the template's steps by display name, with those under a `${{ if }}` block
// read as the steps they become when the block holds.
func azureSteps(t *testing.T) map[string]map[string]any {
	t.Helper()
	raw, err := os.ReadFile(azureTemplate)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Steps []map[string]any `yaml:"steps"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("Azure would refuse this file: %v", err)
	}
	steps := map[string]map[string]any{}
	var walk func(items []any)
	walk = func(items []any) {
		for _, item := range items {
			step, ok := item.(map[string]any)
			if !ok {
				continue
			}
			if name, ok := step["displayName"].(string); ok {
				steps[name] = step
				continue
			}
			for key, inner := range step {
				if list, ok := inner.([]any); ok && strings.HasPrefix(key, "${{") {
					walk(list)
				}
			}
		}
	}
	items := make([]any, len(doc.Steps))
	for i, s := range doc.Steps {
		items[i] = s
	}
	walk(items)
	return steps
}

// azureScript is the named step's script, as the agent hands it to bash: the descriptor parameter
// expanded and each `$(Variable)` macro replaced from vars. A macro vars does not name fails the
// test, rather than reaching bash as a command substitution.
func azureScript(t *testing.T, name string, vars map[string]string) string {
	t.Helper()
	step, ok := azureSteps(t)[name]
	if !ok {
		t.Fatalf("the template has no step named %q", name)
	}
	script, ok := step["script"].(string)
	if !ok {
		t.Fatalf("the %q step runs no script", name)
	}
	script = regexp.MustCompile(`\$\{\{\s*parameters\.saga\s*\}\}`).ReplaceAllString(script, "draugr.saga.yaml")
	return regexp.MustCompile(`\$\(([A-Za-z]+(?:\.[A-Za-z]+)+)\)`).ReplaceAllStringFunc(script, func(m string) string {
		v, ok := vars[m[2:len(m)-1]]
		if !ok {
			t.Fatalf("the %q step reads %s, which this test does not provide", name, m)
		}
		return v
	})
}

// A pull request's code has not merged, so the Scan step publishes nothing on its build: a server
// would keep the run beside the default branch's, an issue publisher could act on it, and a comment
// publisher would post beside the diff's comment. It still writes the reports the Tests tab and the
// artifact read. A push build publishes as before.
func TestTheAzureScanPublishesOnlyFromAPushBuild(t *testing.T) {
	t.Parallel()
	for reason, wantPublish := range map[string]bool{
		"PullRequest":  false,
		"IndividualCI": true,
		"BatchedCI":    true,
		"Manual":       true,
		"Schedule":     true,
	} {
		t.Run(reason, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			bin, out, log := filepath.Join(root, "bin"), filepath.Join(root, "staging"), filepath.Join(root, "scans.log")
			if err := os.MkdirAll(bin, 0o750); err != nil {
				t.Fatal(err)
			}
			stub := "#!/usr/bin/env bash\necho \"$*\" >> \"$STUB_LOG\"\n"
			// #nosec G306 -- the stub has to be executable to stand in for the binary
			standin.Write(t, filepath.Join(bin, "draugr"), []byte(stub), 0o700)
			script := azureScript(t, "Scan", map[string]string{"Build.ArtifactStagingDirectory": out})
			// #nosec G204 -- the template's own checked-in script, run as the agent runs it
			cmd := exec.Command("bash", "-c", script)
			cmd.Dir = root
			cmd.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
				"STUB_LOG="+log, "BUILD_REASON="+reason)
			if b, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("the Scan step failed: %v\n%s", err, b)
			}
			b, err := os.ReadFile(log) // #nosec G304 -- written by the stub under t.TempDir()
			if err != nil {
				t.Fatalf("the Scan step never ran draugr: %v", err)
			}
			scan := strings.TrimSpace(string(b))
			if !strings.HasPrefix(scan, "scan draugr.saga.yaml") || strings.Count(scan, "\n") != 0 {
				t.Fatalf("want one scan of the descriptor, got:\n%s", scan)
			}
			for _, want := range []string{"--report junit,sarif,html", "-o " + out} {
				if !strings.Contains(scan, want) {
					t.Errorf("the scan does not write its reports, no %q in: %s", want, scan)
				}
			}
			if published := !strings.Contains(scan, "--no-publish"); published != wantPublish {
				t.Errorf("a %s build publishes = %v, want %v: %s", reason, published, wantPublish, scan)
			}
		})
	}
}

// The gate step runs only on a pull request, so both of its scans leave the publishing to the diff,
// which posts the one comment. A scan without --no-publish there runs every publisher in the
// descriptor on the base branch and on the unmerged head.
func TestTheAzureGateScansPublishNothing(t *testing.T) {
	t.Parallel()
	step, ok := azureSteps(t)["Gate on new findings"]
	if !ok {
		t.Fatal("the template has no Gate on new findings step")
	}
	if cond, _ := step["condition"].(string); !strings.Contains(cond, "'PullRequest'") {
		t.Fatalf("the gate step no longer runs only on a pull request (condition %q), so this test checks the wrong thing", cond)
	}
	script, _ := step["script"].(string)
	scans := 0
	for i, line := range strings.Split(script, "\n") {
		code := strings.TrimSpace(line)
		if strings.HasPrefix(code, "#") || !strings.Contains(code, "draugr scan ") {
			continue
		}
		scans++
		if !strings.Contains(code, "--no-publish") {
			t.Errorf("gate step line %d scans without --no-publish: %s", i+1, code)
		}
	}
	if scans != 2 {
		t.Errorf("want the base and the head scan in the gate step, found %d", scans)
	}
}
