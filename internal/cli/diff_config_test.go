package cli

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/config"
)

// threeFindings is a head report with three findings, so a cap of one shows.
func threeFindings() string {
	return `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Draugr","rules":[]}},"results":[` +
		`{"ruleId":"CVE-1","level":"error","message":{"text":"CVE-1 msg"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a"}}}],"properties":{"tool":"trivy","priority":"P1"}},` +
		`{"ruleId":"CVE-2","level":"error","message":{"text":"CVE-2 msg"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"b"}}}],"properties":{"tool":"trivy","priority":"P2"}},` +
		`{"ruleId":"CVE-3","level":"error","message":{"text":"CVE-3 msg"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"c"}}}],"properties":{"tool":"trivy","priority":"P3"}}` +
		`]}]}`
}

// diffCommandOutput runs `draugr diff` on head with args, from the working directory.
func diffCommandOutput(t *testing.T, head string, args ...string) string {
	t.Helper()
	var out bytes.Buffer
	cmd := newDiffCommand()
	cmd.SetArgs(append([]string{head}, args...))
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("diff: %v\n%s", err, out.String())
	}
	return out.String()
}

// runDiffOutput is what runDiff renders for head with these options, the answer the command must
// match once the configuration is folded in.
func runDiffOutput(t *testing.T, head string, opts diffOptions) string {
	t.Helper()
	opts.format = "console"
	var out bytes.Buffer
	if err := runDiff(context.Background(), "", head, opts, &out); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

// output.view and output.top set the defaults `diff` uses, by the precedence `scan` follows: the
// project file over the home file, --config alone in place of both, and a typed flag over all of
// them.
func TestDiffReadsOutputSettingsAsScanDoes(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv(config.EnvVar, "")
	project := t.TempDir()
	t.Chdir(project)
	head := writeFile(t, "head.sarif", threeFindings())

	compactAll := runDiffOutput(t, head, diffOptions{view: "compact"})
	compactOne := runDiffOutput(t, head, diffOptions{view: "compact", top: 1})
	actionsOne := runDiffOutput(t, head, diffOptions{view: "actions", top: 1})
	findingsOne := runDiffOutput(t, head, diffOptions{view: "findings", top: 1})
	findingsAll := runDiffOutput(t, head, diffOptions{})
	if compactAll == compactOne || compactOne == actionsOne || findingsOne == compactOne {
		t.Fatal("the fixtures do not tell the views and caps apart, so this test cannot say anything")
	}

	if got := diffCommandOutput(t, head); got != findingsAll {
		t.Errorf("with no configuration the defaults moved:\n%s", got)
	}

	writeConfigFile(t, filepath.Join(home, ".draugr", "config.yaml"), "output:\n  view: compact\n  top: 1\n")
	if got := diffCommandOutput(t, head); got != compactOne {
		t.Errorf("the home file's view and top were not applied:\n%s", got)
	}

	writeConfigFile(t, filepath.Join(project, config.FileName), "output:\n  view: actions\n")
	if got := diffCommandOutput(t, head); got != actionsOne {
		t.Errorf("the project file's view should win, keeping the home file's top:\n%s", got)
	}

	if got := diffCommandOutput(t, head, "--view", "findings"); got != findingsOne {
		t.Errorf("a typed --view should win over both files:\n%s", got)
	}
	// --top 0 typed asks for every row, over a configured cap.
	if got := diffCommandOutput(t, head, "--view", "compact", "--top", "0"); got != compactAll {
		t.Errorf("a typed --top 0 should show every row:\n%s", got)
	}

	explicit := filepath.Join(t.TempDir(), "ci.yaml")
	writeConfigFile(t, explicit, "output:\n  view: compact\n")
	withRootConfig(t, explicit)
	if got := diffCommandOutput(t, head); got != compactAll {
		t.Errorf("--config should be read alone, without the discovered files' top:\n%s", got)
	}
}

// `top: 0` in the file means the built-in default, which for diff is every row, as it is for scan's
// own default. output.evidence has nothing to set on a diff and changes nothing.
func TestDiffTopZeroAndEvidenceInTheFileChangeNothing(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv(config.EnvVar, "")
	t.Chdir(t.TempDir())
	head := writeFile(t, "head.sarif", threeFindings())
	explicit := filepath.Join(t.TempDir(), "ci.yaml")
	writeConfigFile(t, explicit, "output:\n  top: 0\n  evidence: true\n")
	withRootConfig(t, explicit)
	if got, want := diffCommandOutput(t, head), runDiffOutput(t, head, diffOptions{}); got != want {
		t.Errorf("top: 0 or evidence changed the diff:\n%s\nwant:\n%s", got, want)
	}
}

// A config file that does not load refuses the diff, as it refuses every command that reads it.
func TestDiffRefusesABrokenConfig(t *testing.T) {
	t.Chdir(t.TempDir())
	head := writeFile(t, "head.sarif", threeFindings())
	broken := filepath.Join(t.TempDir(), "broken.yaml")
	writeConfigFile(t, broken, "output:\n  view: veiw\n")
	withRootConfig(t, broken)
	cmd := newDiffCommand()
	cmd.SetArgs([]string{head})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "output.view") {
		t.Errorf("err = %v, want the bad view refused", err)
	}
}

// The rule scan applies is the one diff reads, field by field.
func TestUntypedOutputLeavesTypedFlagsAlone(t *testing.T) {
	yes := true
	cfg := config.OutputSettings{View: "compact", Evidence: &yes, Top: 5}
	if d := untypedOutput(cfg, nil); d.view != "compact" || d.evidence == nil || d.top != 5 {
		t.Errorf("nothing typed: %+v", d)
	}
	typed := map[string]bool{"view": true, "evidence": true, "top": true}
	if d := untypedOutput(cfg, typed); d != (configuredOutput{}) {
		t.Errorf("everything typed should leave nothing to set: %+v", d)
	}
}
