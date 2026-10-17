package cli

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// uninstallHome lays down a Draugr install of trivy and retire under a scratch home, with a Trivy
// cache, and returns the bin directory.
func uninstallHome(t *testing.T) (home, bin string) {
	t.Helper()
	home = t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CACHE_HOME", filepath.Join(home, ".cache"))
	t.Setenv("TRIVY_CACHE_DIR", "")
	bin = filepath.Join(home, ".draugr", "bin")
	files := map[string]string{
		filepath.Join(bin, "trivy"):                                     strings.Repeat("t", 2048),
		filepath.Join(bin, "retire"):                                    "#!/bin/sh",
		filepath.Join(home, ".draugr", "node", "retire", "index.js"):    "node",
		filepath.Join(home, ".draugr", "data", "retirejs", "repo.json"): "{}",
		filepath.Join(home, ".cache", "trivy", "db", "trivy.db"):        strings.Repeat("d", 3*1024*1024),
		filepath.Join(bin, ".draugr-tools.json"):                        `{"trivy":{"version":"0.74.0"},"retire":{"version":"5.7.0"}}`,
	}
	for path, body := range files {
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	orig := uninstallLookPath
	uninstallLookPath = func(name string) (string, error) {
		if name == "kubectl" {
			return "/usr/local/bin/kubectl", nil
		}
		return "", errors.New("not found")
	}
	t.Cleanup(func() { uninstallLookPath = orig })
	return home, bin
}

func forceTTY(t *testing.T, tty bool) {
	t.Helper()
	orig := isTTY
	isTTY = func(io.Reader) bool { return tty }
	t.Cleanup(func() { isTTY = orig })
}

func TestToolsUninstallAllPrintsThePlanAndRemovesEveryTool(t *testing.T) {
	home, bin := uninstallHome(t)
	forceTTY(t, false)
	var out bytes.Buffer
	if err := runToolsUninstall(&out, strings.NewReader(""), bin, nil, toolsUninstallOptions{all: true}); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	for _, want := range []string{
		"PLAN\n",
		"Tool    Version  Size  Also removes",
		"retire  5.7.0    15B   node env, data 2B",
		"trivy   0.74.0   2.0K",
		"2 tools to remove from " + filepath.Join(home, ".draugr") + ", 2.0K.",
		"The tools' own caches stay (trivy 3.0M). `--caches` removes them too.",
		"✓ retire 5.7.0 removed\n✓ trivy 0.74.0 removed\n",
		"\n2.0K freed.\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	for _, gone := range []string{filepath.Join(bin, "trivy"), filepath.Join(home, ".draugr", "node", "retire")} {
		if _, err := os.Stat(gone); err == nil {
			t.Errorf("%s is still there", gone)
		}
	}
	if _, err := os.Stat(filepath.Join(home, ".cache", "trivy")); err != nil {
		t.Error("the Trivy cache went without --caches")
	}
}

func TestToolsUninstallWithCachesCountsThemInWhatItFrees(t *testing.T) {
	home, bin := uninstallHome(t)
	forceTTY(t, false)
	var out bytes.Buffer
	if err := runToolsUninstall(&out, strings.NewReader(""), bin, []string{"trivy"}, toolsUninstallOptions{caches: true}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"The tools' own caches go too (trivy 3.0M).", "3.0M freed."} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in:\n%s", want, out.String())
		}
	}
	if _, err := os.Stat(filepath.Join(home, ".cache", "trivy")); err == nil {
		t.Error("the Trivy cache stayed with --caches")
	}
	if _, err := os.Stat(filepath.Join(bin, "retire")); err != nil {
		t.Error("removing trivy took retire with it")
	}
}

func TestToolsUninstallDryRunRemovesNothing(t *testing.T) {
	_, bin := uninstallHome(t)
	var out bytes.Buffer
	if err := runToolsUninstall(&out, strings.NewReader(""), bin, []string{"trivy"}, toolsUninstallOptions{dryRun: true}); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(out.String(), "\n(dry run, nothing removed)\n") {
		t.Errorf("no dry-run line:\n%s", out.String())
	}
	if _, err := os.Stat(filepath.Join(bin, "trivy")); err != nil {
		t.Error("a dry run removed trivy")
	}
}

func TestToolsUninstallAsksBeforeRemoving(t *testing.T) {
	_, bin := uninstallHome(t)
	forceTTY(t, true)

	var out bytes.Buffer
	if err := runToolsUninstall(&out, strings.NewReader("n\n"), bin, []string{"trivy"}, toolsUninstallOptions{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Proceed? [y/N] Aborted.") {
		t.Errorf("no prompt and abort:\n%s", out.String())
	}
	if _, err := os.Stat(filepath.Join(bin, "trivy")); err != nil {
		t.Fatal("removed trivy after a no")
	}

	out.Reset()
	if err := runToolsUninstall(&out, strings.NewReader("y\n"), bin, []string{"trivy"}, toolsUninstallOptions{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Proceed? [y/N] ✓ trivy 0.74.0 removed") {
		t.Errorf("no removal after a yes:\n%s", out.String())
	}
}

func TestToolsUninstallNamesACopyDraugrDidNotInstall(t *testing.T) {
	_, bin := uninstallHome(t)
	forceTTY(t, false)
	var out bytes.Buffer
	err := runToolsUninstall(&out, strings.NewReader(""), bin, []string{"kubectl", "trivy", "grype"}, toolsUninstallOptions{})
	if err == nil || err.Error() != "2 tools not removed" {
		t.Errorf("error = %v, want 2 tools not removed", err)
	}
	for _, want := range []string{
		"✗ kubectl: not installed by Draugr (found at /usr/local/bin/kubectl). Remove it the way it was installed.\n",
		"✗ grype: not installed by Draugr.\n",
		"✓ trivy 0.74.0 removed",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in:\n%s", want, out.String())
		}
	}

	out.Reset()
	if err := runToolsUninstall(&out, strings.NewReader(""), bin, []string{"kubectl"}, toolsUninstallOptions{}); err == nil {
		t.Error("no error when nothing named could be removed")
	}
	if strings.Contains(out.String(), "PLAN") {
		t.Errorf("printed a plan with nothing in it:\n%s", out.String())
	}
}

func TestToolsUninstallRefusesBadSelections(t *testing.T) {
	_, bin := uninstallHome(t)
	cases := map[string]struct {
		args []string
		opts toolsUninstallOptions
		want string
	}{
		"both":    {[]string{"trivy"}, toolsUninstallOptions{all: true}, "--all and an explicit tool list"},
		"neither": {nil, toolsUninstallOptions{}, "name the tools to remove, or pass --all"},
		"typo":    {[]string{"trivvy"}, toolsUninstallOptions{}, `cannot uninstall "trivvy", which is not a tool Draugr knows; did you mean "trivy"?`},
		"unknown": {[]string{"zzzzzz", "yyyyyy"}, toolsUninstallOptions{}, `cannot uninstall "zzzzzz", "yyyyyy", which is not a tool Draugr knows`},
	}
	for name, c := range cases {
		err := runToolsUninstall(io.Discard, strings.NewReader(""), bin, c.args, c.opts)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error = %v, want %q", name, err, c.want)
		}
	}
}

func TestToolsUninstallAllWithNothingInstalled(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	bin := filepath.Join(home, ".draugr", "bin")
	var out bytes.Buffer
	if err := runToolsUninstall(&out, strings.NewReader(""), bin, nil, toolsUninstallOptions{all: true}); err != nil {
		t.Fatal(err)
	}
	if want := "Nothing to uninstall: Draugr has installed no tools in " + bin + ".\n"; out.String() != want {
		t.Errorf("got %q, want %q", out.String(), want)
	}
}

func TestToolsUninstallReportsAToolItCouldNotRemove(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("needs a directory this user cannot write")
	}
	home, bin := uninstallHome(t)
	forceTTY(t, false)
	node := filepath.Join(home, ".draugr", "node")
	// #nosec G302 -- a directory this test makes unwritable, to see a removal fail
	if err := os.Chmod(node, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(node, 0o750) }) // #nosec G302 -- restores it so t.TempDir can clean up

	var out bytes.Buffer
	err := runToolsUninstall(&out, strings.NewReader(""), bin, nil, toolsUninstallOptions{all: true})
	if err == nil || err.Error() != "1 tool not removed" {
		t.Errorf("error = %v, want 1 tool not removed", err)
	}
	if !strings.Contains(out.String(), "✗ retire: remove ") || !strings.Contains(out.String(), "✓ trivy 0.74.0 removed") {
		t.Errorf("output:\n%s", out.String())
	}
}

func TestHumanSize(t *testing.T) {
	for n, want := range map[int64]string{
		0: "0B", 1023: "1023B", 1024: "1.0K", 96 * 1024: "96K", 4_500_000: "4.3M",
		141_178_250: "135M", 1_288_490_189: "1.2G", 3 << 40: "3.0T",
	} {
		if got := humanSize(n); got != want {
			t.Errorf("humanSize(%d) = %q, want %q", n, got, want)
		}
	}
}

func TestToolsUninstallIsRegistered(t *testing.T) {
	cmd := newToolsCommand()
	sub, _, err := cmd.Find([]string{"uninstall"})
	if err != nil || sub.Name() != "uninstall" {
		t.Fatalf("tools uninstall is not registered: %v", err)
	}
	for _, flag := range []string{"all", "caches", "dry-run", "yes"} {
		if sub.Flags().Lookup(flag) == nil {
			t.Errorf("no --%s", flag)
		}
	}
}
