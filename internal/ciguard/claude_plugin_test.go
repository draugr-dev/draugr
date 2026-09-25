package ciguard

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const (
	pluginDir       = "../../contrib/claude-plugin"
	pluginManifest  = pluginDir + "/.claude-plugin/plugin.json"
	marketplaceFile = "../../.claude-plugin/marketplace.json"
	pluginHook      = pluginDir + "/scripts/check-draugr.sh"

	// installCommand is the install line the README documents. The hook prints it, so the two
	// are checked against each other rather than trusted to agree.
	installCommand = "curl -fsSL https://draugr.dev/install.sh | sh"
)

type pluginJSON struct {
	Name       string `json:"name"`
	Version    string `json:"version"`
	MCPServers map[string]struct {
		Command string   `json:"command"`
		Args    []string `json:"args"`
	} `json:"mcpServers"`
}

func readJSON(t *testing.T, path string, v any) {
	t.Helper()
	raw, err := os.ReadFile(path) // #nosec G304 -- a fixed path inside this repository
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if err := json.Unmarshal(raw, v); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
}

// TestThePluginVersionIsTheLatestRelease keeps installed plugins moving with the releases.
//
// Claude Code gives a user a new copy of the plugin only when the version in plugin.json changes.
// A version left behind is a plugin that silently stops updating, and nothing about it looks
// wrong: it validates, it installs, and it serves whatever binary the user already has.
func TestThePluginVersionIsTheLatestRelease(t *testing.T) {
	t.Parallel()
	var p pluginJSON
	readJSON(t, pluginManifest, &p)

	changelog, err := os.ReadFile("../../CHANGELOG.md")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^## \[(\d+\.\d+\.\d+)\]`).FindSubmatch(changelog)
	if m == nil {
		t.Fatal("CHANGELOG.md has no released section")
	}
	if want := string(m[1]); p.Version != want {
		t.Errorf("plugin.json says version %q and the latest release is %q; "+
			"scripts/set-plugin-version.sh %s sets it", p.Version, want, want)
	}
}

// TestTheMarketplaceListsThePlugin keeps `/plugin install draugr@draugr` resolving.
//
// The install id is the entry name and the marketplace name, and a manifest name that differs from
// the entry name fails the install with "not found in marketplace". A version on the entry is a
// second copy that Claude Code ignores whenever plugin.json has one, so it is refused outright.
func TestTheMarketplaceListsThePlugin(t *testing.T) {
	t.Parallel()
	var market struct {
		Name    string `json:"name"`
		Plugins []struct {
			Name    string  `json:"name"`
			Source  string  `json:"source"`
			Version *string `json:"version"`
		} `json:"plugins"`
	}
	readJSON(t, marketplaceFile, &market)
	var p pluginJSON
	readJSON(t, pluginManifest, &p)

	if market.Name != "draugr" {
		t.Errorf("marketplace name is %q; the documented install is draugr@draugr", market.Name)
	}
	if len(market.Plugins) != 1 {
		t.Fatalf("marketplace lists %d plugins, want the one in contrib/claude-plugin", len(market.Plugins))
	}
	entry := market.Plugins[0]
	if entry.Name != p.Name || entry.Name != "draugr" {
		t.Errorf("entry name %q and plugin.json name %q must both be draugr", entry.Name, p.Name)
	}
	if entry.Source != "./contrib/claude-plugin" {
		t.Errorf("entry source is %q, want ./contrib/claude-plugin", entry.Source)
	}
	if entry.Version != nil {
		t.Error("the marketplace entry sets a version; plugin.json carries it, and a second copy is ignored until it disagrees")
	}
}

// TestThePluginRunsTheServerWithItsOwnDefaults keeps the consent decision in one place.
//
// Which scans an assistant may start is decided by `draugr mcp` and documented with it. A `--scan`
// argument written into the plugin would make that decision for everyone who installs it, and
// differently from what the documentation for the server says.
func TestThePluginRunsTheServerWithItsOwnDefaults(t *testing.T) {
	t.Parallel()
	var p pluginJSON
	readJSON(t, pluginManifest, &p)

	server, ok := p.MCPServers["draugr"]
	if !ok || len(p.MCPServers) != 1 {
		t.Fatalf("plugin.json must declare exactly one MCP server, draugr; got %d", len(p.MCPServers))
	}
	if server.Command != "draugr" || !slices.Equal(server.Args, []string{"mcp"}) {
		t.Errorf("the server runs %q %q, want draugr [mcp]", server.Command, server.Args)
	}
}

// TestReleasePrepareSetsThePluginVersion keeps the version bump inside the release pull request.
//
// The bump has to land in the commit the tag is cut from. Anywhere after the tag cannot reach
// main without a second pull request, and anywhere before the promotion does not know the version.
func TestReleasePrepareSetsThePluginVersion(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("../../.github/workflows/release-prepare.yml")
	if err != nil {
		t.Fatal(err)
	}
	var wf struct {
		Jobs map[string]struct {
			Steps []struct {
				Run string `yaml:"run"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(raw, &wf); err != nil {
		t.Fatal(err)
	}
	for _, step := range wf.Jobs["prepare"].Steps {
		promote := strings.Index(step.Run, `changelog.sh promote "$VERSION"`)
		if promote < 0 {
			continue
		}
		bump := strings.Index(step.Run, `set-plugin-version.sh "$VERSION"`)
		commit := strings.Index(step.Run, "git commit -am")
		if bump < promote || commit < bump {
			t.Error("the step that promotes the CHANGELOG must run set-plugin-version.sh after the " +
				"promotion and before the commit, so the release pull request carries both")
		}
		return
	}
	t.Fatal("no step in release-prepare.yml promotes the CHANGELOG")
}

// TestSetPluginVersionChangesOnlyTheVersion keeps the release diff to one line.
func TestSetPluginVersionChangesOnlyTheVersion(t *testing.T) {
	t.Parallel()
	original, err := os.ReadFile(pluginManifest)
	if err != nil {
		t.Fatal(err)
	}
	var p pluginJSON
	readJSON(t, pluginManifest, &p)

	path := filepath.Join(t.TempDir(), "plugin.json")
	if err := os.WriteFile(path, original, 0o600); err != nil { // #nosec G703 -- this test's temp file
		t.Fatal(err)
	}
	run := func(version string) ([]byte, error) {
		cmd := exec.Command("../../scripts/set-plugin-version.sh", version, path) // #nosec G204 -- arguments are this test's
		return cmd.CombinedOutput()
	}

	// Rewriting the current version must reproduce the committed file byte for byte, or every
	// release rewrites the whole manifest and the one line that matters is lost in the diff.
	if out, err := run(p.Version); err != nil {
		t.Fatalf("set-plugin-version.sh %s: %v\n%s", p.Version, err, out)
	}
	if got, _ := os.ReadFile(path); !bytes.Equal(got, original) { // #nosec G304 -- this test's temp file
		t.Errorf("rewriting the same version changed the file's formatting:\n%s", got)
	}

	if out, err := run("v9.8.7"); err != nil {
		t.Fatalf("set-plugin-version.sh v9.8.7: %v\n%s", err, out)
	}
	got, _ := os.ReadFile(path) // #nosec G304 -- this test's temp file
	want := strings.Replace(string(original), `"version": "`+p.Version+`"`, `"version": "9.8.7"`, 1)
	if string(got) != want {
		t.Errorf("set-plugin-version.sh changed more than the version:\n%s", got)
	}

	if out, err := run("9.8"); err == nil {
		t.Errorf("set-plugin-version.sh accepted 9.8, which is not X.Y.Z:\n%s", out)
	}
}

// runHook runs the SessionStart hook the way Claude Code does, with PATH set to dir alone.
func runHook(t *testing.T, dir string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the hook is a POSIX shell script")
	}
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Fatalf("sh is not on PATH: %v", err)
	}
	cmd := exec.Command(sh, pluginHook) // #nosec G204 -- a fixed script in this repository
	cmd.Env = []string{"PATH=" + dir}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("hook exited with %v; a SessionStart hook that fails shows an error notice instead of its message\n%s",
			err, stderr.String())
	}
	if stderr.Len() > 0 {
		t.Errorf("hook wrote to stderr: %s", stderr.String())
	}
	return string(out)
}

// TestTheHookNamesTheInstallCommandWhenDraugrIsMissing covers the case the hook exists for.
//
// Without the binary the plugin's server fails to start, and the only trace is a failed entry in
// /mcp. The message has to reach the user, which for SessionStart means `systemMessage`: plain
// stdout reaches Claude alone.
func TestTheHookNamesTheInstallCommandWhenDraugrIsMissing(t *testing.T) {
	t.Parallel()
	out := runHook(t, t.TempDir())

	var got struct {
		SystemMessage      string `json:"systemMessage"`
		HookSpecificOutput struct {
			HookEventName     string `json:"hookEventName"`
			AdditionalContext string `json:"additionalContext"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("hook output is not JSON, so Claude Code would treat it as context for Claude alone: %v\n%s", err, out)
	}
	if got.HookSpecificOutput.HookEventName != "SessionStart" {
		t.Errorf("hookEventName = %q, want SessionStart", got.HookSpecificOutput.HookEventName)
	}
	for name, text := range map[string]string{
		"systemMessage":     got.SystemMessage,
		"additionalContext": got.HookSpecificOutput.AdditionalContext,
	} {
		if !strings.Contains(text, installCommand) {
			t.Errorf("%s does not carry the install command %q:\n%s", name, installCommand, text)
		}
	}

	readme, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(readme), installCommand) {
		t.Errorf("the README no longer documents %q, and the hook still prints it", installCommand)
	}
}

// TestTheHookIsSilentWhenDraugrIsInstalled keeps the hook out of every session that needs nothing.
func TestTheHookIsSilentWhenDraugrIsInstalled(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "draugr"), []byte("#!/bin/sh\n"), 0o700); err != nil { // #nosec G306 -- must be executable to be found
		t.Fatal(err)
	}
	if out := runHook(t, dir); out != "" {
		t.Errorf("hook printed output with draugr on PATH:\n%s", out)
	}
}

// TestTheHookConfigRunsTheScript keeps hooks.json pointing at a script that exists.
func TestTheHookConfigRunsTheScript(t *testing.T) {
	t.Parallel()
	var cfg struct {
		Hooks map[string][]struct {
			Hooks []struct {
				Type    string `json:"type"`
				Command string `json:"command"`
			} `json:"hooks"`
		} `json:"hooks"`
	}
	readJSON(t, pluginDir+"/hooks/hooks.json", &cfg)
	groups := cfg.Hooks["SessionStart"]
	if len(groups) != 1 || len(groups[0].Hooks) != 1 {
		t.Fatalf("hooks.json must declare one SessionStart hook, got %+v", groups)
	}
	h := groups[0].Hooks[0]
	want := `sh "${CLAUDE_PLUGIN_ROOT}/scripts/check-draugr.sh"`
	if h.Type != "command" || h.Command != want {
		t.Errorf("SessionStart hook is %s %q, want command %q", h.Type, h.Command, want)
	}
	if _, err := os.Stat(pluginHook); err != nil {
		t.Errorf("the hook script is missing: %v", err)
	}
}
