package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/config"
)

// An edit goes to the file a scan reads. --config and DRAUGR_CONFIG name a file read alone, so it
// goes there, and --global with either is refused: the global file is not read while they are set.
func TestConfigEditsTheFileAScanReads(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv(config.EnvVar, "")
	project := t.TempDir()
	t.Chdir(project)

	if got, _ := configPath(false); got != filepath.Join(project, config.FileName) {
		t.Errorf("project edit went to %s", got)
	}
	if got, _ := configPath(true); got != filepath.Join(home, ".draugr", "config.yaml") {
		t.Errorf("--global edit went to %s", got)
	}

	fromEnv := filepath.Join(t.TempDir(), "env.yaml")
	t.Setenv(config.EnvVar, fromEnv)
	if got, _ := configPath(false); got != fromEnv {
		t.Errorf("with DRAUGR_CONFIG the edit went to %s, want %s", got, fromEnv)
	}
	if _, err := configPath(true); err == nil || !strings.Contains(err.Error(), "while DRAUGR_CONFIG is set to") {
		t.Errorf("--global with DRAUGR_CONFIG: %v", err)
	}

	fromFlag := filepath.Join(t.TempDir(), "flag.yaml")
	withRootConfig(t, fromFlag)
	if got, _ := configPath(false); got != fromFlag {
		t.Errorf("--config wins over DRAUGR_CONFIG: edit went to %s", got)
	}
	if _, err := configPath(true); err == nil || !strings.Contains(err.Error(), "while --config is set to") {
		t.Errorf("--global with --config: %v", err)
	}
}

// A key whose field is a boolean or a number is a setting Draugr has, whatever an unset `get`
// probes it with.
func TestEveryKindOfKeyIsASetting(t *testing.T) {
	for key, want := range map[string]bool{
		"output.evidence": true, "output.offerInstall": true, "output.top": true,
		"output.view": true, "output.nope": false,
	} {
		if got := isSetting(key); got != want {
			t.Errorf("isSetting(%q) = %v, want %v", key, got, want)
		}
	}
}

// The later file's answer wins, and a file that does not mention the key leaves the earlier one.
func TestOfferInstallMergesLikeEveryOtherSetting(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv(config.EnvVar, "")
	project := t.TempDir()
	write := func(path, body string) {
		t.Helper()
		if err := editConfigAt(path, func([]byte) ([]byte, error) { return []byte(body), nil }); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(home, ".draugr", "config.yaml"), "output:\n  offerInstall: false\n")
	res, err := config.Load("", project)
	if err != nil {
		t.Fatal(err)
	}
	if res.File.Output.Offers() {
		t.Error("the global false did not apply")
	}
	write(filepath.Join(project, config.FileName), "output:\n  top: 5\n")
	if res, _ = config.Load("", project); res.File.Output.Offers() {
		t.Error("a project file that does not mention the key reset it")
	}
	write(filepath.Join(project, config.FileName), "output:\n  offerInstall: true\n")
	if res, _ = config.Load("", project); !res.File.Output.Offers() {
		t.Error("the project's true did not override the global false")
	}
}
