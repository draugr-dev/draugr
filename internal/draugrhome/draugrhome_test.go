package draugrhome

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestDirDefaultsToDotDraugrInHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv(EnvVar, "")
	got, err := Dir()
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(home, ".draugr"); got != want {
		t.Errorf("Dir() = %q, want %q", got, want)
	}
	if FromEnv() {
		t.Error("FromEnv() with DRAUGR_HOME unset")
	}
	if err := Check(); err != nil {
		t.Errorf("Check() with DRAUGR_HOME unset = %v", err)
	}
}

func TestDirReadsDraugrHome(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(EnvVar, dir+string(filepath.Separator))
	got, err := Dir()
	if err != nil {
		t.Fatal(err)
	}
	if got != filepath.Clean(dir) {
		t.Errorf("Dir() = %q, want %q", got, filepath.Clean(dir))
	}
	if !FromEnv() {
		t.Error("FromEnv() with DRAUGR_HOME set")
	}
	if err := Check(); err != nil {
		t.Errorf("Check() = %v", err)
	}
}

// A relative path would name another directory from each place a command runs, so it is refused,
// and the message names the variable and the value so the reader knows what to change.
func TestDirRefusesARelativeDraugrHome(t *testing.T) {
	for _, v := range []string{"tools", "./tools", "~/tools"} {
		t.Setenv(EnvVar, v)
		_, err := Dir()
		if err == nil {
			t.Fatalf("Dir() accepted DRAUGR_HOME=%q", v)
		}
		for _, want := range []string{"DRAUGR_HOME", "absolute", `"` + v + `"`} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q does not mention %s", err, want)
			}
		}
		if Check() == nil {
			t.Errorf("Check() accepted DRAUGR_HOME=%q", v)
		}
	}
}

// With no home directory and no DRAUGR_HOME there is nowhere to install, which Dir says and Check,
// asked only about the variable, does not.
func TestDirWithoutAHomeDirectory(t *testing.T) {
	t.Setenv("HOME", "")
	t.Setenv(EnvVar, "")
	if _, err := Dir(); err == nil {
		t.Error("Dir() found a directory with no HOME")
	}
	if err := Check(); err != nil {
		t.Errorf("Check() = %v", err)
	}
}
