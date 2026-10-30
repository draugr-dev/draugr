package config

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// machineFiles writes a user file and a project file, as a scan finds them, and returns the
// project's directory and both paths.
func machineFiles(t *testing.T, user, project string) (dir, userPath, projectPath string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv(EnvVar, "")
	userPath = filepath.Join(home, ".draugr", "config.yaml")
	if err := os.MkdirAll(filepath.Dir(userPath), 0o750); err != nil {
		t.Fatal(err)
	}
	write(t, userPath, user)
	dir = t.TempDir()
	projectPath = filepath.Join(dir, FileName)
	write(t, projectPath, project)
	return dir, userPath, projectPath
}

// The project's value wins key by key, `0` included, and a key the project leaves out keeps the
// user's. offline is the exception: it only turns on, and the project's false is reported.
func TestMachineSettingsLayerTheProjectOverTheUser(t *testing.T) {
	dir, user, project := machineFiles(t,
		"scan:\n  jobs: 4\nlog:\n  level: debug\n  format: json\noutput:\n  tips: false\noffline: true\n",
		"scan:\n  jobs: 0\nlog:\n  level: warn\noutput:\n  tips: true\noffline: false\n")

	res, err := Load("", dir)
	if err != nil {
		t.Fatal(err)
	}
	f := res.File
	if f.Scan.Jobs == nil || *f.Scan.Jobs != 0 {
		t.Errorf("scan.jobs = %v, want the project's 0", f.Scan.Jobs)
	}
	if f.Log.Level != "warn" {
		t.Errorf("log.level = %q, want the project's warn", f.Log.Level)
	}
	if f.Log.Format != "json" {
		t.Errorf("log.format = %q, want the user's json, which the project does not mention", f.Log.Format)
	}
	if f.Output.Tips == nil || !*f.Output.Tips {
		t.Errorf("output.tips = %v, want the project's true", f.Output.Tips)
	}
	if !On(f.Offline) {
		t.Error("offline: the project's false turned off the user's true")
	}
	if got, want := res.Overrides(), []Override{{Key: "offline", Path: project, By: user}}; !reflect.DeepEqual(got, want) {
		t.Errorf("Overrides() = %+v, want %+v", got, want)
	}
	if got := res.OfflineBy(); got != user {
		t.Errorf("OfflineBy() = %q, want the user's file, whose true is the one in force", got)
	}
}

// A file may turn offline on whichever file it is, and the most specific file saying true is the
// one named for it.
func TestOfflineOnlyTurnsOnAcrossFiles(t *testing.T) {
	for name, tc := range map[string]struct {
		user, project string
		on            bool
		by            string
	}{
		"neither":             {"", "", false, ""},
		"the user's true":     {"offline: true\n", "", true, "user"},
		"the project's true":  {"offline: false\n", "offline: true\n", true, "project"},
		"both true":           {"offline: true\n", "offline: true\n", true, "project"},
		"the project's false": {"offline: true\n", "offline: false\n", true, "user"},
		"both false":          {"offline: false\n", "offline: false\n", false, ""},
	} {
		t.Run(name, func(t *testing.T) {
			dir, user, project := machineFiles(t, tc.user, tc.project)
			res, err := Load("", dir)
			if err != nil {
				t.Fatal(err)
			}
			if On(res.File.Offline) != tc.on {
				t.Errorf("offline = %v, want %v", res.File.Offline, tc.on)
			}
			want := map[string]string{"": "", "user": user, "project": project}[tc.by]
			if got := res.OfflineBy(); got != want {
				t.Errorf("OfflineBy() = %q, want %q", got, want)
			}
		})
	}
}

// An explicit file is read alone, so its offline is the one in force whatever the discovered files
// say.
func TestAnExplicitFileDecidesOfflineAlone(t *testing.T) {
	dir, _, _ := machineFiles(t, "offline: true\n", "offline: true\n")
	named := filepath.Join(t.TempDir(), "ci.yaml")
	write(t, named, "scan:\n  jobs: 2\n")
	res, err := Load(named, dir)
	if err != nil {
		t.Fatal(err)
	}
	if res.File.Offline != nil || res.OfflineBy() != "" {
		t.Errorf("the discovered files' offline reached a run that named its own file: %v", res.File.Offline)
	}
	if j := res.File.Scan.Jobs; j == nil || *j != 2 {
		t.Errorf("scan.jobs = %v, want the named file's 2", j)
	}
}

func TestOneWayKeysNamesEverySettingThatOnlyTurnsOn(t *testing.T) {
	if got, want := OneWayKeys(), []string{"cache.readOnly", "cache.requireDigest", "offline"}; !reflect.DeepEqual(got, want) {
		t.Errorf("OneWayKeys() = %v, want %v", got, want)
	}
}

// A value of the wrong type is reported by its key in the file's terms, and a misspelled key with
// the nearest real one.
func TestParseNamesAMachineSettingByItsKey(t *testing.T) {
	doc := "offline: maybe\n" +
		"scan:\n  jobs: many\n" +
		"log:\n  levl: debug\n" +
		"output:\n  tips: sometimes\n"
	_, err := Parse([]byte(doc), "x.yaml")
	var p *Problems
	if !errors.As(err, &p) {
		t.Fatalf("want *Problems, got %T: %v", err, err)
	}
	want := []string{
		`offline: expected true or false, got maybe`,
		`scan.jobs: expected a whole number, got many`,
		`log: "levl" is not a setting Draugr has, did you mean "level"?`,
		`output.tips: expected true or false, got sometimes`,
	}
	if !reflect.DeepEqual(p.List, want) {
		t.Errorf("problems:\n%s\nwant:\n%s", strings.Join(p.List, "\n"), strings.Join(want, "\n"))
	}
	if p.Hint != KeysHint {
		t.Errorf("hint = %q, want the list of keys, for the misspelled one", p.Hint)
	}
}
