package tools

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
)

// fakeHome points every directory Draugr and the tools derive from the home at a scratch one.
func fakeHome(t *testing.T) (home, bin string) {
	t.Helper()
	home = t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CACHE_HOME", filepath.Join(home, ".cache"))
	t.Setenv("TRIVY_CACHE_DIR", "")
	t.Setenv("GRYPE_DB_CACHE_DIR", "")
	return home, filepath.Join(home, ".draugr", "bin")
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func pathExists(path string) bool { _, err := os.Lstat(path); return err == nil }

// threeInstalled lays down what an install of trivy, semgrep and retire leaves, with their caches.
func threeInstalled(t *testing.T, home, bin string) {
	t.Helper()
	draugr := filepath.Join(home, ".draugr")
	writeFile(t, filepath.Join(bin, "trivy"), "trivy binary")
	writeFile(t, filepath.Join(bin, "semgrep"), "#!/bin/sh")
	writeFile(t, filepath.Join(draugr, "venv", "semgrep", "lib", "site.py"), "venv")
	writeFile(t, filepath.Join(bin, "retire"), "#!/bin/sh")
	writeFile(t, filepath.Join(draugr, "node", "retire", "index.js"), "node")
	writeFile(t, filepath.Join(draugr, "data", "retirejs", "jsrepository.json"), "{}")
	writeFile(t, filepath.Join(home, ".cache", "trivy", "db", "trivy.db"), "trivy database")
	writeFile(t, filepath.Join(home, ".semgrep", "settings.yml"), "id: 1")
	for name, version := range map[string]string{"trivy": "0.74.0", "semgrep": "1.177.0", "retire": "5.7.0"} {
		recordInstall(bin, name, installRecord{Version: version})
	}
}

func TestPlanUninstallListsEachToolsFilesAndCachesApart(t *testing.T) {
	home, bin := fakeHome(t)
	threeInstalled(t, home, bin)
	draugr := filepath.Join(home, ".draugr")

	cases := map[string]Removal{
		"trivy": {Name: "trivy", Version: "0.74.0",
			Files:  []RemovedPath{{KindBinary, filepath.Join(bin, "trivy"), 12}},
			Caches: []RemovedPath{{KindCache, filepath.Join(home, ".cache", "trivy"), 14}}},
		"semgrep": {Name: "semgrep", Version: "1.177.0",
			Files: []RemovedPath{{KindBinary, filepath.Join(bin, "semgrep"), 9},
				{KindPythonEnv, filepath.Join(draugr, "venv", "semgrep"), 4}},
			Caches: []RemovedPath{{KindCache, filepath.Join(home, ".semgrep"), 5}}},
		"retire": {Name: "retire", Version: "5.7.0",
			Files: []RemovedPath{{KindBinary, filepath.Join(bin, "retire"), 9},
				{KindNodeEnv, filepath.Join(draugr, "node", "retire"), 4},
				{KindData, filepath.Join(draugr, "data", "retirejs"), 2}}},
	}
	for name, want := range cases {
		got, ok := PlanUninstall(bin, name)
		if !ok {
			t.Fatalf("%s: not planned", name)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s:\n got %+v\nwant %+v", name, got, want)
		}
	}
	if r := cases["semgrep"]; r.Size() != 13 || r.CacheSize() != 5 {
		t.Errorf("semgrep sizes: %d files, %d caches", r.Size(), r.CacheSize())
	}
}

func TestUninstallLeavesTheOtherToolsAndTheCaches(t *testing.T) {
	home, bin := fakeHome(t)
	threeInstalled(t, home, bin)

	r, _ := PlanUninstall(bin, "trivy")
	if err := Uninstall(bin, r, false); err != nil {
		t.Fatal(err)
	}
	if pathExists(filepath.Join(bin, "trivy")) {
		t.Error("the trivy binary is still there")
	}
	if !pathExists(filepath.Join(home, ".cache", "trivy")) {
		t.Error("the trivy cache went without --caches")
	}
	if !pathExists(filepath.Join(bin, "semgrep")) || !pathExists(filepath.Join(home, ".draugr", "node", "retire")) {
		t.Error("removing trivy took another tool with it")
	}
	m := loadManifest(bin)
	if _, ok := m["trivy"]; ok {
		t.Error("trivy is still in the install record")
	}
	if len(m) != 2 {
		t.Errorf("install record lost another tool: %v", m)
	}
}

func TestUninstallWithCachesRemovesThemAndTheEmptyRecord(t *testing.T) {
	home, bin := fakeHome(t)
	moved := filepath.Join(home, "elsewhere", "trivy-cache")
	t.Setenv("TRIVY_CACHE_DIR", moved)
	writeFile(t, filepath.Join(moved, "db", "trivy.db"), "trivy database")
	writeFile(t, filepath.Join(home, ".cache", "trivy", "db", "trivy.db"), "not the one in use")
	writeFile(t, filepath.Join(bin, "trivy"), "trivy binary")
	recordInstall(bin, "trivy", installRecord{Version: "0.74.0"})

	r, _ := PlanUninstall(bin, "trivy")
	if len(r.Caches) != 1 || r.Caches[0].Path != moved {
		t.Fatalf("TRIVY_CACHE_DIR not honored: %+v", r.Caches)
	}
	if err := Uninstall(bin, r, true); err != nil {
		t.Fatal(err)
	}
	if pathExists(moved) {
		t.Error("the cache stayed with --caches")
	}
	if !pathExists(filepath.Join(home, ".cache", "trivy")) {
		t.Error("removed a cache the plan did not list")
	}
	if pathExists(manifestPath(bin)) {
		t.Error("an empty install record was left behind")
	}
}

func TestPlanUninstallRefusesWhatDraugrDidNotInstall(t *testing.T) {
	_, bin := fakeHome(t)
	if _, ok := PlanUninstall(bin, "trivy"); ok {
		t.Error("planned removing a tool that is not there")
	}
}

// The record is best-effort, so a binary in Draugr's own directory without one is still Draugr's.
func TestUninstallableIncludesABinaryWithNoRecord(t *testing.T) {
	home, bin := fakeHome(t)
	threeInstalled(t, home, bin)
	writeFile(t, filepath.Join(bin, "gitleaks"), "gitleaks binary")
	recordInstall(bin, "not-a-tool", installRecord{Version: "1"})

	got := Uninstallable(bin)
	want := []string{"gitleaks", "retire", "semgrep", "trivy"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Uninstallable = %v, want %v", got, want)
	}
	r, ok := PlanUninstall(bin, "gitleaks")
	if !ok || r.Version != "" {
		t.Errorf("gitleaks with no record: ok=%v version=%q", ok, r.Version)
	}
}

func TestAnEmptyCacheIsNeitherListedNorRemoved(t *testing.T) {
	home, bin := fakeHome(t)
	writeFile(t, filepath.Join(bin, "syft"), "syft binary")
	empty := filepath.Join(home, ".cache", "syft")
	if err := os.MkdirAll(empty, 0o750); err != nil {
		t.Fatal(err)
	}
	r, _ := PlanUninstall(bin, "syft")
	if len(r.Caches) != 0 {
		t.Errorf("listed an empty cache: %+v", r.Caches)
	}
}

func TestUninstallKeepsTheRecordWhenAPathCannotBeRemoved(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs a directory this user cannot write")
	}
	home, bin := fakeHome(t)
	threeInstalled(t, home, bin)
	r, _ := PlanUninstall(bin, "retire")
	node := filepath.Join(home, ".draugr", "node")
	// #nosec G302 -- a directory this test makes unwritable, to see a removal fail
	if err := os.Chmod(node, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(node, 0o750) }) // #nosec G302 -- restores it so t.TempDir can clean up

	if err := Uninstall(bin, r, false); err == nil {
		t.Fatal("no error for a path that could not be removed")
	}
	data, _ := os.ReadFile(manifestPath(bin))
	var m map[string]installRecord
	_ = json.Unmarshal(data, &m)
	if _, ok := m["retire"]; !ok {
		t.Error("a half-removed tool was dropped from the install record")
	}
}

func TestScanDataDir(t *testing.T) {
	home, _ := fakeHome(t)
	if got, want := ScanDataDir("gitleaks"), filepath.Join(home, ".draugr", "data", "gitleaks"); got != want {
		t.Errorf("ScanDataDir(gitleaks) = %q, want %q", got, want)
	}
	if got := ScanDataDir("trivy"); got != "" {
		t.Errorf("ScanDataDir(trivy) = %q, want none", got)
	}
}

// Each location is the tool's own default, so a change upstream shows up here rather than as a
// cache somebody asked to remove and still has.
func TestCacheDirsAreEachToolsDefault(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("os.UserCacheDir ignores XDG_CACHE_HOME on macOS")
	}
	home, _ := fakeHome(t)
	cache := filepath.Join(home, ".cache")
	t.Setenv("GRYPE_DB_CACHE_DIR", "/elsewhere/grype")
	want := map[string][]string{
		"trivy":    {filepath.Join(cache, "trivy")},
		"grype":    {"/elsewhere/grype"},
		"syft":     {filepath.Join(cache, "syft")},
		"notation": {filepath.Join(cache, "notation")},
		"nuclei":   {filepath.Join(home, "nuclei-templates"), filepath.Join(home, ".config", "nuclei")},
		"semgrep":  {filepath.Join(home, ".semgrep")},
		"cosign":   {filepath.Join(home, ".sigstore")},
		"gitleaks": nil,
	}
	for tool, dirs := range want {
		if got := cacheDirs(tool); !reflect.DeepEqual(got, dirs) {
			t.Errorf("cacheDirs(%s) = %v, want %v", tool, got, dirs)
		}
	}
}

// A binary in Draugr's directory with no record is removed without touching the record.
func TestUninstallWithNoRecordLeavesTheOthers(t *testing.T) {
	home, bin := fakeHome(t)
	threeInstalled(t, home, bin)
	writeFile(t, filepath.Join(bin, "gitleaks"), "gitleaks binary")
	r, _ := PlanUninstall(bin, "gitleaks")
	if err := Uninstall(bin, r, false); err != nil {
		t.Fatal(err)
	}
	if len(loadManifest(bin)) != 3 {
		t.Errorf("install record changed: %v", loadManifest(bin))
	}
}
