package tools

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
)

// Kinds of path an uninstall removes, as the plan names them.
const (
	KindBinary    = "binary"
	KindPythonEnv = "python env"
	KindNodeEnv   = "node env"
	KindData      = "data"
	KindCache     = "cache"
)

// RemovedPath is one file or directory an uninstall removes, with its size on disk.
type RemovedPath struct {
	Kind string
	Path string
	Size int64
}

// Removal is what uninstalling one tool takes off this machine: the files Draugr put under
// ~/.draugr for it, and separately the caches the tool keeps for itself.
type Removal struct {
	Name string
	// Version is what the install record says was installed, or "" where the binary is in Draugr's
	// directory with no record beside it.
	Version string
	Files   []RemovedPath
	Caches  []RemovedPath
}

// Size is the space Draugr's own files for the tool take.
func (r Removal) Size() int64 { return total(r.Files) }

// CacheSize is the space the tool's own caches take.
func (r Removal) CacheSize() int64 { return total(r.Caches) }

func total(paths []RemovedPath) int64 {
	var n int64
	for _, p := range paths {
		n += p.Size
	}
	return n
}

// scanDataDirs names the directory under DataRoot a scanner writes for a tool at scan time, as
// opposed to InstallSpec.DataDir, which the install itself writes. Both go when the tool does.
var scanDataDirs = map[string]string{
	"gitleaks": "gitleaks",
	"retire":   "retirejs",
}

// ScanDataDir is where a scanner keeps what it writes for tool at scan time, or "" when it writes
// nothing or there is no home directory.
func ScanDataDir(tool string) string {
	sub, ok := scanDataDirs[tool]
	if !ok {
		return ""
	}
	root, err := DataRoot()
	if err != nil {
		return ""
	}
	return filepath.Join(root, sub)
}

// cacheDirs are where each tool keeps what it downloads for itself, outside ~/.draugr, at the
// tool's own default or where the environment variable it reads moves it. Another install of the
// same tool reads the same place, which is why removing them is asked for separately.
//
// Downloaded data only. A tool's settings are somebody's configuration and can hold a login, so
// ~/.config/nuclei and ~/.semgrep are not here, though both sit beside what the tools download.
func cacheDirs(tool string) []string {
	cache, _ := os.UserCacheDir()
	home, _ := os.UserHomeDir()
	in := func(base string, parts ...string) string {
		if base == "" {
			return ""
		}
		return filepath.Join(append([]string{base}, parts...)...)
	}
	env := func(name, fallback string) string {
		if v := os.Getenv(name); v != "" {
			return v
		}
		return fallback
	}
	switch tool {
	case "trivy":
		return []string{env("TRIVY_CACHE_DIR", in(cache, "trivy"))}
	case "grype":
		return []string{env("GRYPE_DB_CACHE_DIR", in(cache, "grype"))}
	case "syft":
		return []string{in(cache, "syft")}
	case "notation":
		return []string{in(cache, "notation")}
	case "nuclei":
		return []string{in(home, "nuclei-templates")}
	case "cosign":
		return []string{in(home, ".sigstore")}
	}
	return nil
}

// Uninstallable lists the tools Draugr installed into destDir: those in its install record, and
// any provisionable tool whose binary is there without one, since the record is best-effort and
// destDir holds nothing Draugr did not put there. Sorted.
func Uninstallable(destDir string) []string {
	seen := map[string]bool{}
	for name := range loadManifest(destDir) {
		if _, ok := installable[name]; ok || ManagedVersion(name) != "" {
			seen[name] = true
		}
	}
	for _, name := range Installable() {
		if _, err := os.Lstat(binaryPath(destDir, name)); err == nil {
			seen[name] = true
		}
	}
	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// binaryPath is where the install puts name's binary or shim in destDir.
func binaryPath(destDir, name string) string {
	if spec, ok := installable[name]; ok && spec.Binary != "" {
		return filepath.Join(destDir, spec.Binary)
	}
	return filepath.Join(destDir, name)
}

// PlanUninstall describes what removing name from destDir takes off the machine. Only paths that
// exist are listed. The second result is false when Draugr did not install name there.
func PlanUninstall(destDir, name string) (Removal, bool) {
	rec, recorded := loadManifest(destDir)[name]
	bin := binaryPath(destDir, name)
	if _, err := os.Lstat(bin); err != nil && !recorded {
		return Removal{}, false
	}
	r := Removal{Name: name, Version: rec.Version}
	root := filepath.Dir(destDir)
	add := func(list *[]RemovedPath, kind, path string) {
		if path == "" {
			return
		}
		if _, err := os.Lstat(path); err != nil {
			return
		}
		size := diskSize(path)
		// An empty cache is a directory the tool made and never filled. Listing it as 0B is noise,
		// and removing a path the plan did not list is worse, so it is neither.
		if kind == KindCache && size == 0 {
			return
		}
		*list = append(*list, RemovedPath{Kind: kind, Path: path, Size: size})
	}
	add(&r.Files, KindBinary, bin)
	if _, ok := PythonTool(name); ok {
		add(&r.Files, KindPythonEnv, pythonEnvDir(root, name))
	}
	if _, ok := NodeTool(name); ok {
		add(&r.Files, KindNodeEnv, nodeEnvDir(root, name))
	}
	add(&r.Files, KindData, DataDirFor(name))
	add(&r.Files, KindData, ScanDataDir(name))
	for _, dir := range cacheDirs(name) {
		add(&r.Caches, KindCache, dir)
	}
	return r, true
}

// Uninstall removes what r lists, the caches too when withCaches is set, and then drops the tool
// from destDir's install record. A path that cannot be removed stops it before the record changes,
// so a tool half removed is still listed as installed and a second run can finish it.
func Uninstall(destDir string, r Removal, withCaches bool) error {
	paths := r.Files
	if withCaches {
		paths = append(append([]RemovedPath(nil), r.Files...), r.Caches...)
	}
	for _, p := range paths {
		if err := os.RemoveAll(p.Path); err != nil {
			return fmt.Errorf("remove %s: %w", p.Path, err)
		}
	}
	return forget(destDir, r.Name)
}

// forget drops name from destDir's install record, and the record itself once it is empty.
func forget(destDir, name string) error {
	m := loadManifest(destDir)
	if _, ok := m[name]; !ok {
		return nil
	}
	delete(m, name)
	if len(m) == 0 {
		if err := os.Remove(manifestPath(destDir)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return nil
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(manifestPath(destDir), data, 0o600)
}

// diskSize is the total size of the regular files under path, without following symbolic links.
// A file that cannot be read counts as nothing rather than failing the plan.
func diskSize(path string) int64 {
	var n int64
	_ = filepath.WalkDir(path, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.Type().IsRegular() {
			if info, err := d.Info(); err == nil {
				n += info.Size()
			}
		}
		return nil
	})
	return n
}
