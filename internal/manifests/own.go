package manifests

import (
	"bytes"
	"encoding/json"
	"path"
	"strings"

	"gopkg.in/yaml.v3"
)

// OwnPackage is a package a dependency file records as the project itself rather than as a
// dependency fetched from somewhere else.
type OwnPackage struct {
	// Name is the package as the file names it.
	Name string
	// Version is the version the file records, or empty where it records none, which matches any.
	Version string
}

// Matches reports whether a scanner's package is this one: the same name, and the same version
// where both say one. A CocoaPods subspec, `Flutter/Core`, is its pod's.
func (o OwnPackage) Matches(name, version string) bool {
	if name != o.Name && !strings.HasPrefix(name, o.Name+"/") {
		return false
	}
	return o.Version == "" || version == "" || o.Version == version
}

// OwnFile reports whether OwnPackages reads a file of this name.
func OwnFile(rel string) bool {
	switch path.Base(rel) {
	case "package-lock.json", "npm-shrinkwrap.json":
		return !inNodeModules(rel)
	case "Cargo.lock", "pubspec.yaml", "pubspec.lock", "Podfile.lock":
		return true
	}
	return false
}

// OwnPackages reads the project's own packages from the dependency file at rel, a slash-separated
// path, with read returning the content of a path beside it or an error.
//
//   - package-lock.json and npm-shrinkwrap.json: the root and every workspace member, each entry under
//     packages keyed by a folder of the project rather than by a path under node_modules. A root
//     with no name of its own takes the lockfile's top-level name and version, and then the
//     package.json beside it.
//   - Cargo.lock: every [[package]] with no source, which Cargo writes for the project's own crates
//     and for a dependency by path.
//   - pubspec.yaml: the package it declares, where it says publish_to: none, so no package of that
//     name can be this one on pub.dev.
//   - pubspec.lock: every package with source: path, which Dart writes for a package in a folder
//     of the project rather than one from pub.dev.
//   - Podfile.lock: every pod under EXTERNAL SOURCES taken from a :path:.
//
// A file that cannot be read or parsed has none.
func OwnPackages(rel string, read func(rel string) ([]byte, error)) []OwnPackage {
	if !OwnFile(rel) {
		return nil
	}
	content, err := read(rel)
	if err != nil {
		return nil
	}
	switch path.Base(rel) {
	case "Cargo.lock":
		return cargoOwnPackages(content)
	case "pubspec.yaml":
		return pubspecOwnPackage(content)
	case "pubspec.lock":
		return pubspecLockOwnPackages(content)
	case "Podfile.lock":
		return podOwnPackages(content)
	}
	beside := func() []byte {
		b, err := read(path.Join(path.Dir(rel), "package.json"))
		if err != nil {
			return nil
		}
		return b
	}
	return npmOwnPackages(content, beside)
}

// inNodeModules reports whether a path lies under a node_modules folder, where every file belongs to
// an installed dependency rather than to the project.
func inNodeModules(rel string) bool {
	return strings.Contains("/"+rel, "/node_modules/")
}

// npmManifest is the name and version a package.json, a lockfile's top level or one of its
// packages entries records.
type npmManifest struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// npmOwnPackages reads the root and workspace members of a package-lock.json or npm-shrinkwrap.json.
// beside is the package.json in the same folder, read only where the lockfile names no root.
func npmOwnPackages(content []byte, beside func() []byte) []OwnPackage {
	var lock struct {
		npmManifest
		Packages map[string]npmManifest `json:"packages"`
	}
	if json.Unmarshal(content, &lock) != nil {
		return nil
	}
	var out []OwnPackage
	root := lock.Packages[""].or(lock.npmManifest)
	if root.Name == "" || root.Version == "" {
		var m npmManifest
		// A package.json that is missing or does not parse adds nothing.
		if json.Unmarshal(beside(), &m) == nil {
			root = root.or(m)
		}
	}
	if root.Name != "" {
		out = append(out, OwnPackage(root))
	}
	for key, entry := range lock.Packages {
		if key == "" || entry.Name == "" || inNodeModules(key+"/") {
			continue
		}
		out = append(out, OwnPackage(entry))
	}
	return out
}

// or fills the name and version m leaves empty from another record of the same package.
func (m npmManifest) or(other npmManifest) npmManifest {
	if m.Name == "" {
		m.Name = other.Name
	}
	if m.Version == "" {
		m.Version = other.Version
	}
	return m
}

// cargoOwnPackages reads the [[package]] entries of a Cargo.lock that carry no source. A name and
// version Cargo also records from a registry is not the project's, whichever entry a scanner read.
func cargoOwnPackages(content []byte) []OwnPackage {
	type entry struct {
		name, version string
		sourced       bool
	}
	var entries []entry
	var cur *entry
	for line := range bytes.Lines(content) {
		line = bytes.TrimSpace(line)
		if bytes.HasPrefix(line, []byte("[")) {
			cur = nil
			if string(line) == "[[package]]" {
				entries = append(entries, entry{})
				cur = &entries[len(entries)-1]
			}
			continue
		}
		if cur == nil {
			continue
		}
		key, value, ok := bytes.Cut(line, []byte("="))
		if !ok {
			continue
		}
		v := strings.Trim(string(bytes.TrimSpace(value)), `"`)
		switch string(bytes.TrimSpace(key)) {
		case "name":
			cur.name = v
		case "version":
			cur.version = v
		case "source":
			cur.sourced = true
		}
	}
	sourced := map[OwnPackage]bool{}
	for _, e := range entries {
		if e.sourced {
			sourced[OwnPackage{e.name, e.version}] = true
		}
	}
	var out []OwnPackage
	for _, e := range entries {
		p := OwnPackage{e.name, e.version}
		if e.name != "" && !sourced[p] {
			out = append(out, p)
		}
	}
	return out
}

// pubspecOwnPackage reads the package a pubspec.yaml declares, where the file says it is never
// published.
func pubspecOwnPackage(content []byte) []OwnPackage {
	var spec struct {
		Name      string `yaml:"name"`
		Version   string `yaml:"version"`
		PublishTo string `yaml:"publish_to"`
	}
	if yaml.Unmarshal(content, &spec) != nil || spec.Name == "" || spec.PublishTo != "none" {
		return nil
	}
	return []OwnPackage{{Name: spec.Name, Version: spec.Version}}
}

// pubspecLockOwnPackages reads the packages a pubspec.lock takes from a folder, each with source:
// path. The other sources, hosted, git and sdk, name somebody else's package.
func pubspecLockOwnPackages(content []byte) []OwnPackage {
	var lock struct {
		Packages map[string]struct {
			Source  string `yaml:"source"`
			Version string `yaml:"version"`
		} `yaml:"packages"`
	}
	if yaml.Unmarshal(content, &lock) != nil {
		return nil
	}
	var out []OwnPackage
	for name, p := range lock.Packages {
		if p.Source == "path" {
			out = append(out, OwnPackage{Name: name, Version: p.Version})
		}
	}
	return out
}

// podOwnPackages reads the pods a Podfile.lock takes from a folder, each under EXTERNAL SOURCES with
// a :path:. Any version, because the folder is the pod's source whatever its podspec says.
func podOwnPackages(content []byte) []OwnPackage {
	var lock struct {
		External map[string]map[string]string `yaml:"EXTERNAL SOURCES"`
	}
	if yaml.Unmarshal(content, &lock) != nil {
		return nil
	}
	var out []OwnPackage
	for name, source := range lock.External {
		if _, local := source[":path"]; local {
			out = append(out, OwnPackage{Name: name})
		}
	}
	return out
}
