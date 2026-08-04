// Package config is Draugr's machine- and organisation-level configuration, kept apart from the
// Saga on purpose.
//
// A Saga describes an application: which repositories it has, how exposed a component is, which
// controls must pass. Those are facts about the software, they belong in its repository, and they
// are meant to differ between projects.
//
// This file describes the machine or the organisation running the scan: which build of a scanner
// to install, and what a control should default to before any project says otherwise. Those want
// to be *uniform*, and putting them in a Saga makes them diverge silently — a descriptor that can
// pin its own scanner version is a descriptor that can downgrade one until a finding disappears.
//
// See https://github.com/draugr-dev/draugr/issues/129.
package config

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/draugr-dev/draugr/pkg/saga"
)

// FileName is the config a project may carry beside its Saga.
const FileName = "draugr.config.yaml"

// EnvVar names a config file explicitly, which is the organisation-wide lever: set it in a
// runner image and every pipeline picks up the same defaults with no per-repository change.
const EnvVar = "DRAUGR_CONFIG"

// File is a parsed configuration.
type File struct {
	// Tools pins the build of each external scanner. Provisioning rather than behaviour, and
	// deliberately not readable from a Saga.
	Tools map[string]ToolSettings `yaml:"tools,omitempty"`
	// Controllers are default settings merged *underneath* the Saga's, so a project overrides
	// only the keys it cares about and inherits the rest.
	Controllers map[string]saga.ControllerSettings `yaml:"controllers,omitempty"`
}

// ToolSettings pins one external tool.
type ToolSettings struct {
	// Version is the release to install, e.g. "0.69.3".
	Version string `yaml:"version,omitempty"`
}

// Source records where a loaded file came from, so a reader can be told which one to edit.
type Source struct {
	Path string
	File File
}

// Resolved is the configuration in effect, and the files it came from, nearest last.
type Resolved struct {
	File    File
	Sources []Source
}

// Load reads the configuration in effect.
//
// An explicit path — `--config` or DRAUGR_CONFIG — is used *alone*. Explicit means explicit: a
// runner image that names a config expects that config, not that one layered over whatever
// happens to be in the working directory.
//
// Otherwise the home file is layered under the project file, so a personal default can be
// overridden by a repository that has an opinion. Missing files are not an error; a machine with
// no configuration is the normal case.
func Load(explicit, workDir string) (Resolved, error) {
	if explicit == "" {
		explicit = os.Getenv(EnvVar)
	}
	if explicit != "" {
		f, err := loadFile(explicit)
		if err != nil {
			return Resolved{}, err
		}
		return Resolved{File: f, Sources: []Source{{Path: explicit, File: f}}}, nil
	}

	var out Resolved
	for _, path := range discover(workDir) {
		if _, err := os.Stat(path); err != nil {
			continue
		}
		f, err := loadFile(path)
		if err != nil {
			return Resolved{}, err
		}
		out.Sources = append(out.Sources, Source{Path: path, File: f})
		out.File = merge(out.File, f)
	}
	return out, nil
}

// discover lists the candidate files, least specific first.
func discover(workDir string) []string {
	var paths []string
	if home, err := os.UserHomeDir(); err == nil {
		paths = append(paths, filepath.Join(home, ".draugr", "config.yaml"))
	}
	return append(paths, filepath.Join(workDir, FileName))
}

// loadFile reads and validates one file.
func loadFile(path string) (File, error) {
	data, err := os.ReadFile(path) //nolint:gosec // operator-provided config path
	if err != nil {
		return File{}, fmt.Errorf("read %s: %w", path, err)
	}
	return Parse(data, path)
}

// Parse decodes and validates a configuration.
//
// Strict: an unknown key is an error rather than something ignored. A misspelled setting that is
// silently dropped is a setting somebody believes is in force, and this file exists to make
// behaviour uniform — a typo that quietly opts one machine out defeats the point of having it.
func Parse(data []byte, path string) (File, error) {
	var f File
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil {
		// An empty file decodes as EOF and is a perfectly good configuration: it says nothing,
		// so nothing is overridden.
		if errors.Is(err, io.EOF) {
			return File{}, nil
		}
		return File{}, fmt.Errorf("%s: %w\n\nrun `draugr config validate` to check it, or "+
			"`draugr config init --force` to start again from the built-in defaults", path, err)
	}
	return f, nil
}

// merge lays b over a, most specific winning per key.
func merge(a, b File) File {
	out := File{
		Tools:       map[string]ToolSettings{},
		Controllers: map[string]saga.ControllerSettings{},
	}
	for k, v := range a.Tools {
		out.Tools[k] = v
	}
	for k, v := range b.Tools {
		out.Tools[k] = v
	}
	for k, v := range a.Controllers {
		out.Controllers[k] = v
	}
	for k, v := range b.Controllers {
		out.Controllers[k] = DeepMerge(out.Controllers[k], v)
	}
	if len(out.Tools) == 0 {
		out.Tools = nil
	}
	if len(out.Controllers) == 0 {
		out.Controllers = nil
	}
	return out
}

// DeepMerge lays src over dst, recursing into nested maps so an override replaces only the keys
// it names. Exported because the same rule applies when these defaults meet a Saga's.
func DeepMerge(dst, src saga.ControllerSettings) saga.ControllerSettings {
	if dst == nil {
		dst = saga.ControllerSettings{}
	}
	out := saga.ControllerSettings{}
	for k, v := range dst {
		out[k] = v
	}
	for k, v := range src {
		if sub, ok := asSettings(v); ok {
			if existing, ok := asSettings(out[k]); ok {
				out[k] = DeepMerge(existing, sub)
				continue
			}
		}
		out[k] = v
	}
	return out
}

// asSettings normalises a decoded mapping. YAML decodes a nested mapping as the enclosing named
// type, which a plain map[string]any assertion misses.
func asSettings(v any) (saga.ControllerSettings, bool) {
	switch m := v.(type) {
	case saga.ControllerSettings:
		return m, true
	case map[string]any:
		return m, true
	default:
		return nil, false
	}
}
