package engine

import (
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/draugr-dev/draugr/internal/git"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// Declarations is what a descriptor declared, as one run read it: how each component is
// classified, which controls it turned on, and which findings it set aside.
//
// Recorded on the run so that results.sarif can carry it. A comparison judges a change against its
// base, and the change's own descriptor is part of the change: read alone, a pull request that
// declares its component less exposed, turns a control off or excludes its own finding is judged by
// the declaration it introduces. The base's record is what holds it to the declaration that was
// already in force.
type Declarations struct {
	// Components are the components this run covered, in the descriptor's order.
	Components []ComponentDeclaration
	// Controls are the project-wide controls the descriptor turned on and this run covered, sorted.
	Controls []string
	// Exclusions are the config.exclude rules in force for this run, lapsed ones left out.
	Exclusions []saga.ExcludeRule
	// Settings are the settings of each of Controls, keyed by control. A control with none is
	// absent.
	Settings map[string]ControlSettings
	// Files are the files outside the descriptor that can set findings aside or change what a
	// scanner finds, as this run read them, sorted: the VEX documents the descriptor names, the
	// scanners' own configuration files at the root of each checkout, and the rulesets and
	// templates a control's settings name. Each is recorded by a digest of its content, never the
	// content. A file that is not there is not recorded.
	//
	// Recorded because a change can set its own finding aside in a file of its own as surely as in
	// the descriptor, and edit a ruleset in place under a setting that does not change.
	Files []DeclaredFile
}

// FileKind is where a declared file was read from.
type FileKind string

const (
	// FileVEX is a VEX document the descriptor names, under config.vexSources or a component's vex.
	FileVEX FileKind = "vex"
	// FileScanner is one of the scanners' own configuration files at the root of a checkout, such
	// as `.trivyignore` (see git.RootConfig).
	FileScanner FileKind = "scanner"
	// FileSetting is a file or directory a control's setting names, such as a Semgrep ruleset.
	FileSetting FileKind = "setting"
)

// DeclaredFile is one file a run read that can set findings aside or change what a scanner finds.
type DeclaredFile struct {
	Kind FileKind `json:"kind"`
	// Repository is the URL of the repository whose checkout held a scanner's file, as the
	// descriptor writes it. Empty for the other kinds, which are read where Draugr runs or from
	// where the descriptor points.
	Repository string `json:"repository,omitempty"`
	// Path is as written: a scanner's file from the root of its checkout, a VEX source's path, URL
	// or `repository#path`, or the path a setting gives.
	Path string `json:"path"`
	// Digests name what each read of the file found, sorted, each once: more than one where
	// components read one repository at two revisions. None for a VEX document fetched from a URL
	// or read from another repository, which a change cannot edit and which is compared by where
	// it is.
	Digests []string `json:"digests,omitempty"`
}

// UnlistedSetAside is a scanner's configuration file that kept findings from the scanner without
// listing what it kept.
type UnlistedSetAside struct {
	// Repository is the URL of the repository whose checkout held the file, as the descriptor
	// writes it.
	Repository string `json:"repository"`
	// File is its path from the root of the checkout.
	File string `json:"file"`
	// Scanner is the scanner that honored it.
	Scanner string `json:"scanner"`
}

// ControlSettings are a control's settings as a run read them, one digest for each top-level key: a
// scanner's block, or a setting of the control's own. The enabled flag is left out, since Controls
// already says whether the control runs.
//
// Recorded because a control left on can still be told to read less: another scanner in place of
// the default, a narrower ruleset, fewer package types. Each changes what the scan looks for as
// surely as turning the control off. Only digests, never the values: a setting may hold a
// credential, and results.sarif is uploaded where others read it.
type ControlSettings map[string]string

// ComponentDeclaration is what a descriptor declared for one component.
type ComponentDeclaration struct {
	Name string
	// Exposure and Criticality are as declared, empty where the descriptor declares none. The
	// ranking reads an empty one as the most exposed or most critical level.
	Exposure    saga.Exposure
	Criticality saga.Criticality
	// Controls are the per-component controls the descriptor turned on for it and this run
	// covered, sorted.
	Controls []string
	// Repositories are the URLs of the repositories it declares, as written. A comparison follows a
	// repository from one component to another by them, where a change renames a component or moves
	// a repository between two.
	Repositories []string
	// Scopes are the same repositories, each with the part of it the component's scans read: the
	// paths, the ignore entries and the revision. Two components that share a repository split it
	// by paths, so a control still runs on the repository after one of them stops it on its own
	// part, and only the scope says which part nobody scans any more. Empty in a report written
	// before scans recorded them.
	Scopes []RepositoryScope
	// Settings are the settings of each of Controls for this component, keyed by control: the
	// project's with the component's own laid over them. A control with none is absent.
	Settings map[string]ControlSettings
}

// RepositoryScope is one repository a component declares and the part of it the component's scans
// read.
//
// Each field narrows what a scan reads, so each is recorded: a change's own descriptor could
// otherwise narrow what its scan reads, with an ignore entry over the file it adds a finding to or a
// revision pinned to a commit that does not hold the change, and pass with nothing new.
type RepositoryScope struct {
	URL string `json:"url"`
	// Paths are as the descriptor wrote them, none for the whole repository.
	Paths []string `json:"paths,omitempty"`
	// Ignore are the entries the descriptor's ignore removes from the scan, as written.
	Ignore []string `json:"ignore,omitempty"`
	// Revision is the revision the descriptor pins, empty where it pins none.
	Revision string `json:"revision,omitempty"`
}

// declarations reads what model declares, for the part of it this engine's scope covers.
//
// Read from the descriptor rather than from the jobs that were planned. A control that planned
// nothing, a component with no image under images, still ran as far as the descriptor is
// concerned, and the question a comparison asks of it is whether the change turned it off.
//
// Settings and each repository's scope are recorded as the descriptor wrote them, each `${{ }}`
// reference as the reference: a pipeline variable can hold a different value on every run, such as
// a path under a temporary directory or the commit a job checked out, and a pull request cannot
// change it. The content of a file such a path names is recorded among Files.
func (e *Engine) declarations(model saga.Model, now time.Time) Declarations {
	var d Declarations
	for _, name := range sortedControllerNames(e.reg.controllers) {
		if !e.scope.includesControl(name) {
			continue
		}
		if e.reg.controllers[name].Info().Scope == plugin.ScopeProject && model.Config.ControllerEnabled(name) {
			d.Controls = append(d.Controls, name)
			d.Settings = withSettings(d.Settings, name, SettingsOf(model.SettingsAsWritten(model.Config.Controls[name]), nil))
		}
	}
	for i := range model.Components {
		comp := &model.Components[i]
		if !e.scope.IncludesComponent(comp.Name) {
			continue
		}
		c := ComponentDeclaration{Name: comp.Name, Exposure: comp.Exposure, Criticality: comp.Criticality}
		for _, repo := range comp.Repositories {
			c.Repositories = append(c.Repositories, repo.URL)
			c.Scopes = append(c.Scopes, scopeAsWritten(&model, repo))
		}
		for _, name := range sortedControllerNames(e.reg.controllers) {
			if !e.scope.includesControl(name) || e.reg.controllers[name].Info().Scope != plugin.ScopeComponent {
				continue
			}
			if comp.ControllerEnabled(name, model.Config) {
				c.Controls = append(c.Controls, name)
				c.Settings = withSettings(c.Settings, name, SettingsOf(model.SettingsAsWritten(model.Config.Controls[name]),
					model.SettingsAsWritten(comp.Controls[name])))
			}
		}
		d.Components = append(d.Components, c)
	}
	for _, rule := range model.Config.Exclude {
		if !rule.ExpiredOn(now) {
			d.Exclusions = append(d.Exclusions, rule)
		}
	}
	slices.Sort(d.Controls)
	return d
}

// scopeAsWritten is the part of repo a component's scans read, as the descriptor wrote it. A revision
// written as `${{ GITHUB_SHA }}` holds the base's commit in the base's scan and the head's in the
// head's, so recording the value would read every pull request as moving the revision.
func scopeAsWritten(model *saga.Model, repo saga.Repository) RepositoryScope {
	s := RepositoryScope{
		URL:      model.AsWritten(repo.URL).(string),
		Revision: model.AsWritten(repo.Revision).(string),
	}
	if repo.Paths != nil {
		s.Paths = model.AsWritten(repo.Paths).([]string)
	}
	if repo.Ignore != nil {
		s.Ignore = model.AsWritten(repo.Ignore).([]string)
	}
	return s
}

// SettingsOf is a control's settings as a run reads them, project with component laid over it as
// controllers merge a component's block over the project's, one digest per top-level key. Nil
// where there are none beside the enabled flag. A project-wide control passes a nil component.
//
// Where both set one key, its digest covers the project's value as well as the merged one. A control
// that unions the two rather than letting the component's win, as licenses does with its lists,
// would otherwise read an entry removed from the project's list, under a component's own list, as
// no change.
func SettingsOf(project, component saga.ControllerSettings) ControlSettings {
	merged := saga.MergeSettings(project, component)
	var out ControlSettings
	for key, value := range merged {
		if key == "enabled" {
			continue
		}
		if out == nil {
			out = ControlSettings{}
		}
		under, inProject := project[key]
		if _, inComponent := component[key]; inProject && inComponent {
			out[key] = SettingDigest([]any{value, under})
			continue
		}
		out[key] = SettingDigest(value)
	}
	return out
}

// withSettings is m with control's settings s added, m unchanged where s is empty.
func withSettings(m map[string]ControlSettings, control string, s ControlSettings) map[string]ControlSettings {
	if len(s) == 0 {
		return m
	}
	if m == nil {
		m = map[string]ControlSettings{}
	}
	m[control] = s
	return m
}

// SettingDigest names one setting's value in sixteen hex characters: the first eight bytes of the
// SHA-256 of its JSON, which writes a map's keys in sorted order, so two descriptors that write one
// value with its keys in another order name it alike.
func SettingDigest(value any) string {
	b, err := json.Marshal(value)
	if err != nil {
		// A value JSON cannot write, a map keyed by something other than strings. Go's formatting
		// also writes a map's keys in sorted order, so the same value still names itself alike.
		b = []byte(fmt.Sprintf("%#v", value))
	}
	return git.ContentDigest(b)
}
