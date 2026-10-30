// Package config is Draugr's machine- and organization-level configuration, kept apart from the
// Saga on purpose.
//
// A Saga describes an application: which repositories it has, how exposed a component is, which
// controls must pass. Those are facts about the software, they belong in its repository, and they
// are meant to differ between projects.
//
// This file describes the machine or the organization running the scan: which build of a scanner
// to install, and what a control should default to before any project says otherwise. Those want
// to be *uniform*, and putting them in a Saga makes them diverge silently. A descriptor that can
// pin its own scanner version is a descriptor that can downgrade one until a finding disappears.
//
// See https://github.com/draugr-dev/draugr/issues/129.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/draugr-dev/draugr/pkg/saga"
)

// The keys of the per-control section, current and older.
const (
	controlsKey      = "controls"
	olderControlsKey = "controllers"
)

// FileName is the config a project may carry beside its Saga.
const FileName = "draugr.config.yaml"

// EnvVar names a config file explicitly, which is the organization-wide lever: set it in a
// runner image and every pipeline picks up the same defaults with no per-repository change.
const EnvVar = "DRAUGR_CONFIG"

// File is a parsed configuration.
type File struct {
	// Tools pins the build of each external scanner. Provisioning rather than behavior, and
	// deliberately not readable from a Saga.
	Tools map[string]ToolSettings `yaml:"tools,omitempty"`
	// Controls are default settings merged *underneath* the Saga's, so a project overrides only
	// the keys it cares about and inherits the rest. The same name and shape as a descriptor's
	// `config.controls`.
	Controls map[string]saga.ControllerSettings `yaml:"controls,omitempty"`
	// Controllers is the older spelling, still read so no file breaks.
	//
	// Deprecated: write `controls`. Folded into Controls when a file is parsed, so nothing else has
	// to know both names.
	Controllers map[string]saga.ControllerSettings `yaml:"controllers,omitempty"`
	// Cache is where scan results are reused between runs, and for how long.
	//
	// Here rather than in a Saga for the same reason as Tools: a cache directory is a fact about
	// a machine or a runner image, not about the application being described. Two projects on one
	// runner want the same cache; one project on two runners does not want its descriptor
	// naming a path that exists on only one of them.
	Cache CacheSettings `yaml:"cache,omitempty"`
	// Publish holds defaults for where a run is delivered.
	//
	// Here rather than in a Saga because an endpoint is a fact about an organization, not about
	// an application: forty projects pointing at one install would otherwise repeat the URL in
	// forty descriptors and change it in forty places when the host moves.
	Publish PublishSettings `yaml:"publish,omitempty"`
	// Output is how a report is rendered for whoever reads it here.
	//
	// A rendering preference belongs to a person or a machine, not to an application: an auditor
	// wants the evidence on every scan they run, and a pipeline wants the same listing for every
	// repository it builds. Putting either in a descriptor asserts it on everyone else who scans
	// that application.
	Output OutputSettings `yaml:"output,omitempty"`
}

// PublishSettings holds defaults for the publishers a run delivers to.
type PublishSettings struct {
	// APIURL is where the draugr-api publisher posts when $DRAUGR_API_URL is unset.
	//
	// Who wrote it decides how far it is trusted, because the publisher sends its token there.
	// From ~/.draugr/config.yaml, or the file --config or $DRAUGR_CONFIG names, it is the machine's
	// answer. From the draugr.config.yaml in the directory being scanned, which is committed with the
	// repository and changes by pull request, it is held to the rule for a url: in the Saga: used
	// only on the machine's server's origin, or one $DRAUGR_API_ORIGINS lists.
	//
	// No token here, and there never will be. This file is committed alongside a project, and a
	// credential in it is a credential in somebody's git history.
	APIURL string `yaml:"apiUrl,omitempty"`
}

// OutputSettings configures how the console renders a run. Each has a `--flag` that overrides it,
// except OfferInstall, which answers a question only a terminal is asked.
type OutputSettings struct {
	// View is what a console report shows: "findings" (a row each, with what argued with the band
	// under it), "actions" (a row per thing to do) or "compact" (one line each).
	View string `yaml:"view,omitempty"`
	// Evidence also prints what stands behind the verdict, tool provenance, what each control
	// measured against, the scanned revision, what the run cost. A pointer, so a more specific
	// file's `false` is a setting that overrides a less specific file's `true`.
	Evidence *bool `yaml:"evidence,omitempty"`
	// Top caps how many rows the fix list shows. Zero means the built-in default rather than
	// "show none": a file that omits a field is not asking for an empty list.
	Top int `yaml:"top,omitempty"`
	// OfferInstall is whether `draugr scan` on a terminal offers to install the scanners it is
	// missing before it runs. Unset means it offers; answering "never" writes false.
	OfferInstall *bool `yaml:"offerInstall,omitempty"`
}

// Offers reports whether a scan on a terminal may offer to install missing scanners.
func (o OutputSettings) Offers() bool { return o.OfferInstall == nil || *o.OfferInstall }

// CacheSettings configures result caching.
type CacheSettings struct {
	// Dir enables caching and says where. Empty leaves caching off, which stays the default:
	// a cache is a promise that an unchanged input has an unchanged answer, and that is a promise
	// somebody should opt into.
	Dir string `yaml:"dir,omitempty"`
	// TTL is how long an entry stays usable. Unset leaves the built-in default; `0s` written in
	// the file means no expiry, as `--cache-ttl 0` does. A pointer, so the two are told apart and
	// a more specific file's `0s` overrides a less specific file's duration.
	TTL *time.Duration `yaml:"ttl,omitempty"`
	// ReadOnly serves entries without writing them, for a run whose results the next run should
	// not trust. Layered one way: a more specific file's `false` does not clear a less specific
	// file's `true`, and Resolved.Overrides reports the `false` that was outranked.
	ReadOnly *bool `yaml:"readOnly,omitempty"`
	// RequireDigest refuses to cache an image named only by a tag, which can be rebuilt under the
	// same name. Layered one way, as ReadOnly is.
	RequireDigest *bool `yaml:"requireDigest,omitempty"`
}

// On reports whether a boolean setting is present and true. An absent one is off.
func On(b *bool) bool { return b != nil && *b }

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
// An explicit path. `--config` or DRAUGR_CONFIG. Is used *alone*. Explicit means explicit: a
// runner image that names a config expects that config, not that one layered over whatever
// happens to be in the working directory.
//
// Otherwise the home file is layered under the project file, so a personal default can be
// overridden by a repository that has an opinion. Missing files are not an error; a machine with
// no configuration is the normal case. Every file is read before an error is returned, so two
// broken files are reported together.
func Load(explicit, workDir string) (Resolved, error) {
	var sources []Source
	var errs []error
	for _, path := range Files(explicit, workDir) {
		f, err := loadFile(path)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		sources = append(sources, Source{Path: path, File: f})
	}
	if len(errs) > 0 {
		return Resolved{}, errors.Join(errs...)
	}
	return Resolve(sources), nil
}

// Resolve layers sources, least specific first, into the configuration in effect: the rule Load
// applies, for a caller that reads and checks the files itself.
func Resolve(sources []Source) Resolved {
	out := Resolved{Sources: sources}
	for _, s := range sources {
		out.File = merge(out.File, s.File)
	}
	return out
}

// Files lists the files Load reads, least specific first: the explicit file alone when one is
// named, whether or not it exists, or else each discovered file that exists.
func Files(explicit, workDir string) []string {
	if explicit = Explicit(explicit); explicit != "" {
		return []string{explicit}
	}
	return Discovered(workDir)
}

// Discovered lists the files that exist where Load looks when no file is named, least specific
// first. With a file named, these are the ones it skips.
func Discovered(workDir string) []string {
	var out []string
	for _, path := range discover(workDir) {
		if _, err := os.Stat(path); err == nil {
			out = append(out, path)
		}
	}
	return out
}

// CurrentKey is a dotted key with the older `controllers` spelling of its first segment replaced
// by `controls`, the name the section is read under.
func CurrentKey(key string) string {
	if rest, ok := strings.CutPrefix(key, olderControlsKey+"."); ok {
		return controlsKey + "." + rest
	}
	if key == olderControlsKey {
		return controlsKey
	}
	return key
}

// ProjectFile is where Load looks for a project's file: FileName in the working directory.
func ProjectFile(workDir string) string { return filepath.Join(workDir, FileName) }

// Explicit is the file named by `--config`, or by DRAUGR_CONFIG when the flag is empty, or "" when
// neither names one. Reading and editing both resolve it here, so `config set` writes the file a
// scan reads.
func Explicit(flag string) string {
	if flag != "" {
		return flag
	}
	return os.Getenv(EnvVar)
}

// discover lists the candidate files, least specific first.
func discover(workDir string) []string {
	var paths []string
	if home, err := os.UserHomeDir(); err == nil {
		paths = append(paths, filepath.Join(home, ".draugr", "config.yaml"))
	}
	return append(paths, ProjectFile(workDir))
}

// loadFile reads and validates one file.
func loadFile(path string) (File, error) {
	data, err := os.ReadFile(path) // #nosec G304 G703 -- operator-provided config path
	if err != nil {
		return File{}, fmt.Errorf("read %s: %w", path, err)
	}
	return Parse(data, path)
}

// Parse decodes and validates a configuration.
//
// Strict: an unknown key is an error rather than something ignored. A misspelled setting that is
// silently dropped is a setting somebody believes is in force, and this file exists to make
// behavior uniform, a typo that quietly opts one machine out defeats the point of having it.
//
// A failure is a *Problems naming every key at fault in the file's own terms, rather than the Go
// types it decodes into, returned beside whatever of the file did decode.
func Parse(data []byte, path string) (File, error) {
	var f File
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	err := dec.Decode(&f)
	foldOlderSpelling(&f)
	empties := emptyValues(data)
	switch {
	case err == nil:
		if len(empties) > 0 {
			return f, &Problems{Path: path, List: empties}
		}
		return f, nil
	case errors.Is(err, io.EOF):
		// An empty file decodes as EOF and is a perfectly good configuration: it says nothing,
		// so nothing is overridden.
		return File{}, nil
	}
	// The decoder carries on past a key it cannot hold, so what it did decode is returned with the
	// problems, for a caller that checks the rest of the file in the same pass.
	var te *yaml.TypeError
	if errors.As(err, &te) {
		return f, &Problems{Path: path, List: append(describe(data, te.Errors), empties...), Hint: keysHintFor(te.Errors)}
	}
	// Not YAML at all. The decoder's message names the line, which is all there is to say.
	return File{}, &Problems{Path: path, List: []string{strings.TrimPrefix(err.Error(), "yaml: ")}}
}

// emptyValues reports each key written with no value, `tools:` on a line of its own or an explicit
// `null` or `~`, by the key it is under.
//
// The decoder reads any of these as the key being absent, so a setting somebody started and did not
// finish is silently not in force, while the JSON Schema an editor holds the file to refuses null.
// Refused for the reason a descriptor refuses it: an editor marking an error in a file Draugr
// accepts teaches its reader to ignore the editor.
func emptyValues(data []byte) []string {
	var root yaml.Node
	if yaml.Unmarshal(data, &root) != nil {
		return nil // the decoder reports the syntax error
	}
	var out []string
	for _, e := range saga.EmptyValues(&root) {
		out = append(out, fmt.Sprintf("%s: no value on line %d; give it one or delete it", CurrentKey(e.Path), e.Line))
	}
	return out
}

// foldOlderSpelling moves `controllers` onto `controls`, once, where a file is parsed, as a
// descriptor's are where it loads.
//
// A file carries both after `config set controls…` writes into one that used the older name, so
// the two are deep-merged rather than one replacing the other: a key only `controllers` sets stays
// in force, and `controls` wins where both set one, because the newer name is the one somebody
// meant.
func foldOlderSpelling(f *File) {
	older := f.Controllers
	f.Controllers = nil
	if len(older) == 0 {
		return
	}
	if f.Controls == nil {
		f.Controls = make(map[string]saga.ControllerSettings, len(older))
	}
	for k, v := range older {
		f.Controls[k] = DeepMerge(v, f.Controls[k])
	}
}

// merge lays b over a, most specific winning per key.
//
// Field by field, and every field has to be named here. A new one added to File and forgotten is
// dropped on every load, not overridden, not defaulted, just absent, with the file on disk
// plainly containing it and `config show` reporting that it sets nothing. TestMergeCarriesEvery
// Field walks the struct so the omission fails a test rather than a user's afternoon.
func merge(a, b File) File {
	out := File{
		Tools:    map[string]ToolSettings{},
		Controls: map[string]saga.ControllerSettings{},
	}
	for k, v := range a.Tools {
		out.Tools[k] = v
	}
	for k, v := range b.Tools {
		out.Tools[k] = v
	}
	for k, v := range a.Controls {
		out.Controls[k] = v
	}
	for k, v := range b.Controls {
		out.Controls[k] = DeepMerge(out.Controls[k], v)
	}
	// Field by field rather than whole-struct, so a project file setting only `ttl` keeps the
	// `dir` the machine file supplied. Replacing the struct would make the more specific file
	// silently discard settings it never mentioned.
	out.Cache = a.Cache
	if b.Cache.Dir != "" {
		out.Cache.Dir = b.Cache.Dir
	}
	if b.Cache.TTL != nil {
		out.Cache.TTL = b.Cache.TTL
	}
	out.Cache.ReadOnly = oneWay(out.Cache.ReadOnly, b.Cache.ReadOnly)
	out.Cache.RequireDigest = oneWay(out.Cache.RequireDigest, b.Cache.RequireDigest)

	out.Publish = a.Publish
	if b.Publish.APIURL != "" {
		out.Publish.APIURL = b.Publish.APIURL
	}

	out.Output = a.Output
	if b.Output.View != "" {
		out.Output.View = b.Output.View
	}
	if b.Output.Evidence != nil {
		out.Output.Evidence = b.Output.Evidence
	}
	if b.Output.Top != 0 {
		out.Output.Top = b.Output.Top
	}
	if b.Output.OfferInstall != nil {
		out.Output.OfferInstall = b.Output.OfferInstall
	}

	if len(out.Tools) == 0 {
		out.Tools = nil
	}
	if len(out.Controls) == 0 {
		out.Controls = nil
	}
	return out
}

// oneWay lays b over a for a setting that only turns on across files.
//
// A machine that declared its results untrustworthy, or refused to cache an image named by a tag,
// keeps that answer when a project file says false. Resolved.Overrides reports each false this
// outranks, so the file that says it is told rather than ignored.
func oneWay(a, b *bool) *bool {
	if b == nil || On(a) {
		return a
	}
	return b
}

// Override is a setting a file makes that a less specific file outranks.
type Override struct {
	// Key is the dotted setting, e.g. "cache.readOnly".
	Key string
	// Path is the file whose value does not take effect.
	Path string
	// By is the less specific file whose value stays in force.
	By string
}

// oneWaySettings are the booleans oneWay layers, by the key a file writes them under.
var oneWaySettings = []struct {
	key string
	get func(File) *bool
}{
	{"cache.readOnly", func(f File) *bool { return f.Cache.ReadOnly }},
	{"cache.requireDigest", func(f File) *bool { return f.Cache.RequireDigest }},
}

// Overrides lists the settings a source makes that do not take effect: a false for a one-way
// setting that a less specific source turned on.
func (r Resolved) Overrides() []Override {
	var out []Override
	for _, s := range oneWaySettings {
		on := ""
		for _, src := range r.Sources {
			v := s.get(src.File)
			switch {
			case v == nil:
			case *v:
				on = src.Path
			case on != "":
				out = append(out, Override{Key: s.key, Path: src.Path, By: on})
			}
		}
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

// asSettings normalizes a decoded mapping. YAML decodes a nested mapping as the enclosing named
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
