package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/tui"
)

// scanModel resolves a scan target into a Saga model. An empty target means the current
// directory. A directory target is scanned zero-config with a synthesized Saga (the
// zeroConfigControls over that repo); a file target is loaded as a Saga descriptor. Returns whether the
// model was synthesized so the caller can note it.
func scanModel(target string) (m *saga.Model, synthesized bool, err error) {
	if target == "" {
		target = "."
	}
	if info, statErr := os.Stat(target); statErr == nil && info.IsDir() {
		// A directory holding a descriptor is not a directory to scan zero-config. Everything
		// in that file — the controls chosen, the components declared, the exposure and
		// criticality that drive prioritization — would otherwise be discarded in favour of
		// four defaults, and nothing in the output would say so.
		//
		// Deliberately not a fallback: if the descriptor is there but unreadable, that is an
		// error. Falling back would reproduce the bug this exists to fix, with an extra step —
		// the reason a descriptor was skipped has to be reported, never shrugged at.
		found, ferr := descriptorsIn(target)
		if ferr != nil {
			return nil, false, ferr
		}
		switch len(found) {
		case 0:
			return syntheticSaga(target), true, nil
		case 1:
			m, err = loadSaga(found[0])
			return m, false, err
		default:
			// Two descriptors are two different accounts of what this project is. Ask when there
			// is someone to ask; refuse with the list when there is not.
			if choice, ok := chooser(found); ok {
				m, err = loadSaga(choice)
				return m, false, err
			}
			return nil, false, ambiguousDescriptors(target, found)
		}
	}
	m, err = loadSaga(target)
	return m, false, err
}

// DescriptorName is the file `draugr init` writes. It is one of several names a scan will find,
// not the only one — see descriptorsIn.
const DescriptorName = "draugr.saga.yaml"

// descriptorSuffixes are the endings that make a file a Saga descriptor.
//
// Any `*.saga.yaml` counts, not just `draugr.saga.yaml`. These are the names our SchemaStore
// entry claims, so an editor already offers completion and validation on all of them — a scan
// that then ignored three of the four would be contradicting our own editor integration. It also
// covers the dotfile form on its own, since `.saga.yaml` has no stem before the suffix.
var descriptorSuffixes = []string{".saga.yaml", ".saga.yml"}

// descriptorsIn returns every Saga descriptor directly in dir, sorted for a stable message.
// Subdirectories are not searched: a descriptor names the project it sits beside, and walking
// would pick up fixtures and vendored trees that describe something else entirely.
func descriptorsIn(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", dir, err)
	}
	var found []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		for _, suffix := range descriptorSuffixes {
			if strings.HasSuffix(e.Name(), suffix) {
				found = append(found, filepath.Join(dir, e.Name()))
				break
			}
		}
	}
	sort.Strings(found)
	return found, nil
}

// chooser asks which descriptor to use. A var so a test can answer without a terminal.
var chooser = promptForDescriptor

// ambiguousDescriptors refuses a directory holding more than one descriptor.
//
// Not a guess. Two descriptors are two different accounts of what this project is: different
// components, different controls, different exposure driving different priorities. Picking one
// by name would produce a verdict about something the reader did not ask about, and nothing in
// the output would say which.
//
// Nor are both scanned. A descriptor carries a release and yields one verdict; running two and
// merging them answers a question nobody asked, and running two and reporting twice is a
// different command from the one that was typed.
//
// Reached only when there was nobody to ask — a prompt in CI would hang a pipeline, which is the
// one outcome worse than stopping.
func ambiguousDescriptors(dir string, found []string) error {
	names := make([]string, len(found))
	for i, p := range found {
		names[i] = filepath.Base(p)
	}
	return fmt.Errorf("%s holds %d descriptors (%s) — name the one to scan, e.g. `draugr scan %s`",
		dir, len(found), strings.Join(names, ", "), filepath.Join(dir, names[0]))
}

// promptForDescriptor asks which descriptor to scan, on a terminal only.
func promptForDescriptor(found []string) (string, bool) {
	if !tui.IsTerminal(os.Stdin) {
		return "", false
	}
	fmt.Fprintf(os.Stderr, "More than one descriptor here. Which should I scan?\n")
	for i, p := range found {
		fmt.Fprintf(os.Stderr, "  %d) %s\n", i+1, filepath.Base(p))
	}
	fmt.Fprintf(os.Stderr, "Choose [1-%d], or anything else to cancel: ", len(found))

	var answer string
	if _, err := fmt.Fscanln(os.Stdin, &answer); err != nil {
		return "", false
	}
	n, err := strconv.Atoi(strings.TrimSpace(answer))
	if err != nil || n < 1 || n > len(found) {
		return "", false
	}
	return found[n-1], true
}

// zeroConfigControls are the controls a zero-config scan enables: the repository-based ones,
// which need nothing but the directory in front of them. This is the single source of truth —
// the help text and the run notice render it rather than restating it, so adding a control here
// can't leave stale prose behind.
var zeroConfigControls = []string{"sca", "secrets", "sast", "iac"}

// ZeroConfigControls lists those controls in a readable form, e.g. "sca, secrets, sast, and iac".
func ZeroConfigControls(conjunction string) string {
	switch len(zeroConfigControls) {
	case 0:
		return ""
	case 1:
		return zeroConfigControls[0]
	}
	head := zeroConfigControls[:len(zeroConfigControls)-1]
	tail := zeroConfigControls[len(zeroConfigControls)-1]
	if conjunction == "" {
		return strings.Join(zeroConfigControls, ", ")
	}
	return strings.Join(head, ", ") + ", " + conjunction + " " + tail
}

// syntheticSaga builds the default zero-config Saga: one component scanning the given directory
// with the repository-based controls. Used when `draugr scan` is pointed at a directory.
func syntheticSaga(dir string) *saga.Model {
	abs, err := filepath.Abs(dir)
	if err != nil {
		abs = dir
	}
	name := filepath.Base(abs)
	if name == "" || name == "." || name == string(filepath.Separator) {
		name = "repo"
	}
	return &saga.Model{
		Release: saga.Release{Name: name, Version: "0.0.0"},
		Config:  saga.Config{Controllers: zeroConfigControllers()},
		Components: []saga.Component{{
			Name:         name,
			Repositories: []saga.Repository{{URL: abs}},
		}},
	}
}

// loadSaga loads a Saga for a command that needs it, presenting any parse/validation failure
// with consistent, actionable context: which file was bad, every problem (Validate aggregates
// them), and a nudge to `draugr validate`. Commands should use this instead of saga.LoadFile
// directly so a bad descriptor reads the same everywhere. (`draugr validate` itself calls
// saga.LoadFile directly — it *is* the check, so the hint would be circular.)
func loadSaga(path string) (*saga.Model, error) {
	model, err := saga.LoadFile(path)
	if err != nil {
		// Indent the underlying (possibly multi-line, aggregated) error under the summary.
		detail := strings.ReplaceAll(err.Error(), "\n", "\n  ")
		return nil, fmt.Errorf("%q is not a valid Saga:\n  %s\nrun `draugr validate %s` to check the descriptor",
			path, detail, path)
	}
	return model, nil
}

// zeroConfigControllers enables each zero-config control in a fresh settings map.
func zeroConfigControllers() map[string]saga.ControllerSettings {
	out := make(map[string]saga.ControllerSettings, len(zeroConfigControls))
	for _, name := range zeroConfigControls {
		out[name] = saga.ControllerSettings{"enabled": true}
	}
	return out
}
