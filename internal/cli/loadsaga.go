package cli

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/draugr-dev/draugr/internal/builtins"
	"github.com/draugr-dev/draugr/internal/git"
	"github.com/draugr-dev/draugr/internal/inventory"
	"github.com/draugr-dev/draugr/internal/sagafetch"
	"github.com/draugr-dev/draugr/internal/scaffold"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/tui"
)

// scanModel resolves a scan target into a Saga model. An empty target means the current
// directory. A directory target with no descriptor is scanned zero-config, with the model `draugr
// init` would write for it; a file target is loaded as a Saga descriptor. Returns whether the model
// was synthesized so the caller can note it.
func scanModel(target string) (m *saga.Model, synthesized bool, err error) {
	res, zc, err := scanResolved(target)
	if err != nil {
		return nil, zc != nil, err
	}
	return res.Model, zc != nil, nil
}

// scanResolved is scanModel keeping the resolution, for the caller that reports which files the
// scan was driven by, and what the tree held where there was no descriptor to say.
//
// A synthesized model has no files behind it, and its Resolved carries no sources rather than one
// naming a file that was never read. Its zeroConfig is nil for a model loaded from a descriptor.
func scanResolved(target string) (*saga.Resolved, *zeroConfig, error) {
	path, found, err := resolveDescriptor(target, "scan")
	if err != nil {
		return nil, nil, err
	}
	if !found {
		if target == "" {
			target = "."
		}
		zc, err := synthesize(target)
		if err != nil {
			return nil, nil, err
		}
		return &saga.Resolved{Model: zc.model}, zc, nil
	}
	res, err := loadResolved(context.Background(), path, true)
	return res, nil, err
}

// resolveDescriptor turns a path that may be a directory into the descriptor to act on. An empty
// target means the current directory. A file is taken as given; a directory is looked in.
//
// found is false, with no error, only when a directory holds no descriptor at all. That is the
// one outcome commands differ on: `scan` synthesizes one and says so, and everything that reads
// or edits a descriptor has nothing to work with and must say that instead.
//
// A directory holding a descriptor is never treated as a bare directory. Everything in that file,
// the controls chosen, the components declared, the exposure and criticality that drive
// prioritization. Would otherwise be discarded in favor of defaults, with nothing in the output
// saying so. Nor is it a fallback: if the descriptor is there but unreadable, that is an error.
// Falling back would reproduce the bug this exists to prevent with an extra step, because the
// reason a descriptor was skipped has to be reported, never shrugged at.
//
// cmdName appears in the message that refuses an ambiguous directory, so the suggestion it prints
// is a command the reader can actually run.
func resolveDescriptor(target, cmdName string) (path string, found bool, err error) {
	if target == "" {
		target = "."
	}
	info, statErr := os.Stat(target)
	if errors.Is(statErr, fs.ErrNotExist) {
		// Said here rather than by the loader, whose message ends by suggesting `draugr validate`
		// on the same missing file.
		return "", false, fmt.Errorf("%s does not exist", target)
	}
	if statErr != nil || !info.IsDir() {
		return target, true, nil
	}
	descriptors, err := descriptorsIn(target)
	if err != nil {
		return "", false, err
	}
	switch len(descriptors) {
	case 0:
		return "", false, nil
	case 1:
		return descriptors[0], true, nil
	default:
		// Two descriptors are two different accounts of what this project is. Ask when there is
		// someone to ask; refuse with the list when there is not.
		if choice, ok := chooser(descriptors); ok {
			return choice, true, nil
		}
		return "", false, ambiguousDescriptors(target, cmdName, descriptors)
	}
}

// DescriptorName is the file `draugr init` writes. It is one of several names a scan will find, not
// the only one. See descriptorsIn.
const DescriptorName = "draugr.saga.yaml"

// descriptorSuffixes are the endings that make a file a Saga descriptor.
//
// Any `*.saga.yaml` counts, not just `draugr.saga.yaml`. These are the names our SchemaStore entry
// claims, so an editor already offers completion and validation on all of them, a scan that then
// ignored three of the four would be contradicting our own editor integration. It also covers the
// dotfile form on its own, since `.saga.yaml` has no stem before the suffix.
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
// Reached only when there was nobody to ask. A prompt in CI would hang a pipeline, which is the one
// outcome worse than stopping.
func ambiguousDescriptors(dir, cmdName string, found []string) error {
	names := make([]string, len(found))
	for i, p := range found {
		names[i] = filepath.Base(p)
	}
	return fmt.Errorf("%s holds %d descriptors (%s). Name the one to use, e.g. `draugr %s %s`",
		dir, len(found), strings.Join(names, ", "), cmdName, filepath.Join(dir, names[0]))
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

// zeroConfigBase is what a zero-config scan runs on a tree that holds nothing a scanner is chosen for:
// the controls `draugr init` turns on whatever the tree holds, each with its default scanners.
var zeroConfigBase = sync.OnceValues(func() (*saga.Model, error) {
	return scaffold.Model(inventory.Tree{}, "app")
})

// zeroConfigControls are the controls a zero-config scan enables on any tree, read off zeroConfigBase,
// in name order. The help text and `draugr tools install` render them rather than restating them,
// so a control the scaffold gains cannot leave stale prose behind.
func zeroConfigControls() []string {
	m, err := zeroConfigBase()
	if err != nil {
		return nil
	}
	var out []string
	for name := range m.Config.Controls {
		if m.Config.ControllerEnabled(name) {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// ZeroConfigControls lists those controls in a readable form, e.g. "iac, sast, sca, and secrets".
func ZeroConfigControls(conjunction string) string {
	controls := zeroConfigControls()
	switch len(controls) {
	case 0:
		return ""
	case 1:
		return controls[0]
	}
	if conjunction == "" {
		return strings.Join(controls, ", ")
	}
	head, tail := controls[:len(controls)-1], controls[len(controls)-1]
	return strings.Join(head, ", ") + ", " + conjunction + " " + tail
}

// zeroConfig is a scan of a directory that holds no descriptor: what the tree held, and the model
// made of it.
type zeroConfig struct {
	tree  inventory.Tree
	model *saga.Model
}

// synthesize reads dir as `draugr init` does and returns the model init would write for it, with
// one component scanning the directory.
//
// The model is read from the text init writes (scaffold.Model), so a zero-config scan runs every
// scanner the tree calls for and nothing init leaves commented out. The project, the component and
// the repository are named as init names them, read from the working directory. A finding's
// identity includes its component and its repository, so a run after `init` and a zero-config run
// of the same directory report the same findings.
//
// The repository is the one change from the text. init writes Here, for a descriptor that sits in
// the directory it describes; a scan may be pointed at the directory from anywhere, and the url is
// that directory as the working directory reaches it.
func synthesize(dir string) (*zeroConfig, error) {
	tree := inventory.Read(dir)
	m, err := scaffold.Model(tree, scaffold.NameFor(dir))
	if err != nil {
		return nil, err
	}
	m.Components[0].Repositories[0].URL = scaffold.RepositoryURL(dir)
	return &zeroConfig{tree: tree, model: m}, nil
}

// syntheticSaga is the model a zero-config scan of dir runs.
func syntheticSaga(dir string) (*saga.Model, error) {
	zc, err := synthesize(dir)
	if err != nil {
		return nil, err
	}
	return zc.model, nil
}

// loadSaga loads a Saga for a command that needs it, presenting any parse/validation failure with
// consistent, actionable context: which file was bad, every problem (Validate aggregates them), and
// a nudge to `draugr validate`. Commands should use this instead of saga.LoadFile directly so a bad
// descriptor reads the same everywhere. (`draugr validate` itself calls saga.LoadFile directly. It
// *is* the check, so the hint would be circular.)
func loadSaga(path string) (*saga.Model, error) { return loadSagaCtx(context.Background(), path) }

// loadSagaCtx is loadSaga with a context, so fetching a remote fragment can be canceled with the
// rest of the run.
func loadSagaCtx(ctx context.Context, path string) (*saga.Model, error) {
	res, err := loadResolvedCtx(ctx, path)
	if err != nil {
		return nil, err
	}
	return res.Model, nil
}

// loadResolvedCtx is loadSagaCtx keeping the resolution: which files the descriptor was assembled
// from, and their digests.
//
// A caller that only needs the model should use loadSagaCtx. A run that will be published needs the
// sources, because a report recording what was found and not what was asked for cannot answer why a
// control ran. And the resolution is discarded the moment the process exits.
func loadResolvedCtx(ctx context.Context, path string) (*saga.Resolved, error) {
	return loadResolved(ctx, path, false)
}

// loadResolved is loadResolvedCtx, and with history set it also records what git's history says
// about the line each exclusion is written at, for the report.
//
// Recorded here, before the fetcher is closed, because closing it removes the checkout of every
// fragment fetched from another repository, and that checkout is the only copy of its history on
// this machine. Only a scan asks: the history is evidence in a report, and every other command
// that loads a descriptor would run git for nothing.
func loadResolved(ctx context.Context, path string, history bool) (*saga.Resolved, error) {
	fetcher := sagafetch.New(ctx)
	defer fetcher.Close()

	res, err := saga.ResolveFile(path, fetcher)
	var model *saga.Model
	if res != nil {
		model = res.Model
	}
	if err != nil {
		// Indent the underlying (possibly multi-line, aggregated) error under the summary.
		detail := strings.ReplaceAll(err.Error(), "\n", "\n  ")
		return nil, fmt.Errorf("%q is not a valid Saga:\n  %s\nrun `draugr validate %s` to check the descriptor",
			path, detail, path)
	}
	if err := checkDescriptorControls(builtins.Registry(), path, model); err != nil {
		return nil, err
	}
	if history {
		git.RecordExclusionHistory(ctx, model.Config.Exclude)
	}
	return res, nil
}

// checkDescriptorControls is checkControlNames for a loaded descriptor, with the path in the message.
// One function for every command that loads a descriptor to act on it, so a misspelled control is
// refused with the same did-you-mean by scan, doctor and validate alike.
//
// Checked here rather than in pkg/saga: only the registry knows what this build can run, and
// pkg/saga cannot import it without a cycle. Which is also why the schema's control list is
// generated from the registry rather than written beside it.
func checkDescriptorControls(reg *engine.Registry, path string, model *saga.Model) error {
	if err := checkControlNames(reg, model); err != nil {
		return fmt.Errorf("%q names a control Draugr cannot run:\n  %s",
			path, strings.ReplaceAll(err.Error(), "\n", "\n  "))
	}
	return nil
}
