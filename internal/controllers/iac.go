package controllers

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

const trivyConfigScanner = "trivy-config"

// Keys of the trivyConfig block this controller reads.
const (
	checksKey     = "checks"
	namespacesKey = "namespaces"
)

// IAC is the Infrastructure-as-Code / misconfiguration control: it scans a component's
// repositories for insecure IaC (Terraform, Kubernetes manifests, Dockerfiles, …). It plans
// one scan per repository.
type IAC struct{}

// NewIAC returns the iac controller.
func NewIAC() plugin.Controller { return IAC{} }

// Info identifies the controller (component-scoped).
func (IAC) Info() plugin.ControllerInfo {
	return plugin.ControllerInfo{
		Name:            "iac",
		Scope:           plugin.ScopeComponent,
		Summary:         "Find settings that leave a door open, in Terraform, Kubernetes and Dockerfiles.",
		DefaultScanners: []string{"trivy-config"},
	}
}

// Plan produces one scan job per repository declared on the component.
func (IAC) Plan(model saga.Model, comp *saga.Component) ([]plugin.ScanJob, error) {
	if comp == nil {
		return nil, nil
	}
	selections, err := iacSelections(model, comp)
	if err != nil {
		return nil, err
	}
	jobs := make([]plugin.ScanJob, 0, len(comp.Repositories)*len(selections))
	for _, repo := range comp.Repositories {
		target := plugin.RepositoryTarget{URL: repo.URL, Revision: repo.Revision,
			Paths: repo.Paths, Ignore: repo.Ignore,
			Upstream: comp.PublishedBy(repo) == saga.BuiltByUpstream}
		for _, sel := range selections {
			jobs = append(jobs, plugin.ScanJob{Scanner: sel.Name, Target: target, Config: sel.Config})
		}
	}
	return jobs, nil
}

// iacSelections resolves the component's scanners and their config, with trivy-config's
// namespaces derived from its checks where the descriptor names none.
//
// Through resolveScanners rather than named directly, even with one scanner to choose from. Naming
// it here would discard the descriptor's iac block before anything could look at it, so an option
// written there would neither take effect nor be reported, and the scanner's declared schema,
// which exists to make that an error, would never be consulted.
func iacSelections(model saga.Model, comp *saga.Component) ([]scannerSelection, error) {
	selections := resolveScanners(model, comp, "iac", []string{trivyConfigScanner})
	for i, sel := range selections {
		if sel.Name != trivyConfigScanner {
			continue
		}
		cfg, err := withCheckNamespaces(sel.Config)
		if err != nil {
			return nil, fmt.Errorf("components[%q].controls.iac.trivyConfig.checks: %w", comp.Name, err)
		}
		selections[i].Config = cfg
	}
	return selections, nil
}

// Validate reports a set of checks whose namespaces cannot be derived: a path that cannot be read,
// a check file with no package line, a directory holding no check. Each is reported once, at the
// first component that reaches it.
//
// Trivy evaluates a custom check only when the top-level name of its package is among the
// namespaces it is given, and it is given none by default. A descriptor that names checks and no
// namespaces has them derived from the checks' own package lines, so a check the derivation cannot
// read would otherwise evaluate nothing and report a clean scan.
func (IAC) Validate(model saga.Model) []error {
	var problems []error
	seen := map[string]bool{}
	for i := range model.Components {
		if _, err := iacSelections(model, &model.Components[i]); err != nil {
			cause := errors.Unwrap(err).Error()
			if !seen[cause] {
				seen[cause] = true
				problems = append(problems, err)
			}
		}
	}
	return problems
}

// Explain states the namespaces derived for each component whose checks name none.
//
// The derived list decides which checks run at all, and it is written nowhere in the descriptor,
// so it is printed where somebody can compare it against the packages they meant to evaluate.
func (IAC) Explain(model saga.Model) []string {
	var out []string
	for i := range model.Components {
		comp := &model.Components[i]
		for _, sel := range resolveScanners(model, comp, "iac", []string{trivyConfigScanner}) {
			if sel.Name != trivyConfigScanner || len(stringsAt(sel.Config, namespacesKey)) > 0 {
				continue
			}
			cfg, err := withCheckNamespaces(sel.Config)
			if namespaces := stringsAt(cfg, namespacesKey); err == nil && len(namespaces) > 0 {
				out = append(out, fmt.Sprintf("iac: component %q evaluates the namespaces its checks declare\n"+
					"trivyConfig.namespaces: [%s]", comp.Name, strings.Join(namespaces, ", ")))
			}
		}
	}
	return out
}

// withCheckNamespaces returns cfg with namespaces derived from the checks' package lines, when it
// names checks and no namespaces, and cfg unchanged otherwise. cfg itself is not modified.
func withCheckNamespaces(cfg plugin.Config) (plugin.Config, error) {
	checks := stringsAt(cfg, checksKey)
	if len(checks) == 0 || len(stringsAt(cfg, namespacesKey)) > 0 {
		return cfg, nil
	}
	namespaces, err := checkNamespaces(checks)
	if err != nil {
		return cfg, err
	}
	out := maps.Clone(cfg)
	list := make([]any, len(namespaces))
	for i, ns := range namespaces {
		list[i] = ns
	}
	out[namespacesKey] = list
	return out, nil
}

// checkNamespaces returns the top-level namespace of every Rego check under paths, sorted and
// without repeats. A path is a check file or a directory walked for them, relative to where Draugr
// runs, which is how the scanner resolves it too.
//
// The top-level name, because that is what Trivy compares: a check in `package user.draugr.tags`
// runs under `--check-namespaces user` and under neither `user.draugr` nor the full package.
func checkNamespaces(paths []string) ([]string, error) {
	found := map[string]bool{}
	for _, path := range paths {
		files, err := regoFiles(path)
		if err != nil {
			return nil, err
		}
		for _, file := range files {
			ns, err := regoNamespace(file)
			if err != nil {
				return nil, err
			}
			found[ns] = true
		}
	}
	return slices.Sorted(maps.Keys(found)), nil
}

// regoFiles lists the check files a path names: the file itself, or every .rego file under a
// directory other than a test. A directory holding none is an error, because Trivy loads nothing
// from it, evaluates nothing, and reports a clean scan.
func regoFiles(path string) ([]string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, unwrapPathError(err))
	}
	if !info.IsDir() {
		return []string{path}, nil
	}
	var files []string
	err = filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && isRegoCheck(d.Name()) {
			files = append(files, p)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, unwrapPathError(err))
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("%s holds no .rego check to derive a namespace from; "+
			"add one or set trivyConfig.namespaces", path)
	}
	return files, nil
}

// isRegoCheck reports whether a file name is a check Trivy loads: Rego, and not a Rego test.
func isRegoCheck(name string) bool {
	return strings.HasSuffix(name, ".rego") && !strings.HasSuffix(name, "_test.rego")
}

// unwrapPathError drops the operation and path an fs error repeats, since the message already
// opens on the path.
func unwrapPathError(err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
}

// regoNamespace returns the top-level name of the package a Rego file declares.
//
// The package line is the first statement of a Rego module, preceded only by comments such as the
// METADATA block. A file without one is not a module and Trivy refuses it when it loads the
// checks, so it is refused here, before anything runs, with the file named.
func regoNamespace(file string) (string, error) {
	f, err := os.Open(file) // #nosec G304 -- a check file the descriptor names
	if err != nil {
		return "", fmt.Errorf("%s: %w", file, unwrapPathError(err))
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		rest, ok := strings.CutPrefix(line, "package")
		if !ok || (rest != "" && rest[0] != ' ' && rest[0] != '\t') {
			break
		}
		if ns := topLevelName(strings.TrimSpace(rest)); ns != "" {
			return ns, nil
		}
		return "", fmt.Errorf("%s: %q names no package to derive a namespace from; "+
			"correct it or set trivyConfig.namespaces", file, line)
	}
	if err := sc.Err(); err != nil {
		return "", fmt.Errorf("%s: %w", file, err)
	}
	return "", fmt.Errorf("%s declares no package to derive a namespace from; "+
		"add a package line or set trivyConfig.namespaces", file)
}

// topLevelName is the first name in a package path: `user` in `user.draugr.tags` and in
// `user["draugr"]`. Rego roots every package under `data`, and a path may say so.
func topLevelName(pkg string) string {
	pkg = strings.TrimPrefix(pkg, "data.")
	end := strings.IndexFunc(pkg, func(r rune) bool {
		return r != '_' && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9')
	})
	if end < 0 {
		end = len(pkg)
	}
	return pkg[:end]
}

// Aggregate merges the scan reports and summarizes findings by severity. Trivy reports
// per-check severity, so severity is taken as reported.
func (IAC) Aggregate(reports []sarif.Report) (plugin.ControlResult, error) {
	merged := sarif.Merge(reports...)
	counts := merged.Counts()
	return plugin.ControlResult{
		Control: "iac",
		Report:  merged,
		Summary: plugin.Summary{
			Errors:   counts.Error,
			Warnings: counts.Warning,
			Notes:    counts.Note,
		},
	}, nil
}
