// Package inventory lists what a source tree holds that a control has something to say about:
// dependency files, vendored JavaScript, infrastructure code, Dockerfiles, API documents, and SARIF
// files another tool wrote, in the tree or from a CI step.
//
// It is what `draugr init` reads to decide what a descriptor enables. Dependency files come from
// internal/manifests, so the files init proposes a scanner for are the files a scan later accounts
// for, and the two cannot disagree about what counts as one. A go.mod is found on its own as well,
// because the Go controls check a module that requires nothing and a scan has no packages to read
// from it.
package inventory

import (
	"bytes"
	"io/fs"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/draugr-dev/draugr/internal/manifests"
	"github.com/draugr-dev/draugr/internal/nonshipping"
)

// Tree is what a directory holds. Every path is slash-separated and relative to the root.
type Tree struct {
	// Dependencies are the files that declare or pin packages.
	Dependencies []manifests.File
	// Unresolved are the dependency files a manifest scanner takes no packages from: a declared
	// manifest with no lockfile, a requirements file with no exact version.
	Unresolved []manifests.Unread
	// TrivyUnread are dependency files Trivy does not read and Grype does.
	TrivyUnread []manifests.File
	// TrivyByPattern are the requirements files Trivy reads only where trivyFs.filePatterns names
	// them: its pip analyzer opens requirements.txt and no other name.
	TrivyByPattern []manifests.File
	// Go are the directories holding a go.mod, whether or not it requires anything: standard-library
	// code still has SAST findings, and still builds with a toolchain that has advisories of its own.
	Go []string
	// VendoredJS are JavaScript files committed as copies of a library rather than written here.
	VendoredJS []string
	// Terraform are the directories holding Terraform or OpenTofu code or variables.
	Terraform []string
	// Kubernetes are manifests outside a Helm chart.
	Kubernetes []string
	// Helm are the directories holding a Chart.yaml.
	Helm []string
	// Dockerfiles are the files an image is built from.
	Dockerfiles []string
	// CloudFormation are AWS CloudFormation templates.
	CloudFormation []string
	// AzureARM are Azure Resource Manager templates.
	AzureARM []string
	// TerraformPlans are Terraform plans written as JSON.
	TerraformPlans []string
	// Ansible are the entries that make a directory an Ansible project to Trivy: an ansible.cfg, an
	// inventory, group_vars, host_vars, roles or playbooks, or a playbook.
	Ansible []string
	// OpenAPI are OpenAPI and Swagger documents.
	OpenAPI []string
	// Serves are the files that say the tree runs something reached over a network: a Dockerfile
	// that exposes a port, a Kubernetes Service or Ingress, and a Compose file that publishes ports.
	Serves []string
	// Parts are the directories below the root that hold their own dependency file or go.mod, the
	// units a monorepo is made of. A JavaScript workspace member, a directory the root package.json
	// or pnpm-workspace.yaml names, is not one by its package.json alone: the lockfile at the
	// workspace root resolves it, so it stays with that root.
	Parts []string
	// NonShipping are the directories holding documentation, examples or tests, by the names
	// internal/nonshipping lists, outermost only: `test/` and not `test/integration/testdata/` beneath
	// it. A directory under vendor/ is someone else's and is left out.
	NonShipping []string
	// SARIF are the SARIF files another tool wrote that a descriptor could import: the ones in the
	// tree, then the ones a CI step writes or uploads that the tree does not hold. Draugr's own output
	// and files under NonShipping are left out.
	SARIF []SARIF
}

// trivyUnread names the dependency files Trivy's filesystem scan does not parse and Grype's does.
// Everything else manifests recognizes, Trivy reads, except a requirements file named anything but
// trivyPip.
var trivyUnread = []string{"setup.py", "pdm.lock"}

// trivyPip is the one requirements file Trivy's pip analyzer opens by name. requirements-dev.txt,
// dev-requirements.txt and requirements/test.txt are read only where a file pattern names them.
const trivyPip = "requirements.txt"

// skipDirs hold installed copies of other people's code, or tooling state. vendor/ is walked here,
// unlike in manifests: a vendored Go module is not the project's, but a vendored jquery.js is
// exactly the file retire.js exists to find.
var skipDirs = []string{".git", "node_modules", ".venv", "venv", "site-packages", "__pycache__", ".tox", ".terraform"}

// versioned matches a library file named for its release: jquery-1.8.3.js, angular.1.2.min.js.
var versioned = regexp.MustCompile(`[-.@]v?\d+\.\d+(\.\d+)?([-.][0-9A-Za-z]+)*\.js$`)

// headBytes is how much of a YAML or JSON file is read to decide what it is. The keys that say so
// open the document.
const headBytes = 4096

// Read walks root and returns what it holds.
func Read(root string) Tree {
	t := Tree{Dependencies: manifests.Find(root)}
	for _, f := range t.Dependencies {
		switch {
		case slices.Contains(trivyUnread, path.Base(f.Path)):
			t.TrivyUnread = append(t.TrivyUnread, f)
		case manifests.FormatOf(f.Path) == trivyPip && path.Base(f.Path) != trivyPip:
			t.TrivyByPattern = append(t.TrivyByPattern, f)
		}
	}
	// Accounted as though nothing had been read: what is left once NotRead is set aside is what no
	// scanner could read, which is the part known before a scan runs.
	for _, u := range manifests.Account(root, nil) {
		if u.Reason != manifests.NotRead {
			t.Unresolved = append(t.Unresolved, u)
		}
	}

	terraform, helm, goMods := map[string]bool{}, map[string]bool{}, map[string]bool{}
	var yamls, nonShipping, sarifs []string
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // an unreadable subtree holds nothing init can propose for
		}
		if d.IsDir() {
			if p != root && slices.Contains(skipDirs, d.Name()) {
				return filepath.SkipDir
			}
			if p == root {
				return nil
			}
			rel, err := filepath.Rel(root, p)
			if err != nil {
				return nil //nolint:nilerr // outside the root cannot happen under WalkDir
			}
			rel = filepath.ToSlash(rel)
			// Recorded and still walked: a Dockerfile under tests/ is still something iac reads.
			if nonshipping.DirKind(d.Name()) != "" {
				nonShipping = append(nonShipping, rel)
			}
			if isAnsibleAnchor(rel) {
				t.Ansible = append(t.Ansible, rel)
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return nil //nolint:nilerr // outside the root cannot happen under WalkDir
		}
		rel = filepath.ToSlash(rel)
		base := d.Name()
		if isAnsibleAnchor(rel) {
			t.Ansible = append(t.Ansible, rel)
		}
		switch {
		case base == "go.mod":
			// Found here rather than taken from Dependencies: manifests leaves out a go.mod that
			// requires nothing, because a scan has no packages to read from it, and the Go
			// controls still have code to check. A vendored module's go.mod is not the project's.
			if !slices.Contains(strings.Split(path.Dir(rel), "/"), "vendor") {
				goMods[path.Dir(rel)] = true
			}
		case isDockerfile(base):
			t.Dockerfiles = append(t.Dockerfiles, rel)
			if exposes(readUpTo(p, dockerfileBytes)) {
				t.Serves = append(t.Serves, rel)
			}
		case base == "Chart.yaml":
			helm[path.Dir(rel)] = true
		case isTerraform(base):
			terraform[path.Dir(rel)] = true
		case strings.HasSuffix(base, ".sarif"):
			sarifs = append(sarifs, rel)
		case strings.HasSuffix(base, ".js"):
			if isVendoredJS(rel) {
				t.VendoredJS = append(t.VendoredJS, rel)
			}
		case strings.HasSuffix(base, ".yaml"), strings.HasSuffix(base, ".yml"), strings.HasSuffix(base, ".json"):
			yamls = append(yamls, rel)
		}
		return nil
	})
	t.Terraform = sortedKeys(terraform)
	t.Helm = sortedKeys(helm)
	t.Go = sortedKeys(goMods)
	t.NonShipping = outermost(nonShipping)

	// A workspace member's package.json is resolved by the lockfile at the workspace root, so it
	// makes its directory no part. A lockfile of its own, or a dependency file of another
	// ecosystem, still does.
	wss := workspaces(root, yamls)
	parts := map[string]bool{}
	for _, f := range t.Dependencies {
		dir := path.Dir(f.Path)
		if f.Ecosystem == "npm" && f.Kind == manifests.Declared && member(dir, wss) {
			continue
		}
		parts[dir] = true
	}
	for _, dir := range t.Go {
		parts[dir] = true
	}
	delete(parts, ".")
	t.Parts = sortedKeys(parts)

	for _, rel := range yamls {
		data := readUpTo(filepath.Join(root, filepath.FromSlash(rel)), sniffBytes)
		head := data[:min(len(data), headBytes)]
		switch {
		case isOpenAPI(rel, head):
			t.OpenAPI = append(t.OpenAPI, rel)
		case isKubernetes(rel, head) && !insideAny(rel, t.Helm):
			t.Kubernetes = append(t.Kubernetes, rel)
		default:
			switch iacKind(rel, data) {
			case kindCloudFormation:
				t.CloudFormation = append(t.CloudFormation, rel)
			case kindAzureARM:
				t.AzureARM = append(t.AzureARM, rel)
			case kindTerraformPlan:
				t.TerraformPlans = append(t.TerraformPlans, rel)
			case kindKubernetes:
				if !insideAny(rel, t.Helm) {
					t.Kubernetes = append(t.Kubernetes, rel)
				}
			case kindAnsible:
				t.Ansible = append(t.Ansible, rel)
			}
		}
		if !strings.HasSuffix(rel, ".json") && (declaresService(data) || isCompose(path.Base(rel)) && publishesPorts(data)) {
			t.Serves = append(t.Serves, rel)
		}
	}
	slices.Sort(t.Dockerfiles)
	slices.Sort(t.CloudFormation)
	slices.Sort(t.AzureARM)
	slices.Sort(t.TerraformPlans)
	slices.Sort(t.Ansible)
	slices.Sort(t.Serves)
	slices.Sort(t.VendoredJS)
	slices.Sort(t.OpenAPI)
	slices.Sort(t.Kubernetes)

	var workflows []string
	for _, rel := range yamls {
		if isWorkflow(rel) {
			workflows = append(workflows, rel)
		}
	}
	slices.Sort(workflows)
	inTree := sarifInTree(root, sarifs, t.NonShipping)
	t.SARIF = append(inTree, sarifInCI(root, workflows, inTree)...)
	return t
}

// outermost are the directories not beneath another of them, sorted, and none under vendor/.
func outermost(dirs []string) []string {
	slices.Sort(dirs)
	var out []string
	for _, d := range dirs {
		if slices.Contains(strings.Split(d, "/"), "vendor") || insideAny(d, out) {
			continue
		}
		out = append(out, d)
	}
	return out
}

// isDockerfile matches the names Trivy reads as a Dockerfile: Dockerfile, Dockerfile.prod,
// api.Dockerfile and api.dockerfile, and the same with Containerfile.
func isDockerfile(base string) bool {
	for _, name := range []string{"Dockerfile", "Containerfile"} {
		if base == name || strings.HasPrefix(base, name+".") || strings.EqualFold(path.Ext(base), "."+name) {
			return true
		}
	}
	return false
}

// isVendoredJS reports whether a .js file is a copy of a library: kept under a directory named
// vendor, or minified or named for a release. Code written in the repository is none of these, and
// a lockfile already accounts for a library installed through one.
//
// The name is not trusted for a test: a file named `*.test.js` or `*.spec.js`, or one under a test
// directory, carries a version or `.min` in its name as often to say what it tests as because it is
// a library, so only vendor/ marks one of those as a copy.
func isVendoredJS(rel string) bool {
	if slices.Contains(strings.Split(path.Dir(rel), "/"), "vendor") {
		return true
	}
	base := path.Base(rel)
	if strings.HasSuffix(base, ".test.js") || strings.HasSuffix(base, ".spec.js") || nonshipping.KindOf(rel) == nonshipping.Test {
		return false
	}
	return strings.HasSuffix(base, ".min.js") || versioned.MatchString(base)
}

// isOpenAPI reports whether a document opens with the key an OpenAPI 3 or Swagger 2 document
// must carry.
func isOpenAPI(rel string, head []byte) bool {
	if strings.HasSuffix(rel, ".json") {
		return bytes.Contains(head, []byte(`"openapi"`)) || bytes.Contains(head, []byte(`"swagger"`))
	}
	return topLevelKey(head, "openapi") || topLevelKey(head, "swagger")
}

// isKubernetes reports whether a YAML file declares a Kubernetes object: apiVersion and kind at the
// top level. A Helm Chart.yaml has the first and not the second.
func isKubernetes(rel string, head []byte) bool {
	if strings.HasSuffix(rel, ".json") {
		return false
	}
	return topLevelKey(head, "apiVersion") && topLevelKey(head, "kind")
}

// topLevelKey reports whether a YAML document has key at column zero.
func topLevelKey(head []byte, key string) bool {
	for line := range bytes.SplitSeq(head, []byte("\n")) {
		if bytes.HasPrefix(line, []byte(key+":")) {
			return true
		}
	}
	return false
}

// insideAny reports whether rel is beneath one of dirs.
func insideAny(rel string, dirs []string) bool {
	for _, d := range dirs {
		if d == "." || strings.HasPrefix(rel, d+"/") {
			return true
		}
	}
	return false
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}
