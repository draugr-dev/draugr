// Package inventory lists what a source tree holds that a control has something to say about:
// dependency files, vendored JavaScript, infrastructure code, Dockerfiles and API documents.
//
// It is what `draugr init` reads to decide what a descriptor enables. Dependency files come from
// internal/manifests, so the files init proposes a scanner for are the files a scan later accounts
// for, and the two cannot disagree about what counts as one. A go.mod is found on its own as well,
// because the Go controls check a module that requires nothing and a scan has no packages to read
// from it.
package inventory

import (
	"bytes"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/draugr-dev/draugr/internal/manifests"
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
	// Terraform are the directories holding a .tf file.
	Terraform []string
	// Kubernetes are manifests outside a Helm chart.
	Kubernetes []string
	// Helm are the directories holding a Chart.yaml.
	Helm []string
	// Dockerfiles are the files an image is built from.
	Dockerfiles []string
	// OpenAPI are OpenAPI and Swagger documents.
	OpenAPI []string
	// Parts are the directories below the root that hold their own dependency file or go.mod, the
	// units a monorepo is made of.
	Parts []string
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
	var yamls []string
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // an unreadable subtree holds nothing init can propose for
		}
		if d.IsDir() {
			if p != root && slices.Contains(skipDirs, d.Name()) {
				return filepath.SkipDir
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
		case base == "Chart.yaml":
			helm[path.Dir(rel)] = true
		case strings.HasSuffix(base, ".tf"):
			terraform[path.Dir(rel)] = true
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

	parts := map[string]bool{}
	for _, f := range t.Dependencies {
		parts[path.Dir(f.Path)] = true
	}
	for _, dir := range t.Go {
		parts[dir] = true
	}
	delete(parts, ".")
	t.Parts = sortedKeys(parts)

	for _, rel := range yamls {
		head := readHead(filepath.Join(root, filepath.FromSlash(rel)))
		switch {
		case isOpenAPI(rel, head):
			t.OpenAPI = append(t.OpenAPI, rel)
		case isKubernetes(rel, head) && !insideAny(rel, t.Helm):
			t.Kubernetes = append(t.Kubernetes, rel)
		}
	}
	slices.Sort(t.Dockerfiles)
	slices.Sort(t.VendoredJS)
	slices.Sort(t.OpenAPI)
	slices.Sort(t.Kubernetes)
	return t
}

// isDockerfile matches Dockerfile, Dockerfile.prod, api.Dockerfile and Containerfile.
func isDockerfile(base string) bool {
	return base == "Dockerfile" || base == "Containerfile" ||
		strings.HasPrefix(base, "Dockerfile.") || strings.HasSuffix(base, ".Dockerfile")
}

// isVendoredJS reports whether a .js file is a copy of a library: minified, named for a release,
// or kept under a directory named vendor. Code written in the repository is none of the three,
// and a lockfile already accounts for a library installed through one.
func isVendoredJS(rel string) bool {
	base := path.Base(rel)
	if strings.HasSuffix(base, ".min.js") || versioned.MatchString(base) {
		return true
	}
	return slices.Contains(strings.Split(path.Dir(rel), "/"), "vendor")
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

func readHead(p string) []byte {
	f, err := os.Open(p) // #nosec G304 -- a file under the tree being initialized
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	head, _ := io.ReadAll(io.LimitReader(f, headBytes))
	return head
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}
