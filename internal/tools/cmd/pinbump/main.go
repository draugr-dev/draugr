// Command pinbump moves one pinned scanner to a new version and records what that version hashes
// to.
//
//	go run ./internal/tools/cmd/pinbump trivy            # to whatever its upstream publishes now
//	go run ./internal/tools/cmd/pinbump trivy 0.74.0     # to a version you name
//
// Only the manifest. Whether the new version still works is a different question, answered by
// installing it and scanning with it, which is what the workflow around this does and what a
// hash can never tell you.
//
// **Every hash is of the bytes.** Where an upstream also publishes a checksums file it is read and
// compared, because a checksums file is a claim and the bytes are the fact, and nothing is written
// unless every platform agreed.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/draugr-dev/draugr/internal/tools"
)

func main() {
	if len(os.Args) < 2 || len(os.Args) > 3 {
		fail("usage: pinbump <tool> [version]")
	}
	// Both arguments reach a file path, a URL and a subprocess, so both are checked against what
	// they are allowed to be before anything uses them. A tool has to be one this build pins,
	// which is a closed set, and a version has to look like one. Cheaper than reasoning about
	// where each value ends up, and it turns a confusing failure deep in a rewrite into one
	// sentence here.
	tool := os.Args[1]
	if !known(tool) {
		fail("%q is not a tool this build pins; one of %s", tool, strings.Join(tools.Installable(), " "))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	version := ""
	if len(os.Args) == 3 {
		version = strings.TrimPrefix(os.Args[2], "v")
		if !versionLike.MatchString(version) {
			fail("%q is not a version; expected digits and dots, as 1.2.3", version)
		}
	} else {
		latest, err := tools.Latest(ctx, nil, tool)
		if err != nil {
			fail("%s: %v", tool, err)
		}
		// Held to the same shape as one typed by hand. It arrived over the network from a service
		// naming its own tags, and a tag is a string somebody upstream chose.
		if !versionLike.MatchString(latest) {
			fail("%s publishes %q as its newest version, which is not a shape this writes into a "+
				"manifest", tool, latest)
		}
		version = latest
	}

	was := tools.PinnedVersion(tool)
	if was == "" {
		fail("%s: not a tool this build pins", tool)
	}
	if was == version {
		fmt.Printf("%s is already at %s\n", tool, version)
		return
	}

	root, err := repoRoot()
	if err != nil {
		fail("%v", err)
	}

	switch {
	case isBinary(tool):
		err = bumpBinary(ctx, root, tool, was, version)
	case isGo(tool):
		err = bumpConst(filepath.Join(root, "internal/tools/gotool.go"),
			"govulncheckVersion", was, version)
	case isPython(tool):
		err = bumpPython(root, tool, was, version)
	case isNode(tool):
		err = bumpNode(root, tool, was, version)
	default:
		err = fmt.Errorf("%s: nothing here knows how it is packaged", tool)
	}
	if err != nil {
		fail("%v", err)
	}
	fmt.Printf("%s: %s to %s\n", tool, was, version)
}

// versionLike is what a pinned version may look like. Every upstream here publishes dotted
// numbers, and anything else is either a mistake or an attempt to reach somewhere else.
var versionLike = regexp.MustCompile(`^[0-9]+(\.[0-9]+)*$`)

// known reports whether this is a tool the manifest pins.
func known(name string) bool {
	for _, n := range tools.Installable() {
		if n == name {
			return true
		}
	}
	return false
}

func isBinary(name string) bool { _, ok := tools.Spec(name); return ok }
func isGo(name string) bool     { _, ok := tools.GoTool(name); return ok }
func isPython(name string) bool { _, ok := tools.PythonTool(name); return ok }
func isNode(name string) bool   { _, ok := tools.NodeTool(name); return ok }

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "pinbump: "+format+"\n", args...)
	os.Exit(1)
}

// repoRoot is the checkout this is running inside.
func repoRoot() (string, error) {
	out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return "", fmt.Errorf("finding the repository root: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

var (
	// blockStart finds where each tool's spec begins in the manifest.
	blockStart = regexp.MustCompile(`(?m)^\t"([a-z-]+)": \{\n\t\tBinary:\s+"`)
	// templateAt finds an asset's URL template, which is what every rewrite is anchored to.
	templateAt = regexp.MustCompile(`URLTemplate:(\s+)"([^"]+)"`)
	// digestAt finds a recorded hash.
	digestAt = regexp.MustCompile(`SHA256:(\s+)"([a-f0-9]{64})"`)
	// versionAt finds the pinned version.
	versionAt = regexp.MustCompile(`Version: "([^"]+)"`)
)

// bumpBinary rewrites one tool's block in the manifest.
func bumpBinary(ctx context.Context, root, tool, was, version string) error {
	path := filepath.Join(root, "internal/tools/install.go")
	source, err := os.ReadFile(path) // #nosec G304 G703 -- a fixed path under the checkout root
	if err != nil {
		return err
	}
	text := string(source)
	start, end, err := blockOf(text, tool)
	if err != nil {
		return err
	}
	body := text[start:end]

	// Hash every platform before rewriting anything, so a release missing one asset leaves the
	// manifest on the version that is known to be whole.
	fresh := map[string]string{}
	claimed, err := publishedSums(ctx, body, version)
	if err != nil {
		return err
	}
	for _, m := range templateAt.FindAllStringSubmatch(body, -1) {
		url := strings.ReplaceAll(m[2], "{version}", version)
		sum, err := hashOf(ctx, url)
		if err != nil {
			return fmt.Errorf("%s\nthe asset names may have changed at %s; the manifest is "+
				"untouched: %w", url, version, err)
		}
		name := url[strings.LastIndex(url, "/")+1:]
		if want, ok := claimed[name]; ok && want != sum {
			return fmt.Errorf("%s: the checksums file says %s and the bytes hash to %s; the "+
				"manifest is untouched", name, want, sum)
		}
		fresh[url] = sum
		fmt.Printf("  %s %s\n", name, sum)
	}

	body = versionAt.ReplaceAllString(body, `Version: "`+version+`"`)
	// URLs are rebuilt from the template rather than string-replaced on the old version, which
	// would also rewrite a version that happens to appear inside a path.
	for _, m := range templateAt.FindAllStringSubmatch(body, -1) {
		body = strings.ReplaceAll(body,
			`"`+strings.ReplaceAll(m[2], "{version}", was)+`"`,
			`"`+strings.ReplaceAll(m[2], "{version}", version)+`"`)
	}
	body = rewriteDigests(body, version, fresh)

	// #nosec G703 -- path is filepath.Join(root, <constant>); the tool name selects a block
	// inside the file, never the file
	return os.WriteFile(path, []byte(text[:start]+body+text[end:]), 0o600)
}

// rewriteDigests puts each hash under the template it belongs to.
//
// Anchored to the template above it, never paired by position in a flat list. A signing block
// declares a checksums file and its bundle and carries no hash of its own, so a flat pairing walks
// out of step at the first one and writes the hash of a checksums file into a platform's binary,
// which pins a value the bytes never had.
func rewriteDigests(body, version string, fresh map[string]string) string {
	for {
		templates := templateAt.FindAllStringSubmatchIndex(body, -1)
		changed := false
		for i, t := range templates {
			stop := len(body)
			if i+1 < len(templates) {
				stop = templates[i+1][0]
			}
			d := digestAt.FindStringSubmatchIndex(body[t[1]:stop])
			if d == nil {
				continue // a signing URL, which has no hash of its own
			}
			url := strings.ReplaceAll(body[t[4]:t[5]], "{version}", version)
			want, ok := fresh[url]
			if !ok {
				continue
			}
			at, to := t[1]+d[0], t[1]+d[1]
			if body[t[1]+d[4]:t[1]+d[5]] == want {
				continue // already right
			}
			body = body[:at] + "SHA256:" + body[t[1]+d[2]:t[1]+d[3]] + `"` + want + `"` + body[to:]
			changed = true
			break // offsets moved; find them again
		}
		if !changed {
			return body
		}
	}
}

// blockOf is where a tool's spec starts and ends, so an edit cannot reach into its neighbor.
func blockOf(text, tool string) (int, int, error) {
	starts := blockStart.FindAllStringSubmatchIndex(text, -1)
	for i, s := range starts {
		if text[s[2]:s[3]] != tool {
			continue
		}
		end := len(text)
		if i+1 < len(starts) {
			end = starts[i+1][0]
		}
		return s[0], end, nil
	}
	return 0, 0, fmt.Errorf("%s: no spec for it in the manifest", tool)
}

// publishedSums is the upstream's own checksums file, keyed by asset filename. Empty where none is
// published, which is most of them.
func publishedSums(ctx context.Context, body, version string) (map[string]string, error) {
	m := regexp.MustCompile(`ChecksumsURLTemplate:\s+"([^"]+)"`).FindStringSubmatch(body)
	if m == nil {
		return nil, nil
	}
	url := strings.ReplaceAll(m[1], "{version}", version)
	text, err := fetch(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("the checksums file for %s is not there: %w", version, err)
	}
	out := map[string]string{}
	for _, line := range strings.Split(string(text), "\n") {
		if fields := strings.Fields(line); len(fields) == 2 {
			out[strings.TrimPrefix(fields[1], "*")] = fields[0]
		}
	}
	return out, nil
}

func hashOf(ctx context.Context, url string) (string, error) {
	body, err := fetch(ctx, url)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:]), nil
}

// maxAsset caps a download. Scanner archives are tens of megabytes.
const maxAsset = 512 << 20

func fetch(ctx context.Context, url string) ([]byte, error) {
	// #nosec G704 -- every URL is a template already in the manifest with a validated version
	// substituted, so the host and path are Draugr's own and only the version varies
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "draugr-pinbump")
	resp, err := http.DefaultClient.Do(req) // #nosec G704 -- as above
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s answered %s", url, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxAsset))
}

// bumpConst moves a pinned version held as a Go constant.
func bumpConst(path, name, was, version string) error {
	source, err := os.ReadFile(path) // #nosec G304 G703 -- a fixed path under the checkout root
	if err != nil {
		return err
	}
	old := fmt.Sprintf("const %s = %q", name, was)
	if !strings.Contains(string(source), old) {
		return fmt.Errorf("%s: %s is not %q in %s", name, name, was, path)
	}
	next := strings.Replace(string(source), old, fmt.Sprintf("const %s = %q", name, version), 1)
	// #nosec G703 -- path is a constant chosen by the caller, not built from an argument
	return os.WriteFile(path, []byte(next), 0o600)
}

// bumpPython moves Semgrep and regenerates the hash-pinned requirements its install reads.
//
// The generator already exists and resolves on this machine, which is the documented limit of that
// pin. Regenerated rather than edited, because sixty-six hashes edited by hand are sixty-six
// nobody can check.
func bumpPython(root, tool, was, version string) error {
	if err := bumpConst(filepath.Join(root, "internal/tools/install.go"),
		"semgrepVersion", was, version); err != nil {
		return err
	}
	gen := filepath.Join(root, "internal/tools/pythonpins/generate.py")
	cmd := exec.Command("python3", gen, tool, version) // #nosec G204 G702 -- the generator is this checkout's, and both arguments are validated above
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("regenerating the %s pins: %w", tool, err)
	}
	return nil
}

// bumpNode moves retire.js and regenerates the lockfile its install reads.
//
// npm resolves against a manifest named `package.json` and nothing else, so the pair is copied
// into a scratch directory under their working names and copied back. Writing the lockfile in
// place would leave npm reporting "up to date" over a manifest it never read.
func bumpNode(root, tool, was, version string) error {
	if err := bumpConst(filepath.Join(root, "internal/tools/node.go"),
		"retireVersion", was, version); err != nil {
		return err
	}
	pins := filepath.Join(root, "internal/tools/nodepins")
	manifest := filepath.Join(pins, tool+".package.json")
	source, err := os.ReadFile(manifest) // #nosec G304 G703 -- a fixed path under the checkout root
	if err != nil {
		return err
	}
	next := strings.Replace(string(source), fmt.Sprintf("%q: %q", tool, was),
		fmt.Sprintf("%q: %q", tool, version), 1)
	if next == string(source) {
		return fmt.Errorf("%s: %s is not %q in %s", tool, tool, was, manifest)
	}

	dir, err := os.MkdirTemp("", "draugr-nodepins-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	// #nosec G703 -- dir came from os.MkdirTemp and the name is a constant
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(next), 0o600); err != nil {
		return err
	}
	cmd := exec.Command("npm", "install", "--package-lock-only", "--ignore-scripts")
	cmd.Dir, cmd.Stdout, cmd.Stderr = dir, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("resolving %s@%s: %w", tool, version, err)
	}

	lock, err := os.ReadFile(filepath.Join(dir, "package-lock.json")) // #nosec G304 G703 -- a file this function just wrote
	if err != nil {
		return fmt.Errorf("npm wrote no lockfile: %w", err)
	}
	// #nosec G703 -- manifest is built from a tool name the manifest already pins
	if err := os.WriteFile(manifest, []byte(next), 0o600); err != nil {
		return err
	}
	// #nosec G703 -- tool is one of the names the manifest pins, checked before anything ran
	return os.WriteFile(filepath.Join(pins, tool+".package-lock.json"), lock, 0o600)
}
