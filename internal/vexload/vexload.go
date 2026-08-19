// Package vexload resolves the VEX sources a descriptor names into documents a run can apply.
//
// Separate from pkg/vex, which parses and matches, and separate from pkg/engine, which applies.
// Resolving is the part that touches the world — a file, an HTTPS fetch, a git clone — and the
// engine deliberately reaches the network only through the scanners it runs. Keeping this out of
// it is what lets a scan stay something you can reason about offline.
package vexload

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/draugr-dev/draugr/internal/git"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/vex"
)

// maxDocument is the most a VEX document may be. Generous for a document of statements, and small
// enough that a URL answering with something else entirely — a login page, an error, a tarball —
// fails as a size rather than being parsed as JSON for however long that takes.
const maxDocument = 32 << 20 // 32 MiB

// fetchTimeout bounds a single HTTPS fetch. A supplier's document is evidence for a scan, not the
// scan itself, and a run should not hang on a server that accepted the connection and then went
// quiet.
const fetchTimeout = 30 * time.Second

// Loader resolves sources. The zero value works; the fields exist so a test can supply its own
// transport and checkout without reaching the network.
type Loader struct {
	// Client fetches URL sources. nil uses a client with fetchTimeout.
	Client *http.Client
	// Checkout clones a repository and returns the tree plus a cleanup. nil uses internal/git.
	Checkout func(ctx context.Context, url, ref string) (dir string, revision string, cleanup func(), err error)
	// Now is the clock, for the ReadAt stamp.
	Now func() time.Time
}

// Load resolves every source a descriptor names.
//
// One error per source that could not be read, joined — rather than the first. A run configured
// with four supplier documents and two bad paths should be told about both, because the operator
// fixing them is going to fix them together.
//
// A source that cannot be read is an error and never a silent skip. The alternative is a scan
// that reports fewer findings than the last one for a reason nothing states, which reads exactly
// like a codebase that improved.
func (l *Loader) Load(ctx context.Context, model *saga.Model) (vex.Set, error) {
	set := vex.Set{ByComponent: map[string][]vex.Resolved{}}
	var errs []error

	for i, src := range model.Config.VEXSources {
		r, err := l.one(ctx, src)
		if err != nil {
			errs = append(errs, fmt.Errorf("config.vexSources[%d]: %w", i, err))
			continue
		}
		set.Project = append(set.Project, r)
	}
	for _, comp := range model.Components {
		for i, src := range comp.VEX {
			r, err := l.one(ctx, src)
			if err != nil {
				errs = append(errs, fmt.Errorf("component %q: vex[%d]: %w", comp.Name, i, err))
				continue
			}
			set.ByComponent[comp.Name] = append(set.ByComponent[comp.Name], r)
		}
	}
	if len(set.ByComponent) == 0 {
		set.ByComponent = nil
	}
	return set, errors.Join(errs...)
}

func (l *Loader) one(ctx context.Context, src saga.VEXSource) (vex.Resolved, error) {
	switch {
	case src.Path != "":
		return l.fromPath(src.Path)
	case src.URL != "":
		return l.fromURL(ctx, src.URL)
	case src.Repository != nil:
		return l.fromRepository(ctx, *src.Repository)
	}
	// Validation refuses this shape, so reaching it means a descriptor was built in code rather
	// than loaded. Saying so beats returning an empty document that excuses nothing.
	return vex.Resolved{}, errors.New("names no path, url or repository")
}

func (l *Loader) fromPath(path string) (vex.Resolved, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- a descriptor-supplied path, like every other input
	if err != nil {
		return vex.Resolved{}, err
	}
	return l.resolve(data, vex.Provenance{Kind: "path", Location: filepath.ToSlash(path)})
}

func (l *Loader) fromURL(ctx context.Context, url string) (vex.Resolved, error) {
	client := l.Client
	if client == nil {
		client = &http.Client{Timeout: fetchTimeout}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return vex.Resolved{}, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return vex.Resolved{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return vex.Resolved{}, fmt.Errorf("fetch returned %s", resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxDocument+1))
	if err != nil {
		return vex.Resolved{}, err
	}
	if len(data) > maxDocument {
		return vex.Resolved{}, fmt.Errorf("document is larger than %d bytes — is that URL a VEX document?", maxDocument)
	}
	return l.resolve(data, vex.Provenance{Kind: "url", Location: url})
}

func (l *Loader) fromRepository(ctx context.Context, r saga.VEXRepository) (vex.Resolved, error) {
	checkout := l.Checkout
	if checkout == nil {
		checkout = gitCheckout
	}
	dir, revision, cleanup, err := checkout(ctx, r.URL, r.Ref)
	if err != nil {
		return vex.Resolved{}, fmt.Errorf("clone %s: %w", r.URL, err)
	}
	defer cleanup()

	// Joined and then checked, because a path that climbs out of the checkout would read a file
	// from the machine running the scan while looking like it came from the supplier.
	full := filepath.Join(dir, filepath.FromSlash(r.Path))
	rel, err := filepath.Rel(dir, full)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return vex.Resolved{}, fmt.Errorf("path %q escapes the repository", r.Path)
	}
	data, err := os.ReadFile(full) // #nosec G304 -- contained above, inside Draugr's own checkout
	if err != nil {
		return vex.Resolved{}, fmt.Errorf("%s: %w", r.Path, err)
	}
	return l.resolve(data, vex.Provenance{
		Kind:     "repository",
		Location: r.URL + "#" + r.Path,
		Revision: revision,
	})
}

// gitCheckout is the real clone, wrapped so a test can replace it.
func gitCheckout(ctx context.Context, url, ref string) (string, string, func(), error) {
	tree, cleanup, err := git.Checkout(ctx, url, ref, git.Scope{})
	if err != nil {
		return "", "", func() {}, err
	}
	return tree.Dir, tree.Revision, cleanup, nil
}

// resolve parses the bytes and completes the provenance.
func (l *Loader) resolve(data []byte, p vex.Provenance) (vex.Resolved, error) {
	doc, err := vex.Read(strings.NewReader(string(data)))
	if err != nil {
		return vex.Resolved{}, err
	}
	sum := sha256.Sum256(data)
	p.Digest = "sha256:" + hex.EncodeToString(sum[:])
	p.ReadAt = l.now()
	p.Author = doc.Author
	p.Timestamp = doc.Timestamp
	p.Statements = len(doc.Statements)
	return vex.Resolved{Document: doc, Provenance: p}, nil
}

func (l *Loader) now() time.Time {
	if l.Now != nil {
		return l.Now()
	}
	return time.Now()
}
