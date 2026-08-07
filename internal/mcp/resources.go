package mcp

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Saga descriptors are exposed as MCP resources so a client can attach one as context directly,
// without spending a tool call and a round trip to read a file it can already see. It also puts
// the descriptor in front of the model unprompted, which is the point: the Saga is the scope,
// and an assistant that hasn't read it will invent one.

// sagaSuffix is the descriptor naming convention. A project can have several — azure.saga.yaml,
// draugr-api.saga.yaml — so this matches the type, not one filename.
const sagaSuffix = ".saga.yaml"

// maxScanDepth bounds discovery. Descriptors live near the top of a repository; walking an
// entire monorepo at startup to find one is a cost with no matching benefit.
const maxScanDepth = 3

// maxResources caps how many descriptors are advertised, so a repository with an unusual number
// of them can't flood a client's resource list.
const maxResources = 50

// skipDirs are directories never worth walking: build output and dependency trees, where any
// *.saga.yaml belongs to something else.
var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, "dist": true,
	"build": true, "target": true, ".venv": true, "__pycache__": true,
}

// addSagaResources registers each descriptor found under root. Discovery happens once, at
// startup: a descriptor added later won't appear until the server restarts, which is a fair
// trade for not re-walking the tree on every list.
func addSagaResources(s *mcp.Server, root string) error {
	paths, err := findSagas(root)
	if err != nil {
		return err
	}
	for _, path := range paths {
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			rel = path
		}
		rel = filepath.ToSlash(rel)
		s.AddResource(&mcp.Resource{
			// A file:// URI so a client can relate the resource to something on disk.
			URI:      "file://" + filepath.ToSlash(path),
			Name:     rel,
			Title:    "Saga descriptor: " + rel,
			MIMEType: "application/yaml",
			Description: "The committed declaration of what this application is and which " +
				"security controls apply to it. Read it before reasoning about the project's " +
				"security posture — it is the scope, and it outranks any guess.",
		}, readFileResource(path))
	}
	return nil
}

// readFileResource serves one file's contents. The path is captured at registration rather than
// taken from the request, so a client cannot read arbitrary files by asking for a different URI.
func readFileResource(path string) mcp.ResourceHandler {
	return func(_ context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		data, err := os.ReadFile(path) // #nosec G304 -- a path this server chose, not one the client supplied
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{
			URI:      req.Params.URI,
			MIMEType: "application/yaml",
			Text:     string(data),
		}}}, nil
	}
}

// findSagas returns descriptor paths under root, shallowest first so the project's main
// descriptor leads. Unreadable directories are skipped rather than failing discovery: a server
// that won't start because one subdirectory is unreadable is worse than one that finds less.
func findSagas(root string) ([]string, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	var found []string
	err = filepath.WalkDir(abs, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if path != abs && (skipDirs[name] || strings.HasPrefix(name, ".") && name != ".draugr") {
				return fs.SkipDir
			}
			if depth(abs, path) >= maxScanDepth {
				return fs.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(d.Name(), sagaSuffix) {
			found = append(found, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(found, func(i, j int) bool {
		di, dj := depth(abs, found[i]), depth(abs, found[j])
		if di != dj {
			return di < dj
		}
		return found[i] < found[j]
	})
	if len(found) > maxResources {
		found = found[:maxResources]
	}
	return found, nil
}

// depth counts path separators between root and path.
func depth(root, path string) int {
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == "." {
		return 0
	}
	return strings.Count(filepath.ToSlash(rel), "/")
}
