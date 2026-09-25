package mcp

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/draugr-dev/draugr/internal/inventory"
	"github.com/draugr-dev/draugr/internal/scaffold"
)

// --- propose_saga ---

// ProposeInput names the directory to propose a descriptor for.
type ProposeInput struct {
	Path string `json:"path,omitempty" jsonschema:"the directory to propose a descriptor for, absolute or relative to the directory the server was started in; defaults to that directory"`
	// PerDirectory is `draugr init --per-directory`.
	PerDirectory bool `json:"perDirectory,omitempty" jsonschema:"one component per directory that holds its own dependency file, and a root component for the rest of the tree"`
}

// ProposeOutput is a descriptor to look at, the same shape survey returns.
type ProposeOutput struct {
	// Saga is the descriptor as YAML, byte for byte what `draugr init` would write.
	Saga string `json:"saga" jsonschema:"the descriptor draugr init would write for this directory, as YAML, with a comment naming the files behind each scanner it enables"`
	// Path is where the descriptor belongs: its repositories are written relative to it.
	Path string `json:"path" jsonschema:"the file to save the descriptor as; its repository URLs are relative to this directory"`
	// Components and Controls describe what the proposal asks for without parsing it.
	Components []string `json:"components,omitempty"`
	Controls   []string `json:"controls,omitempty"`
	// Existing names the descriptors already in the directory. `draugr init` refuses to overwrite
	// one, and a proposal handed back beside an existing file reads as a replacement for it unless
	// something says the file is there.
	Existing []string `json:"existing,omitempty" jsonschema:"descriptors already in this directory; the project's committed scope, which this proposal does not replace"`
	Note     string   `json:"note,omitempty"`
	Warning  string   `json:"warning,omitempty"`
}

// sagaFile is the name `draugr init` writes.
const sagaFile = "draugr.saga.yaml"

// addProposeSaga registers propose_saga, confined to root.
func addProposeSaga(s *mcp.Server, root string) {
	mcp.AddTool(s, &mcp.Tool{
		Name: "propose_saga",
		Description: "Return the Saga descriptor `draugr init` would write for a directory, as " +
			"YAML, with the controls its dependency files, infrastructure code and Dockerfiles " +
			"call for. Call this when a project has no descriptor, before writing one from " +
			"get_saga_schema. It writes nothing; show the proposal to the user, who decides " +
			"whether and where to save it.",
	}, ProposeSagaTool(root))
}

// ProposeSagaTool reads a directory and returns the descriptor `draugr init` would write for it.
//
// It returns the descriptor rather than writing one, for the reason survey does: a tool that
// writes a file has to ask first, and whether a project wants a descriptor, and where, belongs to
// whoever owns it. The scaffold is the one `draugr init` writes, from the same package, so the
// assistant and the CLI never propose two different descriptors for one tree.
func ProposeSagaTool(root string) mcp.ToolHandlerFor[ProposeInput, ProposeOutput] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in ProposeInput) (*mcp.CallToolResult, ProposeOutput, error) {
		dir, err := withinRoot(root, in.Path)
		if err != nil {
			return nil, ProposeOutput{}, err
		}
		tree := inventory.Read(dir)
		out := ProposeOutput{
			Saga: scaffold.Saga(tree, scaffold.ProjectName(filepath.Base(dir)), in.PerDirectory),
			Path: filepath.Join(dir, sagaFile),
		}
		// The proposal goes through validate_saga's own check, so a descriptor this tool hands back
		// is one the next tool the assistant calls accepts, and its components and controls are
		// named the way validate_saga names them. With content given, the only error is the
		// descriptor's own, which v carries.
		_, v, _ := ValidateSagaTool(ctx, nil, ValidateInput{Content: out.Saga})
		if !v.Valid {
			return nil, ProposeOutput{}, fmt.Errorf("the proposed descriptor does not validate: %s", v.Error)
		}
		out.Components, out.Controls = v.Components, v.Controls

		if in.PerDirectory && len(tree.Parts) == 0 {
			out.Warning = "perDirectory: no directory below " + dir + " holds its own dependency " +
				"file · the descriptor has one component"
		}
		if out.Existing, err = descriptorsIn(dir); err != nil {
			return nil, ProposeOutput{}, err
		}
		if len(out.Existing) > 0 {
			out.Note = "not written to disk · " + dir + " already holds a descriptor · check it " +
				"with validate_saga and compare this proposal with it before changing anything"
			return nil, out, nil
		}
		out.Note = "not written to disk · validate it with validate_saga, then save it as " + out.Path
		return nil, out, nil
	}
}

// descriptorsIn names the Saga descriptors directly in dir.
func descriptorsIn(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".saga.yaml") {
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}
	return out, nil
}

// withinRoot resolves path against root and refuses anything that leaves it.
//
// Reading a directory walks every file beneath it, and the names it finds come back to the
// client. Confining the walk to the directory the server was started in keeps a request for `/`
// or a home directory from listing the machine, and symlinks are resolved first so a link inside
// root cannot lead out of it.
func withinRoot(root, path string) (string, error) {
	base, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	if base, err = filepath.EvalSymlinks(base); err != nil {
		return "", fmt.Errorf("resolve root %s: %w", root, err)
	}
	target := path
	if target == "" {
		target = base
	} else if !filepath.IsAbs(target) {
		target = filepath.Join(base, target)
	}
	resolved, err := filepath.EvalSymlinks(target)
	if err != nil {
		return "", fmt.Errorf("path %s: %w", path, err)
	}
	rel, err := filepath.Rel(base, resolved)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path %s is outside %s, the directory this server reads beneath", path, base)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", fmt.Errorf("path %s is a file; give the directory it belongs to", path)
	}
	return resolved, nil
}
