package scaffold

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/draugr-dev/draugr/internal/inventory"
)

// importControls are the controls a known tool's findings belong in: code it reads to sast, the
// packages a project pulls in to sca, infrastructure code to iac.
var importControls = map[string]string{
	inventory.ToolCodeQL:          "sast",
	inventory.ToolSemgrep:         "sast",
	inventory.ToolGosec:           "sast",
	inventory.ToolBandit:          "sast",
	inventory.ToolSnykCode:        "sast",
	inventory.ToolTrivy:           "sca",
	inventory.ToolGrype:           "sca",
	inventory.ToolOSVScanner:      "sca",
	inventory.ToolSnykOpenSource:  "sca",
	inventory.ToolSnykContainer:   "sca",
	inventory.ToolDependencyCheck: "sca",
	inventory.ToolTrivyConfig:     "iac",
	inventory.ToolCheckov:         "iac",
	inventory.ToolKICS:            "iac",
	inventory.ToolSnykIaC:         "iac",
}

// unknownControl is the control proposed for a tool init does not know, with a comment saying to
// check it: most tools that write SARIF read code.
const unknownControl = "sast"

// writeImports proposes an import for each SARIF file, commented out. url is the repository the
// component names, which a file's path is joined to, since an import's file is read from where Draugr
// runs. Nothing where there are none.
//
// Commented out because an import changes what a scan reads and what can fail it: a file that names
// another commit stops the run, and one left from last month counts its findings as today's.
// Somebody turns each one on.
func writeImports(b *strings.Builder, files []inventory.SARIF, url string) {
	if len(files) == 0 {
		return
	}
	b.WriteString("    # imports:          # SARIF another tool wrote. Uncommenting one changes what a scan reads\n")
	for _, f := range files {
		control, known := importControls[f.Tool]
		if !known {
			control = unknownControl
		}
		fmt.Fprintf(b, "    #   - control: %-4s   # %s · %s\n", control, toolNote(f.Tool, known), sourceNote(f))
		line := "    #     file: " + importFile(url, f.Path)
		switch {
		case f.InTree:
		case f.Path == "":
			line += "   # the step names no file · point it at where the CI writes one; an import reads a local file"
		default:
			line += "   # not in the tree · point it at where the CI writes it; an import reads a local file"
		}
		b.WriteString(line + "\n")
	}
}

// toolNote names the tool behind a proposal, and says to check the control where init does not know
// the tool.
func toolNote(tool string, known bool) string {
	switch {
	case known:
		return tool
	case tool != "":
		return OneLine(tool) + ", a tool init does not know · check the control"
	}
	return "tool not known · check the control"
}

// sourceNote says where init saw the file: in the tree, or in the CI file whose step writes it.
func sourceNote(f inventory.SARIF) string {
	if f.InTree {
		return "in the tree"
	}
	return OneLine(f.Workflow)
}

// importFile is the file an import names: the path joined to the repository's url, as a scalar.
// Empty where the step names no file, which an import refuses until somebody fills it in.
func importFile(url, rel string) string {
	if rel == "" {
		return `""`
	}
	p := rel
	if url != Here {
		p = filepath.ToSlash(filepath.Join(url, filepath.FromSlash(rel)))
	}
	if q := OneLine(p); q != p {
		return q
	}
	return Scalar(p)
}

// ownedSARIF are the SARIF files that belong to the component rooted at dir: beneath it and not
// beneath a part nested inside it.
func ownedSARIF(files []inventory.SARIF, dir string, parts []string) []inventory.SARIF {
	var out []inventory.SARIF
	for _, f := range files {
		if owner(f.Where(), parts) == dir {
			out = append(out, f)
		}
	}
	return out
}
