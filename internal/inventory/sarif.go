package inventory

import (
	"encoding/json"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// SARIF is a SARIF file another tool wrote: one the tree holds, or one a CI step writes or uploads.
// `draugr init` proposes importing it, commented out.
type SARIF struct {
	// Path is the file, relative to the root. Empty where a CI step does not say which file it writes.
	Path string
	// Tool is the tool that wrote it, by the name Tools gives it, by the name the file states where
	// that is not one of them, or empty where nothing says.
	Tool string
	// InTree reports whether the file is in the tree.
	InTree bool
	// Workflow is the CI file whose step writes or uploads the file, empty where none does.
	Workflow string
	// Dir is the directory the step runs in, relative to the root, and "." for a file in the tree.
	// It places a file the step does not name.
	Dir string
}

// Where is the path that decides which component the file belongs to: the file, or the directory
// its step runs in where the step does not name it.
func (s SARIF) Where() string {
	if s.Path != "" {
		return s.Path
	}
	return s.Dir
}

// The tools Draugr recognizes by name, in a SARIF file's tool.driver.name or on a CI step.
const (
	ToolCodeQL          = "CodeQL"
	ToolSemgrep         = "Semgrep"
	ToolGosec           = "gosec"
	ToolBandit          = "Bandit"
	ToolSnykCode        = "Snyk Code"
	ToolTrivy           = "Trivy"
	ToolTrivyConfig     = "Trivy config"
	ToolGrype           = "Grype"
	ToolOSVScanner      = "OSV-Scanner"
	ToolSnykOpenSource  = "Snyk Open Source"
	ToolSnykContainer   = "Snyk Container"
	ToolSnykIaC         = "Snyk IaC"
	ToolDependencyCheck = "dependency-check"
	ToolCheckov         = "Checkov"
	ToolKICS            = "KICS"
)

// draugrDriver is the tool.driver.name Draugr writes into its own results.sarif.
const draugrDriver = "Draugr"

// sarifHeadBytes bounds how much of a SARIF file is read for the name of its tool. The driver opens
// each run, ahead of the results.
const sarifHeadBytes = 1 << 20

// workflowBytes bounds how much of a CI file is read.
const workflowBytes = 1 << 20

// byName are the tools known by a name folded to lowercase letters and digits, longest first where
// one name begins another, so snykcode is not read as snyk.
var byName = []struct{ prefix, tool string }{
	{"codeql", ToolCodeQL},
	{"semgrep", ToolSemgrep},
	{"gosec", ToolGosec},
	{"bandit", ToolBandit},
	{"snykcode", ToolSnykCode},
	{"snykiac", ToolSnykIaC},
	{"snykinfrastructure", ToolSnykIaC},
	{"snykcontainer", ToolSnykContainer},
	{"snyk", ToolSnykOpenSource},
	{"trivy", ToolTrivy},
	{"grype", ToolGrype},
	{"osvscanner", ToolOSVScanner},
	{"dependencycheck", ToolDependencyCheck},
	{"checkov", ToolCheckov},
	{"kics", ToolKICS},
}

// fold is s in lowercase letters and digits only.
func fold(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// toolNamed is the tool a SARIF file's driver name, or a name holding one, means, or "".
func toolNamed(name string, prefixOnly bool) string {
	f := fold(name)
	for _, n := range byName {
		if strings.HasPrefix(f, n.prefix) || (!prefixOnly && strings.Contains(f, n.prefix)) {
			return n.tool
		}
	}
	return ""
}

// sarifDriver is the tool.driver.name of the first run in a SARIF file, or "" where the file does not
// state one within its first sarifHeadBytes.
//
// Read token by token and stopped at the name, so a file of any size costs its opening.
func sarifDriver(p string) string {
	f, err := os.Open(p) // #nosec G304 -- a file under the tree being initialized
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	dec := json.NewDecoder(io.LimitReader(f, sarifHeadBytes))
	for {
		tok, err := dec.Token()
		if err != nil {
			return ""
		}
		if tok != "driver" || !dec.More() {
			continue
		}
		if open, err := dec.Token(); err != nil || open != json.Delim('{') {
			return ""
		}
		for dec.More() {
			key, err := dec.Token()
			if err != nil {
				return ""
			}
			if key == "name" {
				var name string
				if dec.Decode(&name) != nil {
					return ""
				}
				return name
			}
			var skip json.RawMessage
			if dec.Decode(&skip) != nil {
				return ""
			}
		}
		return ""
	}
}

// isDraugrOutput reports whether a SARIF file is one Draugr wrote: anything under a .draugr
// directory, where a scan keeps what it writes, or a file whose tool is Draugr, wherever -o put it.
// Importing Draugr's own report would count every finding twice.
func isDraugrOutput(rel, driver string) bool {
	return slices.Contains(strings.Split(path.Dir(rel), "/"), ".draugr") || driver == draugrDriver
}

// sarifInTree is the SARIF files the tree holds, less Draugr's own and those under directories of
// docs, examples and tests, which describe somebody's fixture rather than this code.
func sarifInTree(root string, rels, nonShipping []string) []SARIF {
	var out []SARIF
	for _, rel := range rels {
		if insideAny(rel, nonShipping) {
			continue
		}
		driver := sarifDriver(filepath.Join(root, filepath.FromSlash(rel)))
		if isDraugrOutput(rel, driver) {
			continue
		}
		tool := toolNamed(driver, true)
		if tool == "" {
			tool = driver
		}
		out = append(out, SARIF{Path: rel, Tool: tool, InTree: true, Dir: "."})
	}
	slices.SortFunc(out, func(a, b SARIF) int { return strings.Compare(a.Path, b.Path) })
	return out
}

// isWorkflow reports whether rel is a CI file init reads for SARIF steps: a GitHub Actions workflow
// or GitLab's pipeline file.
func isWorkflow(rel string) bool {
	return isActionsWorkflow(rel) || rel == ".gitlab-ci.yml"
}

func isActionsWorkflow(rel string) bool {
	return path.Dir(rel) == ".github/workflows" && (strings.HasSuffix(rel, ".yml") || strings.HasSuffix(rel, ".yaml"))
}

// readCapped reads at most workflowBytes of a file under the root.
func readCapped(p string) []byte {
	f, err := os.Open(p) // #nosec G304 -- a file under the tree being initialized
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	data, _ := io.ReadAll(io.LimitReader(f, workflowBytes))
	return data
}

// sarifInCI is the SARIF files the steps of the tree's CI files write or upload, each once, joined
// to the file in the tree where the step's file is one.
func sarifInCI(root string, workflows []string, inTree []SARIF) []SARIF {
	var found []SARIF
	for _, rel := range workflows {
		data := readCapped(filepath.Join(root, filepath.FromSlash(rel)))
		if isActionsWorkflow(rel) {
			found = append(found, actionsSARIF(rel, data)...)
		} else {
			found = append(found, gitlabSARIF(rel, data)...)
		}
	}
	var out []SARIF
	seen := map[[3]string]bool{}
	for _, s := range found {
		if s.Path != "" && strings.HasPrefix(s.Path, ".draugr/") {
			continue
		}
		if i := slices.IndexFunc(inTree, func(t SARIF) bool { return s.Path != "" && t.Path == s.Path }); i >= 0 {
			if inTree[i].Workflow == "" {
				inTree[i].Workflow = s.Workflow
			}
			if inTree[i].Tool == "" {
				inTree[i].Tool = s.Tool
			}
			continue
		}
		// A file is proposed once, however many steps name it. A step that names none is proposed
		// once for each workflow and tool.
		key := [3]string{s.Path, s.Tool, ""}
		if s.Path == "" {
			key[2] = s.Workflow
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, s)
	}
	return out
}

// actionsWorkflow is the part of a GitHub Actions workflow that says what its steps run.
type actionsWorkflow struct {
	Jobs map[string]actionsJob `yaml:"jobs"`
}

type actionsJob struct {
	Defaults struct {
		Run struct {
			WorkingDirectory string `yaml:"working-directory"`
		} `yaml:"run"`
	} `yaml:"defaults"`
	Steps []actionsStep `yaml:"steps"`
}

type actionsStep struct {
	Uses             string         `yaml:"uses"`
	Run              string         `yaml:"run"`
	With             map[string]any `yaml:"with"`
	WorkingDirectory string         `yaml:"working-directory"`
}

// actionsSARIF is what the jobs of a GitHub Actions workflow write or upload as SARIF.
//
// An upload names a file another step in its job wrote, so the two are one proposal, with the tool
// the writing step names. An upload no step in its job accounts for is proposed on its own, with the
// tool its file name or category names, where one does.
func actionsSARIF(rel string, data []byte) []SARIF {
	var wf actionsWorkflow
	if yaml.Unmarshal(data, &wf) != nil {
		return nil
	}
	names := make([]string, 0, len(wf.Jobs))
	for n := range wf.Jobs {
		names = append(names, n)
	}
	slices.Sort(names)
	var out []SARIF
	for _, n := range names {
		job := wf.Jobs[n]
		var writers, uploads []SARIF
		for _, st := range job.Steps {
			// An action's inputs are read from the checkout's root; working-directory moves only a
			// run step.
			with := withStrings(st.With)
			switch {
			case isUploadSARIF(st.Uses):
				up := SARIF{Workflow: rel, Dir: ".", Path: localPath(with["sarif_file"], ".")}
				up.Tool = toolNamed(with["sarif_file"]+" "+with["category"], false)
				uploads = append(uploads, up)
			case st.Uses != "":
				if s, ok := actionWrites(st.Uses, with); ok {
					s.Workflow, s.Dir = rel, "."
					writers = append(writers, s)
				}
			}
			if st.Run != "" {
				dir := workingDir(st.WorkingDirectory, job.Defaults.Run.WorkingDirectory)
				for _, s := range commandsWrite(st.Run, dir) {
					s.Workflow = rel
					writers = append(writers, s)
				}
			}
		}
		var alone []SARIF
		for _, up := range uploads {
			if !joinUpload(up, writers) {
				alone = append(alone, up)
			}
		}
		out = append(append(out, writers...), alone...)
	}
	return out
}

// joinUpload gives an upload's file to the step in writers that wrote it, and reports whether one
// accounts for it: a step that wrote the file, or one beneath the directory it uploads, or the one
// step in the job that wrote SARIF to a file it did not name.
func joinUpload(up SARIF, writers []SARIF) bool {
	var unnamed []int
	for i, w := range writers {
		if up.Path == "" || w.Path == up.Path || strings.HasPrefix(w.Path, up.Path+"/") {
			return true
		}
		if w.Path == "" {
			unnamed = append(unnamed, i)
		}
	}
	if len(unnamed) == 1 && strings.HasSuffix(up.Path, ".sarif") {
		writers[unnamed[0]].Path = up.Path
		return true
	}
	return false
}

// workingDir is the directory a step runs in, relative to the root.
func workingDir(step, job string) string {
	d := step
	if d == "" {
		d = job
	}
	if p := localPath(d, "."); p != "" {
		return p
	}
	return "."
}

// withStrings is a step's with: map, every value as a string.
func withStrings(with map[string]any) map[string]string {
	out := make(map[string]string, len(with))
	for k, v := range with {
		if s, ok := v.(string); ok {
			out[k] = s
		}
	}
	return out
}

// actionRef is an action's owner/name/path, lowercased, without its version.
func actionRef(uses string) string {
	ref, _, _ := strings.Cut(strings.ToLower(uses), "@")
	return ref
}

// isUploadSARIF reports whether a step uses the action that uploads SARIF to code scanning,
// github/codeql-action/upload-sarif, or a copy of it under another owner.
func isUploadSARIF(uses string) bool {
	return strings.HasSuffix(actionRef(uses), "/upload-sarif")
}

// actionWrites is the SARIF a step that uses an action writes, and whether it writes any.
//
// CodeQL's analyze action always does. Any other writes SARIF where an input whose name holds
// "format" asks for it, or an input holds a command line with a SARIF flag. The tool is the one the
// action's name holds, with the input that picks the kind of scan where the action has one. A step
// using Draugr's own action is Draugr's output, and none of these.
func actionWrites(uses string, with map[string]string) (SARIF, bool) {
	ref := actionRef(uses)
	if strings.Contains(ref, "draugr") {
		return SARIF{}, false
	}
	if strings.HasPrefix(ref, "github/codeql-action/analyze") {
		return SARIF{Tool: ToolCodeQL}, true
	}
	keys := make([]string, 0, len(with))
	for k := range with {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	var writes bool
	var file string
	for _, k := range keys {
		v := with[k]
		toks := tokens(v)
		if strings.Contains(strings.ToLower(k), "format") && slices.ContainsFunc(strings.Split(v, ","), isSARIFValue) {
			writes = true
		}
		if hasSARIFFlag(toks) {
			writes = true
		}
		if file == "" {
			file = sarifFileIn(toks)
		}
	}
	if !writes {
		return SARIF{}, false
	}
	return SARIF{Tool: actionTool(ref, with), Path: localPath(file, ".")}, true
}

// actionTool is the tool an action runs, by its name and the input that picks the kind of scan.
func actionTool(ref string, with map[string]string) string {
	switch {
	case strings.HasPrefix(ref, "anchore/scan-action"):
		return ToolGrype
	case strings.Contains(ref, "trivy"):
		if strings.EqualFold(with["scan-type"], "config") {
			return ToolTrivyConfig
		}
		return ToolTrivy
	case strings.HasPrefix(ref, "snyk/"):
		return snykTool(strings.Fields(with["command"]))
	}
	return toolNamed(ref, false)
}

// snykTool is the Snyk product a command line's first word after snyk runs.
func snykTool(args []string) string {
	i := slices.IndexFunc(args, func(a string) bool { return !strings.HasPrefix(a, "-") })
	if i < 0 {
		return ToolSnykOpenSource
	}
	switch args[i] {
	case "code":
		return ToolSnykCode
	case "iac":
		return ToolSnykIaC
	case "container":
		return ToolSnykContainer
	}
	return ToolSnykOpenSource
}

// formatFlags are the flags tools take a report format in: --format sarif, -f sarif, -o sarif,
// --output-format sarif, gosec's -fmt sarif and KICS's --report-formats sarif.
var formatFlags = []string{"--format", "-f", "-o", "--output", "--output-format", "-fmt", "--fmt", "--report-formats"}

// isSARIFValue reports whether a format value asks for SARIF: sarif, CodeQL's sarif-latest and
// sarifv2.1.0, or Grype's sarif=<file>.
func isSARIFValue(v string) bool {
	v = strings.ToLower(strings.TrimSpace(strings.Trim(v, `'"`)))
	return strings.HasPrefix(v, "sarif")
}

// hasSARIFFlag reports whether a command line asks for SARIF: a flag that begins --sarif, such as
// --sarif or --sarif-output=<file>, or a format flag whose value is SARIF.
func hasSARIFFlag(toks []string) bool {
	for i, t := range toks {
		if strings.HasPrefix(t, "--sarif") {
			return true
		}
		name, val, hasVal := strings.Cut(t, "=")
		if !slices.Contains(formatFlags, name) {
			continue
		}
		if !hasVal && i+1 < len(toks) {
			val = toks[i+1]
		}
		if slices.ContainsFunc(strings.Split(val, ","), isSARIFValue) {
			return true
		}
	}
	return false
}

// sarifFileIn is the first .sarif file a command line names: as an argument, a flag's value after
// =, a redirect, or Grype's sarif=<file>.
func sarifFileIn(toks []string) string {
	for _, t := range toks {
		t = strings.TrimLeft(t, ">")
		if i := strings.LastIndex(t, "="); i >= 0 {
			t = t[i+1:]
		}
		if strings.HasSuffix(t, ".sarif") {
			return t
		}
	}
	return ""
}

// workspaceVar matches the ways a CI file names the checkout's root.
var workspaceVar = regexp.MustCompile(`\$\{\{\s*github\.workspace\s*\}\}|\$\{?GITHUB_WORKSPACE\}?|\$\{?CI_PROJECT_DIR\}?`)

// checkoutRoot stands for the checkout's root in a path a CI step names, which anchors the path there
// whatever directory the step runs in.
const checkoutRoot = "\x00"

// tokens splits a command line into words, with the checkout's root written as checkoutRoot and
// quotes taken off each word.
func tokens(line string) []string {
	line = workspaceVar.ReplaceAllString(line, checkoutRoot)
	fields := strings.Fields(line)
	for i, f := range fields {
		fields[i] = strings.Trim(f, `'"`)
	}
	return fields
}

// localPath is a file a CI step names, relative to the root: joined to the directory the step runs
// in, or to the root where the step names it from there, or "" where it is not a path inside the
// checkout, such as one outside it or one built from a variable init cannot read.
func localPath(file, dir string) string {
	file = workspaceVar.ReplaceAllString(file, checkoutRoot)
	if rest, ok := strings.CutPrefix(file, checkoutRoot); ok {
		file, dir = strings.TrimPrefix(rest, "/"), "."
	}
	if file == "" || strings.ContainsAny(file, "$*{}"+checkoutRoot) || path.IsAbs(file) {
		return ""
	}
	p := path.Clean(path.Join(dir, file))
	if p == ".." || strings.HasPrefix(p, "../") {
		return ""
	}
	return p
}

// commandBinaries are the commands that name a tool, by the first word of a command after its
// directory, version tag and extension come off.
var commandBinaries = map[string]string{
	"codeql":           ToolCodeQL,
	"semgrep":          ToolSemgrep,
	"gosec":            ToolGosec,
	"bandit":           ToolBandit,
	"trivy":            ToolTrivy,
	"grype":            ToolGrype,
	"osv-scanner":      ToolOSVScanner,
	"snyk":             ToolSnykOpenSource,
	"dependency-check": ToolDependencyCheck,
	"checkov":          ToolCheckov,
	"kics":             ToolKICS,
	"draugr":           draugrDriver,
}

// commandName is a word as a command names a tool: aquasec/trivy:0.58.0 and ./bin/trivy are trivy,
// dependency-check.sh is dependency-check.
func commandName(word string) string {
	n := path.Base(word)
	n, _, _ = strings.Cut(n, ":")
	n, _, _ = strings.Cut(n, "@")
	for _, ext := range []string{".sh", ".bat", ".py", ".exe"} {
		n = strings.TrimSuffix(n, ext)
	}
	return strings.ToLower(n)
}

// commandsWrite is the SARIF the commands of a script write: each command with a SARIF flag, the
// tool it runs, and the .sarif file it names. A command running Draugr is Draugr's own output.
func commandsWrite(script, dir string) []SARIF {
	script = strings.ReplaceAll(script, "\\\n", " ")
	for _, sep := range []string{"&&", "||", ";", "|"} {
		script = strings.ReplaceAll(script, sep, "\n")
	}
	var out []SARIF
	for line := range strings.SplitSeq(script, "\n") {
		toks := tokens(line)
		if len(toks) == 0 || strings.HasPrefix(toks[0], "#") || !hasSARIFFlag(toks) {
			continue
		}
		tool := commandTool(toks)
		if tool == draugrDriver {
			continue
		}
		out = append(out, SARIF{Tool: tool, Dir: dir, Path: localPath(sarifFileIn(toks), dir)})
	}
	return out
}

// commandTool is the tool a command runs: the first word naming one, with Trivy's and Snyk's
// subcommand deciding which kind of scan, or "" where no word names one.
func commandTool(toks []string) string {
	for i, t := range toks {
		tool, ok := commandBinaries[commandName(t)]
		if !ok {
			continue
		}
		rest := toks[i+1:]
		switch tool {
		case ToolTrivy:
			if len(rest) > 0 && (rest[0] == "config" || rest[0] == "conf") {
				return ToolTrivyConfig
			}
		case ToolSnykOpenSource:
			return snykTool(rest)
		}
		return tool
	}
	return ""
}

// gitlabSARIF is what the jobs of a GitLab pipeline file write as SARIF, from their scripts.
func gitlabSARIF(rel string, data []byte) []SARIF {
	var doc map[string]any
	if yaml.Unmarshal(data, &doc) != nil {
		return nil
	}
	names := make([]string, 0, len(doc))
	for n := range doc {
		names = append(names, n)
	}
	slices.Sort(names)
	var out []SARIF
	for _, n := range names {
		job, ok := doc[n].(map[string]any)
		if !ok {
			continue
		}
		for _, key := range []string{"before_script", "script", "after_script"} {
			for _, line := range scriptLines(job[key]) {
				for _, s := range commandsWrite(line, ".") {
					s.Workflow = rel
					out = append(out, s)
				}
			}
		}
	}
	return out
}

// scriptLines is a GitLab script: one string, or a list of them.
func scriptLines(v any) []string {
	switch s := v.(type) {
	case string:
		return []string{s}
	case []any:
		var out []string
		for _, l := range s {
			if str, ok := l.(string); ok {
				out = append(out, str)
			}
		}
		return out
	}
	return nil
}
