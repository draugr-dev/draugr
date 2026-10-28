package scanners

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/draugr-dev/draugr/internal/english"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// Semgrep finishes a scan, exits 0 and reports findings only from what it checked. Two gaps leave
// no mark among those findings: a file over its size limit, which it leaves out of the scan, and a
// file a rule ran out of time on. The first is listed only under paths.skipped in its JSON, which
// it writes only with --verbose; the second is an entry in errors at level warn. Read from the
// findings alone, a file Semgrep never opened looks the same as one with nothing wrong in it.
//
// So both are read from the JSON report, and each such file is reported unread, the way a
// dependency file no scanner took packages from is, which gate.failOnCaveats can fail the run on.

// semgrepMaxTargetBytes is the size over which Semgrep leaves a file out of the scan. Semgrep's
// own default, passed explicitly so the reason a skipped file is given states the limit the run
// applied, whatever a later release makes the default.
const semgrepMaxTargetBytes = 1_000_000

// semgrepSizeLimit is semgrepMaxTargetBytes as the reason for a skipped file states it.
const semgrepSizeLimit = "1 MB"

// semgrepTimeoutThreshold is how many rules may time out on one file before Semgrep runs no more
// rules on it. Semgrep's default, passed explicitly for the same reason: at the threshold, every
// rule not yet run on the file is left out without an entry of its own, and the reason has to say
// so.
const semgrepTimeoutThreshold = 3

// semgrepSizeReasons are the paths.skipped reasons for a file over the size limit. Every other
// reason is a file Semgrep was told to leave out (.semgrepignore, .gitignore, --exclude), or one it
// reports by an entry in errors instead.
var semgrepSizeReasons = []string{"exceeded_size_limit", "too_big"}

// semgrepTimeout is the errors[].type of a rule that ran out of time on a file.
const semgrepTimeout = "Timeout"

// semgrepCoverage is the part of Semgrep's JSON report that says what it did not finish.
type semgrepCoverage struct {
	Errors []struct {
		// Raw, because Semgrep writes some types as a string and others as a list whose first
		// element is the name ("PartialParsing" with the ranges it could not parse).
		Type   json.RawMessage `json:"type"`
		RuleID string          `json:"rule_id"`
		Path   string          `json:"path"`
	} `json:"errors"`
	Paths struct {
		Skipped []struct {
			Path   string `json:"path"`
			Reason string `json:"reason"`
		} `json:"skipped"`
	} `json:"paths"`
}

// semgrepErrorType is the name of an errors[] entry's type, "" for a shape it does not recognize.
func semgrepErrorType(raw json.RawMessage) string {
	var name string
	if json.Unmarshal(raw, &name) == nil {
		return name
	}
	var list []json.RawMessage
	if json.Unmarshal(raw, &list) == nil && len(list) > 0 {
		_ = json.Unmarshal(list[0], &name)
	}
	return name
}

// semgrepUnread reads doc, the JSON report Semgrep writes beside its SARIF, for each file it left
// out for its size or did not finish because a rule timed out, as one unread input per file sorted
// by path.
//
// A file over the size limit is reported only where a rule could have read it: Semgrep applies the
// limit before it matches files to the rules' languages, so the skipped list also holds large files
// no rule reads, a data file or a lockfile under a ruleset for one language. covers says which
// files a rule reads. Rule ids are shortened by prefixes, as the findings' are.
func semgrepUnread(doc []byte, dir string, covers semgrepLanguages, prefixes []string) ([]sarif.Input, error) {
	var cov semgrepCoverage
	if err := json.Unmarshal(doc, &cov); err != nil {
		return nil, fmt.Errorf("read the JSON report Semgrep writes beside its SARIF: %w", err)
	}
	reasons := map[string][]string{}
	for _, s := range cov.Paths.Skipped {
		if !slices.Contains(semgrepSizeReasons, s.Reason) {
			continue
		}
		p := repoRelPath(dir, s.Path)
		if !covers.reads(dir, p) {
			continue
		}
		reasons[p] = append(reasons[p], "over "+semgrepSizeLimit+", not scanned")
	}
	timedOut := map[string][]string{}
	for _, e := range cov.Errors {
		if semgrepErrorType(e.Type) != semgrepTimeout || e.Path == "" {
			continue
		}
		p := repoRelPath(dir, e.Path)
		rules := timedOut[p]
		if rule := shortSemgrepRule(e.RuleID, prefixes); rule != "" && !slices.Contains(rules, rule) {
			rules = append(rules, rule)
		}
		// Set even with no rule named: it is still a file a rule did not finish on.
		timedOut[p] = rules
	}
	for p, rules := range timedOut {
		reasons[p] = append(reasons[p], semgrepTimeoutReason(rules))
	}
	paths := make([]string, 0, len(reasons))
	for p := range reasons {
		paths = append(paths, p)
	}
	slices.Sort(paths)
	out := make([]sarif.Input, 0, len(paths))
	for _, p := range paths {
		out = append(out, sarif.Input{Path: p, Unread: strings.Join(reasons[p], ", ")})
	}
	return out, nil
}

// semgrepTimeoutReason says which rules timed out on a file: the count first, so a reason cut to
// fit the console keeps it, then each rule. At the threshold Semgrep ran no further rule on the
// file, and the reason says that too, because those rules have no entry to name them by.
func semgrepTimeoutReason(rules []string) string {
	if len(rules) == 0 {
		return "a rule timed out, not checked"
	}
	slices.Sort(rules)
	reason := english.Count(len(rules), "rule") + " timed out, not checked"
	if len(rules) >= semgrepTimeoutThreshold {
		reason = english.Count(len(rules), "rule") + " timed out, other rules not run"
	}
	quoted := make([]string, len(rules))
	for i, r := range rules {
		quoted[i] = strconv.Quote(r)
	}
	return reason + ": " + strings.Join(quoted, ", ")
}

// shortSemgrepRule is a rule id with the first of prefixes it carries removed, the id the
// findings report the rule under (see renameSemgrepRules).
func shortSemgrepRule(id string, prefixes []string) string {
	for _, prefix := range prefixes {
		if short, ok := strings.CutPrefix(id, prefix); ok && short != "" {
			return short
		}
	}
	return id
}

// semgrepLanguages is what the configured rules read: every file, or the files of the languages
// in langs.
type semgrepLanguages struct {
	all   bool
	langs map[string]bool
}

// reads reports whether a rule reads the file at p, relative to dir, judged as Semgrep matches a
// file to a language: by its extension, its name, or the interpreter its first line names.
func (l semgrepLanguages) reads(dir, p string) bool {
	if l.all {
		return true
	}
	base := path.Base(p)
	for _, lang := range semgrepLangByName[base] {
		if l.langs[lang] {
			return true
		}
	}
	for _, lang := range semgrepLangByExt[path.Ext(base)] {
		if l.langs[lang] {
			return true
		}
	}
	for _, lang := range semgrepLangByInterpreter[shebangInterpreter(dir, p)] {
		if l.langs[lang] {
			return true
		}
	}
	return false
}

// shebangInterpreter is the program the first line of the file at p names after #!, the one
// after env where it is env: "node" for `#!/usr/bin/env node`. Empty without one.
func shebangInterpreter(dir, p string) string {
	if !filepath.IsLocal(filepath.FromSlash(p)) {
		return ""
	}
	f, err := os.Open(filepath.Join(dir, filepath.FromSlash(p))) // #nosec G304 -- a path inside the checkout, checked above
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	line, err := bufio.NewReader(f).ReadString('\n')
	if err != nil && line == "" {
		return ""
	}
	rest, ok := strings.CutPrefix(line, "#!")
	if !ok {
		return ""
	}
	fields := strings.Fields(rest)
	if len(fields) == 0 {
		return ""
	}
	prog := path.Base(fields[0])
	if prog == "env" {
		for _, arg := range fields[1:] {
			if !strings.HasPrefix(arg, "-") {
				return path.Base(arg)
			}
		}
		return ""
	}
	return prog
}

// semgrepRuleLanguages is what the rules at config read. A ruleset Semgrep fetches, a registry
// pack or a URL, cannot be read here, so it is taken to read every file: the registry's default
// pack holds regex and generic rules, which do. So is a rules file that cannot be read, because
// leaving a skipped file out of the report on a guess would pass it as checked.
func semgrepRuleLanguages(config string) semgrepLanguages {
	everything := semgrepLanguages{all: true}
	if _, remote := semgrepRemoteHost(config); remote || !filepath.IsAbs(config) {
		return everything
	}
	info, err := os.Stat(config)
	if err != nil {
		return everything
	}
	files := []string{config}
	if info.IsDir() {
		files = nil
		err := filepath.WalkDir(config, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() && p != config && strings.HasPrefix(d.Name(), ".") {
				return fs.SkipDir
			}
			if !d.IsDir() && slices.Contains([]string{".yaml", ".yml", ".json"}, filepath.Ext(p)) {
				files = append(files, p)
			}
			return nil
		})
		if err != nil {
			return everything
		}
	}
	langs := map[string]bool{}
	for _, file := range files {
		raw, err := os.ReadFile(file) // #nosec G304 -- the rules the descriptor configured
		if err != nil {
			return everything
		}
		var doc struct {
			Rules []struct {
				Languages []string `yaml:"languages"`
			} `yaml:"rules"`
		}
		if err := yaml.Unmarshal(raw, &doc); err != nil {
			return everything
		}
		for _, r := range doc.Rules {
			for _, key := range r.Languages {
				lang, known := semgrepLangKeys[strings.ToLower(key)]
				if !known || semgrepAnyFile[lang] {
					return everything
				}
				langs[lang] = true
			}
		}
	}
	if len(langs) == 0 {
		return everything
	}
	return semgrepLanguages{langs: langs}
}

// The tables below are Semgrep's own, from lang.json in semgrep-interfaces: each language's keys,
// the names a rule may give it, and the extensions, file names and interpreters that make a file
// one of its targets. A language a rule names that is not here is taken to read every file.

// semgrepAnyFile are the languages whose rules read a file of any kind.
var semgrepAnyFile = map[string]bool{"generic": true, "aliengrep": true, "regex": true}

// semgrepLangKeys maps each name a rule may give a language to the language.
var semgrepLangKeys = map[string]string{
	"apex": "apex", "bash": "bash", "sh": "bash", "c": "c", "cairo": "cairo", "circom": "circom",
	"clojure": "clojure", "cpp": "cpp", "c++": "cpp", "csharp": "csharp", "c#": "csharp",
	"dart": "dart", "dockerfile": "dockerfile", "docker": "dockerfile", "fga": "fga", "openfga": "fga",
	"ex": "elixir", "elixir": "elixir", "go": "go", "golang": "go", "gosu": "gosu", "hack": "hack",
	"html": "html", "java": "java", "js": "js", "javascript": "js", "json": "json",
	"jsonnet": "jsonnet", "julia": "julia", "kt": "kotlin", "kotlin": "kotlin", "lisp": "lisp",
	"lua": "lua", "move_on_sui": "move_on_sui", "move_on_aptos": "move_on_aptos", "objc": "objc",
	"objectivec": "objc", "objective-c": "objc", "ocaml": "ocaml", "php": "php",
	"powershell": "powershell", "promql": "promql", "proto": "protobuf", "protobuf": "protobuf",
	"proto3": "protobuf", "python2": "python", "python3": "python", "py": "python",
	"python": "python", "r": "r", "ruby": "ruby", "rust": "rust", "scala": "scala",
	"scheme": "scheme", "solidity": "solidity", "sol": "solidity", "swift": "swift",
	"tf": "terraform", "hcl": "terraform", "terraform": "terraform", "ts": "ts", "typescript": "ts",
	"vue": "vue", "xml": "xml", "yaml": "yaml", "generic": "generic", "spacegrep": "generic",
	"aliengrep": "aliengrep", "regex": "regex", "none": "regex",
}

// semgrepLangByExt maps a file extension to the languages whose rules read it.
var semgrepLangByExt = map[string][]string{
	".cls": {"apex"}, ".bash": {"bash"}, ".sh": {"bash"}, ".c": {"c"}, ".h": {"c", "cpp"},
	".cairo": {"cairo"}, ".circom": {"circom"}, ".clj": {"clojure"}, ".cljs": {"clojure"},
	".cljc": {"clojure"}, ".edn": {"clojure"}, ".cc": {"cpp"}, ".cpp": {"cpp"}, ".cxx": {"cpp"},
	".c++": {"cpp"}, ".pcc": {"cpp"}, ".tpp": {"cpp"}, ".C": {"cpp"}, ".hh": {"cpp", "hack"},
	".hpp": {"cpp"}, ".hxx": {"cpp"}, ".inl": {"cpp"}, ".ipp": {"cpp"}, ".cs": {"csharp"},
	".dart": {"dart"}, ".dockerfile": {"dockerfile"}, ".Dockerfile": {"dockerfile"},
	".fga": {"fga"}, ".ex": {"elixir"}, ".exs": {"elixir"}, ".go": {"go"}, ".gs": {"gosu"},
	".hack": {"hack"}, ".hck": {"hack"}, ".htm": {"html"}, ".html": {"html"}, ".java": {"java"},
	".cjs": {"js"}, ".js": {"js"}, ".jsx": {"js"}, ".mjs": {"js"}, ".json": {"json"},
	".ipynb": {"json"}, ".jsonnet": {"jsonnet"}, ".libsonnet": {"jsonnet"}, ".jl": {"julia"},
	".kt": {"kotlin"}, ".kts": {"kotlin"}, ".ktm": {"kotlin"}, ".lisp": {"lisp"}, ".cl": {"lisp"},
	".el": {"lisp"}, ".lua": {"lua"}, ".move": {"move_on_sui", "move_on_aptos"}, ".m": {"objc"},
	".ml": {"ocaml"}, ".mli": {"ocaml"}, ".php": {"php"}, ".tpl": {"php"}, ".phtml": {"php"},
	".ps1": {"powershell"}, ".promql": {"promql"}, ".proto": {"protobuf"}, ".py": {"python"},
	".pyi": {"python"}, ".r": {"r"}, ".R": {"r"}, ".rb": {"ruby"}, ".rs": {"rust"},
	".scala": {"scala"}, ".scm": {"scheme"}, ".ss": {"scheme"}, ".sol": {"solidity"},
	".swift": {"swift"}, ".tf": {"terraform"}, ".tofu": {"terraform"}, ".hcl": {"terraform"},
	".tfvars": {"terraform"}, ".ts": {"ts"}, ".tsx": {"ts"}, ".vue": {"vue"}, ".xml": {"xml"},
	".plist": {"xml"}, ".yml": {"yaml"}, ".yaml": {"yaml"},
}

// semgrepLangByName maps a whole file name to the languages whose rules read it.
var semgrepLangByName = map[string][]string{"Dockerfile": {"dockerfile"}, "dockerfile": {"dockerfile"}}

// semgrepLangByInterpreter maps the program a first line names after #! to the languages whose
// rules read the file.
var semgrepLangByInterpreter = map[string][]string{
	"bash": {"bash"}, "sh": {"bash"}, "hhvm": {"hack"}, "node": {"js"}, "js": {"js"},
	"nodejs": {"js"}, "lua": {"lua"}, "ocaml": {"ocaml"}, "ocamlscript": {"ocaml"}, "php": {"php"},
	"python": {"python"}, "python2": {"python"}, "python3": {"python"}, "ruby": {"ruby"},
	"run-cargo-script": {"rust"}, "scala": {"scala"}, "ts-node": {"ts"},
}
