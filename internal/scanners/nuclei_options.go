package scanners

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/draugr-dev/draugr/internal/netpolicy"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// The tags Nuclei is always told to skip, unless an option below says otherwise.
//
// headers belongs to the native headers control, so dast covers what headers does not. Never
// "http", which would suppress almost every template.
//
// intrusive marks the templates that do more than read. Several write to the endpoint they test:
// one adds a user through an XML-RPC call, another uploads a file with PUT to see whether it
// stays. Nuclei's own ignore list skips dos, fuzz, bruteforce, local and txt-service, and leaves
// these to run. Running them is the `intrusive` option, which declares the mutate effect so that a
// run has to accept it.
const (
	nucleiHeadersTag    = "headers"
	nucleiIntrusiveTag  = "intrusive"
	nucleiIntrusiveKey  = "intrusive"
	nucleiInteractshKey = "interactsh"
)

// nucleiConfigSchema is the JSON Schema for the nuclei block (controllers.dast.nuclei).
//
// What is absent is deliberate, and each absence has its own reason:
//
//   - -s and -es filter findings by severity, which options.go explains no option may do.
//   - -itags and -it lift an exclusion, so either would run intrusive or headers templates
//     without the mutate effect being declared.
//   - -fr makes every HTTP template follow redirects, which can send probe traffic to a host the
//     descriptor never named.
//   - -p puts a proxy URL, which commonly carries a credential, in the process list.
//   - -mt ends the scan at a deadline and exits as though it had finished, so a partial scan
//     would read as a complete one.
//   - -code, -headless, -dast and -lfa load templates that run commands on this machine, drive a
//     browser, fuzz every parameter or read local files, which are decisions of their own.
//   - -jsonl, -nc, -duc and -H keep the output parseable, the run deterministic and the
//     credential out of argv, so none of them is the operator's to change.
const nucleiConfigSchema = `{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "intrusive": {
      "type": "boolean",
      "default": false,
      "description": "Also run the templates tagged intrusive, some of which write to the endpoint, such as creating a user or uploading a file with PUT. Declares the mutate effect, so config.allowEffects must list mutate."
    },
    "rateLimit": {
      "type": "integer",
      "default": 150,
      "description": "Most requests sent per second, across the whole scan. 1 to 10000."
    },
    "concurrency": {
      "type": "integer",
      "default": 25,
      "description": "Most templates run at once. 1 to 1000."
    },
    "timeout": {
      "type": "string",
      "pattern": "^(.*\\$\\{\\{.*\\}\\}.*|([0-9]+(\\.[0-9]+)?(ns|us|µs|ms|s|m|h))+)$",
      "default": "10s",
      "description": "How long to wait for each response, in whole seconds, e.g. \"30s\". 1s to 10m."
    },
    "retries": {
      "type": "integer",
      "default": 1,
      "description": "Times a failed request is sent again. 0 to 10."
    },
    "tags": {
      "type": "array",
      "items": { "type": "string", "pattern": "^(.*\\$\\{\\{.*\\}\\}.*|[a-z0-9][a-z0-9_.-]*)$" },
      "description": "Run only the templates carrying one of these tags, e.g. [\"cve\", \"exposure\"]. Lowercase. headers is refused, and intrusive needs intrusive: true."
    },
    "excludeTags": {
      "type": "array",
      "items": { "type": "string", "pattern": "^(.*\\$\\{\\{.*\\}\\}.*|[a-z0-9][a-z0-9_.-]*)$" },
      "description": "Template tags to skip, e.g. [\"wordpress\"]. Lowercase. Added to headers and intrusive, which are skipped whatever this lists, intrusive until intrusive is true."
    },
    "templates": {
      "type": "array",
      "items": { "type": "string" },
      "description": "Template files or directories to run instead of the community set, relative to where Draugr runs. Tag exclusions apply to them too, so a template of yours that writes to the endpoint should carry the intrusive tag. They run as written, including any that connect to another port or host."
    },
    "interactsh": {
      "type": "boolean",
      "default": true,
      "description": "Whether to run the templates that need Nuclei's public callback servers (oast.pro, oast.live, oast.site, oast.online, oast.fun, oast.me). false skips them and contacts none of the servers."
    }
  }
}`

// nucleiIntOption is an integer option and the Nuclei flag it becomes.
//
// The bounds are Draugr's, because the schema validator has no minimum or maximum. Each lower
// bound is where Nuclei's own meaning changes: a rate limit or concurrency of 0 is not "slow" to
// it, and a negative retry count is not a count.
type nucleiIntOption struct {
	key, flag string
	min, max  int
}

var nucleiIntOptions = []nucleiIntOption{
	{key: "rateLimit", flag: "-rl", min: 1, max: 10000},
	{key: "concurrency", flag: "-c", min: 1, max: 1000},
	{key: "retries", flag: "-retries", min: 0, max: 10},
}

// nucleiTimeoutRange is what timeout accepts. Nuclei takes whole seconds.
const (
	nucleiTimeoutMin = time.Second
	nucleiTimeoutMax = 10 * time.Minute
)

// nucleiOptionArgs turns a job's nuclei block into flags, and refuses a block Nuclei would run
// differently from what it says.
//
// The exclusions are always passed, and the operator's are added to Draugr's rather than
// replacing them. In the pinned Nuclei, -tags selects templates and never lifts an -etags
// exclusion: only -itags and -it do, and neither is an option here. The refusals on tags hold
// whatever a Nuclei on PATH does with the combination, because a tag in both lists selects
// templates and then excludes every one of them, which is a scan of nothing.
func nucleiOptionArgs(cfg plugin.Config) ([]string, error) {
	intrusive, _ := cfg[nucleiIntrusiveKey].(bool)
	tags := stringList(cfg, "tags")
	extra := stringList(cfg, "excludeTags")

	for _, tag := range tags {
		switch {
		case tag == nucleiHeadersTag:
			return nil, fmt.Errorf("nuclei: tags: headers templates are excluded so the headers control " +
				"owns those checks; enable controls.headers instead")
		case tag == nucleiIntrusiveTag && !intrusive:
			return nil, fmt.Errorf("nuclei: tags: intrusive runs only with intrusive: true, which " +
				"declares the mutate effect for config.allowEffects to accept")
		case slices.Contains(extra, tag):
			return nil, fmt.Errorf("nuclei: %q is in both tags and excludeTags, so no template carrying "+
				"it would run", tag)
		}
	}
	if intrusive && slices.Contains(extra, nucleiIntrusiveTag) {
		return nil, fmt.Errorf("nuclei: excludeTags lists intrusive and intrusive is true; remove one")
	}

	excluded := []string{nucleiHeadersTag}
	if !intrusive {
		excluded = append(excluded, nucleiIntrusiveTag)
	}
	for _, tag := range extra {
		if !slices.Contains(excluded, tag) {
			excluded = append(excluded, tag)
		}
	}
	args := []string{"-etags", strings.Join(excluded, ",")}
	if len(tags) > 0 {
		args = append(args, "-tags", strings.Join(tags, ","))
	}
	// A template the descriptor names is run as written, whatever it reaches: somebody chose it and
	// committed the choice, and -ept would drop it with nothing said.
	if !nucleiNamesTemplates(cfg) {
		args = append(args, "-ept", nucleiExcludedTypes)
	}

	for _, path := range stringList(cfg, "templates") {
		arg, err := nucleiTemplateArg(path)
		if err != nil {
			return nil, err
		}
		args = append(args, "-t", arg)
	}

	for _, o := range nucleiIntOptions {
		v, ok := configInt(cfg, o.key)
		if !ok {
			continue
		}
		if v < o.min || v > o.max {
			return nil, fmt.Errorf("nuclei: %s: %d is outside %d to %d", o.key, v, o.min, o.max)
		}
		args = append(args, o.flag, strconv.Itoa(v))
	}

	if raw, ok := cfg["timeout"].(string); ok && raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil {
			return nil, fmt.Errorf("nuclei: timeout: %q is not a duration such as 30s", raw)
		}
		if d < nucleiTimeoutMin || d > nucleiTimeoutMax || d%time.Second != 0 {
			return nil, fmt.Errorf("nuclei: timeout: %s is not a whole number of seconds from 1s to 10m", raw)
		}
		args = append(args, "-timeout", strconv.Itoa(int(d/time.Second)))
	}

	// Offline, the callback templates are skipped too: registering with the servers and polling
	// them is the network an offline run does not use.
	if on, set := cfg[nucleiInteractshKey].(bool); (set && !on) || netpolicy.Offline() {
		args = append(args, "-ni")
	}
	return args, nil
}

// nucleiNamesTemplates reports whether the descriptor replaces the community set with its own.
func nucleiNamesTemplates(cfg plugin.Config) bool { return len(stringList(cfg, "templates")) > 0 }

// nucleiTemplateArg is one templates entry as -t has to receive it.
//
// Absolute, because Nuclei resolves a relative path against its own template directory first,
// and the entry means a path beside the descriptor.
//
// Quoted, because Nuclei's flag parser reads any existing file it is given as a list of paths,
// one per line, so a template file passed bare becomes its own YAML lines. A quoted value is
// never taken for a file name, and the parser removes the quotes. A path holding a quote cannot
// be passed this way, and neither can a URL, which Nuclei would download.
func nucleiTemplateArg(path string) (string, error) {
	path = strings.TrimSpace(path)
	switch {
	case path == "":
		return "", fmt.Errorf("nuclei: templates: an entry is empty")
	case strings.Contains(path, "://"):
		return "", fmt.Errorf("nuclei: templates: %q is a URL; templates are read from disk, so "+
			"download it beside the descriptor and name the file", path)
	case strings.ContainsAny(path, "'\"`"):
		return "", fmt.Errorf("nuclei: templates: %q holds a quote; rename the file or directory without one", path)
	}
	return "'" + absPath(path) + "'", nil
}

// nucleiOptionFields records the options that change what a scan examined, for its provenance.
// Each is present only where the descriptor set it, so a default run records what it always has.
func nucleiOptionFields(cfg plugin.Config) []sarif.Field {
	var out []sarif.Field
	if on, _ := cfg[nucleiIntrusiveKey].(bool); on {
		out = append(out, sarif.Field{Key: "intrusive", Value: "true"})
	}
	for _, key := range []string{"tags", "excludeTags", "templates"} {
		if v := commaList(cfg, key); v != "" {
			out = append(out, sarif.Field{Key: key, Value: strings.ReplaceAll(v, ",", ", ")})
		}
	}
	if on, set := cfg["interactsh"].(bool); set && !on {
		out = append(out, sarif.Field{Key: "interactsh", Value: "false"})
	}
	return out
}
