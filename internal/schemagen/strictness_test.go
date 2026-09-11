package schemagen

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/builtins"
)

// The schema is how an editor answers before Draugr does, so every place it is looser than the
// loader is a place somebody is told a descriptor is fine and finds out from CI that it is not.
//
// Closing one field at a time does not hold: the next field arrives, the reasoning is not written
// down anywhere the author of that field will read, and the schema drifts open again. So the rule
// is a test rather than a habit. A string property is either closed, or it is listed below with
// the reason it is open, and there is no third option that compiles.
//
// Adding a field to the Saga therefore costs one decision, once, at the moment it is easiest to
// make.

// openStrings are the string properties that are deliberately free-form, each with why.
//
// A reason, not a checkmark. "It is a name" and "we have not got round to it" look identical in a
// list of paths, and only one of them should survive review.
// #nosec G101 -- schema paths and the reasons beside them. Two of the paths end in `tokenEnv` and
// `productToken`, which are the names of fields that hold the *name of an environment variable*;
// a descriptor has no field for a credential and this map holds no value from one.
var openStrings = map[string]string{
	// Identities and names. The organization's vocabulary, not ours.
	"$defs.component.properties.name":                        "the component's own name",
	"$defs.host.properties.name":                             "the endpoint's own name",
	"$defs.release.properties.version":                       "the project's version string, in whatever scheme it uses",
	"$defs.infrastructure.properties.ref":                    "a cluster name, chosen by whoever runs it",
	"$defs.vexConfig.properties.author":                      "who is asserting, free text",
	"$defs.vexConfig.properties.product":                     "the product identifier a consumer will match on",
	"$defs.excludeRule.properties.reason":                    "why somebody excused a finding, in their words",
	"$defs.excludeRule.properties.acceptedBy":                "who accepted it: an address or a name",
	"$defs.component.properties.labels.additionalProperties": "the organization's own label values",

	// Locations. Paths, URLs and refs cannot be enumerated.
	"$defs.repository.properties.url":                  "a git URL or a local path",
	"$defs.repository.properties.revision":             "a branch, tag or commit",
	"$defs.repository.properties.paths.items":          "a path within the repository",
	"$defs.repository.properties.ignore.items":         "a path within the repository",
	"$defs.fragmentRef.properties.path":                "a path to a fragment",
	"$defs.fragmentRef.properties.url":                 "a repository holding fragments",
	"$defs.fragmentRef.properties.revision":            "a branch, tag or commit",
	"$defs.hostSpec.properties.path":                   "a path to an OpenAPI document",
	"$defs.host.properties.url":                        "the endpoint's address",
	"$defs.image.properties.image":                     "an image reference",
	"$defs.image.properties.digest":                    "a content digest",
	"$defs.vexSource.properties.path":                  "a path to a VEX document",
	"$defs.vexSource.properties.url":                   "a URL to a VEX document",
	"$defs.vexRepository.properties.url":               "a repository holding VEX documents",
	"$defs.vexRepository.properties.path":              "a path within it",
	"$defs.vexRepository.properties.ref":               "a branch, tag or commit",
	"$defs.reference.properties.link":                  "a link to a document",
	"$defs.excludeRule.properties.paths.items":         "a path the rule applies to",
	"$defs.infrastructure.properties.namespaces.items": "a namespace name",
	"$defs.publisherConfig.properties.dir":             "a directory to write into",
	"$defs.publisherConfig.properties.url":             "a forge's base URL",
	"$defs.publisherConfig.properties.org":             "an organization on that forge",
	"$defs.publisherConfig.properties.project":         "a project on that forge",
	"$defs.publisherConfig.properties.repo":            "a repository on that forge",
	"$defs.publisherConfig.properties.ref":             "a branch, tag or commit",
	"$defs.publisherConfig.properties.commit":          "a commit to attach a comment to",
	"$defs.publisherConfig.properties.marker":          "the marker identifying our own comment",
	"$defs.reportConfig.properties.filename":           "what to call the file",
	"$defs.reportConfig.properties.template":           "an inline Go template",
	"$defs.reportConfig.properties.templateFile":       "a path to one",

	// Another tool's vocabulary. Enumerating it here would freeze a list that tool owns and that
	// changes on its release schedule, not ours, and the schema would then reject a value the
	// tool accepts.
	"$defs.control_sast.properties.semgrep.properties.config":                      "a Semgrep registry ref or a path",
	"$defs.control_secrets.properties.gitleaks.properties.config":                  "a path to a gitleaks ruleset",
	"$defs.control_infrastructure.properties.kubeBench.properties.benchmark":       "kube-bench's own benchmark names",
	"$defs.control_infrastructure.properties.kubeBench.properties.targets":         "kube-bench's own target names",
	"$defs.control_infrastructure.properties.kubeBench.properties.version":         "a Kubernetes version",
	"$defs.control_infrastructure.properties.kubeBench.properties.context":         "a kubeconfig context name",
	"$defs.control_infrastructure.properties.kubeBench.properties.configDir":       "a path inside the image",
	"$defs.control_infrastructure.properties.kubeBenchJob.properties.benchmark":    "kube-bench's own benchmark names",
	"$defs.control_infrastructure.properties.kubeBenchJob.properties.targets":      "kube-bench's own target names",
	"$defs.control_infrastructure.properties.kubeBenchJob.properties.context":      "a kubeconfig context name",
	"$defs.control_infrastructure.properties.kubeBenchJob.properties.image":        "an image reference",
	"$defs.control_infrastructure.properties.kubeBenchJob.properties.namespace":    "a namespace name",
	"$defs.control_infrastructure.properties.kubeBenchJob.properties.nodeSelector": "a node label selector",
	"$defs.control_infrastructure.properties.kubeBenchJob.properties.timeout":      "a duration",
	"$defs.control_licenses.properties.mendLicenses.properties.project":            "a project name in Mend",
	"$defs.control_licenses.properties.mendLicenses.properties.productToken":       "a token identifying a Mend product",
	"$defs.control_licenses.properties.mendLicenses.properties.resultTimeout":      "a duration",
	"$defs.control_sca.properties.mendSca.properties.project":                      "a project name in Mend",
	"$defs.control_sca.properties.mendSca.properties.productToken":                 "a token identifying a Mend product",
	"$defs.control_sca.properties.mendSca.properties.resultTimeout":                "a duration",

	// A keyword or a path. The keywords are in `examples`, which offers them without rejecting
	// the path, and an enum here would reject every real file.
	"$defs.exploitabilityConfig.properties.kev":    `"cache", "auto", or a path`,
	"$defs.exploitabilityConfig.properties.epss":   `"cache", "auto", or a path`,
	"$defs.exploitabilityConfig.properties.maxAge": "a duration",

	// Credentials are never in the descriptor; these name the variable holding one, and the name
	// is the author's choice.
	"$defs.hostAuth.properties.tokenEnv":        "the environment variable holding the credential",
	"$defs.publisherConfig.properties.tokenEnv": "the environment variable holding the credential",
	"$defs.hostAuth.properties.header":          "a header name",

	// The author's own taxonomy rather than ours: a reference is whatever document they keep.
	"$defs.reference.properties.type": "the author's own kind of document",

	// Scanner rule ids. Ours are stable but a scanner's are its own, and an exclusion is written
	// against whatever the tool emitted.
	"$defs.excludeRule.properties.rules.items": "a scanner's own rule id",
	// A date, shaped by `pattern` rather than enumerated.
	"$defs.excludeRule.properties.expires": "a date, held to a pattern instead",
	// Generated from the registry elsewhere in this package; the bare definition is the target of
	// a $ref and carries the enum on the properties that use it.
	"$defs.controlName":  "generated from the registry by controlNameDef",
	"properties.project": "the project's own identifier, held to a pattern",
}

// openObjects are the objects that deliberately accept keys we do not know, each with why.
var openObjects = map[string]string{
	"$defs.control_licenses.properties.mendLicenses.properties.settings": "Unified Agent keys, passed through verbatim",
	"$defs.control_sca.properties.mendSca.properties.settings":           "Unified Agent keys, passed through verbatim",
}

// isObject reports whether a node describes an object whose keys matter.
//
// `type: object` with no `properties` counts. That shape accepts every key and names none, which is
// the loosest thing the schema can say and the easiest to miss: a check that looks only for
// `properties` walks straight past it.
func isObject(n map[string]any) bool {
	if n["type"] == "object" {
		return true
	}
	_, has := n["properties"]
	return has
}

// closed reports whether a node enumerates its values, in any of the spellings this schema uses.
//
// Scalars use `anyOf` of `const`, which is what makes an editor show a description beside each
// completion; arrays use `items.enum`. A checker that knows only one of them reports the other as
// a gap, which is how an audit comes to claim `exposure` is unconstrained.
func closed(n map[string]any) bool {
	if _, ok := n["enum"]; ok {
		return true
	}
	if _, ok := n["const"]; ok {
		return true
	}
	if _, ok := n["pattern"]; ok {
		return true
	}
	for _, key := range []string{"anyOf", "oneOf", "allOf"} {
		vs, ok := n[key].([]any)
		if !ok || len(vs) == 0 {
			continue
		}
		every := true
		for _, v := range vs {
			m, ok := v.(map[string]any)
			if !ok {
				every = false
				break
			}
			_, hasConst := m["const"]
			_, hasEnum := m["enum"]
			if !hasConst && !hasEnum {
				every = false
				break
			}
		}
		if every {
			return true
		}
	}
	if items, ok := n["items"].(map[string]any); ok {
		return closed(items)
	}
	return false
}

// walkSchema visits every node, naming it by the path a reader can follow in the file.
func walkSchema(n any, path string, visit func(string, map[string]any)) {
	switch v := n.(type) {
	case map[string]any:
		visit(path, v)
		for k, child := range v {
			if k == "description" || k == "examples" || k == "default" {
				continue
			}
			next := k
			if path != "" {
				next = path + "." + k
			}
			walkSchema(child, next, visit)
		}
	case []any:
		for i, child := range v {
			walkSchema(child, fmt.Sprintf("%s[%d]", path, i), visit)
		}
	}
}

func loadSchema(t *testing.T) map[string]any {
	t.Helper()
	data, err := os.ReadFile(schemaPath())
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

// TestEveryStringIsClosedOrSaysWhyNot is the rule that keeps the schema from drifting open.
//
// A new string property fails this until its author decides: enumerate it from whatever in Go
// already knows the answer, or list it above with the reason it cannot be. Both are cheap at that
// moment and neither is cheap six months later, when the field is in descriptors people have
// written and an editor has been telling them a typo is fine.
func TestEveryStringIsClosedOrSaysWhyNot(t *testing.T) {
	var loose []string
	walkSchema(loadSchema(t), "", func(path string, n map[string]any) {
		if n["type"] != "string" || closed(n) {
			return
		}
		if _, ok := n["$ref"]; ok {
			return
		}
		if _, known := openStrings[path]; known {
			return
		}
		loose = append(loose, path)
	})
	sort.Strings(loose)
	for _, p := range loose {
		t.Errorf("%s accepts any string.\n"+
			"    Close it — an `anyOf` of `const` for a scalar, `items.enum` for an array, "+
			"generated from whatever in Go already knows the values — or add it to openStrings "+
			"with the reason it cannot be closed.", p)
	}
}

// TestEveryObjectIsClosedOrSaysWhyNot is the same rule for keys rather than values.
//
// `additionalProperties: false` is what makes an editor flag a misspelled key where it is typed.
// Without it a descriptor can carry a block Draugr never reads, and nothing says so: the run
// succeeds, the setting does nothing, and the only symptom is a control behaving as though it was
// never configured.
func TestEveryObjectIsClosedOrSaysWhyNot(t *testing.T) {
	var open []string
	walkSchema(loadSchema(t), "", func(path string, n map[string]any) {
		if !isObject(n) {
			return
		}
		switch ap := n["additionalProperties"].(type) {
		case bool:
			if !ap {
				return // closed
			}
		case map[string]any:
			return // a typed map: the values are constrained, which is the point
		}
		if _, known := openObjects[path]; known {
			return
		}
		open = append(open, path)
	})
	sort.Strings(open)
	for _, p := range open {
		t.Errorf("%s accepts keys Draugr does not read.\n"+
			"    Set additionalProperties: false so an editor flags a misspelled key where it is "+
			"typed, or add it to openObjects with the reason it has to stay open.", p)
	}
}

// TestNothingIsExcusedThatIsNoLongerThere keeps the two lists honest.
//
// An entry for a field that has been closed, renamed or removed is an excuse nobody is using, and
// a list of those is how the next person comes to believe the rule is advisory. It also catches a
// rename: the old path stops matching, which would otherwise let the renamed field through
// silently under its excuse.
func TestNothingIsExcusedThatIsNoLongerThere(t *testing.T) {
	seenString := map[string]bool{}
	seenObject := map[string]bool{}
	walkSchema(loadSchema(t), "", func(path string, n map[string]any) {
		if n["type"] == "string" {
			seenString[path] = true
		}
		if isObject(n) {
			seenObject[path] = true
		}
	})
	for path, why := range openStrings {
		if !seenString[path] {
			t.Errorf("openStrings has %q (%s) and the schema has no such string. "+
				"Closed, renamed or removed: drop the entry.", path, why)
		}
	}
	for path, why := range openObjects {
		if !seenObject[path] {
			t.Errorf("openObjects has %q (%s) and the schema has no such object. "+
				"Closed, renamed or removed: drop the entry.", path, why)
		}
	}
}

// TestTheFragmentSchemaIsHeldToTheSameRule, because a fragment is a descriptor somebody writes in
// an editor too, and it is generated from the Saga's schema rather than authored.
func TestTheFragmentSchemaIsHeldToTheSameRule(t *testing.T) {
	data, err := os.ReadFile(strings.Replace(schemaPath(), "draugr.saga.schema.json",
		"draugr.saga-fragment.schema.json", 1))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	var loose []string
	walkSchema(doc, "", func(path string, n map[string]any) {
		if n["type"] != "string" || closed(n) {
			return
		}
		if _, ok := n["$ref"]; ok {
			return
		}
		if _, known := openStrings[path]; known {
			return
		}
		loose = append(loose, path)
	})
	sort.Strings(loose)
	for _, p := range loose {
		t.Errorf("fragment schema: %s accepts any string, and the Saga's does not excuse it", p)
	}
}

// TestApplyRefusesASchemaItCannotFillIn covers the guards on every definition the generator writes
// into.
//
// They look like paranoia about a file in this repository, and they are the difference between a
// rename landing as a failed build and landing as a schema that is quietly missing an enum. A
// generator that writes what it can and returns success is exactly how the schema drifts open
// again, which is the thing the rest of this file exists to prevent.
func TestApplyRefusesASchemaItCannotFillIn(t *testing.T) {
	for _, def := range []string{
		"$defs", "controllers", "config", "reportConfig", "reachabilityConfig", "infrastructure",
	} {
		t.Run(def, func(t *testing.T) {
			doc := loadSchema(t)
			if def == "$defs" {
				delete(doc, "$defs")
			} else {
				delete(doc["$defs"].(map[string]any), def)
			}
			raw, err := json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Apply(raw, builtins.Registry()); err == nil {
				t.Errorf("Apply succeeded with %q missing, so a rename would ship a schema with "+
					"that part ungenerated", def)
			} else if !strings.Contains(err.Error(), def) && def != "$defs" {
				t.Errorf("error does not name what is missing: %v", err)
			}
		})
	}
	// And the same for a definition that is present but the wrong shape, which is what a hand edit
	// produces.
	doc := loadSchema(t)
	doc["$defs"].(map[string]any)["reachabilityConfig"] = map[string]any{"type": "string"}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(raw, builtins.Registry()); err == nil {
		t.Error("Apply accepted a reachabilityConfig with no properties")
	}
	if _, err := Apply([]byte("not json"), builtins.Registry()); err == nil {
		t.Error("Apply accepted something that is not a schema")
	}
}
