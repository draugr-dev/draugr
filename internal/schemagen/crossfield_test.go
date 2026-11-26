package schemagen

import (
	"maps"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/draugr-dev/draugr/internal/sagatest"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// TestTheEditorAndDraugrHoldImportKeysToFormatAndKind writes one import for each rule that ties an
// import's keys to its format or to whether it reads a file or a source, in the shape the rule
// refuses and in one it accepts, and requires the JSON Schema and the loader to give the same
// answer as the case does.
//
// The schema closes each key on its own, so a one-field change to an example never moves a key onto
// the wrong format or kind; this is the half of the parity those changes cannot reach. An import
// with no format is read as SARIF, so the cases that leave format out are the ones that hold the
// schema to that default.
func TestTheEditorAndDraugrHoldImportKeysToFormatAndKind(t *testing.T) {
	severity := map[string]any{"property": "acme-severity", "values": map[string]any{"Blocker": "critical"}}
	conv := map[string]any{"name": "acme", "contract": 1}
	file := func(kv map[string]any) map[string]any {
		out := map[string]any{"control": "sast", "file": "reports/tool.out"}
		maps.Copy(out, kv)
		return out
	}
	source := func(kv map[string]any) map[string]any {
		out := map[string]any{"control": "sast", "source": saga.ImportSourceGitHubCodeScanning}
		maps.Copy(out, kv)
		return out
	}
	cases := []struct {
		name     string
		imp      map[string]any
		fragment bool
		ok       bool
	}{
		{"a file", file(nil), false, true},
		{"a source", source(nil), false, true},

		{"tokenEnv on a source", source(map[string]any{"tokenEnv": "GH_TOKEN"}), false, true},
		{"tokenEnv on a file", file(map[string]any{"tokenEnv": "GH_TOKEN"}), false, false},
		{"repository on a source", source(map[string]any{"repository": "acme/web"}), false, true},
		{"repository on a file", file(map[string]any{"repository": "acme/web"}), false, false},

		{"format on a source", source(map[string]any{"format": saga.ImportFormatSARIF}), false, false},
		{"severity on a source", source(map[string]any{"severity": severity}), false, false},
		{"commit on a file", file(map[string]any{"commit": "0123abc"}), false, true},
		{"commit on a source", source(map[string]any{"commit": "0123abc"}), false, false},
		{"converter on a source", source(map[string]any{"converter": conv}), false, false},
		{"suppressions on a source", source(map[string]any{"suppressions": "count"}), false, true},

		{"severity with no format", file(map[string]any{"severity": severity}), false, true},
		{"severity on sarif", file(map[string]any{"format": saga.ImportFormatSARIF, "severity": severity}), false, true},
		{"severity on trivy-json", file(map[string]any{"format": saga.ImportFormatTrivyJSON, "severity": severity}), false, false},
		{"severity on osv-scanner-json", file(map[string]any{"format": saga.ImportFormatOSVScannerJSON, "severity": severity}), false, false},
		{"severity on veracode-pipeline-json", file(map[string]any{"format": saga.ImportFormatVeracodePipelineJSON, "severity": severity}), false, false},
		{"severity on gitlab-sast", file(map[string]any{"format": saga.ImportFormatGitLabSAST, "severity": severity}), false, false},
		{"severity on gitlab-dependency-scanning", file(map[string]any{"format": saga.ImportFormatGitLabDependencyScanning, "severity": severity}), false, false},
		{"severity on jfrog-simple-json", file(map[string]any{"format": saga.ImportFormatJFrogSimpleJSON, "severity": severity}), false, false},

		{"suppressions with no format", file(map[string]any{"suppressions": "count"}), false, true},
		{"suppressions on trivy-json", file(map[string]any{"format": saga.ImportFormatTrivyJSON, "control": "sca", "suppressions": "count"}), false, true},
		{"suppressions on osv-scanner-json", file(map[string]any{"format": saga.ImportFormatOSVScannerJSON, "suppressions": "honor"}), false, false},
		{"suppressions on veracode-pipeline-json", file(map[string]any{"format": saga.ImportFormatVeracodePipelineJSON, "suppressions": "count"}), false, false},
		{"suppressions on gitlab-sast", file(map[string]any{"format": saga.ImportFormatGitLabSAST, "suppressions": "honor"}), false, false},
		{"suppressions on gitlab-dependency-scanning", file(map[string]any{"format": saga.ImportFormatGitLabDependencyScanning, "suppressions": "count"}), false, false},
		{"suppressions on jfrog-simple-json", file(map[string]any{"format": saga.ImportFormatJFrogSimpleJSON, "suppressions": "honor"}), false, false},

		{"checkmarx-one-json into sast", file(map[string]any{"format": saga.ImportFormatCheckmarxOneJSON}), false, true},
		{"checkmarx-one-json into iac", file(map[string]any{"format": saga.ImportFormatCheckmarxOneJSON, "control": "iac"}), false, true},
		{"checkmarx-one-json into secrets", file(map[string]any{"format": saga.ImportFormatCheckmarxOneJSON, "control": "secrets"}), false, false},
		{"suppressions on checkmarx-one-json", file(map[string]any{"format": saga.ImportFormatCheckmarxOneJSON, "suppressions": "count"}), false, true},
		{"severity on checkmarx-one-json", file(map[string]any{"format": saga.ImportFormatCheckmarxOneJSON, "severity": severity}), false, false},
		{"checkmarx-one-json into dast in a fragment", file(map[string]any{"format": saga.ImportFormatCheckmarxOneJSON, "control": "dast"}), true, false},

		{"mend-json into sca", file(map[string]any{"format": saga.ImportFormatMendJSON, "control": "sca"}), false, true},
		{"mend-json into sast", file(map[string]any{"format": saga.ImportFormatMendJSON, "control": "sast"}), false, false},
		{"mend-json into sast in a fragment", file(map[string]any{"format": saga.ImportFormatMendJSON, "control": "sast"}), true, false},
		{"severity on mend-json", file(map[string]any{"format": saga.ImportFormatMendJSON, "control": "sca", "severity": severity}), false, false},
		{"trivy-json into sca", file(map[string]any{"format": saga.ImportFormatTrivyJSON, "control": "sca"}), false, true},
		{"trivy-json into images", file(map[string]any{"format": saga.ImportFormatTrivyJSON, "control": "images"}), false, true},
		{"trivy-json into secrets", file(map[string]any{"format": saga.ImportFormatTrivyJSON, "control": "secrets"}), false, false},
		{"trivy-json into iac in a fragment", file(map[string]any{"format": saga.ImportFormatTrivyJSON, "control": "iac"}), true, false},
		{"govulncheck-json into sca", file(map[string]any{"format": saga.ImportFormatGovulncheckJSON, "control": "sca"}), false, true},
		{"govulncheck-json into sast", file(map[string]any{"format": saga.ImportFormatGovulncheckJSON, "control": "sast"}), false, false},
		{"govulncheck-json into sast in a fragment", file(map[string]any{"format": saga.ImportFormatGovulncheckJSON, "control": "sast"}), true, false},
		{"grype-json into sca", file(map[string]any{"format": saga.ImportFormatGrypeJSON, "control": "sca"}), false, true},
		{"grype-json into images", file(map[string]any{"format": saga.ImportFormatGrypeJSON, "control": "images"}), false, false},
		{"grype-json into images in a fragment", file(map[string]any{"format": saga.ImportFormatGrypeJSON, "control": "images"}), true, false},
		{"osv-scanner-json into sca", file(map[string]any{"format": saga.ImportFormatOSVScannerJSON, "control": "sca"}), false, true},
		{"osv-scanner-json into licenses", file(map[string]any{"format": saga.ImportFormatOSVScannerJSON, "control": "licenses"}), false, false},
		{"osv-scanner-json into licenses in a fragment", file(map[string]any{"format": saga.ImportFormatOSVScannerJSON, "control": "licenses"}), true, false},
		{"veracode-pipeline-json into sast", file(map[string]any{"format": saga.ImportFormatVeracodePipelineJSON, "control": "sast"}), false, true},
		{"veracode-pipeline-json into sca", file(map[string]any{"format": saga.ImportFormatVeracodePipelineJSON, "control": "sca"}), false, false},
		{"veracode-pipeline-json into sca in a fragment", file(map[string]any{"format": saga.ImportFormatVeracodePipelineJSON, "control": "sca"}), true, false},
		{"gitlab-sast into sast", file(map[string]any{"format": saga.ImportFormatGitLabSAST, "control": "sast"}), false, true},
		{"gitlab-sast into sca", file(map[string]any{"format": saga.ImportFormatGitLabSAST, "control": "sca"}), false, false},
		{"gitlab-sast into sca in a fragment", file(map[string]any{"format": saga.ImportFormatGitLabSAST, "control": "sca"}), true, false},
		{"gitlab-dependency-scanning into sca", file(map[string]any{"format": saga.ImportFormatGitLabDependencyScanning, "control": "sca"}), false, true},
		{"gitlab-dependency-scanning into sast", file(map[string]any{"format": saga.ImportFormatGitLabDependencyScanning, "control": "sast"}), false, false},
		{"gitlab-dependency-scanning into sast in a fragment", file(map[string]any{"format": saga.ImportFormatGitLabDependencyScanning, "control": "sast"}), true, false},
		{"jfrog-simple-json into sca", file(map[string]any{"format": saga.ImportFormatJFrogSimpleJSON, "control": "sca"}), false, true},
		{"jfrog-simple-json into sast", file(map[string]any{"format": saga.ImportFormatJFrogSimpleJSON, "control": "sast"}), false, false},
		{"jfrog-simple-json into sast in a fragment", file(map[string]any{"format": saga.ImportFormatJFrogSimpleJSON, "control": "sast"}), true, false},
		{"suppressions on mend-json", file(map[string]any{"format": saga.ImportFormatMendJSON, "control": "sca", "suppressions": "count"}), false, false},

		{"twistcli-json into images", file(map[string]any{"format": saga.ImportFormatTwistcliJSON, "control": "images"}), false, true},
		{"twistcli-json into sca", file(map[string]any{"format": saga.ImportFormatTwistcliJSON, "control": "sca"}), false, false},
		{"twistcli-json into sca in a fragment", file(map[string]any{"format": saga.ImportFormatTwistcliJSON, "control": "sca"}), true, false},
		{"severity on twistcli-json", file(map[string]any{"format": saga.ImportFormatTwistcliJSON, "control": "images", "severity": severity}), false, false},
		{"suppressions on twistcli-json", file(map[string]any{"format": saga.ImportFormatTwistcliJSON, "control": "images", "suppressions": "count"}), false, false},

		{"draugr-converter with its converter", file(map[string]any{"format": saga.ImportFormatConverter, "converter": conv}), false, true},
		{"draugr-converter with no converter", file(map[string]any{"format": saga.ImportFormatConverter}), false, false},
		{"suppressions on draugr-converter", file(map[string]any{"format": saga.ImportFormatConverter, "converter": conv, "suppressions": "count"}), false, false},
		{"converter on sarif", file(map[string]any{"format": saga.ImportFormatSARIF, "converter": conv}), false, false},
		{"converter with no format", file(map[string]any{"converter": conv}), false, false},
		{"converter on grype-json", file(map[string]any{"format": saga.ImportFormatGrypeJSON, "converter": conv}), false, false},

		{"a file in a fragment", file(nil), true, true},
		{"tokenEnv on a source in a fragment", source(map[string]any{"tokenEnv": "GH_TOKEN"}), true, true},
		{"tokenEnv on a file in a fragment", file(map[string]any{"tokenEnv": "GH_TOKEN"}), true, false},
		{"repository on a file in a fragment", file(map[string]any{"repository": "acme/web"}), true, false},
		{"format on a source in a fragment", source(map[string]any{"format": saga.ImportFormatTrivyJSON}), true, false},
		{"commit on a source in a fragment", source(map[string]any{"commit": "0123abc"}), true, false},
		{"severity with no format in a fragment", file(map[string]any{"severity": severity}), true, true},
		{"severity on govulncheck-json in a fragment", file(map[string]any{"format": saga.ImportFormatGovulncheckJSON, "severity": severity}), true, false},
		{"suppressions on osv-scanner-json in a fragment", file(map[string]any{"format": saga.ImportFormatOSVScannerJSON, "suppressions": "count"}), true, false},
	}
	for _, c := range cases {
		doc := map[string]any{"components": []any{map[string]any{"name": "web", "imports": []any{c.imp}}}}
		if !c.fragment {
			doc["project"] = "shop"
		}
		bothJudge(t, c.name, doc, c.fragment, c.ok)
	}
}

// bothJudge requires the loader and the JSON Schema each to accept doc exactly when ok says so.
func bothJudge(t *testing.T, name string, doc map[string]any, fragment, ok bool) {
	t.Helper()
	data, err := yaml.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	var loadErr error
	if fragment {
		_, loadErr = saga.LoadFragment(data, "rules.saga-fragment.yaml")
	} else {
		_, loadErr = saga.Load(data)
	}
	schemaErr := sagatest.SchemaError(t, doc, fragment)
	if (loadErr == nil) != ok || (schemaErr == nil) != ok {
		t.Errorf("%s: draugr validate accepts=%v, the schema accepts=%v, want %v\n  validate: %v\n  schema: %v",
			name, loadErr == nil, schemaErr == nil, ok, loadErr, schemaErr)
	}
}

// TestTheEditorAndDraugrAgreeWhereNoMutationReaches holds both readers to the rules across keys that
// a change to one key of the parity corpus cannot reach: a key whose value would have to change
// together with another's, such as an item type beside children, or a key on an object a list holds
// one of.
func TestTheEditorAndDraugrAgreeWhereNoMutationReaches(t *testing.T) {
	descriptor := func(component map[string]any, config map[string]any) map[string]any {
		c := map[string]any{"name": "web"}
		maps.Copy(c, component)
		doc := map[string]any{"project": "shop", "components": []any{c}}
		if config != nil {
			doc["config"] = config
		}
		return doc
	}
	host := func(auth map[string]any) map[string]any {
		return map[string]any{"hosts": []any{map[string]any{"url": "https://api.example.com", "auth": auth}}}
	}
	publisher := func(p map[string]any) map[string]any {
		entry := map[string]any{"kind": "gitlab-issue"}
		maps.Copy(entry, p)
		return map[string]any{"publishers": []any{entry}}
	}
	exclude := func(e map[string]any) map[string]any {
		entry := map[string]any{"reason": "accepted risk"}
		maps.Copy(entry, e)
		return map[string]any{"exclude": []any{entry}}
	}
	images := map[string]any{"images": []any{map[string]any{"image": "alpine:3.19"}}}
	for _, c := range []struct {
		name string
		doc  map[string]any
		ok   bool
	}{
		{"a header named with type header", descriptor(host(map[string]any{"type": "header", "header": "X-API-Key", "tokenEnv": "API_KEY"}), nil), true},
		{"no header with type header", descriptor(host(map[string]any{"type": "header", "tokenEnv": "API_KEY"}), nil), false},
		{"bearer", descriptor(host(map[string]any{"type": "bearer", "tokenEnv": "API_KEY"}), nil), true},
		{"a header with type bearer", descriptor(host(map[string]any{"type": "bearer", "header": "X-API-Key", "tokenEnv": "API_KEY"}), nil), false},

		{"children: controls with split: component", descriptor(images, publisher(map[string]any{"children": "controls", "split": "component"})), true},
		{"children: controls with split: control", descriptor(images, publisher(map[string]any{"children": "controls", "split": "control"})), false},
		{"children: actions with split: control", descriptor(images, publisher(map[string]any{"children": "actions", "split": "control"})), true},
		{"maxChildren with children: actions", descriptor(images, publisher(map[string]any{"children": "actions", "maxChildren": 5})), true},
		{"maxChildren with children: none", descriptor(images, publisher(map[string]any{"children": "none", "maxChildren": 5})), false},
		{"maxChildren with no children", descriptor(images, publisher(map[string]any{"maxChildren": 5})), false},
		{"a GitLab task with no children", descriptor(images, publisher(map[string]any{"item": map[string]any{"type": "task"}})), true},
		{"a GitLab task with children: none", descriptor(images, publisher(map[string]any{"item": map[string]any{"type": "task"}, "children": "none"})), true},
		{"a GitLab task with children: actions", descriptor(images, publisher(map[string]any{"item": map[string]any{"type": "task"}, "children": "actions"})), false},
		{"a GitLab issue with children: actions", descriptor(images, publisher(map[string]any{"item": map[string]any{"type": "issue"}, "children": "actions"})), true},
		{"a select naming controls", descriptor(images, publisher(map[string]any{"select": map[string]any{"controls": []any{"images"}}})), true},
		{"a select naming nothing", descriptor(images, publisher(map[string]any{"select": map[string]any{}})), false},
		{"a select of empty lists", descriptor(images, publisher(map[string]any{"select": map[string]any{"components": []any{}, "labels": map[string]any{}}})), false},

		{"an exclusion by rule", descriptor(images, exclude(map[string]any{"rules": []any{"CVE-2024-0001"}})), true},
		{"an exclusion by neither", descriptor(images, exclude(nil)), false},
		{"an exclusion of empty lists", descriptor(images, exclude(map[string]any{"rules": []any{}, "paths": []any{}})), false},

		{"a VEX source by path", descriptor(map[string]any{"vex": []any{map[string]any{"path": "vex.json"}}}, nil), true},
		{"a VEX source by path and url", descriptor(map[string]any{"vex": []any{map[string]any{"path": "vex.json", "url": "https://example.com/vex.json"}}}, nil), false},
		{"a VEX source naming no place", descriptor(map[string]any{"vex": []any{map[string]any{}}}, nil), false},
	} {
		bothJudge(t, c.name, c.doc, false, c.ok)
	}
	for _, c := range []struct {
		name      string
		reference map[string]any
		ok        bool
	}{
		{"a reference", map[string]any{"type": "ThreatModel", "link": "https://example.com/tm"}, true},
		{"a reference with no link", map[string]any{"type": "ThreatModel"}, false},
		{"a reference with no type", map[string]any{"link": "https://example.com/tm"}, false},
	} {
		doc := descriptor(images, nil)
		doc["references"] = []any{c.reference}
		bothJudge(t, c.name, doc, false, c.ok)
	}
}
