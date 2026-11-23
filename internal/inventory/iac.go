package inventory

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// The iac control runs `trivy config` with Trivy's default misconfiguration scanners. The checks in
// this file decide which files those scanners read the way Trivy 0.76.1 does
// (pkg/iac/detection/detect.go and pkg/iac/scanners/ansible/parser/discovery.go), so a tree init
// leaves iac off for is one Trivy would have read nothing in. Where a check here is looser than
// Trivy's, init turns iac on and Trivy reads nothing, which costs one line; where it were stricter,
// a tree's infrastructure would go unchecked with nothing said.

// sniffBytes is how much of a YAML or JSON file is read to decide whether it is infrastructure code.
// A CloudFormation template may open with a long Parameters section, so the head that names an
// OpenAPI document is not enough; a file larger than this is judged by what it opens with.
const sniffBytes = 8 << 20

// ansibleAnchors are the names that make the directory holding them an Ansible project to Trivy,
// whether a file or a directory carries the name.
var ansibleAnchors = []string{"ansible.cfg", "inventory", "group_vars", "host_vars", "roles", "playbooks"}

// isTerraform matches the files Trivy's Terraform scanner reads: HCL, its JSON form, variable
// files, and OpenTofu's.
func isTerraform(base string) bool {
	for _, ext := range []string{".tf", ".tf.json", ".tfvars", ".tofu", ".tofu.json"} {
		if strings.HasSuffix(base, ext) {
			return true
		}
	}
	return false
}

// readUpTo reads at most n bytes of the file at p, nothing where it cannot be read.
func readUpTo(p string, n int64) []byte {
	f, err := os.Open(p) // #nosec G304 -- a file under the tree being initialized
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	data, _ := io.ReadAll(io.LimitReader(f, n))
	return data
}

// iacKind names the infrastructure code a YAML or JSON file is to Trivy, or "" for none: a
// CloudFormation template, an Azure Resource Manager template, a Terraform plan, a Kubernetes
// manifest written as JSON, or an Ansible playbook.
func iacKind(rel string, data []byte) string {
	if strings.HasSuffix(rel, ".json") {
		return jsonIaCKind(data)
	}
	return yamlIaCKind(data)
}

const (
	kindCloudFormation = "cloudformation"
	kindAzureARM       = "azure-arm"
	kindTerraformPlan  = "terraformplan-json"
	kindKubernetes     = "kubernetes"
	kindAnsible        = "ansible"
)

// armSchema opens the $schema of every Azure Resource Manager template.
const armSchema = "https://schema.management.azure.com/schemas"

// jsonIaCKind reads a JSON document's top-level keys, exactly as written: encoding/json matches a
// struct's fields without regard to case, and CloudFormation's Resources and an ARM template's
// resources are different keys.
func jsonIaCKind(data []byte) string {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		// An ARM template may carry comments, which Trivy strips before decoding and encoding/json
		// refuses, and a file past sniffBytes arrives cut short.
		if bytes.Contains(data, []byte(`"$schema"`)) && bytes.Contains(data, []byte(armSchema)) {
			return kindAzureARM
		}
		return ""
	}
	has := func(keys ...string) bool {
		for _, k := range keys {
			if _, ok := top[k]; !ok {
				return false
			}
		}
		return true
	}
	switch {
	case isJSONObject(top["Resources"]):
		return kindCloudFormation
	case isARMTemplate(top):
		return kindAzureARM
	case has("terraform_version", "format_version"):
		return kindTerraformPlan
	case has("apiVersion", "kind", "metadata"):
		return kindKubernetes
	}
	return ""
}

// isARMTemplate reports whether a JSON document's top level is an ARM template's: the schema, no
// handler (which marks a portal UI definition instead), and parameters or resources to read.
func isARMTemplate(top map[string]json.RawMessage) bool {
	var schema string
	if json.Unmarshal(top["$schema"], &schema) != nil || !strings.HasPrefix(schema, armSchema) {
		return false
	}
	if _, ok := top["handler"]; ok {
		return false
	}
	var params map[string]json.RawMessage
	_ = json.Unmarshal(top["parameters"], &params)
	var resources any
	_ = json.Unmarshal(top["resources"], &resources)
	switch r := resources.(type) {
	case []any:
		return len(params) > 0 || len(r) > 0
	case map[string]any:
		return len(params) > 0 || len(r) > 0
	}
	return len(params) > 0
}

// isJSONObject reports whether a raw JSON value is an object.
func isJSONObject(raw json.RawMessage) bool {
	return len(bytes.TrimSpace(raw)) > 0 && bytes.TrimSpace(raw)[0] == '{'
}

// yamlIaCKind reads a YAML file's first document: a top-level Resources mapping is a CloudFormation
// template, and a list of plays naming their hosts is an Ansible playbook. Both are looked for in
// the text before the document is parsed, so a large lockfile is not decoded to learn it is neither.
func yamlIaCKind(data []byte) string {
	resources := topLevelKey(data, "Resources")
	playbook := opensWithAListItem(data)
	if !resources && !playbook {
		return ""
	}
	var doc yaml.Node
	if err := yaml.NewDecoder(bytes.NewReader(data)).Decode(&doc); err != nil || len(doc.Content) == 0 {
		return ""
	}
	root := doc.Content[0]
	switch {
	case resources && root.Kind == yaml.MappingNode:
		for i := 0; i+1 < len(root.Content); i += 2 {
			if root.Content[i].Value == "Resources" && root.Content[i+1].Kind == yaml.MappingNode {
				return kindCloudFormation
			}
		}
	case playbook && root.Kind == yaml.SequenceNode:
		if slices.ContainsFunc(root.Content, namesHosts) {
			return kindAnsible
		}
	}
	return ""
}

// namesHosts reports whether a play names the hosts it runs on.
func namesHosts(play *yaml.Node) bool {
	if play.Kind != yaml.MappingNode {
		return false
	}
	for i := 0; i+1 < len(play.Content); i += 2 {
		if play.Content[i].Value == "hosts" {
			v := play.Content[i+1]
			return v.Value != "" || len(v.Content) > 0
		}
	}
	return false
}

// opensWithAListItem reports whether the first line of a YAML document that is not a comment, a
// directive or a document marker opens a list item.
func opensWithAListItem(data []byte) bool {
	for line := range bytes.SplitSeq(data, []byte("\n")) {
		line = bytes.TrimRight(line, "\r")
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) == 0 || trimmed[0] == '#' || trimmed[0] == '%' || bytes.Equal(trimmed, []byte("---")) {
			continue
		}
		return bytes.HasPrefix(line, []byte("- ")) || bytes.Equal(line, []byte("-"))
	}
	return false
}

// servesKinds are the Kubernetes objects that put something in front of a network.
var servesKinds = []string{"Service", "Ingress"}

// declaresService reports whether a YAML file declares a Kubernetes Service or Ingress, in any of
// its documents, a Helm template's included.
func declaresService(data []byte) bool {
	for line := range bytes.SplitSeq(data, []byte("\n")) {
		k, ok := bytes.CutPrefix(bytes.TrimRight(line, "\r "), []byte("kind:"))
		if ok && slices.Contains(servesKinds, string(bytes.TrimSpace(k))) {
			return true
		}
	}
	return false
}

// isCompose matches the file names Docker Compose reads by default.
func isCompose(base string) bool {
	stem := strings.TrimSuffix(strings.TrimSuffix(base, ".yaml"), ".yml")
	if stem == base {
		return false
	}
	return stem == "compose" || stem == "docker-compose" ||
		strings.HasPrefix(stem, "compose.") || strings.HasPrefix(stem, "docker-compose.")
}

// publishesPorts reports whether a Compose file publishes a port for some service.
func publishesPorts(data []byte) bool {
	for line := range bytes.SplitSeq(data, []byte("\n")) {
		if bytes.HasPrefix(bytes.TrimSpace(line), []byte("ports:")) {
			return true
		}
	}
	return false
}

// exposes reports whether a Dockerfile declares a port the image listens on.
func exposes(data []byte) bool {
	for line := range bytes.SplitSeq(data, []byte("\n")) {
		fields := strings.Fields(string(line))
		if len(fields) > 1 && strings.EqualFold(fields[0], "EXPOSE") {
			return true
		}
	}
	return false
}

// dockerfileBytes is how much of a Dockerfile is read for an EXPOSE instruction.
const dockerfileBytes = 1 << 20

// isAnsibleAnchor reports whether an entry's name makes its directory an Ansible project.
func isAnsibleAnchor(rel string) bool {
	return slices.Contains(ansibleAnchors, path.Base(rel))
}
