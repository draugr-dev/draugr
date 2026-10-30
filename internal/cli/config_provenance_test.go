package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/config"
	"github.com/draugr-dev/draugr/pkg/sarif"
	"github.com/draugr-dev/draugr/pkg/skald"
)

// provenanceSaga enables the fake images control, declares one component and takes a second from a
// fragment, so the descriptor block has a fragment beside any configuration file.
const provenanceSaga = `project: payments
release:
  version: "2.4"
fragments:
  - path: security/more.saga-fragment.yaml
config:
  controls:
    images:
      enabled: true
    secrets:
      enabled: true
components:
  - name: api
    images:
      - image: repo/api:1
`

const provenanceFragment = `components:
  - name: worker
    images:
      - image: repo/worker:1
`

// The two files of the scenario: one at each level, each supplying a different default, and the
// project's also pinning a tool, which supplies nothing to the descriptor.
const (
	machineConfig = "controls:\n  secrets:\n    gitleaks:\n      config: /etc/draugr/gitleaks-org.toml\noutput:\n  evidence: true\n"
	projectConfig = "# Team defaults for this repository.\ncontrols:\n  secrets:\n    gitleaks:\n      history: true\ntools:\n  gitleaks:\n    version: 8.30.1\n"
)

// provenanceProject writes the descriptor, its fragment and the given files into a fresh directory
// and makes it the working directory, as `draugr scan` run from a checkout has it.
func provenanceProject(t *testing.T, saga string, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	all := map[string]string{
		"draugr.saga.yaml":                 saga,
		"security/more.saga-fragment.yaml": provenanceFragment,
	}
	for k, v := range files {
		all[k] = v
	}
	for rel, body := range all {
		writeConfigFile(t, filepath.Join(dir, rel), body)
	}
	t.Chdir(dir)
	return dir
}

// scanDescriptor runs a scan of the working directory's descriptor and returns report.json's
// descriptor block, parsed and as written.
func scanDescriptor(t *testing.T) (*skald.DescriptorRef, json.RawMessage) {
	t.Helper()
	var buf bytes.Buffer
	err := runScan(context.Background(), "draugr.saga.yaml",
		scanOptions{failOn: "error", format: "json"}, fakeRegistry(sarif.LevelNote), &buf)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Descriptor json.RawMessage `json:"descriptor"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("unreadable report: %v\n%s", err, buf.String())
	}
	var d skald.DescriptorRef
	if err := json.Unmarshal(doc.Descriptor, &d); err != nil {
		t.Fatal(err)
	}
	return &d, doc.Descriptor
}

// scanEvidence runs the same scan with the evidence shown and returns what the console printed.
func scanEvidence(t *testing.T) string {
	t.Helper()
	t.Setenv("COLUMNS", "")
	var buf bytes.Buffer
	err := runScan(context.Background(), "draugr.saga.yaml",
		scanOptions{failOn: "error", format: "console", evidence: true, noTips: true,
			setFlags: map[string]bool{"no-tips": true}},
		fakeRegistry(sarif.LevelNote), &buf)
	if err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

// configs is each configuration source of a descriptor block, by path, as "config digest".
func configs(d *skald.DescriptorRef) []string {
	var out []string
	for _, s := range d.Sources {
		if s.Config != "" {
			out = append(out, s.Path+" "+s.Config+" "+s.Digest)
		}
	}
	return out
}

// Each file that supplied a control default joins descriptor.sources after the descriptor and its
// fragment, least specific first, with where it was found and the digest of its bytes, and
// descriptor.contributed names the file behind each setting.
func TestAScanRecordsEachConfigFileThatSuppliedAControlDefault(t *testing.T) {
	configHome(t, machineConfig)
	provenanceProject(t, provenanceSaga, map[string]string{config.FileName: projectConfig})

	d, _ := scanDescriptor(t)
	var paths []string
	for _, s := range d.Sources {
		paths = append(paths, s.Path)
	}
	wantPaths := []string{"draugr.saga.yaml", "security/more.saga-fragment.yaml",
		"~/.draugr/config.yaml", "./draugr.config.yaml"}
	if !reflect.DeepEqual(paths, wantPaths) {
		t.Fatalf("sources = %v, want %v", paths, wantPaths)
	}
	wantConfigs := []string{
		"~/.draugr/config.yaml machine " + config.Digest([]byte(machineConfig)),
		"./draugr.config.yaml project " + config.Digest([]byte(projectConfig)),
	}
	if got := configs(d); !reflect.DeepEqual(got, wantConfigs) {
		t.Errorf("config sources = %v, want %v", got, wantConfigs)
	}
	if !d.Sources[0].Root || d.Sources[1].Root || d.Sources[1].Config != "" {
		t.Errorf("the descriptor's own files changed: %+v", d.Sources[:2])
	}
	wantContributed := map[string][]string{
		"secrets.gitleaks.config":  {"~/.draugr/config.yaml"},
		"secrets.gitleaks.history": {"./draugr.config.yaml"},
	}
	if !reflect.DeepEqual(d.Contributed, wantContributed) {
		t.Errorf("contributed = %v, want %v", d.Contributed, wantContributed)
	}
	// The digest is still taken over what ran, the defaults included.
	if !strings.Contains(d.Effective, "history: true") || d.Digest != digestOf(d.Effective) {
		t.Errorf("digest %s is not over the effective descriptor:\n%s", d.Digest, d.Effective)
	}

	out := scanEvidence(t)
	section := out[strings.Index(out, "DESCRIPTOR\n"):]
	section = section[:strings.Index(section, "\n\n")]
	var rows []string
	for line := range strings.Lines(section) {
		rows = append(rows, strings.Join(strings.Fields(line), " "))
	}
	wantRows := []string{
		"DESCRIPTOR",
		"draugr.saga.yaml root · digest " + shortHex(d.Sources[0].Digest),
		"security/more.saga-fragment.yaml digest " + shortHex(d.Sources[1].Digest),
		"~/.draugr/config.yaml config · digest " + shortHex(config.Digest([]byte(machineConfig))) +
			" · secrets.gitleaks.config",
		"./draugr.config.yaml config · digest " + shortHex(config.Digest([]byte(projectConfig))) +
			" · secrets.gitleaks.history",
	}
	if !reflect.DeepEqual(rows, wantRows) {
		t.Errorf("Descriptor section =\n %q\nwant\n %q", rows, wantRows)
	}
	want := "  descriptor  draugr.saga.yaml + 1 fragment · merged digest " + shortHex(d.Digest) +
		" · includes config defaults\n"
	if !strings.Contains(out, want) {
		t.Errorf("evidence lacks %q:\n%s", want, out)
	}
}

// A file that sets nothing under controls supplied nothing to the descriptor and is not listed, and
// neither is one whose only default the descriptor overrode, because it never reached the digest.
func TestAConfigFileThatSuppliedNoDefaultIsNotASource(t *testing.T) {
	configHome(t, "tools:\n  gitleaks:\n    version: 8.30.1\noutput:\n  evidence: true\ncache:\n  ttl: 12h\nscan:\n  jobs: 2\n")
	provenanceProject(t, provenanceSaga, map[string]string{config.FileName: projectConfig})

	d, _ := scanDescriptor(t)
	want := []string{"./draugr.config.yaml project " + config.Digest([]byte(projectConfig))}
	if got := configs(d); !reflect.DeepEqual(got, want) {
		t.Errorf("config sources = %v, want only the project's", got)
	}
	if len(d.Sources) != 3 {
		t.Errorf("sources = %+v", d.Sources)
	}

	// The descriptor writes history itself, so the machine file's default for it reached nothing,
	// and the project's other default still did.
	overriding := strings.Replace(provenanceSaga, "    secrets:\n      enabled: true\n",
		"    secrets:\n      enabled: true\n      gitleaks:\n        history: false\n", 1)
	configHome(t, "controls:\n  secrets:\n    gitleaks:\n      history: true\n")
	provenanceProject(t, overriding, map[string]string{
		config.FileName: "controls:\n  secrets:\n    gitleaks:\n      history: true\n      config: p/team.toml\n",
	})
	d, _ = scanDescriptor(t)
	if got := configs(d); len(got) != 1 || !strings.HasPrefix(got[0], "./draugr.config.yaml project ") {
		t.Errorf("config sources = %v, want only the project's", got)
	}
	if want := map[string][]string{"secrets.gitleaks.config": {"./draugr.config.yaml"}}; !reflect.DeepEqual(d.Contributed, want) {
		t.Errorf("contributed = %v, want the default the descriptor did not set", d.Contributed)
	}
	if !strings.Contains(d.Effective, "history: false") {
		t.Errorf("the descriptor's value did not win:\n%s", d.Effective)
	}
}

// A file named by --config or $DRAUGR_CONFIG is read alone, and recorded by the name of what named
// it. The discovered files beside it are not read, so they are not sources.
func TestANamedConfigFileIsRecordedByWhatNamedIt(t *testing.T) {
	configHome(t, machineConfig)
	dir := provenanceProject(t, provenanceSaga, map[string]string{config.FileName: projectConfig})
	named := filepath.Join(dir, "ci", "draugr.yaml")
	body := "controls:\n  secrets:\n    gitleaks:\n      config: p/ci.toml\n"
	writeConfigFile(t, named, body)
	contributed := map[string][]string{"secrets.gitleaks.config": {"./ci/draugr.yaml"}}

	t.Setenv(config.EnvVar, named)
	d, _ := scanDescriptor(t)
	if got, want := configs(d), []string{"./ci/draugr.yaml DRAUGR_CONFIG " + config.Digest([]byte(body))}; !reflect.DeepEqual(got, want) {
		t.Errorf("with DRAUGR_CONFIG, config sources = %v, want %v", got, want)
	}
	if !reflect.DeepEqual(d.Contributed, contributed) {
		t.Errorf("contributed = %v, want %v", d.Contributed, contributed)
	}

	t.Setenv(config.EnvVar, "")
	prev := rootConfigPath
	rootConfigPath = named
	t.Cleanup(func() { rootConfigPath = prev })
	d, _ = scanDescriptor(t)
	if got, want := configs(d), []string{"./ci/draugr.yaml --config " + config.Digest([]byte(body))}; !reflect.DeepEqual(got, want) {
		t.Errorf("with --config, config sources = %v, want %v", got, want)
	}
	if !reflect.DeepEqual(d.Contributed, contributed) {
		t.Errorf("contributed = %v, want %v", d.Contributed, contributed)
	}
}

// With no configuration file the descriptor block is the one the descriptor alone produces, and
// the evidence reads as it always has.
func TestWithNoConfigFileTheDescriptorBlockIsTheDescriptorsAlone(t *testing.T) {
	configHome(t, "")
	provenanceProject(t, strings.Replace(provenanceSaga,
		"fragments:\n  - path: security/more.saga-fragment.yaml\n", "", 1), nil)

	_, raw := scanDescriptor(t)
	res, err := loadResolved(context.Background(), "draugr.saga.yaml", true)
	if err != nil {
		t.Fatal(err)
	}
	alone, err := json.Marshal(skald.DescriptorFrom(res))
	if err != nil {
		t.Fatal(err)
	}
	var got bytes.Buffer
	if err := json.Compact(&got, raw); err != nil {
		t.Fatal(err)
	}
	if got.String() != string(alone) {
		t.Errorf("descriptor block =\n %s\nwant the descriptor's alone\n %s", got.String(), alone)
	}

	out := scanEvidence(t)
	if strings.Contains(out, "DESCRIPTOR") || strings.Contains(out, "config defaults") {
		t.Errorf("a single-file descriptor with no configuration file printed more than its row:\n%s", out)
	}
	if want := "  descriptor  draugr.saga.yaml · merged digest " + shortHex(skald.DescriptorFrom(res).Digest) + "\n"; !strings.Contains(out, want) {
		t.Errorf("evidence lacks %q:\n%s", want, out)
	}
}

// shortHex is a digest as the console shortens it.
func shortHex(digest string) string {
	return strings.TrimPrefix(digest, "sha256:")[:12]
}

// digestOf is the digest report.json gives the effective descriptor.
func digestOf(effective string) string {
	return config.Digest([]byte(effective))
}
