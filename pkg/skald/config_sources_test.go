package skald

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/saga"
)

// A configuration file that supplied a control default is a source of the merged descriptor,
// marked with where it was found, and named beside each setting it supplied.
func TestAConfigFileReachesTheDescriptorBlock(t *testing.T) {
	model := &saga.Model{Project: "p", Config: saga.Config{Controls: map[string]saga.ControllerSettings{
		"secrets": {"gitleaks": map[string]any{"history": true}},
	}}}
	res := &saga.Resolved{Model: model, Sources: []saga.Source{
		{Path: "./draugr.saga.yaml", Root: true, Digest: "sha256:21f1945335b5"},
	}}
	res.AddConfig(saga.Source{Path: "./draugr.config.yaml", Config: "project", Digest: "sha256:5053be34ab49"},
		[]string{"secrets.gitleaks.history"})

	got := DescriptorFrom(res)
	if len(got.Sources) != 2 || got.Sources[1].Config != "project" || got.Sources[0].Config != "" {
		t.Fatalf("sources = %+v", got.Sources)
	}
	if files := got.Contributed["secrets.gitleaks.history"]; len(files) != 1 || files[0] != "./draugr.config.yaml" {
		t.Errorf("contributed = %v", got.Contributed)
	}

	// In report.json the marker sits beside the path, and the root's entry is written as it always was.
	raw, err := json.Marshal(got.Sources)
	if err != nil {
		t.Fatal(err)
	}
	want := `[{"path":"./draugr.saga.yaml","digest":"sha256:21f1945335b5","root":true},` +
		`{"path":"./draugr.config.yaml","config":"project","digest":"sha256:5053be34ab49"}]`
	if string(raw) != want {
		t.Errorf("sources =\n %s\nwant\n %s", raw, want)
	}
	if !strings.Contains(got.Effective, "history: true") {
		t.Errorf("the default is not in the effective descriptor:\n%s", got.Effective)
	}
}
