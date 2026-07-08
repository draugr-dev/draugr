package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/surveyor"
)

type stubSurveyor struct {
	name string
	comp saga.Component
}

func (s stubSurveyor) Info() plugin.SurveyorInfo { return plugin.SurveyorInfo{Name: s.name} }
func (s stubSurveyor) Survey(context.Context, plugin.SurveyScope) (saga.Fragment, error) {
	return saga.Fragment{Components: []saga.Component{s.comp}}, nil
}

func stubRegistry() *surveyor.Registry {
	r := surveyor.NewRegistry()
	r.Register(stubSurveyor{name: "k8s-images", comp: saga.Component{
		Name: "cluster", Images: []saga.Image{{Image: "repo/x:1"}},
	}})
	r.Register(stubSurveyor{name: "github-org-repos", comp: saga.Component{
		Name: "svc", Repositories: []saga.Repository{{URL: "https://git/svc.git", Revision: "main"}},
	}})
	return r
}

func TestRunSurveyNoSurveyors(t *testing.T) {
	err := runSurvey(context.Background(), surveyOptions{}, stubRegistry(), &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected error when no surveyors selected")
	}
}

func TestRunSurveyToStdout(t *testing.T) {
	var buf bytes.Buffer
	opts := surveyOptions{k8sImages: true, name: "app", version: "1.0"}
	if err := runSurvey(context.Background(), opts, stubRegistry(), &buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "cluster") || !strings.Contains(out, "repo/x:1") {
		t.Errorf("expected discovered component in output:\n%s", out)
	}
	// Output must be a loadable Saga.
	if _, err := saga.Load(buf.Bytes()); err != nil {
		t.Errorf("survey output is not a valid Saga: %v", err)
	}
}

func TestRunSurveyWritesFile(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "draugr.saga.yaml")
	opts := surveyOptions{githubOrg: "acme", version: "1.0", output: out}
	if err := runSurvey(context.Background(), opts, stubRegistry(), &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(out) //nolint:gosec // test reads a temp file
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "svc") {
		t.Errorf("expected repo component in file:\n%s", data)
	}
}

func TestRunSurveyMerge(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "draugr.saga.yaml")
	// Pre-existing Saga with a hand-written component.
	existing := "release:\n  name: app\n  version: \"1.0\"\ncomponents:\n  - name: existing\n"
	if err := os.WriteFile(out, []byte(existing), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := surveyOptions{k8sImages: true, output: out, merge: true}
	if err := runSurvey(context.Background(), opts, stubRegistry(), &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(out) //nolint:gosec // test reads a temp file
	s := string(data)
	if !strings.Contains(s, "existing") || !strings.Contains(s, "cluster") {
		t.Errorf("merged Saga should contain both components:\n%s", s)
	}
}

func TestSurveyCommandViaCobraNoSelection(t *testing.T) {
	cmd := newRootCommand()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"survey"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("survey with no surveyors selected should error")
	}
}
