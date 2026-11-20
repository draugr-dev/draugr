package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/report"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// pulledImages plans a job per declared image, with the target the images control plans.
type pulledImages struct{}

func (pulledImages) Info() plugin.ControllerInfo {
	return plugin.ControllerInfo{Name: "images", Scope: plugin.ScopeComponent}
}

func (pulledImages) Plan(_ saga.Model, comp *saga.Component) ([]plugin.ScanJob, error) {
	if comp == nil {
		return nil, nil
	}
	var jobs []plugin.ScanJob
	for _, img := range comp.Images {
		jobs = append(jobs, plugin.ScanJob{Scanner: "pull", Target: plugin.ImageTarget{Ref: img.Image, Digest: img.Digest}})
	}
	return jobs, nil
}

func (pulledImages) Aggregate(reports []sarif.Report) (plugin.ControlResult, error) {
	return plugin.ControlResult{Control: "images", Report: sarif.Merge(reports...)}, nil
}

// vulnerableImage finds one vulnerability in every image, located as the image scanners locate one:
// by the reference they pulled, which is also the finding's image.
type vulnerableImage struct{}

func (vulnerableImage) Info() plugin.ScannerInfo { return plugin.ScannerInfo{Name: "pull"} }

func (vulnerableImage) Scan(_ context.Context, t plugin.Target, _ plugin.Config) (sarif.Report, error) {
	ref := t.(plugin.ImageTarget).PinnedRef()
	return sarif.Report{Tool: "pull", Results: []sarif.Result{{
		RuleID: "CVE-2024-0001", Level: sarif.LevelWarning, Message: "openssl", Tool: "pull",
		Location: sarif.Location{URI: ref}, Image: ref,
	}}}, nil
}

func imageRegistry() *engine.Registry {
	reg := engine.NewRegistry()
	reg.RegisterController(pulledImages{})
	reg.RegisterScanner(vulnerableImage{})
	return reg
}

// placedAt reads a SARIF file and returns where each result is, by the image it is about:
// "path:line", or "" for a result with no location.
func placedAt(t *testing.T, file string) map[string]string {
	t.Helper()
	doc, err := os.ReadFile(file) // #nosec G304 -- the test's own output
	if err != nil {
		t.Fatal(err)
	}
	if refused, err := sarif.CodeScanningRefuses(doc); err != nil || (strings.HasSuffix(file, "code-scanning.sarif") && len(refused) > 0) {
		t.Errorf("%s: refused %q, err %v", file, refused, err)
	}
	var log struct {
		Runs []struct {
			Results []struct {
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
						Region *struct {
							StartLine int `json:"startLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
				Properties struct {
					Image string `json:"image"`
				} `json:"properties"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(doc, &log); err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, r := range log.Runs[0].Results {
		at := ""
		if len(r.Locations) > 0 {
			p := r.Locations[0].PhysicalLocation
			at = p.ArtifactLocation.URI
			if p.Region != nil {
				at += ":" + strconv.Itoa(p.Region.StartLine)
			}
		}
		out[r.Properties.Image] = at
	}
	return out
}

const declaringSaga = `project: shop
release: {version: "1"}
config:
  controllers: {images: {enabled: true}}
components:
  - name: api
    images:
      - image: python:3.8-slim
fragments:
  - path: "saga/*.saga-fragment.yaml"
`

const declaringFragment = `components:
  - name: worker
    images:
      - image: ghcr.io/acme/worker:2
        digest: sha256:` + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" + `
`

// The code-scanning report places a finding on an image on the line of the file in the repository
// that declares the image, the descriptor or a fragment, as a path from the repository's root
// wherever in it Draugr runs. results.sarif keeps the image reference as the finding's location.
func TestCodeScanningPlacesImageFindingsOnTheLinesThatDeclareThem(t *testing.T) {
	repo := gitRepo(t, "saga")
	writeSagaAt(t, repo, "draugr.saga.yaml", declaringSaga)
	writeSagaAt(t, filepath.Join(repo, "saga"), "worker.saga-fragment.yaml", declaringFragment)
	pinned := "ghcr.io/acme/worker:2@sha256:" + strings.Repeat("a", 64)

	for _, tc := range []struct{ name, wd, descriptor string }{
		{"from the root", ".", "draugr.saga.yaml"},
		{"from a directory in it", "saga", "../draugr.saga.yaml"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Chdir(filepath.Join(repo, tc.wd))
			out := t.TempDir()
			opts := scanOptions{format: "json", outputDir: out, reports: []string{"sarif", report.CodeScanningFormat}, noPublish: true}
			_ = runScan(context.Background(), tc.descriptor, opts, imageRegistry(), io.Discard)

			got := placedAt(t, filepath.Join(out, "code-scanning.sarif"))
			want := map[string]string{
				"python:3.8-slim": "draugr.saga.yaml:8",
				pinned:            "saga/worker.saga-fragment.yaml:4",
			}
			for image, at := range want {
				if got[image] != at {
					t.Errorf("%s: placed at %q, want %q (all: %v)", image, got[image], at, got)
				}
			}
			record := placedAt(t, filepath.Join(out, "results.sarif"))
			for image := range want {
				if record[image] != image {
					t.Errorf("results.sarif locates %s at %q, want the reference", image, record[image])
				}
			}
		})
	}
}

// A descriptor outside the repository Draugr runs in declares its images in no file code scanning
// can show, so their findings go up with no location rather than on a path in some other repository.
func TestCodeScanningLeavesImagesDeclaredOutsideTheRepositoryUnplaced(t *testing.T) {
	repo := gitRepo(t)
	elsewhere := gitRepo(t, "saga")
	descriptor := writeSagaAt(t, elsewhere, "draugr.saga.yaml", declaringSaga)
	writeSagaAt(t, filepath.Join(elsewhere, "saga"), "worker.saga-fragment.yaml", declaringFragment)
	t.Chdir(repo)
	out := t.TempDir()
	opts := scanOptions{format: "json", outputDir: out, reports: []string{report.CodeScanningFormat}, noPublish: true}
	_ = runScan(context.Background(), descriptor, opts, imageRegistry(), io.Discard)
	got := placedAt(t, filepath.Join(out, "code-scanning.sarif"))
	if len(got) != 2 {
		t.Fatalf("results = %v, want both images'", got)
	}
	for image, at := range got {
		if at != "" {
			t.Errorf("%s: placed at %q, want no location", image, at)
		}
	}
}

// `draugr diff --format sarif` places a new finding on an image on the line of the head's descriptor
// that declares it, whether it read the descriptor for the gate or only for this.
func TestDiffSARIFPlacesANewImageFindingOnItsDeclaration(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("DRAUGR_CONFIG", "")
	repo := gitRepo(t, "saga")
	writeSagaAt(t, repo, "draugr.saga.yaml", declaringSaga)
	writeSagaAt(t, filepath.Join(repo, "saga"), "worker.saga-fragment.yaml", declaringFragment)
	t.Chdir(repo)
	head := sarif.Report{Tool: "draugr", Results: []sarif.Result{{
		RuleID: "CVE-2024-0001", Level: sarif.LevelWarning, Message: "openssl", Tool: "pull", Control: "images",
		Component: "api", Priority: "P3", Location: sarif.Location{URI: "python:3.8-slim"}, Image: "python:3.8-slim",
	}}}
	doc, err := head.MarshalSARIF()
	if err != nil {
		t.Fatal(err)
	}
	headPath := filepath.Join(t.TempDir(), "results.sarif")
	if err := os.WriteFile(headPath, doc, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{headPath, "--format", "sarif"},
		{headPath, "--format", "sarif", "--saga", "draugr.saga.yaml"},
		{headPath, "--format", "sarif", "--fail-on-new", "P1"},
	} {
		var out, errOut bytes.Buffer
		cmd := newDiffCommand()
		cmd.SetArgs(args)
		cmd.SetOut(&out)
		cmd.SetErr(&errOut)
		if err := cmd.Execute(); err != nil {
			t.Fatalf("%v: %v\n%s", args, err, errOut.String())
		}
		written := filepath.Join(t.TempDir(), "new.sarif")
		if err := os.WriteFile(written, out.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := placedAt(t, written)["python:3.8-slim"]; got != "draugr.saga.yaml:8" {
			t.Errorf("%v: placed at %q, want draugr.saga.yaml:8", args, got)
		}
	}
}

// With a threshold typed, the descriptor is read only to place images, and one that cannot be
// read, or a choice of several, is said rather than failing the diff.
func TestDiffSARIFSaysWhyItPlacedNothing(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("DRAUGR_CONFIG", "")
	dir := gitRepo(t)
	t.Chdir(dir)
	if m := placingDescriptor(io.Discard); m != nil {
		t.Errorf("no descriptor read as %+v", m)
	}
	writeSagaAt(t, dir, "a.saga.yaml", "project: [")
	var said bytes.Buffer
	if m := placingDescriptor(&said); m != nil || !strings.Contains(said.String(), "no location") {
		t.Errorf("an unreadable descriptor: model %+v, said %q", m, said.String())
	}
	writeSagaAt(t, dir, "b.saga.yaml", declaringSaga)
	said.Reset()
	if m := placingDescriptor(&said); m != nil || !strings.Contains(said.String(), "2 descriptors") {
		t.Errorf("two descriptors: model %+v, said %q", m, said.String())
	}
}
