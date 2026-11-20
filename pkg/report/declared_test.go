package report

import (
	"encoding/json"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// Each declared image is keyed under its component by the reference its findings carry, the digest
// beside it included, and by `image:` as written. An image with no file behind it, or declared in a
// file outside the repository, has no entry.
func TestImageDeclarationsKeysEachImageAsItsFindingsNameIt(t *testing.T) {
	repo := filepath.FromSlash("/work/app")
	digest := "sha256:" + strings.Repeat("a", 64)
	model := &saga.Model{Components: []saga.Component{
		{Name: "api", Images: []saga.Image{
			{Image: "python:3.8-slim", File: filepath.Join(repo, "draugr.saga.yaml"), Line: 6},
			{Image: "ghcr.io/acme/api:1.2", Digest: digest, File: filepath.Join(repo, "saga", "api.saga-fragment.yaml"), Line: 4},
			// Found by a survey.
			{Image: "nginx:1.25"},
			// Declared in a descriptor outside the repository.
			{Image: "redis:7", File: filepath.FromSlash("/elsewhere/draugr.saga.yaml"), Line: 9},
		}},
		{Name: "worker", Images: []saga.Image{
			{Image: "python:3.8-slim", File: filepath.Join(repo, "draugr.saga.yaml"), Line: 12},
		}},
	}}
	inRepo := func(file string) (string, bool) {
		rel, err := filepath.Rel(repo, file)
		if err != nil || strings.HasPrefix(rel, "..") {
			return "", false
		}
		return filepath.ToSlash(rel), true
	}
	got := ImageDeclarations(model, inRepo)
	want := sarif.Declarations{
		{Component: "api", Ref: "python:3.8-slim"}:                {Path: "draugr.saga.yaml", Line: 6},
		{Component: "api", Ref: "ghcr.io/acme/api:1.2@" + digest}: {Path: "saga/api.saga-fragment.yaml", Line: 4},
		{Component: "api", Ref: "ghcr.io/acme/api:1.2"}:           {Path: "saga/api.saga-fragment.yaml", Line: 4},
		{Component: "worker", Ref: "python:3.8-slim"}:             {Path: "draugr.saga.yaml", Line: 12},
	}
	if len(got) != len(want) {
		t.Errorf("declarations = %v, want %v", got, want)
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%+v: %+v, want %+v", k, got[k], w)
		}
	}
	// The digest spelling is the one the images control's scanners carry.
	pulled := plugin.ImageTarget{Ref: "ghcr.io/acme/api:1.2", Digest: digest}.PinnedRef()
	if _, ok := got[sarif.DeclaredImage{Component: "api", Ref: pulled}]; !ok {
		t.Errorf("no declaration under %q, the reference the scanners pull", pulled)
	}

	if ImageDeclarations(nil, inRepo) != nil || ImageDeclarations(model, nil) != nil {
		t.Error("declarations from no model, or with no repository to place them in")
	}
	if got := ImageDeclarations(&saga.Model{Components: []saga.Component{{Name: "x", Images: []saga.Image{{Image: "a"}}}}}, inRepo); got != nil {
		t.Errorf("declarations = %v for images with no file", got)
	}
}

// The code-scanning report places a finding on an image on the line Data.Declared names, and the
// sarif report rendered from the same run keeps the image reference as its location.
func TestBuildCodeScanningPlacesAnImageFindingOnItsDeclaration(t *testing.T) {
	data := Data{
		Run: engine.Result{Controls: map[string]plugin.ControlResult{
			"images": {Control: "images", Report: sarif.Report{Tool: "trivy", Results: []sarif.Result{{
				RuleID: "CVE-1", Level: sarif.LevelError, Priority: "P1", Tool: "trivy", Control: "images",
				Component: "api", Location: sarif.Location{URI: "debian:11"}, Image: "debian:11",
			}}}},
		}},
		Declared: sarif.Declarations{{Component: "api", Ref: "debian:11"}: {Path: "draugr.saga.yaml", Line: 14}},
	}
	locationOf := func(format string) string {
		t.Helper()
		a, err := Build(saga.ReportConfig{Format: format}, data)
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Runs []struct {
				Results []struct {
					Locations []struct {
						PhysicalLocation struct {
							ArtifactLocation struct {
								URI string `json:"uri"`
							} `json:"artifactLocation"`
							Region struct {
								StartLine int `json:"startLine"`
							} `json:"region"`
						} `json:"physicalLocation"`
					} `json:"locations"`
				} `json:"results"`
			} `json:"runs"`
		}
		if err := json.Unmarshal(a.Bytes, &doc); err != nil {
			t.Fatal(err)
		}
		loc := doc.Runs[0].Results[0].Locations[0].PhysicalLocation
		if loc.Region.StartLine > 0 {
			return loc.ArtifactLocation.URI + ":" + strconv.Itoa(loc.Region.StartLine)
		}
		return loc.ArtifactLocation.URI
	}
	if got := locationOf(CodeScanningFormat); got != "draugr.saga.yaml:14" {
		t.Errorf("code-scanning places the finding at %q, want draugr.saga.yaml:14", got)
	}
	if got := locationOf("sarif"); got != "debian:11" {
		t.Errorf("sarif locates the finding at %q, want the image reference", got)
	}
}
