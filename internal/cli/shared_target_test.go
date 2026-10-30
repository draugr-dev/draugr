package cli

import (
	"bytes"
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// imagesTwice plans a job per image a component declares, for each of two scanners, so one
// image can fail twice for one component and once more for each other component declaring it.
type imagesTwice struct{}

func (imagesTwice) Info() plugin.ControllerInfo {
	return plugin.ControllerInfo{Name: "images", Scope: plugin.ScopeComponent}
}

func (imagesTwice) Plan(_ saga.Model, comp *saga.Component) ([]plugin.ScanJob, error) {
	if comp == nil {
		return nil, nil
	}
	var jobs []plugin.ScanJob
	for _, img := range comp.Images {
		for _, s := range []string{"pull-a", "pull-b"} {
			jobs = append(jobs, plugin.ScanJob{Scanner: s, Target: plugin.ImageTarget{Ref: img.Image}})
		}
	}
	return jobs, nil
}

func (imagesTwice) Aggregate(reports []sarif.Report) (plugin.ControlResult, error) {
	return plugin.ControlResult{Control: "images", Report: sarif.Merge(reports...)}, nil
}

// refusedPull is a scanner whose registry refuses every pull.
type refusedPull struct{ name string }

func (s refusedPull) Info() plugin.ScannerInfo { return plugin.ScannerInfo{Name: s.name} }

func (s refusedPull) Scan(_ context.Context, t plugin.Target, _ plugin.Config) (sarif.Report, error) {
	return sarif.Report{}, errors.New(s.name + ": " + t.Identity() + ": unauthorized: authentication required")
}

// Two components declaring one image no scanner can pull both read ERROR, beside a third with an
// unreadable image of its own. The image is one row under ERRORS naming both components, and each
// component counts it once however many of its scanners failed on it.
func TestEveryComponentSharingAnUnreadImageReadsError(t *testing.T) {
	path := writeSaga(t, `
project: shop
release: {version: "1"}
config:
  controllers: {images: {enabled: true}}
components:
  - name: gateway
    images: [{image: contoso.example/gateway:2}]
  - name: ingress
    images: [{image: contoso.example/istio/proxyv2:1.30.5}]
  - name: mesh
    images: [{image: contoso.example/istio/proxyv2:1.30.5}]
`)
	registry := func() *engine.Registry {
		reg := engine.NewRegistry()
		reg.RegisterController(imagesTwice{})
		reg.RegisterScanner(refusedPull{"pull-a"})
		reg.RegisterScanner(refusedPull{"pull-b"})
		return reg
	}

	var console bytes.Buffer
	if err := runScan(context.Background(), path, scanOptions{format: "console"}, registry(), &console); err == nil {
		t.Fatal("a run that reached no image must fail")
	}
	out := console.String()
	for _, name := range []string{"gateway", "ingress", "mesh"} {
		if !regexp.MustCompile(`(?m)^  ` + name + ` +ERROR`).MatchString(out) {
			t.Errorf("%s should read ERROR:\n%s", name, out)
		}
	}
	if !strings.Contains(out, "2 of 2 targets not reached") {
		t.Errorf("want both images counted once each:\n%s", out)
	}
	rows := regexp.MustCompile(`(?m)^ +image contoso\.example/istio/proxyv2:1\.30\.5 +(.+?)  `).FindAllStringSubmatch(out, -1)
	if len(rows) != 1 || rows[0][1] != "ingress, mesh" {
		t.Errorf("want the shared image once, naming ingress and mesh, got %q:\n%s", rows, out)
	}

	var md bytes.Buffer
	_ = runScan(context.Background(), path, scanOptions{format: "markdown"}, registry(), &md)
	for _, name := range []string{"gateway", "ingress", "mesh"} {
		row := regexp.MustCompile(`(?m)^\| ` + name + ` \|.*$`).FindString(md.String())
		if !strings.Contains(row, "**ERROR**") || !strings.Contains(row, "1/1 image not scanned") {
			t.Errorf("%s row = %q, want ERROR with its one image counted once", name, row)
		}
	}
}
