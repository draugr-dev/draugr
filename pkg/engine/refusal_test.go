package engine

import (
	"context"
	"fmt"
	"maps"
	"net/http"
	"os/exec"
	"sync"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// imagesController plans one job per image a component declares.
type imagesController struct{}

func (imagesController) Info() plugin.ControllerInfo {
	return plugin.ControllerInfo{Name: "images", Scope: plugin.ScopeComponent}
}

func (imagesController) Plan(_ saga.Model, comp *saga.Component) ([]plugin.ScanJob, error) {
	var jobs []plugin.ScanJob
	for _, img := range comp.Images {
		jobs = append(jobs, plugin.ScanJob{Scanner: "pull", Target: plugin.ImageTarget{Ref: img.Image, Digest: img.Digest}})
	}
	return jobs, nil
}

func (imagesController) Aggregate(reports []sarif.Report) (plugin.ControlResult, error) {
	return plugin.ControlResult{Control: "images", Report: sarif.Merge(reports...)}, nil
}

// refusingScanner fails as a tool does: a process that exits 1 having printed stderr, wrapped in the
// one line the scanner keeps of it.
type refusingScanner struct {
	stderr, kept map[string]string // by image reference
}

func (refusingScanner) Info() plugin.ScannerInfo { return plugin.ScannerInfo{Name: "pull"} }

func (s refusingScanner) Scan(ctx context.Context, t plugin.Target, _ plugin.Config) (sarif.Report, error) {
	ref := t.(plugin.ImageTarget).Ref
	stderr, ok := s.stderr[ref]
	if !ok {
		return sarif.Report{Tool: "pull"}, nil
	}
	// #nosec G204 -- a fixed script; the text it prints is an argument, never parsed as shell.
	_, err := exec.CommandContext(ctx, "sh", "-c", `printf '%s\n' "$0" >&2; exit 1`, stderr).Output()
	return sarif.Report{}, fmt.Errorf("run pull: %w: %s", err, s.kept[ref])
}

// Trivy's answers from Azure Container Registry and Artifact Registry to a pull with no credential,
// as it printed them and as a scan keeps them. The second is kept shortened past the registry's code.
const (
	acrStderr = "\t* remote error: GET https://contoso.azurecr.io/oauth2/token?scope=repository%3Aacme%2Fapi%3Apull&service=contoso.azurecr.io: UNAUTHORIZED: authentication required, visit https://aka.ms/acr/authorization for more information. CorrelationId: 81470148-3d21-40ce-b341-135807330139"
	acrKept   = "… UNAUTHORIZED: authentication required, visit https://aka.ms/acr/authorization for more information. CorrelationId: 81470148-3d21-40ce-b341-135807330139"
	garStderr = `	* remote error: GET https://us-docker.pkg.dev/v2/token?scope=repository%3Aacme-example-not-a-project%2Fimages%2Fapi%3Apull&service=: DENIED: Unauthenticated request. Unauthenticated requests do not have permission "artifactregistry.repositories.downloadArtifacts" on resource "projects/acme-example-not-a-project/locations/us/repositories/images" (or it may not exist)`
	garKept   = `run error: image scan error: scan error: unable to in … resource "projects/acme-example-not-a-project/locations/us/repositories/images" (or it may not exist)`
)

// Two images on one registry, one of them declared by two components, an image on a second
// registry, an image the scan read, and one that failed for another reason. Each refused image
// carries its registry's answer and whether this machine holds a credential for it, asked once per
// registry; the rest carry nothing.
func TestARefusedImageCarriesItsRegistrysAnswer(t *testing.T) {
	const (
		pilot   = "contoso.azurecr.io/istio/pilot:1.30.5"
		proxy   = "contoso.azurecr.io/istio/proxyv2:1.30.5"
		api     = "us-docker.pkg.dev/acme-example-not-a-project/images/api:1.0"
		public  = "gcr.io/distroless/static-debian12:nonroot"
		missing = "ghcr.io/acme/gone:1"
	)
	reg := NewRegistry()
	reg.RegisterController(imagesController{})
	reg.RegisterScanner(refusingScanner{
		stderr: map[string]string{pilot: acrStderr, proxy: acrStderr, api: garStderr,
			missing: "\t* remote error: GET https://ghcr.io/v2/acme/gone/manifests/1: MANIFEST_UNKNOWN: manifest unknown"},
		kept: map[string]string{pilot: acrKept, proxy: acrKept, api: garKept, missing: "… MANIFEST_UNKNOWN: manifest unknown"},
	})
	var mu sync.Mutex
	asked := map[string]int{}
	held := func(_ context.Context, host string) (bool, error) {
		mu.Lock()
		defer mu.Unlock()
		asked[host]++
		return host == "us-docker.pkg.dev", nil
	}
	on := map[string]saga.ControllerSettings{"images": {}}
	res, _ := New(reg, WithRegistryCredentials(held)).Run(context.Background(), saga.Model{
		Release: saga.Release{Version: "1"},
		Components: []saga.Component{
			{Name: "mesh", Controls: on, Images: []saga.Image{{Image: pilot}, {Image: proxy}, {Image: missing}}},
			{Name: "ingress", Controls: on, Images: []saga.Image{{Image: proxy}, {Image: public}, {Image: api}}},
		},
	})

	no, yes := false, true
	want := map[string]*Refusal{
		pilot:   {Registry: "contoso.azurecr.io", Status: http.StatusUnauthorized, Credential: &no},
		proxy:   {Registry: "contoso.azurecr.io", Status: http.StatusUnauthorized, Credential: &no},
		api:     {Registry: "us-docker.pkg.dev", Status: http.StatusForbidden, Credential: &yes},
		public:  nil,
		missing: nil,
	}
	if len(res.Targets) != len(want) {
		t.Fatalf("targets = %+v, want %d", res.Targets, len(want))
	}
	for _, o := range res.Targets {
		w, g := want[o.Target], o.Refusal
		switch {
		case w == nil && g != nil:
			t.Errorf("%s: refusal %+v, want none", o.Target, *g)
		case w != nil && (g == nil || g.Registry != w.Registry || g.Status != w.Status ||
			g.Credential == nil || *g.Credential != *w.Credential):
			t.Errorf("%s: refusal %+v, want %+v", o.Target, g, *w)
		}
	}
	if !maps.Equal(asked, map[string]int{"contoso.azurecr.io": 1, "us-docker.pkg.dev": 1}) {
		t.Errorf("credentials asked for %v, want each refusing registry once", asked)
	}
}

// With nothing to ask, the refusal is still reported, without a word about the credential; and a
// credential that could not be read is reported the same way.
func TestARefusalWithoutAnAnswerAboutTheCredential(t *testing.T) {
	const pilot = "contoso.azurecr.io/istio/pilot:1.30.5"
	reg := NewRegistry()
	reg.RegisterController(imagesController{})
	reg.RegisterScanner(refusingScanner{stderr: map[string]string{pilot: acrStderr}, kept: map[string]string{pilot: acrKept}})
	model := saga.Model{Release: saga.Release{Version: "1"}, Components: []saga.Component{
		{Name: "mesh", Controls: map[string]saga.ControllerSettings{"images": {}}, Images: []saga.Image{{Image: pilot}}},
	}}
	unreadable := func(context.Context, string) (bool, error) { return false, fmt.Errorf("config.json: unexpected EOF") }
	for _, opts := range [][]Option{nil, {WithRegistryCredentials(unreadable)}} {
		res, _ := New(reg, opts...).Run(context.Background(), model)
		if len(res.Targets) != 1 {
			t.Fatalf("targets = %+v", res.Targets)
		}
		r := res.Targets[0].Refusal
		if r == nil || r.Status != http.StatusUnauthorized || r.Credential != nil {
			t.Errorf("refusal = %+v, want 401 with nothing said of the credential", r)
		}
	}
}

// A failure that is not a tool's, read from its message alone.
func TestARefusalIsReadFromTheMessageWhenNoToolRan(t *testing.T) {
	img := plugin.ImageTarget{Ref: "ghcr.io/acme/api", Digest: "sha256:ab"}
	r := refusalOf(img, fmt.Errorf("GET https://ghcr.io/token?scope=repository%%3Aacme%%2Fapi%%3Apull&service=ghcr.io: DENIED: requested access to the resource is denied"))
	if r == nil || r.Registry != "ghcr.io" || r.Status != http.StatusForbidden {
		t.Errorf("refusal = %+v, want ghcr.io 403", r)
	}
	if r := refusalOf(plugin.RepositoryTarget{URL: "https://github.com/acme/api"}, fmt.Errorf("DENIED")); r != nil {
		t.Errorf("a repository read as a registry refusal: %+v", r)
	}
	if r := refusalOf(plugin.ImageTarget{}, fmt.Errorf("DENIED")); r != nil {
		t.Errorf("an image with no reference read as a refusal: %+v", r)
	}
	// Docker Hub is named as `docker login` names it.
	r = refusalOf(plugin.ImageTarget{Ref: "acme/api:1"}, fmt.Errorf("GET https://index.docker.io/v2/acme/api/manifests/1: UNAUTHORIZED: authentication required"))
	if r == nil || r.Registry != "docker.io" {
		t.Errorf("refusal = %+v, want docker.io", r)
	}
}
