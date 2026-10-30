package engine

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// TestTrulyUnscannedIgnoresTargetsAnotherScannerRead is the mirror of the bug this data exists to
// prevent, pointed the other way.
//
// Two scanners can serve one control and both plan a job for the same image. If one fails and the
// other succeeds, the image *was* examined. Calling it unscanned is a claim about coverage that
// nothing established, and it would push a component to ERROR over a gap that does not exist.
func TestTrulyUnscannedIgnoresTargetsAnotherScannerRead(t *testing.T) {
	failed := []Unscanned{
		{Control: "images", Scanner: "grype", Component: "mesh", Kind: "image", Target: "r/a:1"},
		{Control: "images", Scanner: "grype", Component: "mesh", Kind: "image", Target: "r/b:1"},
	}
	// Trivy read the first one.
	examined := map[string]bool{examinedKey("mesh", plugin.ImageTarget{Ref: "r/a:1"}): true}

	got := trulyUnscanned(failed, examined)
	if len(got) != 1 {
		t.Fatalf("want only the target nothing read, got %d: %+v", len(got), got)
	}
	if got[0].Target != "r/b:1" {
		t.Errorf("kept the wrong one: %+v", got[0])
	}
}

// TestTrulyUnscannedCountsATargetOnce: where every scanner fails on one target, it went
// unexamined once, not once per scanner, and a count of jobs would say "2/1 images not scanned".
func TestTrulyUnscannedCountsATargetOnce(t *testing.T) {
	failed := []Unscanned{
		{Control: "images", Scanner: "trivy", Component: "mesh", Kind: "image", Target: "r/a:1"},
		{Control: "images", Scanner: "grype", Component: "mesh", Kind: "image", Target: "r/a:1"},
	}
	if got := trulyUnscanned(failed, nil); len(got) != 1 {
		t.Errorf("one target failed twice should be one gap, got %d", len(got))
	}
}

// unscannedPairs names each entry by its component and target, sorted, so two orders of the same
// failures can be compared.
func unscannedPairs(us []Unscanned) []string {
	out := make([]string, 0, len(us))
	for _, u := range us {
		out = append(out, u.Component+" "+u.Target)
	}
	slices.Sort(out)
	return out
}

// Two components that declare one image each rest their verdict on it, so each keeps its own
// entry, whichever job failed first. Collapsed by target alone, the entry names the component
// whose job happened to finish first and the other reads as passing with its image unread.
func TestTrulyUnscannedKeepsEveryComponentThatDeclaresTheTarget(t *testing.T) {
	mesh := Unscanned{Control: "images", Scanner: "trivy", Component: "mesh", Kind: "image", Target: "r/proxy:1"}
	ingress := Unscanned{Control: "images", Scanner: "trivy", Component: "ingress", Kind: "image", Target: "r/proxy:1"}
	gateway := Unscanned{Control: "images", Scanner: "trivy", Component: "gateway", Kind: "image", Target: "r/gw:1"}
	// mesh's second scanner failed on the same image: still one gap for mesh.
	meshAgain := Unscanned{Control: "images", Scanner: "grype", Component: "mesh", Kind: "image", Target: "r/proxy:1"}
	want := []string{"gateway r/gw:1", "ingress r/proxy:1", "mesh r/proxy:1"}

	for name, order := range map[string][]Unscanned{
		"mesh first":    {mesh, meshAgain, ingress, gateway},
		"ingress first": {ingress, gateway, meshAgain, mesh},
	} {
		if got := unscannedPairs(trulyUnscanned(order, nil)); !slices.Equal(got, want) {
			t.Errorf("%s: got %v, want %v", name, got, want)
		}
	}
}

// A target one component's scanner read is not unscanned for that component, and says nothing about
// another component whose own job failed on it.
func TestTrulyUnscannedCountsAFailureForItsOwnComponent(t *testing.T) {
	failed := []Unscanned{{Control: "images", Scanner: "trivy", Component: "ingress", Kind: "image", Target: "r/proxy:1"}}
	examined := map[string]bool{examinedKey("mesh", plugin.ImageTarget{Ref: "r/proxy:1"}): true}
	if got := unscannedPairs(trulyUnscanned(failed, examined)); !slices.Equal(got, []string{"ingress r/proxy:1"}) {
		t.Errorf("got %v, want ingress's failure kept", got)
	}
}

// turnImage is an image whose job waits for its turn before it reaches the scan, so a test decides
// which of two components' jobs runs a scan they share and which reuses its result. The wait sits
// in CacheDetail, which the engine asks for when it names a job for the in-run deduplication, and
// which adds nothing to that name.
type turnImage struct {
	ref, owner string
	turn       <-chan struct{}
}

func (turnImage) Kind() plugin.TargetKind { return plugin.TargetImage }
func (t turnImage) Identity() string      { return t.ref }

func (t turnImage) CacheDetail() string {
	if t.turn != nil {
		<-t.turn
	}
	return ""
}

// turnController plans one job per image a component declares, waiting on that component's turn.
type turnController struct {
	turns map[string]<-chan struct{}
	// configs gives a component's jobs their own config, which keeps them out of another
	// component's scan of the same image.
	configs map[string]plugin.Config
}

func (turnController) Info() plugin.ControllerInfo {
	return plugin.ControllerInfo{Name: "images", Scope: plugin.ScopeComponent}
}

func (c turnController) Plan(_ saga.Model, comp *saga.Component) ([]plugin.ScanJob, error) {
	var jobs []plugin.ScanJob
	for _, img := range comp.Images {
		jobs = append(jobs, plugin.ScanJob{Scanner: "pull", Config: c.configs[comp.Name],
			Target: turnImage{ref: img.Image, owner: comp.Name, turn: c.turns[comp.Name]}})
	}
	return jobs, nil
}

func (turnController) Aggregate(reports []sarif.Report) (plugin.ControlResult, error) {
	return plugin.ControlResult{Control: "images", Report: sarif.Merge(reports...)}, nil
}

// pullScanner refuses the images it is told to, names the component whose job ran each scan, and
// reads the rest.
type pullScanner struct {
	refuse  []string
	readFor []string // components whose jobs read every image, refused or not
	mu      *sync.Mutex
	ran     *[]string
	started chan string
}

func (pullScanner) Info() plugin.ScannerInfo { return plugin.ScannerInfo{Name: "pull"} }

func (s pullScanner) Scan(_ context.Context, t plugin.Target, _ plugin.Config) (sarif.Report, error) {
	img := t.(turnImage)
	s.mu.Lock()
	*s.ran = append(*s.ran, img.owner+" "+img.ref)
	s.mu.Unlock()
	s.started <- img.owner
	if slices.Contains(s.refuse, img.ref) && !slices.Contains(s.readFor, img.owner) {
		return sarif.Report{}, errors.New("pull " + img.ref + ": unauthorized: authentication required")
	}
	return sarif.Report{Tool: "pull"}, nil
}

// awaitScan waits until owner's job has started a scan, so the next job released reaches the scan
// after it.
func awaitScan(t *testing.T, started <-chan string, owner string) {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case got := <-started:
			if got == owner {
				return
			}
		case <-deadline:
			t.Fatalf("%s's job never reached the scan", owner)
		}
	}
}

// Two components declaring one image that no scanner can pull share one scan of it, and a third
// declares an image of its own. Every component is left with an unread image, whichever of the two
// sharing jobs ran the scan and whichever reused its failure. Each order is forced rather than left
// to the scheduler, because a record that depended on the order would pass one component in some
// runs and the other in the rest.
func TestRunMarksEveryComponentThatSharesAnUnreadImage(t *testing.T) {
	const (
		proxy = "contoso.example/istio/proxyv2:1.30.5"
		gw    = "contoso.example/gateway:2"
	)
	for _, first := range []string{"mesh", "ingress"} {
		t.Run(first+" runs the scan", func(t *testing.T) {
			second := map[string]string{"mesh": "ingress", "ingress": "mesh"}[first]
			turns := map[string]chan struct{}{first: make(chan struct{}), second: make(chan struct{})}
			ran := []string{}
			started := make(chan string, 8)
			reg := NewRegistry()
			reg.RegisterController(turnController{turns: map[string]<-chan struct{}{first: turns[first], second: turns[second]}})
			reg.RegisterScanner(pullScanner{refuse: []string{proxy, gw}, mu: &sync.Mutex{}, ran: &ran, started: started})

			images := func(refs ...string) []saga.Image {
				var out []saga.Image
				for _, r := range refs {
					out = append(out, saga.Image{Image: r})
				}
				return out
			}
			on := map[string]saga.ControllerSettings{"images": {}}
			type outcome struct {
				res Result
				err error
			}
			done := make(chan outcome, 1)
			go func() {
				res, err := New(reg, WithConcurrency(4)).Run(context.Background(), saga.Model{
					Release: saga.Release{Version: "1"},
					Components: []saga.Component{
						{Name: "gateway", Controls: on, Images: images(gw)},
						{Name: "ingress", Controls: on, Images: images(proxy)},
						{Name: "mesh", Controls: on, Images: images(proxy)},
					},
				})
				done <- outcome{res, err}
			}()
			close(turns[first])
			awaitScan(t, started, first)
			close(turns[second])
			out := <-done
			if out.err == nil {
				t.Fatal("want the run to report its failed scans")
			}

			// The shared image was pulled once, by the job released first: the case under test is the
			// one where the other job reused the failure rather than meeting it itself.
			want := []string{"gateway " + gw, first + " " + proxy}
			slices.Sort(ran)
			slices.Sort(want)
			if !slices.Equal(ran, want) {
				t.Fatalf("scans = %v, want %v", ran, want)
			}

			got := unscannedPairs(out.res.Stats.Unscanned)
			if w := []string{"gateway " + gw, "ingress " + proxy, "mesh " + proxy}; !slices.Equal(got, w) {
				t.Errorf("unscanned = %v, want every component with its image", got)
			}
			// The error is the shared scan's, said once, and the account of targets names the image
			// once with both components.
			if n := len(out.res.ScanErrors["images"]); n != 2 {
				t.Errorf("images errors = %v, want one per scan that failed", out.res.ScanErrors["images"])
			}
			for _, o := range out.res.Targets {
				if o.Status != TargetFailed {
					t.Errorf("%s = %s, want failed", o.Target, o.Status)
				}
				if o.Target == proxy && !slices.Equal(o.Components, []string{"ingress", "mesh"}) {
					t.Errorf("%s components = %v, want ingress and mesh", o.Target, o.Components)
				}
			}
			if len(out.res.Targets) != 2 {
				t.Errorf("targets = %+v, want the two images", out.res.Targets)
			}
		})
	}
}

// A component whose job read an image is not left with it unread because another component's job
// failed on it, and that other component is. The jobs carry different configs, so each meets the
// image itself rather than sharing one scan.
func TestRunCountsAFailedImageOnlyForTheComponentWhoseJobFailed(t *testing.T) {
	const proxy = "contoso.example/istio/proxyv2:1.30.5"
	ran := []string{}
	started := make(chan string, 8)
	reg := NewRegistry()
	reg.RegisterController(turnController{configs: map[string]plugin.Config{
		"mesh": {"platform": "linux/amd64"}, "ingress": {"platform": "linux/arm64"},
	}})
	reg.RegisterScanner(pullScanner{refuse: []string{proxy}, readFor: []string{"mesh"},
		mu: &sync.Mutex{}, ran: &ran, started: started})
	on := map[string]saga.ControllerSettings{"images": {}}
	res, err := New(reg).Run(context.Background(), saga.Model{
		Release: saga.Release{Version: "1"},
		Components: []saga.Component{
			{Name: "ingress", Controls: on, Images: []saga.Image{{Image: proxy}}},
			{Name: "mesh", Controls: on, Images: []saga.Image{{Image: proxy}}},
		},
	})
	if err == nil {
		t.Fatal("want the run to report ingress's failed scan")
	}
	if len(ran) != 2 {
		t.Fatalf("scans = %v, want one per component", ran)
	}
	if got := unscannedPairs(res.Stats.Unscanned); !slices.Equal(got, []string{"ingress " + proxy}) {
		t.Errorf("unscanned = %v, want ingress alone", got)
	}
	// The image was read, so it is not a target the run failed to reach; ingress's failure stays
	// the control's error.
	if len(res.Targets) != 1 || res.Targets[0].Status != TargetReached {
		t.Errorf("targets = %+v, want the image reached", res.Targets)
	}
	if msgs := res.ScanErrors["images"]; len(msgs) != 1 || !strings.Contains(msgs[0], "unauthorized") {
		t.Errorf("images errors = %v, want ingress's failure", msgs)
	}
}
