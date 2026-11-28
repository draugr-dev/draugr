package sealed

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"

	"github.com/draugr-dev/draugr/internal/detect"
	"github.com/draugr-dev/draugr/internal/git"
	"github.com/draugr-dev/draugr/internal/inventory"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// commentedSpec is a host's spec path in the block init writes commented out, since it cannot
// know the URL an API document describes.
var commentedSpec = regexp.MustCompile(`(?m)^\s*#\s*spec:\s*\n\s*#\s*path:\s*(\S+)`)

// ObserveInit reads the descriptor `draugr init` wrote, through the loader a scan uses, as the
// controls and scanners it enables and the components it declares, and from its text, the API
// documents it proposes as a host's spec.
//
// The controls are the ones a scan of it runs: for a descriptor that sets config.detect, the ones
// its repositories' files turn on, read from repo, the directory init ran in, where a relative url
// resolves for the scan.
func ObserveInit(path, repo string) (InitExpectation, error) {
	m, err := saga.LoadFile(path)
	if err != nil {
		return InitExpectation{}, fmt.Errorf("the descriptor draugr init wrote does not load: %w", err)
	}
	var got InitExpectation
	controls, reachability, err := detectedIn(m, repo)
	if err != nil {
		return InitExpectation{}, err
	}
	for name, settings := range controls {
		if enabled, _ := settings["enabled"].(bool); enabled {
			got.Controls = append(got.Controls, name)
		}
		for scanner, v := range settings {
			// The loader types a scanner's block as the control's own settings.
			if block, ok := v.(saga.ControllerSettings); ok {
				if enabled, _ := block["enabled"].(bool); enabled {
					got.Scanners = append(got.Scanners, name+"."+scanner)
				}
			}
		}
	}
	sort.Strings(got.Controls)
	sort.Strings(got.Scanners)
	if reachability != nil {
		got.Reachability = slices.Clone(reachability.Analyzers)
	}
	for _, c := range m.Components {
		comp := ComponentExpectation{Name: c.Name}
		for _, r := range c.Repositories {
			comp.Repositories = append(comp.Repositories, r.URL)
			comp.Paths = append(comp.Paths, r.Paths...)
			comp.Ignore = append(comp.Ignore, r.Ignore...)
		}
		got.Components = append(got.Components, comp)
	}
	raw, err := os.ReadFile(path) // #nosec G304 -- the descriptor the test had init write
	if err != nil {
		return InitExpectation{}, err
	}
	for _, m := range commentedSpec.FindAllSubmatch(raw, -1) {
		got.Specs = append(got.Specs, string(m[1]))
	}
	sort.Strings(got.Specs)
	return got, nil
}

// CheckInit compares what `draugr init` wrote with what the scenario expects, one line per
// difference.
func CheckInit(exp, got InitExpectation) []string {
	var problems []string
	for _, c := range []struct {
		what      string
		want, got []string
	}{
		{"enables controls", exp.Controls, got.Controls},
		{"enables scanners", exp.Scanners, got.Scanners},
		{"enables reachability analyzers", exp.Reachability, got.Reachability},
		{"proposes host specs", exp.Specs, got.Specs},
	} {
		want := slices.Clone(c.want)
		sort.Strings(want)
		if !slices.Equal(want, c.got) {
			problems = append(problems, fmt.Sprintf("init %s %v, want %v", c.what, c.got, want))
		}
	}
	if !slices.EqualFunc(exp.Components, got.Components, func(a, b ComponentExpectation) bool {
		return a.Name == b.Name && slices.Equal(a.Repositories, b.Repositories) &&
			slices.Equal(a.Paths, b.Paths) && slices.Equal(a.Ignore, b.Ignore)
	}) {
		problems = append(problems, fmt.Sprintf("init declares components %+v, want %+v", got.Components, exp.Components))
	}
	return problems
}

// detectedIn is m's controls and reachability analysis as a scan run from repo applies them: as
// written, with what config.detect turns on beneath them. m is left as it is, its urls as written.
func detectedIn(m *saga.Model, repo string) (map[string]saga.ControllerSettings, *saga.ReachabilityConfig, error) {
	if !m.Config.Detect {
		return m.Config.Controls, m.Config.Reachability, nil
	}
	rooted := *m
	rooted.Components = slices.Clone(m.Components)
	for i := range rooted.Components {
		repos := slices.Clone(rooted.Components[i].Repositories)
		for j := range repos {
			if !filepath.IsAbs(repos[j].URL) && git.IsLocalPath(filepath.Join(repo, repos[j].URL)) {
				repos[j].URL = filepath.Join(repo, repos[j].URL)
			}
		}
		rooted.Components[i].Repositories = repos
	}
	if _, err := detect.ApplyWith(&rooted, inventory.Read); err != nil {
		return nil, nil, err
	}
	return rooted.Config.Controls, rooted.Config.Reachability, nil
}
