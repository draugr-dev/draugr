package sealed

import (
	"fmt"
	"slices"
	"sort"

	"github.com/draugr-dev/draugr/pkg/saga"
)

// ObserveInit reads the descriptor `draugr init` wrote, through the loader a scan uses, as the
// controls and scanners it enables and the components it declares.
func ObserveInit(path string) (InitExpectation, error) {
	m, err := saga.LoadFile(path)
	if err != nil {
		return InitExpectation{}, fmt.Errorf("the descriptor draugr init wrote does not load: %w", err)
	}
	var got InitExpectation
	for name, settings := range m.Config.Controls {
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
	if m.Config.Reachability != nil {
		got.Reachability = slices.Clone(m.Config.Reachability.Analyzers)
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
		{"controls", exp.Controls, got.Controls},
		{"scanners", exp.Scanners, got.Scanners},
		{"reachability analyzers", exp.Reachability, got.Reachability},
	} {
		want := slices.Clone(c.want)
		sort.Strings(want)
		if !slices.Equal(want, c.got) {
			problems = append(problems, fmt.Sprintf("init enables %s %v, want %v", c.what, c.got, want))
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
