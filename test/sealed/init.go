package sealed

import (
	"fmt"
	"slices"
	"sort"

	"github.com/draugr-dev/draugr/pkg/saga"
)

// ObserveInit reads the descriptor `draugr init` wrote, through the loader a scan uses, as the
// controls it enables and the components it declares.
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
	}
	sort.Strings(got.Controls)
	for _, c := range m.Components {
		comp := ComponentExpectation{Name: c.Name}
		for _, r := range c.Repositories {
			comp.Repositories = append(comp.Repositories, r.URL)
		}
		got.Components = append(got.Components, comp)
	}
	return got, nil
}

// CheckInit compares what `draugr init` wrote with what the scenario expects, one line per
// difference.
func CheckInit(exp, got InitExpectation) []string {
	var problems []string
	want := slices.Clone(exp.Controls)
	sort.Strings(want)
	if !slices.Equal(want, got.Controls) {
		problems = append(problems, fmt.Sprintf("init enables controls %v, want %v", got.Controls, want))
	}
	if !slices.EqualFunc(exp.Components, got.Components, func(a, b ComponentExpectation) bool {
		return a.Name == b.Name && slices.Equal(a.Repositories, b.Repositories)
	}) {
		problems = append(problems, fmt.Sprintf("init declares components %+v, want %+v", got.Components, exp.Components))
	}
	return problems
}
