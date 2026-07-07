package saga

import (
	"errors"
	"fmt"
)

// Validate checks the descriptor for structural correctness, returning all problems at
// once (joined) rather than only the first.
func (m *Model) Validate() error {
	var errs []error

	if m.Release.Version == "" {
		errs = append(errs, errors.New("release.version is required"))
	}

	seen := map[string]bool{}
	for i, c := range m.Components {
		where := fmt.Sprintf("components[%d]", i)
		if c.Name == "" {
			errs = append(errs, fmt.Errorf("%s: name is required", where))
		} else {
			if seen[c.Name] {
				errs = append(errs, fmt.Errorf("%s: duplicate component name %q", where, c.Name))
			}
			seen[c.Name] = true
			where = fmt.Sprintf("component %q", c.Name)
		}

		for j, r := range c.Repositories {
			if r.URL == "" {
				errs = append(errs, fmt.Errorf("%s: repositories[%d].url is required", where, j))
			}
		}
		for j, img := range c.Images {
			if img.Image == "" {
				errs = append(errs, fmt.Errorf("%s: images[%d].image is required", where, j))
			}
		}
		for j, h := range c.Hosts {
			if h.URL == "" {
				errs = append(errs, fmt.Errorf("%s: hosts[%d].url is required", where, j))
			}
		}
	}

	return errors.Join(errs...)
}
