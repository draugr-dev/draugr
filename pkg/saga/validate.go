package saga

import (
	"errors"
	"fmt"
	"strings"
)

// validDigest reports whether s is an OCI content digest of the form "algorithm:hex"
// (e.g. "sha256:…"): a non-empty lowercase-alphanumeric algorithm, a colon, and a
// non-empty lowercase-hex encoded value.
func validDigest(s string) bool {
	algo, hex, ok := strings.Cut(s, ":")
	if !ok || algo == "" || hex == "" {
		return false
	}
	for _, r := range algo {
		if !isLowerAlnum(r) {
			return false
		}
	}
	for _, r := range hex {
		if !isLowerHex(r) {
			return false
		}
	}
	return true
}

func isLowerAlnum(r rune) bool { return r >= 'a' && r <= 'z' || r >= '0' && r <= '9' }
func isLowerHex(r rune) bool   { return r >= 'a' && r <= 'f' || r >= '0' && r <= '9' }

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

		if c.Exposure != "" && !c.Exposure.Valid() {
			errs = append(errs, fmt.Errorf("%s: invalid exposure %q (want one of %v)", where, c.Exposure, Exposures))
		}
		if c.Criticality != "" && !c.Criticality.Valid() {
			errs = append(errs, fmt.Errorf("%s: invalid criticality %q (want one of %v)", where, c.Criticality, Criticalities))
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
			if img.Digest != "" && !validDigest(img.Digest) {
				errs = append(errs, fmt.Errorf("%s: images[%d].digest %q must be of the form algorithm:hex (e.g. sha256:…)", where, j, img.Digest))
			}
		}
		for j, h := range c.Hosts {
			if h.URL == "" {
				errs = append(errs, fmt.Errorf("%s: hosts[%d].url is required", where, j))
			}
		}
	}

	for i, r := range m.Config.Reports {
		if r.Format == "" {
			errs = append(errs, fmt.Errorf("config.reports[%d].format is required", i))
		}
	}
	for i, p := range m.Config.Publishers {
		if p.Kind == "" {
			errs = append(errs, fmt.Errorf("config.publishers[%d].kind is required", i))
		}
	}

	return errors.Join(errs...)
}
