package tools

import (
	"fmt"
	"strings"
)

// SpecFor returns the install spec for a requested version.
//
// An empty version, or the one Draugr ships, returns the pinned spec unchanged — recorded SHAs,
// no network needed to know what to expect. Any other version returns a spec with URLs rendered
// from the templates and **no recorded SHA**, which is what tells Install to verify differently.
//
// Draugr does not refuse a version it cannot vouch for. Refusing would be blocking somebody who
// knows something Draugr does not — an experimental build, a fork, a version newer than this
// release. It installs what was asked for and records how well it could check it, and that record
// travels into every report the tool goes on to produce.
func SpecFor(name, version string) (InstallSpec, error) {
	spec, ok := installable[name]
	if !ok {
		return InstallSpec{}, fmt.Errorf("unknown tool %q (installable: %v)", name, Installable())
	}
	version = strings.TrimPrefix(strings.TrimSpace(version), "v")
	if version == "" || version == spec.Version {
		return spec, nil
	}

	assets := make(map[string]Asset, len(spec.Assets))
	for platform, a := range spec.Assets {
		if a.URLTemplate == "" {
			// No template means Draugr has no idea what this upstream's URLs look like for
			// another version, and guessing at one would download whatever happened to answer.
			continue
		}
		assets[platform] = Asset{
			URL:             render(a.URLTemplate, version),
			BinaryInArchive: a.BinaryInArchive,
			DataInArchive:   a.DataInArchive,
			// Deliberately no SHA256: there is no recorded hash for a version Draugr does not
			// ship, and inventing one is not possible. Its absence is the signal.
		}
	}
	if len(assets) == 0 {
		return InstallSpec{}, fmt.Errorf(
			"%s: Draugr can only install the version it ships (%s) — it has no URL pattern for "+
				"another one. Install %s yourself and Draugr will use it, recorded as external",
			name, spec.Version, name)
	}

	out := spec
	out.Version = version
	out.Assets = assets
	out.Cosign = renderCosign(spec.Cosign, version)
	if spec.ChecksumsURLTemplate != "" {
		out.ChecksumsURLTemplate = render(spec.ChecksumsURLTemplate, version)
	}
	return out, nil
}

// renderCosign renders a signature spec for another version, or nil when it cannot be.
func renderCosign(cs *CosignSpec, version string) *CosignSpec {
	if cs == nil || cs.ChecksumsURLTemplate == "" || cs.BundleURLTemplate == "" {
		return nil
	}
	out := *cs
	out.ChecksumsURL = render(cs.ChecksumsURLTemplate, version)
	out.BundleURL = render(cs.BundleURLTemplate, version)
	return &out
}

// render substitutes {version} — the bare number, since every template that needs a leading "v"
// carries it literally.
func render(tmpl, version string) string {
	return strings.ReplaceAll(tmpl, "{version}", version)
}
