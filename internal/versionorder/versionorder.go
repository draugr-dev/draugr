// Package versionorder orders the versions of one package by the rules of the ecosystem it comes
// from.
//
// Every ecosystem orders differently. Debian's `3.0.17-1~deb12u3` is newer than `3.0.17-1~deb12u2`
// and `1.0~rc1` is older than `1.0`; PEP 440 puts `1.0rc1` before `1.0` and `1.0.post1` after it;
// Maven's `2.13.4.2` follows `2.13.4`. A comparison that reads dotted numbers alone gets each of
// these wrong, and a wrong order recommends an upgrade that leaves findings behind or a downgrade
// of a working dependency.
//
// The rules are osv-scalibr's, which are the ones OSV's own matching uses. Where the ecosystem is
// not one it orders, or a version does not parse in it, Compare says so rather than guessing, and
// the caller keeps every version it was given.
package versionorder

import (
	"strings"

	"github.com/google/osv-scalibr/semantic"
)

// byPURLType maps a package URL's type to the ecosystem whose rules order it.
var byPURLType = map[string]string{
	"apk":      "Alpine",
	"cargo":    "crates.io",
	"composer": "Packagist",
	"conan":    "ConanCenter",
	"cran":     "CRAN",
	"deb":      "Debian",
	"gem":      "RubyGems",
	"golang":   "Go",
	"hackage":  "Hackage",
	"hex":      "Hex",
	"maven":    "Maven",
	"npm":      "npm",
	"nuget":    "NuGet",
	"pub":      "Pub",
	"pypi":     "PyPI",
	"rpm":      "Red Hat",
}

// byReported maps the ecosystem a scanner names, Trivy's result type or Grype's package type, to the
// one whose rules order it, for a finding that carries no package URL.
var byReported = map[string]string{
	"alpine": "Alpine", "apk": "Alpine", "chainguard": "Alpine", "wolfi": "Alpine",
	"debian": "Debian", "ubuntu": "Debian", "deb": "Debian",
	"redhat": "Red Hat", "centos": "Red Hat", "rocky": "Red Hat", "alma": "Red Hat",
	"amazon": "Red Hat", "oracle": "Red Hat", "suse": "Red Hat", "rpm": "Red Hat",
	"npm": "npm", "yarn": "npm", "pnpm": "npm", "bun": "npm", "node-pkg": "npm",
	"pip": "PyPI", "pipenv": "PyPI", "poetry": "PyPI", "uv": "PyPI", "python-pkg": "PyPI", "python": "PyPI",
	"gem": "RubyGems", "gemspec": "RubyGems", "bundler": "RubyGems",
	"gomod": "Go", "gobinary": "Go", "go-module": "Go",
	"cargo": "crates.io", "rust-crate": "crates.io", "rustbinary": "crates.io",
	"composer": "Packagist", "php-composer": "Packagist",
	"nuget": "NuGet", "dotnet-core": "NuGet", "packages-props": "NuGet", "dotnet": "NuGet",
	"jar": "Maven", "pom": "Maven", "gradle": "Maven", "sbt": "Maven", "java-archive": "Maven",
	"pub": "Pub", "hex": "Hex", "conan": "ConanCenter",
}

// Ecosystem names the rules that order a package's versions, from its package URL or, without one,
// from the ecosystem a scanner reported. Empty when neither names rules this package knows.
func Ecosystem(purl, reported string) string {
	if t, ok := strings.CutPrefix(purl, "pkg:"); ok {
		if i := strings.IndexByte(t, '/'); i > 0 {
			if e, known := byPURLType[strings.ToLower(t[:i])]; known {
				return e
			}
		}
	}
	return byReported[strings.ToLower(strings.TrimSpace(reported))]
}

// Compare returns -1, 0 or +1 as a is older than, the same as or newer than b under ecosystem's
// rules. ok is false when the ecosystem is not one this orders, or either version does not parse in
// it, and then the order is unknown rather than equal.
func Compare(ecosystem, a, b string) (order int, ok bool) {
	a, b = strings.TrimSpace(a), strings.TrimSpace(b)
	if ecosystem == "" || !looksLikeAVersion(a) || !looksLikeAVersion(b) {
		return 0, false
	}
	va, err := semantic.Parse(a, ecosystem)
	if err != nil {
		return 0, false
	}
	vb, err := semantic.Parse(b, ecosystem)
	if err != nil {
		return 0, false
	}
	order, err = va.Compare(vb)
	if err != nil {
		return 0, false
	}
	return order, true
}

// looksLikeAVersion reports whether s starts as every ecosystem's versions do, with a digit, after
// an optional "v". The parsers are lenient, PyPI's legacy rules and Alpine's among them, and order
// any string; text that is not a version must have no order rather than an arbitrary one.
func looksLikeAVersion(s string) bool {
	s = strings.TrimPrefix(s, "v")
	return s != "" && s[0] >= '0' && s[0] <= '9'
}
