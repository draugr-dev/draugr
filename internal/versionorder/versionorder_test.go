package versionorder

import "testing"

// Versions are the installed and fixed releases scanners reported: Debian from the demo image's
// openssl, Alpine and Red Hat from Trivy against alpine:3.18.0 and ubi-minimal:8.8, the rest from
// the sealed scenarios' golden reports.
func TestCompareOrdersByEachEcosystemsRules(t *testing.T) {
	for _, c := range []struct {
		ecosystem, a, b string
		want            int
	}{
		// The case a dotted-number comparison calls equal: everything after "-" is the Debian
		// revision, and it decides.
		{"Debian", "3.0.17-1~deb12u2", "3.0.17-1~deb12u3", -1},
		{"Debian", "3.0.14-1~deb12u2", "3.0.22-1~deb12u1", -1},
		{"Debian", "1.0~rc1", "1.0", -1},
		{"Alpine", "1.36.0-r9", "1.36.1-r1", -1},
		{"Alpine", "1.36.1-r7", "1.36.1-r6", 1},
		{"Red Hat", "1.0.6-26.el8", "1.0.6-28.el8_10", -1},
		{"Red Hat", "7.61.1-30.el8_8.3", "7.61.1-33.el8_9.5", -1},
		{"npm", "1.8.3", "1.9.0", -1},
		{"npm", "1.12.2", "3.0.0", -1},
		{"PyPI", "2.2.5", "2.3.2", -1},
		{"PyPI", "1.0rc1", "1.0", -1},
		{"PyPI", "1.0.post1", "1.0", 1},
		{"PyPI", "5.4", "5.3.1", 1},
		{"RubyGems", "2.2.3", "2.2.3.1", -1},
		{"Go", "v0.3.7", "v0.3.8", -1},
		{"Go", "v0.17.0", "v0.9.0", 1},
		{"Maven", "2.14.1", "2.15.0", -1},
		{"Maven", "2.13.4", "2.13.4.2", -1},
		{"NuGet", "12.0.1", "13.0.1", -1},
		{"crates.io", "1.6.0", "1.6.1", -1},
		{"Packagist", "7.4.0", "7.4.3", -1},
		{"npm", "1.2.6", "1.2.6", 0},
		// What deps.dev recommends against a deprecated package, which must only ever be forwards:
		// it offered v1.5.1 against github.com/golang/protobuf@v1.5.4.
		{"Go", "v1.5.4", "v1.5.1", 1},
		{"npm", "1.8.3", "4.0.0", -1},
		{"PyPI", "5.1", "6.0.3", -1},
	} {
		got, ok := Compare(c.ecosystem, c.a, c.b)
		if !ok || got != c.want {
			t.Errorf("Compare(%s, %s, %s) = %d, %v; want %d", c.ecosystem, c.a, c.b, got, ok, c.want)
		}
	}
}

// An order nothing can establish is unknown, never equal: a caller treating it as equal would pick
// one version as sufficient for the other's findings.
func TestCompareSaysWhenItCannotOrder(t *testing.T) {
	for _, c := range []struct{ ecosystem, a, b string }{
		{"", "1.0", "2.0"},
		{"Cobol", "1.0", "2.0"},
		{"PyPI", "not a version", "1.0"},
		{"PyPI", "1.0", "not a version"},
		{"Alpine", "1.0", "@@@"},
	} {
		if got, ok := Compare(c.ecosystem, c.a, c.b); ok {
			t.Errorf("Compare(%q, %q, %q) = %d, ok; want not ok", c.ecosystem, c.a, c.b, got)
		}
	}
}

func TestEcosystemPrefersThePackageURL(t *testing.T) {
	for _, c := range []struct{ purl, reported, want string }{
		{"pkg:deb/debian/openssl@3.0.14-1~deb12u2?arch=amd64", "", "Debian"},
		{"pkg:rpm/redhat/curl@7.61.1-30.el8_8.3?arch=x86_64", "redhat", "Red Hat"},
		{"pkg:apk/alpine/busybox@1.36.0-r9", "", "Alpine"},
		{"pkg:pypi/flask@0.12.2", "pip", "PyPI"},
		{"pkg:golang/golang.org/x/text@v0.3.6", "", "Go"},
		{"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", "", "Maven"},
		{"pkg:NPM/jquery@1.8.3", "", "npm"},
		// No package URL: the scanner's own name for the ecosystem.
		{"", "pipenv", "PyPI"},
		{"", "Bundler", "RubyGems"},
		{"", "gomod", "Go"},
		{"", "java-archive", "Maven"},
		// A package URL type nobody orders falls back to what the scanner said.
		{"pkg:github/actions/checkout@v4", "npm", "npm"},
		{"pkg:swift/github.com/x/y@1.0", "", ""},
		{"", "", ""},
		{"not a purl", "conda-pkg", ""},
	} {
		if got := Ecosystem(c.purl, c.reported); got != c.want {
			t.Errorf("Ecosystem(%q, %q) = %q, want %q", c.purl, c.reported, got, c.want)
		}
	}
}
