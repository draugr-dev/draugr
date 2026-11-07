package manifests

import (
	"errors"
	"io/fs"
	"slices"
	"strings"
	"testing"
)

// filesReader reads from a map of slash-separated paths, and fails for any path it does not hold.
func filesReader(files map[string]string) func(string) ([]byte, error) {
	return func(rel string) ([]byte, error) {
		content, ok := files[rel]
		if !ok {
			return nil, fs.ErrNotExist
		}
		return []byte(content), nil
	}
}

// ownOf reads the own packages of the file at rel, as "name@version" sorted.
func ownOf(t *testing.T, rel string, files map[string]string) []string {
	t.Helper()
	var out []string
	for _, p := range OwnPackages(rel, filesReader(files)) {
		out = append(out, p.Name+"@"+p.Version)
	}
	slices.Sort(out)
	return out
}

func TestOwnPackagesOfAPackageLock(t *testing.T) {
	for name, tc := range map[string]struct {
		files map[string]string
		want  []string
	}{
		"the root entry names itself": {
			files: map[string]string{"package-lock.json": `{"name": "ignored", "lockfileVersion": 3,
				"packages": {"": {"name": "webpack-json", "version": "1.0.0"}}}`},
			want: []string{"webpack-json@1.0.0"},
		},
		"a root entry with no name takes the lockfile's": {
			files: map[string]string{"package-lock.json": `{"name": "site", "version": "2.0.0", "lockfileVersion": 3,
				"packages": {"": {"dependencies": {}}}}`},
			want: []string{"site@2.0.0"},
		},
		"a lockfile version 1 names its root at the top": {
			files: map[string]string{"npm-shrinkwrap.json": `{"name": "site", "version": "2.0.0", "lockfileVersion": 1,
				"dependencies": {"lodash": {"version": "4.17.20"}}}`},
			want: []string{"site@2.0.0"},
		},
		"a root named nowhere in the lockfile takes the package.json beside it": {
			files: map[string]string{
				"web/package-lock.json": `{"lockfileVersion": 3, "packages": {"": {"version": "3.0.0"}}}`,
				"web/package.json":      `{"name": "axios", "version": "9.9.9"}`,
			},
			want: []string{"axios@3.0.0"},
		},
		"a root named nowhere, with no package.json, is no package": {
			files: map[string]string{"package-lock.json": `{"lockfileVersion": 3, "packages": {"": {}}}`},
		},
		"a package.json that does not parse adds nothing": {
			files: map[string]string{
				"package-lock.json": `{"lockfileVersion": 3, "packages": {"": {}}}`,
				"package.json":      `{`,
			},
		},
		"each workspace member is the project's, each installed package is not": {
			files: map[string]string{"package-lock.json": `{"lockfileVersion": 3, "packages": {
				"": {"name": "monorepo", "version": "0.0.0"},
				"packages/a": {"name": "a", "version": "1.0.0"},
				"packages/unnamed": {"version": "1.0.0"},
				"node_modules/a": {"resolved": "packages/a", "link": true},
				"node_modules/lodash": {"name": "lodash", "version": "4.17.20"},
				"packages/a/node_modules/left-pad": {"name": "left-pad", "version": "1.0.0"}}}`},
			want: []string{"a@1.0.0", "monorepo@0.0.0"},
		},
		"a lockfile that does not parse has none": {
			files: map[string]string{"package-lock.json": `[`},
		},
	} {
		t.Run(name, func(t *testing.T) {
			var rel string
			for path := range tc.files {
				if OwnFile(path) {
					rel = path
				}
			}
			if got := ownOf(t, rel, tc.files); !slices.Equal(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestOwnPackagesOfACargoLock(t *testing.T) {
	const lock = `version = 4

[[package]]
name = "app"
version = "0.1.0"
dependencies = [
 "serde",
 "telemetry",
]

[[package]]
name = "serde"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "aaaa"

[[package]]
name = "telemetry"
version = "0.1.0"

[[package]]
name = "dual"
version = "1.0.0"

[[package]]
name = "dual"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"

[metadata]
name = "not-a-package"
`
	got := ownOf(t, "crates/Cargo.lock", map[string]string{"crates/Cargo.lock": lock})
	if want := []string{"app@0.1.0", "telemetry@0.1.0"}; !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestOwnPackagesOfAPubspec(t *testing.T) {
	for content, want := range map[string][]string{
		"name: ffmpeg\nversion: 0.0.1\npublish_to: none\n":  {"ffmpeg@0.0.1"},
		"name: ffmpeg\npublish_to: 'none'\n":                {"ffmpeg@"},
		"name: http\nversion: 1.0.0\n":                      nil,
		"name: http\npublish_to: https://pub.example.com\n": nil,
		"publish_to: none\n":                                nil,
		"name: [unclosed\n":                                 nil,
	} {
		got := ownOf(t, "plugins/ffmpeg/pubspec.yaml", map[string]string{"plugins/ffmpeg/pubspec.yaml": content})
		if !slices.Equal(got, want) {
			t.Errorf("%q: got %v, want %v", content, got, want)
		}
	}
}

func TestOwnPackagesOfAPodfileLock(t *testing.T) {
	const lock = `PODS:
  - Flutter (1.0.0)
  - integration_test (0.0.1):
    - Flutter
  - Remote (2.0.0)
  - Firebase (10.0.0)

EXTERNAL SOURCES:
  Flutter:
    :path: Flutter
  integration_test:
    :path: ".symlinks/plugins/integration_test/ios"
  Remote:
    :git: https://example.com/remote.git

SPEC CHECKSUMS:
  Flutter: aaaa
`
	got := ownOf(t, "ios/Podfile.lock", map[string]string{"ios/Podfile.lock": lock})
	if want := []string{"Flutter@", "integration_test@"}; !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	if got := ownOf(t, "Podfile.lock", map[string]string{"Podfile.lock": "EXTERNAL SOURCES: [\n"}); got != nil {
		t.Errorf("a Podfile.lock that does not parse: got %v, want none", got)
	}
}

func TestOwnPackagesReadsOnlyTheFilesItKnows(t *testing.T) {
	read := func(rel string) ([]byte, error) {
		if strings.HasSuffix(rel, "Cargo.lock") {
			return nil, errors.New("unreadable")
		}
		return []byte(`{"name": "x", "version": "1.0.0"}`), nil
	}
	for _, rel := range []string{"package.json", "requirements.txt", "node_modules/x/package-lock.json", "Cargo.lock"} {
		if got := OwnPackages(rel, read); got != nil {
			t.Errorf("%s: got %v, want none", rel, got)
		}
	}
}

func TestOwnPackageMatches(t *testing.T) {
	for _, tc := range []struct {
		own           OwnPackage
		name, version string
		want          bool
	}{
		{OwnPackage{"telemetry", "0.1.0"}, "telemetry", "0.1.0", true},
		{OwnPackage{"telemetry", "0.1.0"}, "telemetry", "0.2.0", false},
		{OwnPackage{"telemetry", "0.1.0"}, "telemetry", "", true},
		{OwnPackage{"telemetry", "0.1.0"}, "telemetry-core", "0.1.0", false},
		{OwnPackage{"Flutter", ""}, "Flutter", "1.0.0", true},
		{OwnPackage{"Flutter", ""}, "Flutter/Core", "1.0.0", true},
		{OwnPackage{"Flutter", ""}, "FlutterPlugin", "1.0.0", false},
	} {
		if got := tc.own.Matches(tc.name, tc.version); got != tc.want {
			t.Errorf("%+v matches %s %s: %v, want %v", tc.own, tc.name, tc.version, got, tc.want)
		}
	}
}
