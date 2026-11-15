package scanners

import (
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
)

// What Trivy 0.76.1 reports, with --license-full, for two files that grant no license: a test
// holding a © in a string, and a model whose field is named Copyright. Beside them, a LICENSE whose
// text Trivy could not identify, and a package whose metadata names its license Copyright.
const trivyCopyrightJSON = `{"Results":[
 {"Target":"test/sql.test.ts","Class":"license-file","Licenses":[
  {"Severity":"UNKNOWN","Category":"unknown","PkgName":"","FilePath":"test/sql.test.ts","Name":"Copyright","Confidence":1,"Link":"https://spdx.org/licenses/Copyright.html"}]},
 {"Target":"frontend/src/model/photo.js","Class":"license-file","Licenses":[
  {"Severity":"UNKNOWN","Category":"unknown","PkgName":"","FilePath":"frontend/src/model/photo.js","Name":"Copyright","Confidence":1,"Link":"https://spdx.org/licenses/Copyright.html"}]},
 {"Target":"LICENSE","Class":"license-file","Licenses":[
  {"Severity":"UNKNOWN","Category":"unknown","PkgName":"","FilePath":"LICENSE","Name":"Custom-Terms-1.0","Confidence":0.9}]},
 {"Target":"package-lock.json","Class":"lang-pkgs","Type":"npm","Licenses":[
  {"Severity":"UNKNOWN","Category":"unknown","PkgName":"vendored-lib","FilePath":"package-lock.json","Name":"Copyright"}]}
]}`

// A file Trivy names Copyright holds a notice, not a license, and is not reported, even under a
// policy that denies every unidentified license. A license Trivy could not identify is still
// reported, and so is a package whose own metadata says Copyright.
func TestACopyrightNoticeIsNotALicense(t *testing.T) {
	for _, cfg := range []plugin.Config{nil, {denyKey: []string{unknownLicense}}} {
		rep, err := parseTrivyLicenses([]byte(trivyCopyrightJSON), t.TempDir(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, r := range rep.Results {
			got = append(got, r.RuleID)
		}
		want := "license/unknown,license/unknown/vendored-lib"
		if strings.Join(got, ",") != want {
			t.Errorf("policy %v: results %v, want %s", cfg, got, want)
		}
	}
}
