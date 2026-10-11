package publish

import (
	"fmt"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/report"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// configKeys is every yaml key PublisherConfig declares, with the Go field behind it.
func configKeys() map[string]string {
	out := map[string]string{}
	t := reflect.TypeOf(saga.PublisherConfig{})
	for i := range t.NumField() {
		key, _, _ := strings.Cut(t.Field(i).Tag.Get("yaml"), ",")
		if key != "" && key != "-" {
			out[key] = t.Field(i).Name
		}
	}
	return out
}

// A publisher with no entry reads nothing as far as the descriptor's readers know, so every field
// it is given is refused and every field it needs is invisible.
func TestEveryPublisherSaysWhatItReads(t *testing.T) {
	keys := configKeys()
	renderable := map[string]bool{"template": true}
	for _, f := range report.Formats() {
		renderable[f] = true
	}
	for _, kind := range Kinds() {
		if _, ok := reads[kind]; !ok {
			t.Errorf("%s has no entry in reads. Name the descriptor fields it reads", kind)
		}
		if _, ok := accepts[kind]; !ok {
			t.Errorf("%s has no entry in accepts. Name the formats it delivers, or nil for any", kind)
		}
	}
	for _, table := range []map[string][]string{reads, requires, accepts} {
		for kind := range table {
			if _, ok := builders[kind]; !ok {
				t.Errorf("a field table names %q, which is not a publisher this build has", kind)
			}
		}
	}
	for kind, fields := range reads {
		for _, f := range fields {
			if _, ok := keys[f]; !ok || f == "kind" {
				t.Errorf("%s reads %q, which is not a field a publisher entry has", kind, f)
			}
		}
		if IssueKind(kind) && slices.Contains(fields, "reports") {
			t.Errorf("%s builds its body from the run, so it reads no reports", kind)
		}
		if !IssueKind(kind) && !slices.Contains(fields, "reports") {
			t.Errorf("%s is given rendered reports, so it reads reports", kind)
		}
	}
	for kind, fields := range requires {
		for _, f := range fields {
			if !slices.Contains(reads[kind], f) {
				t.Errorf("%s requires %q and does not read it", kind, f)
			}
		}
	}
	for kind, formats := range accepts {
		for _, f := range rendered[kind] {
			if formats != nil && !slices.Contains(formats, f) {
				t.Errorf("%s renders %q for itself and does not deliver it", kind, f)
			}
		}
		for _, f := range formats {
			if !renderable[f] {
				t.Errorf("%s delivers %q, which is not a format Draugr renders", kind, f)
			}
		}
		if IssueKind(kind) && (formats == nil || len(formats) > 0) {
			t.Errorf("%s delivers no report, so it accepts none: write {}", kind)
		}
	}
}

// ciEnv is a CI environment in which every publisher builds rather than skipping, so a field the
// descriptor sets is the only thing that differs between two builds.
func ciEnv(t *testing.T) {
	t.Helper()
	for k, v := range map[string]string{
		"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": "acme/web", "GITHUB_SHA": "abc123",
		"GITHUB_REF": "refs/pull/3/merge", "GITHUB_TOKEN": "gh-token", "GITHUB_API_URL": "",
		"TF_BUILD": "True", "SYSTEM_TEAMFOUNDATIONCOLLECTIONURI": "https://dev.azure.com/acme/",
		"SYSTEM_TEAMPROJECT": "shop", "BUILD_REPOSITORY_NAME": "web",
		"SYSTEM_PULLREQUEST_PULLREQUESTID": "4", "SYSTEM_ACCESSTOKEN": "az-token",
		"GITLAB_CI": "true", "CI_PROJECT_ID": "1", "CI_MERGE_REQUEST_IID": "5", "GITLAB_TOKEN": "gl-token",
		"CI_API_V4_URL": "", "CI_SERVER_URL": "",
		"DRAUGR_API_URL": "https://plane.example", "DRAUGR_API_TOKEN": "api-token",
		"ALT_TOKEN": "alt-token",
	} {
		t.Setenv(k, v)
	}
}

// sample sets one field of cfg to a value that differs from every default ciEnv supplies.
func sample(t *testing.T, cfg *saga.PublisherConfig, key string) {
	t.Helper()
	switch key {
	case "dir":
		cfg.Dir = "other-dir"
	case "repo":
		cfg.Repo = "other/repo"
	case "commit":
		cfg.Commit = "fff999"
	case "ref":
		cfg.Ref = "refs/heads/other"
	case "tokenEnv":
		cfg.TokenEnv = "ALT_TOKEN"
	case "pr":
		cfg.PR = 9
	case "marker":
		cfg.Marker = "<!-- other -->"
	case "org":
		cfg.Org = "https://dev.azure.com/other/"
	case "project":
		cfg.Project = "other"
	case "url":
		cfg.URL = "https://other.example"
	case "reports":
		cfg.Reports = []saga.ReportConfig{{Format: "html"}}
	default:
		t.Fatalf("no sample value for %q; add one", key)
	}
}

// snapshot is what a built publisher holds that a descriptor field could have set: its string,
// number and boolean fields, by name. The config an issue publisher keeps whole is left out, since
// it differs whenever any field does and would make every field look read.
func snapshot(p Publisher, err error) string {
	if err != nil {
		return "error: " + err.Error()
	}
	v := reflect.ValueOf(p)
	if v.Kind() == reflect.Pointer {
		v = v.Elem()
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%T", p)
	for i := range v.NumField() {
		switch f := v.Field(i); f.Kind() {
		case reflect.String, reflect.Int, reflect.Int64, reflect.Bool:
			fmt.Fprintf(&b, " %s=%v", v.Type().Field(i).Name, f)
		}
	}
	return b.String()
}

// A field in reads that the publisher does not use is a field every reader accepts and nothing
// applies, which is the failure the table exists to prevent. So each one is set and the publisher
// built again, and something it holds has to change.
//
// The issue fields are read by the tracker after construction, from the config the publisher
// keeps, so they are held to that instead: TestEveryIssueFieldIsRead.
func TestEveryFieldAPublisherReadsIsUsed(t *testing.T) {
	ciEnv(t)
	for _, kind := range Kinds() {
		base := saga.PublisherConfig{Kind: kind}
		want := snapshot(builders[kind](base))
		for _, key := range reads[kind] {
			if key == "reports" || slices.Contains(issueFields, key) {
				continue
			}
			cfg := base
			sample(t, &cfg, key)
			if got := snapshot(builders[kind](cfg)); got == want {
				t.Errorf("%s: setting %s changes nothing the publisher holds (%s); it does not read it, "+
					"so remove it from reads", kind, key, got)
			}
		}
	}
}

// The issue fields reach the tracker through the config an issue publisher keeps. Each has to be
// read somewhere in this package, or it is a field the schema offers and nothing applies.
func TestEveryIssueFieldIsRead(t *testing.T) {
	keys := configKeys()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var src strings.Builder
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".go") && !strings.HasSuffix(e.Name(), "_test.go") {
			b, err := os.ReadFile(e.Name())
			if err != nil {
				t.Fatal(err)
			}
			src.Write(b)
		}
	}
	for _, key := range issueFields {
		name := keys[key]
		// ChildLimit is how maxChildren is read.
		if key == "maxChildren" {
			name = "ChildLimit"
		}
		if !regexp.MustCompile(`cfg\.` + name + `\b`).MatchString(src.String()) {
			t.Errorf("issue field %s (%s) is read nowhere in pkg/publish", key, name)
		}
	}
}

// A publisher is handed only what its kind reads, so a field the table leaves out reaches no
// constructor, whatever the descriptor wrote.
func TestForHandsAPublisherOnlyWhatItsKindReads(t *testing.T) {
	ciEnv(t)
	keys := configKeys()
	for _, kind := range Kinds() {
		base := saga.PublisherConfig{Kind: kind}
		if kind == "file" {
			base.Dir, base.Reports = "out", []saga.ReportConfig{{Format: "sarif"}}
		}
		want := snapshot(For(base))
		for key := range keys {
			if key == "kind" || slices.Contains(reads[kind], key) || slices.Contains(issueFields, key) {
				continue
			}
			cfg := base
			sample(t, &cfg, key)
			if trimmed := only(cfg); !slices.Equal(trimmed.Written(), only(base).Written()) {
				t.Errorf("%s: only kept %s, which the kind does not read", kind, key)
			}
			if got := snapshot(For(cfg)); got != want {
				t.Errorf("%s: %s reached the publisher although the kind does not read it:\n got %s\nwant %s",
					kind, key, got, want)
			}
		}
	}
}

func TestOnlyKeepsWhatTheDescriptorCannotWrite(t *testing.T) {
	cfg := only(saga.PublisherConfig{Kind: "draugr-api", DefaultURL: "https://org.example", Dir: "out"})
	if cfg.DefaultURL != "https://org.example" || cfg.Dir != "" || cfg.Kind != "draugr-api" {
		t.Errorf("only = %+v; want the kind and the organization's default kept, dir dropped", cfg)
	}
}

func TestUnread(t *testing.T) {
	two := 2
	for _, tc := range []struct {
		cfg  saga.PublisherConfig
		want []string
	}{
		{saga.PublisherConfig{Kind: "github", Repo: "a/b", Dir: "out", Org: "x"}, []string{"dir", "org"}},
		{saga.PublisherConfig{Kind: "file", Dir: "out", Reports: []saga.ReportConfig{{Format: "sarif"}}}, nil},
		{saga.PublisherConfig{Kind: "github-issue", Repo: "a/b", MaxChildren: &two, Reports: []saga.ReportConfig{{Format: "sarif"}}}, []string{"reports"}},
		{saga.PublisherConfig{Kind: "github-pr-comment", LabelBy: saga.LabelBy{}}, []string{"labelBy"}},
		{saga.PublisherConfig{Kind: "no-such-kind", Repo: "a/b"}, []string{"repo"}},
	} {
		if got := Unread(tc.cfg); !slices.Equal(got, tc.want) {
			t.Errorf("Unread(%s) = %v, want %v", tc.cfg.Kind, got, tc.want)
		}
	}
}

func TestTheTablesAreCopies(t *testing.T) {
	Reads("github")[0] = "changed"
	Requires("file")[0] = "changed"
	a, _ := Accepts("github")
	a[0] = "changed"
	again, deliversOnly := Accepts("github")
	if Reads("github")[0] == "changed" || Requires("file")[0] == "changed" || again[0] == "changed" || !deliversOnly {
		t.Error("a caller changed a table through what it was given")
	}
	if formats, deliversOnly := Accepts("file"); formats != nil || deliversOnly {
		t.Errorf("Accepts(file) = %v, %v; want any format", formats, deliversOnly)
	}
	if Reads("no-such-kind") != nil {
		t.Error("an unknown kind reads nothing")
	}
}
