package depsdev

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/draugr-dev/draugr/pkg/dephealth"
)

// Every purl below was taken from a real scan of draugr-demo or from this project's own module
// graph, because a parser tested only on the shapes its author thought of is a parser tested on
// nothing.
func TestParseReadsThePurlsRealScansProduce(t *testing.T) {
	for name, tc := range map[string]struct {
		purl                  string
		indexed               bool
		system, pkg, revision string
	}{
		"npm":                  {"pkg:npm/jquery@1.8.3", true, "NPM", "jquery", "1.8.3"},
		"pypi":                 {"pkg:pypi/pyyaml@5.1", true, "PYPI", "pyyaml", "5.1"},
		"a go module path":     {"pkg:golang/golang.org/x/text@v0.3.0", true, "GO", "golang.org/x/text", "v0.3.0"},
		"maven joins on colon": {"pkg:maven/org.apache.commons/commons-lang3@3.12.0", true, "MAVEN", "org.apache.commons:commons-lang3", "3.12.0"},
		"a scoped npm name":    {"pkg:npm/@babel/core@7.23.0", true, "NPM", "@babel/core", "7.23.0"},
		"cargo":                {"pkg:cargo/serde@1.0.190", true, "CARGO", "serde", "1.0.190"},
		"nuget":                {"pkg:nuget/Newtonsoft.Json@13.0.3", true, "NUGET", "Newtonsoft.Json", "13.0.3"},
		"gem is rubygems":      {"pkg:gem/rails@7.1.0", true, "RUBYGEMS", "rails", "7.1.0"},

		// The majority of a container scan, and none of it indexed. 454 of 509 package findings on
		// draugr-demo were Debian.
		"debian is not indexed": {"pkg:deb/debian/coreutils@9.1-1?arch=amd64&distro=debian-12.7", false, "", "", ""},
		"alpine is not indexed": {"pkg:apk/alpine/musl@1.2.4-r2", false, "", "", ""},

		// Qualifiers describe where a package came from, and the service is keyed without them.
		"a qualifier is dropped": {"pkg:npm/jquery@1.8.3?arch=amd64", true, "NPM", "jquery", "1.8.3"},
		"a subpath is dropped":   {"pkg:golang/example.com/m@v1.0.0#sub/dir", true, "GO", "example.com/m", "v1.0.0"},
		"an escaped name":        {"pkg:npm/%40scope/thing@1.0.0", true, "NPM", "@scope/thing", "1.0.0"},

		"no version":   {"pkg:npm/jquery", false, "", "", ""},
		"no scheme":    {"npm/jquery@1.8.3", false, "", "", ""},
		"empty":        {"", false, "", "", ""},
		"just the pfx": {"pkg:", false, "", "", ""},
	} {
		t.Run(name, func(t *testing.T) {
			k, ok := Parse(tc.purl)
			if ok != tc.indexed {
				t.Fatalf("indexed=%v, wanted %v (%+v)", ok, tc.indexed, k)
			}
			if !ok {
				return
			}
			if k.System != tc.system || k.Name != tc.pkg || k.Version != tc.revision {
				t.Errorf("got %+v, wanted {%s %s %s}", k, tc.system, tc.pkg, tc.revision)
			}
		})
	}
}

// The response shape is the real one, captured from the service on 2026-09-19. It nests three ways
// and only one of them is about the version that was asked for.
const jqueryResponse = `{"responses":[{
  "request":{"versionKey":{"system":"NPM","name":"jquery","version":"1.8.3"}},
  "findings":{
    "versionKey":{"system":"NPM","name":"jquery","version":"1.8.3"},
    "recommendedVersions":[{"versionKey":{"system":"NPM","name":"jquery","version":"4.0.0"},"findings":[]}],
    "requestedVersion":{"versionKey":{"system":"NPM","name":"jquery","version":"1.8.3"},
      "findings":[{"type":"DEPRECATED","risk":"RISK_MEDIUM",
        "deprecatedContext":{"reason":"This version is deprecated. Please upgrade to the latest version."}}]},
    "packageFindings":[]
  }}]}`

func serve(t *testing.T, body string, seen *[]byte) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if seen != nil {
			*seen, _ = io.ReadAll(r.Body)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.Endpoint = srv.URL
	return c
}

func TestLookupReadsTheRealResponseShape(t *testing.T) {
	c := serve(t, jqueryResponse, nil)
	got, err := c.Lookup(context.Background(), []string{"pkg:npm/jquery@1.8.3"})
	if err != nil {
		t.Fatal(err)
	}
	pkg, ok := got["pkg:npm/jquery@1.8.3"]
	if !ok {
		t.Fatalf("nothing came back: %+v", got)
	}
	if len(pkg.Findings) != 1 || pkg.Findings[0].Kind != dephealth.KindDeprecated {
		t.Fatalf("findings read wrong: %+v", pkg.Findings)
	}
	if pkg.Findings[0].Reason == "" {
		t.Error("the publisher's reason was dropped, which is the part worth quoting")
	}
	if pkg.Recommended != "4.0.0" {
		t.Errorf("recommended %q, wanted 4.0.0", pkg.Recommended)
	}
}

// The case that would have shipped bad advice: github.com/golang/protobuf@v1.5.4 is deprecated and
// the version offered against it is v1.5.1, which is older. It must not reach a reader as the fix.
func TestABackwardsRecommendationIsDropped(t *testing.T) {
	const body = `{"responses":[{
	  "request":{"versionKey":{"system":"GO","name":"github.com/golang/protobuf","version":"v1.5.4"}},
	  "findings":{
	    "recommendedVersions":[{"versionKey":{"system":"GO","name":"github.com/golang/protobuf","version":"v1.5.1"}}],
	    "requestedVersion":{"findings":[{"type":"DEPRECATED",
	      "deprecatedContext":{"reason":"Module deprecated: Use the \"google.golang.org/protobuf\" module instead."}}]}
	  }}]}`
	c := serve(t, body, nil)
	got, err := c.Lookup(context.Background(), []string{"pkg:golang/github.com/golang/protobuf@v1.5.4"})
	if err != nil {
		t.Fatal(err)
	}
	pkg := got["pkg:golang/github.com/golang/protobuf@v1.5.4"]
	if pkg.Recommended != "" {
		t.Errorf("offered %q as an upgrade from v1.5.4, which is backwards", pkg.Recommended)
	}
	if len(pkg.Findings) != 1 || pkg.Findings[0].Reason == "" {
		t.Errorf("the deprecation and its reason must survive: %+v", pkg.Findings)
	}
}

// A package-level finding applies to every version, which is how a malicious package arrives.
func TestPackageWideFindingsAreKept(t *testing.T) {
	const body = `{"responses":[{
	  "request":{"versionKey":{"system":"NPM","name":"evil","version":"1.0.0"}},
	  "findings":{"packageFindings":[{"type":"MALICIOUS"}],"requestedVersion":{"findings":[]}}
	}]}`
	c := serve(t, body, nil)
	got, _ := c.Lookup(context.Background(), []string{"pkg:npm/evil@1.0.0"})
	pkg := got["pkg:npm/evil@1.0.0"]
	if len(pkg.Findings) != 1 || pkg.Findings[0].Kind != dephealth.KindMalicious {
		t.Errorf("a package-wide finding was lost: %+v", pkg.Findings)
	}
}

// Ecosystems the service does not index never reach the wire. On a container-heavy project that is
// most of the packages, and a request for them would be wasted every run.
func TestUnindexedEcosystemsAreNotAsked(t *testing.T) {
	var body []byte
	c := serve(t, `{"responses":[]}`, &body)
	_, err := c.Lookup(context.Background(), []string{
		"pkg:deb/debian/coreutils@9.1-1", "pkg:apk/alpine/musl@1.2.4-r2",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(body) != 0 {
		t.Errorf("a request was sent for packages the service does not index: %s", body)
	}
}

// The second scan inside the hour asks nothing, which is the case the cache exists for: somebody
// running a scan repeatedly while fixing something.
func TestASecondLookupInsideTheHourDoesNotAsk(t *testing.T) {
	var body []byte
	c := serve(t, jqueryResponse, &body)
	now := time.Now()
	c.Now = func() time.Time { return now }

	if _, err := c.Lookup(context.Background(), []string{"pkg:npm/jquery@1.8.3"}); err != nil {
		t.Fatal(err)
	}
	body = nil
	if _, err := c.Lookup(context.Background(), []string{"pkg:npm/jquery@1.8.3"}); err != nil {
		t.Fatal(err)
	}
	if len(body) != 0 {
		t.Errorf("asked again inside the hour: %s", body)
	}

	// And past it, it asks again. The hour is a term rather than a preference, so an entry that
	// outlives it has to go back to the source.
	now = now.Add(CacheTTL + time.Minute)
	if _, err := c.Lookup(context.Background(), []string{"pkg:npm/jquery@1.8.3"}); err != nil {
		t.Fatal(err)
	}
	if len(body) == 0 {
		t.Error("a cached entry past its hour was served rather than refetched")
	}
}

// A hundred is what the service returns per request, so a larger set has to be split rather than
// silently truncated at the first page.
func TestMoreThanAPageIsSplit(t *testing.T) {
	var requests int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		var in struct {
			Requests []struct {
				VersionKey struct{ System, Name, Version string } `json:"versionKey"`
			} `json:"requests"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		if len(in.Requests) > pageSize {
			t.Errorf("asked for %d packages in one request, more than the page size", len(in.Requests))
		}
		_, _ = io.WriteString(w, `{"responses":[]}`)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.Endpoint = srv.URL

	var purls []string
	for i := range pageSize*2 + 5 {
		purls = append(purls, "pkg:npm/p"+string(rune('a'+i%26))+string(rune('a'+i/26))+"@1.0.0")
	}
	if _, err := c.Lookup(context.Background(), purls); err != nil {
		t.Fatal(err)
	}
	if requests != 3 {
		t.Errorf("%d packages went in %d requests, wanted 3", len(purls), requests)
	}
}

// The service being unreachable is not a failed scan. This signal never gates, so the caller gets
// an error to report and whatever was already answered.
func TestAnUnreachableServiceReturnsWhatItHasAndSaysSo(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.Endpoint = srv.URL

	got, err := c.Lookup(context.Background(), []string{"pkg:npm/jquery@1.8.3"})
	if err == nil {
		t.Fatal("a 503 was reported as success")
	}
	if got == nil {
		t.Error("the partial result was discarded along with the error")
	}
}

// A response about something nobody asked for is ignored rather than trusted into the result.
func TestAnUnrequestedAnswerIsIgnored(t *testing.T) {
	const body = `{"responses":[{
	  "request":{"versionKey":{"system":"NPM","name":"somethingelse","version":"9.9.9"}},
	  "findings":{"requestedVersion":{"findings":[{"type":"MALICIOUS"}]}}}]}`
	c := serve(t, body, nil)
	got, _ := c.Lookup(context.Background(), []string{"pkg:npm/jquery@1.8.3"})
	if len(got) != 0 {
		t.Errorf("an answer nobody asked for was kept: %+v", got)
	}
}

func TestMalformedJSONIsAnError(t *testing.T) {
	c := serve(t, `{"responses":`, nil)
	if _, err := c.Lookup(context.Background(), []string{"pkg:npm/jquery@1.8.3"}); err == nil {
		t.Error("a truncated response was accepted")
	}
}

// Nothing to ask about is not a request.
func TestAnEmptyLookupIsQuiet(t *testing.T) {
	var body []byte
	c := serve(t, `{"responses":[]}`, &body)
	got, err := c.Lookup(context.Background(), nil)
	if err != nil || len(got) != 0 || len(body) != 0 {
		t.Errorf("an empty lookup did something: %v %+v %s", err, got, body)
	}
}
