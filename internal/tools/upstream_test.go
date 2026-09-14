package tools

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A tool Draugr provisions and cannot ask about is one nothing can notice has gone stale, which is
// the drift the checker exists to end. Held to the installable list rather than to memory.
func TestEveryProvisionedToolHasAnUpstream(t *testing.T) {
	for _, name := range Installable() {
		if _, ok := UpstreamFor(name); !ok {
			t.Errorf("%s is installable and names no upstream, so nothing can tell when it is "+
				"behind; add it to upstreams", name)
		}
	}
	// And the other way: an upstream for something nobody installs is a row that will never be
	// checked against anything.
	installable := map[string]bool{}
	for _, name := range Installable() {
		installable[name] = true
	}
	for name := range upstreams {
		if !installable[name] {
			t.Errorf("%s names an upstream and is not installable", name)
		}
	}
}

// Every pinned tool reports the version it installs, whichever way it is packaged. A tool whose
// pin reads empty compares equal to nothing and is reported current forever.
func TestEveryProvisionedToolReportsItsPinnedVersion(t *testing.T) {
	for _, name := range Installable() {
		if PinnedVersion(name) == "" {
			t.Errorf("%s reports no pinned version", name)
		}
	}
}

// The case that made a separate strategy necessary. A repository holding several modules marks as
// latest whichever release was published most recently, which for golang/vuln is not the newest
// govulncheck: the tags say v1.8.0 and the release says v1.1.4.
func TestTheNewestTagIsFoundWhateverOrderTheyArriveIn(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[
			{"name":"v1.1.4"},
			{"name":"internal/v0.9.0"},
			{"name":"v1.8.0"},
			{"name":"v1.7.0"},
			{"name":"v2.0.0-rc1"},
			{"name":"not-a-version"}
		]`))
	}))
	t.Cleanup(srv.Close)

	got, err := githubTagAt(context.Background(), srv.Client(), srv.URL)
	if err != nil {
		t.Fatalf("githubTag: %v", err)
	}
	// v1.8.0 over v1.1.4 though the older is listed first, and neither the module-scoped tag nor
	// the release candidate: both are real tags and neither is what Draugr would install.
	if got != "1.8.0" {
		t.Errorf("newest tag = %q, want 1.8.0", got)
	}
}

// A listing larger than any upstream publishes is refused as what it is. Decoding a truncated body
// reports a JSON error, which reads as an upstream answering badly rather than as a limit of ours.
func TestAnOversizeListingIsRefusedAsOne(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("[" + strings.Repeat(`{"name":"v1.0.0"},`, 10)))
	}))
	t.Cleanup(srv.Close)

	prior := maxMetadataForTest
	maxMetadataForTest = 8
	t.Cleanup(func() { maxMetadataForTest = prior })

	_, err := githubTagAt(context.Background(), srv.Client(), srv.URL)
	if err == nil || !strings.Contains(err.Error(), "more than") {
		t.Fatalf("err = %v, want the size refusal", err)
	}
}

// Being behind is a difference, never an ordering. A pin ahead of its upstream is a real state, a
// release withdrawn after Draugr pinned it, and somebody needs to see it rather than have it
// reported as current.
func TestBehindIsADifferenceAndNotAComparison(t *testing.T) {
	for _, tc := range []struct {
		name string
		d    Drift
		want bool
	}{
		{"behind", Drift{Pinned: "1.0.0", Latest: "1.1.0"}, true},
		{"ahead of a withdrawn release", Drift{Pinned: "1.1.0", Latest: "1.0.0"}, true},
		{"current", Drift{Pinned: "1.0.0", Latest: "1.0.0"}, false},
		{"unanswered", Drift{Pinned: "1.0.0", Err: context.Canceled}, false},
		{"answered with nothing", Drift{Pinned: "1.0.0"}, false},
	} {
		if got := tc.d.Behind(); got != tc.want {
			t.Errorf("%s: Behind() = %v, want %v", tc.name, got, tc.want)
		}
	}
}
