//go:build integration

package integration

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/draugr-dev/draugr/internal/depsdev"
	"github.com/draugr-dev/draugr/pkg/dephealth"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// The dependency-health signal is the one whose whole value is in what a service somebody else runs
// says today. Its unit tests decode a captured response, which proves the parser matches the
// fixture and proves nothing about whether the fixture still matches the API.
//
// These ask the real one. A response shape that moves, a field that is renamed, a package that
// stops being indexed: none of those change any unit test, and all of them silently turn the
// feature off, because a lookup that returns nothing is indistinguishable from a tree with nothing
// wrong in it.
//
// The packages below were chosen for being stable facts rather than current ones. jquery 1.8.3 was
// deprecated by its publisher years ago and that does not un-happen; Debian is not a language
// ecosystem and will not become one.
const (
	deprecatedPurl = "pkg:npm/jquery@1.8.3"
	// Deprecated in favor of a different module, and the version the service offers against it is
	// older than the one asked about. The case that must never reach a reader as an upgrade.
	backwardsPurl = "pkg:golang/github.com/golang/protobuf@v1.5.4"
	// Operating-system packages are the bulk of a container scan and none of them are indexed.
	unindexedPurl = "pkg:deb/debian/coreutils@9.1-1?arch=amd64&distro=debian-12.7"
)

// reachable reports whether the lookup failed because the network is not there, which is a skip
// rather than a failure unless the job declared itself strict.
func skipIfOffline(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}
	var dns *net.DNSError
	offline := errors.As(err, &dns) || strings.Contains(err.Error(), "no such host") ||
		strings.Contains(err.Error(), "connection refused") || os.IsTimeout(err)
	if offline && os.Getenv(strictEnv) == "" {
		t.Skipf("deps.dev is unreachable (%v); set %s to make this a failure", err, strictEnv)
	}
	t.Fatalf("deps.dev: %v", err)
}

func TestDepsDevStillAnswersWhatWeParse(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	got, err := depsdev.New().Lookup(ctx, []string{deprecatedPurl, backwardsPurl, unindexedPurl})
	skipIfOffline(t, err)

	// An ecosystem the service does not index is skipped rather than reported, which is what keeps
	// a container scan from asking about four hundred Debian packages every run.
	if _, asked := got[unindexedPurl]; asked {
		t.Errorf("%s was looked up; deb is not an indexed ecosystem", unindexedPurl)
	}

	pkg, ok := got[deprecatedPurl]
	if !ok {
		t.Fatalf("no answer for %s; the response shape or the purl encoding has moved", deprecatedPurl)
	}
	var deprecated *dephealth.Finding
	for i := range pkg.Findings {
		if pkg.Findings[i].Kind == dephealth.KindDeprecated {
			deprecated = &pkg.Findings[i]
		}
	}
	if deprecated == nil {
		t.Fatalf("%s is not reported as deprecated: %+v", deprecatedPurl, pkg.Findings)
	}
	// The publisher's own words are the part worth quoting, and the field they arrive in is the
	// one most likely to be renamed without anything else changing.
	if strings.TrimSpace(deprecated.Reason) == "" {
		t.Error("the deprecation carries no reason; deprecatedContext.reason has moved or emptied")
	}
	// Strictly newer or nothing. jquery's recommendation is a major version ahead, so this also
	// proves the comparison is not rejecting everything.
	if pkg.Recommended == "" {
		t.Error("no upgrade offered for a package the service recommends moving off")
	} else if newer, ok := dephealth.Newer("1.8.3", pkg.Recommended); !ok || !newer {
		t.Errorf("recommended %q is not newer than 1.8.3", pkg.Recommended)
	}
}

// The case that would have shipped bad advice, checked against the live service rather than a
// fixture, because it is upstream data that makes it wrong rather than our parsing.
func TestABackwardsRecommendationNeverReachesAReader(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	got, err := depsdev.New().Lookup(ctx, []string{backwardsPurl})
	skipIfOffline(t, err)

	pkg, ok := got[backwardsPurl]
	if !ok {
		t.Fatalf("no answer for %s", backwardsPurl)
	}
	if pkg.Recommended != "" {
		if newer, _ := dephealth.Newer("v1.5.4", pkg.Recommended); !newer {
			t.Errorf("offered %q as an upgrade from v1.5.4, which is backwards", pkg.Recommended)
		}
	}
	// Whatever happens to the recommendation, the reason is what tells somebody what to do, and
	// for this module the remedy is a different module rather than a version.
	var reason string
	for _, f := range pkg.Findings {
		if f.Kind == dephealth.KindDeprecated {
			reason = f.Reason
		}
	}
	if reason == "" {
		t.Skip("no longer reported as deprecated upstream; nothing to check")
	}
	if !strings.Contains(reason, "google.golang.org/protobuf") {
		t.Logf("the deprecation reason has changed upstream: %q", reason)
	}
}

// The signal reaching a band, end to end, through the same Source a scan builds.
func TestALiveLookupRanksAFinding(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	got, err := depsdev.New().Lookup(ctx, []string{deprecatedPurl})
	skipIfOffline(t, err)

	src := dephealth.New(got, time.Now().UTC().Format(time.DateOnly))
	if src.Empty() {
		t.Fatal("the lookup answered nothing, so the signal is off without saying so")
	}
	to, why := src.Explain(sarif.SeverityMedium, deprecatedPurl)
	if why == nil {
		t.Fatalf("a deprecated package did not move a medium finding: %s", to)
	}
	if to != sarif.SeverityHigh {
		t.Errorf("ranked %s, wanted one band above medium", to)
	}
	if why.Signal != dephealth.SignalDeprecated {
		t.Errorf("recorded signal %q", why.Signal)
	}
	if why.AsOf == "" {
		t.Error("the escalation carries no date, so nobody can re-check it")
	}
	// Consulted is what tells a reader the data was read at all. Without it, a tree with nothing
	// wrong and a lookup that never happened look identical in the evidence.
	if c := src.Consulted(); len(c) != 1 || c[0].Entries == 0 {
		t.Errorf("the evidence does not say what was consulted: %+v", c)
	}
}
