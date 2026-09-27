package cli

import (
	"bytes"
	"context"
	"regexp"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/builtins"
	"github.com/draugr-dev/draugr/internal/feeds"
	"github.com/draugr-dev/draugr/internal/netpolicy"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// goOffline puts the process offline for the duration of a test.
func goOffline(t *testing.T) {
	t.Helper()
	netpolicy.SetOffline(true)
	t.Cleanup(func() { netpolicy.SetOffline(false) })
}

func TestFeedsUpdateRefusesOffline(t *testing.T) {
	goOffline(t)
	dir := cacheHome(t)
	calls := stubFetch(t, kevJSON, nil)

	cmd := newFeedsCommand()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	err := updateFeeds(cmd, dir, feeds.Names(), false)
	if err == nil {
		t.Fatal("fetched while offline")
	}
	if *calls != 0 {
		t.Errorf("reached the network %d times while offline", *calls)
	}
	// Naming both URLs is the point: someone preparing an air-gapped runner needs the list of
	// what to bring across, not just to be told no.
	for _, want := range []string{"cisa.gov", "epss", netpolicy.EnvVar} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %q: %v", want, err)
		}
	}
}

func TestToolsInstallRefusesOfflineAndNamesTheTools(t *testing.T) {
	goOffline(t)
	cmd := newToolsCommand()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"install", "trivy", "gitleaks", "-y"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("installed while offline")
	}
	for _, want := range []string{"trivy", "gitleaks", "draugr tools install"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %q: %v", want, err)
		}
	}
}

func TestSelfUpdateRefusesOffline(t *testing.T) {
	goOffline(t)
	// --check reads the network too, so it is refused as well: there is no useful subset of
	// this command to run without one.
	err := runSelfUpdate(context.Background(), &bytes.Buffer{}, strings.NewReader(""),
		selfUpdateOptions{check: true})
	if err == nil {
		t.Fatal("checked for an update while offline")
	}
	if !strings.Contains(err.Error(), "releases/latest") {
		t.Errorf("error does not say what it would have fetched: %v", err)
	}
}

func TestDoctorListsNetworkCalls(t *testing.T) {
	var buf bytes.Buffer
	writeNetworkCalls(&buf, builtins.Registry(), nil)
	got := buf.String()
	if !strings.Contains(got, "draugr scan") {
		t.Errorf("the list does not say it is the scan's:\n%s", got)
	}
	// The hosts are the part somebody pastes into an egress rule. Derived from the registry, so a
	// scanner that declares a source cannot be missing from it.
	for _, want := range []string{"vuln.go.dev", "semgrep.dev", "raw.githubusercontent.com", "grype.anchore.io"} {
		if !strings.Contains(got, want) {
			t.Errorf("host list omits %q, so a reader behind an allowlist cannot permit it:\n%s", want, got)
		}
	}
	// A third party told about a target is listed under its control, beside the data hosts.
	if !regexp.MustCompile(`(?m)^    threats +urlhaus-api\.abuse\.ch +learns each host's name$`).MatchString(got) {
		t.Errorf("the threats control's third party is not listed under it:\n%s", got)
	}
	// Data fetched on every invocation is marked, because it is the difference between a scanner
	// that works behind an allowlist and one that also works without a network.
	if !strings.Contains(got, "every scan") {
		t.Errorf("nothing distinguishes data fetched per scan from data warmed once:\n%s", got)
	}
	// Four Trivy-backed scanners read one database: one row per control, not one per scanner.
	if n := strings.Count(got, "ghcr.io"); n != 3 {
		t.Errorf("ghcr.io listed %d times, want once each for images, licenses and sca:\n%s", n, got)
	}

	goOffline(t)
	buf.Reset()
	writeNetworkCalls(&buf, builtins.Registry(), nil)
	if !strings.Contains(buf.String(), "none of these will happen") {
		t.Errorf("offline heading not shown:\n%s", buf.String())
	}

	buf.Reset()
	writeNetworkCalls(&buf, nil, nil)
	if buf.Len() != 0 {
		t.Errorf("no registry printed %q", buf.String())
	}
}

// Given a descriptor, the list is what that scan contacts: the threats control's default scanner
// and not its alternative, and nothing for a control the descriptor leaves off.
func TestDoctorNetworkCallsFollowTheDescriptor(t *testing.T) {
	model, err := saga.LoadFile(writeSaga(t, `project: app
release:
  version: "1.0"
config:
  controllers:
    threats:
      enabled: true
components:
  - name: web
    hosts:
      - url: https://example.com
`))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	writeNetworkCalls(&buf, builtins.Registry(), model)
	got := buf.String()
	if !strings.Contains(got, "urlhaus-api.abuse.ch") {
		t.Errorf("the enabled control's host is missing:\n%s", got)
	}
	for _, not := range []string{"www.virustotal.com", "semgrep.dev", "ghcr.io"} {
		if strings.Contains(got, not) {
			t.Errorf("%s listed, and this scan would not contact it:\n%s", not, got)
		}
	}
}

// A scanner that tells a third party about a target has to say which host, or the list somebody
// builds an egress rule from is missing the one entry that discloses something.
func TestEveryDisclosingScannerNamesItsHost(t *testing.T) {
	for _, sc := range builtins.Registry().Scanners() {
		info := sc.Info()
		for _, e := range info.Effects {
			if e.Kind != plugin.EffectDisclosure {
				continue
			}
			if _, ok := disclosedTo[info.Name]; !ok {
				t.Errorf("%s declares a disclosure and has no entry in disclosedTo", info.Name)
			}
		}
	}
}
