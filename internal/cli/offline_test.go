package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/feeds"
	"github.com/draugr-dev/draugr/internal/netpolicy"
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
	writeNetworkCalls(&buf)
	got := buf.String()
	// The list is the air-gap preparation checklist. Every command that reaches out has to be
	// on it, or someone finds out one failure at a time.
	for _, want := range []string{"draugr tools install", "draugr feeds update", "draugr self-update", "a scan"} {
		if !strings.Contains(got, want) {
			t.Errorf("network list omits %q:\n%s", want, got)
		}
	}

	goOffline(t)
	buf.Reset()
	writeNetworkCalls(&buf)
	if !strings.Contains(buf.String(), "none of these will happen") {
		t.Errorf("offline heading not shown:\n%s", buf.String())
	}
}
