package scanners

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/netpolicy"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// fakeURLhaus returns a scanner that answers with resp and never touches the network.
func fakeURLhaus(resp urlhausResponse, err error) urlhausScanner {
	s := NewURLhaus().(urlhausScanner)
	s.lookup = func(context.Context, string) (urlhausResponse, error) { return resp, err }
	s.key = func() string { return "test-key" }
	return s
}

func TestURLhausInfo(t *testing.T) {
	info := NewURLhaus().Info()
	if info.Name != "urlhaus" || info.Origin != "abuse.ch" {
		t.Errorf("Info() = %+v", info)
	}
	if len(info.Controls) != 1 || info.Controls[0] != "threats" {
		t.Errorf("controls = %v", info.Controls)
	}
	if len(info.TargetKinds) != 1 || info.TargetKinds[0] != plugin.TargetHost {
		t.Errorf("target kinds = %v", info.TargetKinds)
	}
	// The effect is the point of declaring one: unlike every other host scanner, the traffic
	// goes to a third party rather than to the host being scanned, and somebody approving a scan
	// of an unannounced service deserves to know that before it runs.
	if len(info.Effects) != 1 || info.Effects[0].Kind != plugin.EffectNetwork {
		t.Fatalf("effects = %+v", info.Effects)
	}
	if !strings.Contains(info.Effects[0].Detail, "abuse.ch") {
		t.Errorf("the effect should name who learns the hostname: %q", info.Effects[0].Detail)
	}
}

func TestURLhausSeparatesLiveMalwareFromHistory(t *testing.T) {
	// The judgement in this scanner. A years-old dead record reported at the same level as live
	// malware makes the control cry wolf on any domain with a history, and a control that cries
	// wolf gets switched off — which is worse than one that reports slightly less.
	got := urlhausResults("https://shop.example/", urlhausResponse{
		QueryStatus: "ok",
		URLs: []urlhausEntry{
			{URL: "http://shop.example/a.exe", Status: "online", Threat: "malware_download"},
			{URL: "http://shop.example/old.exe", Status: "offline", Threat: "malware_download"},
		},
	})
	if len(got) != 2 {
		t.Fatalf("want one finding per state, got %d: %+v", len(got), got)
	}
	byRule := map[string]sarif.Result{}
	for _, r := range got {
		byRule[r.RuleID] = r
	}
	if byRule[ruleMalwareHost].Level != sarif.LevelError {
		t.Errorf("live malware = %q, want error", byRule[ruleMalwareHost].Level)
	}
	if byRule[ruleMalwareHostPast].Level != sarif.LevelWarning {
		t.Errorf("historic = %q, want warning", byRule[ruleMalwareHostPast].Level)
	}
	if !strings.Contains(byRule[ruleMalwareHost].Message, "a.exe") {
		t.Errorf("the finding should name what was found: %q", byRule[ruleMalwareHost].Message)
	}
}

func TestURLhausDoesNotReportCleanBlocklists(t *testing.T) {
	// abuse.ch reports every list it consulted, including the ones that came back clean.
	// Reporting "not listed" would be reporting good news as a problem.
	got := urlhausResults("https://ok.example/", urlhausResponse{
		QueryStatus: "ok",
		Blacklists:  map[string]string{"spamhaus_dbl": "not listed", "surbl": "listed"},
	})
	if len(got) != 1 {
		t.Fatalf("want only the real listing, got %+v", got)
	}
	if !strings.Contains(got[0].Message, "surbl") {
		t.Errorf("wrong list reported: %q", got[0].Message)
	}
}

func TestURLhausCleanHostFindsNothingAndSaysSo(t *testing.T) {
	// A control reporting nothing because a feed knows nothing is indistinguishable, in a report,
	// from one that never ran. "abuse.ch has never heard of your host" is the answer you wanted,
	// so it is recorded rather than left as silence.
	s := fakeURLhaus(urlhausResponse{QueryStatus: "no_results"}, nil)
	rep, err := s.Scan(context.Background(), plugin.HostTarget{URL: "https://clean.example/"}, plugin.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 0 {
		t.Errorf("a clean host produced findings: %+v", rep.Results)
	}
	if len(rep.Provenance) != 1 {
		t.Fatalf("no provenance recorded: %+v", rep.Provenance)
	}
	if d := rep.Provenance[0].Describe(); !strings.Contains(d, "no records") {
		t.Errorf("provenance should say the feed was asked and knew nothing: %q", d)
	}
}

func TestURLhausRefusesWithoutAKey(t *testing.T) {
	// abuse.ch made authentication mandatory, so there is no keyless mode. "401 from an API" does
	// not tell anybody what to do next; the variable name and where to get one does.
	s := fakeURLhaus(urlhausResponse{}, nil)
	s.key = func() string { return "" }
	_, err := s.Scan(context.Background(), plugin.HostTarget{URL: "https://x.example/"}, plugin.Config{})
	if err == nil {
		t.Fatal("scanned without a key")
	}
	if !strings.Contains(err.Error(), urlhausKeyEnv) || !strings.Contains(err.Error(), "abuse.ch") {
		t.Errorf("the error should name the variable and where to get a key: %v", err)
	}
}

func TestURLhausRefusesOffline(t *testing.T) {
	// There is no degraded version of a control whose whole job is to ask somebody else. Naming
	// the host is the point: an air-gapped operator needs to know what the scan would have sent.
	netpolicy.SetOffline(true)
	defer netpolicy.SetOffline(false)

	s := fakeURLhaus(urlhausResponse{}, nil)
	_, err := s.Scan(context.Background(), plugin.HostTarget{URL: "https://secret.internal/"}, plugin.Config{})
	if err == nil {
		t.Fatal("reached the network while offline")
	}
	if !strings.Contains(err.Error(), "secret.internal") {
		t.Errorf("the refusal should name what would have been disclosed: %v", err)
	}
}

func TestURLhausRejectsWhatItCannotAsk(t *testing.T) {
	s := fakeURLhaus(urlhausResponse{}, nil)
	for _, target := range []plugin.Target{
		plugin.HostTarget{URL: ""},
		plugin.HostTarget{URL: "://nonsense"},
		plugin.RepositoryTarget{URL: "."},
	} {
		if _, err := s.Scan(context.Background(), target, plugin.Config{}); err == nil {
			t.Errorf("%+v was accepted", target)
		}
	}
}

func TestURLhausSurfacesALookupFailure(t *testing.T) {
	s := fakeURLhaus(urlhausResponse{}, errors.New("abuse.ch returned 429 Too Many Requests"))
	_, err := s.Scan(context.Background(), plugin.HostTarget{URL: "https://x.example/"}, plugin.Config{})
	if err == nil || !strings.Contains(err.Error(), "429") {
		t.Errorf("a failed lookup should not read as a clean host: %v", err)
	}
}

func TestHostnameOf(t *testing.T) {
	// URLhaus keys on the host, so a path would narrow the question and miss malware served
	// from elsewhere on the same machine — which is the case this control exists to catch.
	for in, want := range map[string]string{
		"https://shop.example/cart?a=1": "shop.example",
		"shop.example":                  "shop.example",
		"http://10.0.0.1:8080/x":        "10.0.0.1",
	} {
		got, err := hostnameOf(in)
		if err != nil || got != want {
			t.Errorf("hostnameOf(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := hostnameOf(""); err == nil {
		t.Error("an empty url was accepted")
	}
}

func TestSummariseEntriesStopsAtThree(t *testing.T) {
	// A host can carry a hundred records. Pasting them all into a finding buries the fact that
	// there are a hundred.
	var many []urlhausEntry
	for range 10 {
		many = append(many, urlhausEntry{URL: "http://x.example/a", Threat: "malware_download"})
	}
	got := summariseEntries(many)
	if !strings.Contains(got, "and 7 more") {
		t.Errorf("summary did not stop and count the rest: %q", got)
	}
	if got := summariseEntries([]urlhausEntry{{URL: "http://x.example/a"}}); !strings.Contains(got, "unknown threat") {
		t.Errorf("a record with no threat category should still read sensibly: %q", got)
	}
}
