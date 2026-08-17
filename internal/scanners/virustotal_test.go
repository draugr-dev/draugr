package scanners

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

func fakeVT(d virusTotalDomain, known bool, err error) virusTotalScanner {
	s := NewVirusTotal().(virusTotalScanner)
	s.lookup = func(context.Context, string) (virusTotalDomain, bool, error) { return d, known, err }
	s.key = func() string { return "test-key" }
	return s
}

func TestVirusTotalOnlyEverReadsDomainReports(t *testing.T) {
	// The safety property the whole scanner rests on. VirusTotal's sharing terms attach to
	// "Sample submissions" — files and URLs sent for analysis. A domain report is a lookup of an
	// aggregate they already hold, and there is no submitting a domain. An endpoint that accepts
	// content would put a customer's data into a corpus shared with the community and with
	// premium customers, so the single URL is asserted rather than trusted to review.
	if !strings.HasPrefix(virusTotalAPI, "https://www.virustotal.com/api/v3/domains/") {
		t.Errorf("endpoint changed to %q — if this is deliberate, re-read what VirusTotal shares", virusTotalAPI)
	}
	// Spelled the way VirusTotal spells it. These are their endpoint paths, not our prose, so
	// the American-spelling rule does not reach them — a "corrected" path matches nothing and
	// the guard silently stops guarding.
	for _, forbidden := range []string{"/urls", "/files", "/analyses"} {
		if strings.Contains(virusTotalAPI, forbidden) {
			t.Errorf("endpoint reaches %s, which accepts submissions", forbidden)
		}
	}
}

func TestVirusTotalNeedsTwoEnginesToFailABuild(t *testing.T) {
	// A single detection on a legitimate domain is routine — new registrations, shared hosting,
	// a heuristic having a bad day. Failing a build on one engine's opinion is how a control
	// gets switched off, so one is reported and does not gate.
	got := virusTotalResults("https://x.example/", virusTotalDomain{
		Stats: virusTotalStats{Malicious: 1},
	}, true)
	if len(got) != 1 || got[0].Level != sarif.LevelWarning {
		t.Errorf("one engine should warn, not fail: %+v", got)
	}
	got = virusTotalResults("https://x.example/", virusTotalDomain{
		Stats: virusTotalStats{Malicious: 2},
	}, true)
	if len(got) != 1 || got[0].Level != sarif.LevelError {
		t.Errorf("two engines agreeing should be an error: %+v", got)
	}
}

func TestVirusTotalUnknownDomainIsACleanAnswer(t *testing.T) {
	if got := virusTotalResults("https://x.example/", virusTotalDomain{}, false); got != nil {
		t.Errorf("a domain VirusTotal has never seen is not a finding: %+v", got)
	}
	// And the provenance says the question was asked, so a clean control is distinguishable from
	// one that never ran.
	p := virusTotalProvenance("x.example", virusTotalDomain{}, false)
	if !strings.Contains(p.Describe(), "no report") {
		t.Errorf("provenance = %q", p.Describe())
	}
}

func TestVirusTotalNamesTheEnginesStably(t *testing.T) {
	// A map's iteration order is not stable, and an unstable message makes `draugr diff` report
	// the same finding as fixed and new on every run.
	d := virusTotalDomain{Stats: virusTotalStats{Malicious: 3}, Results: map[string]struct {
		Category string `json:"category"`
		Result   string `json:"result"`
	}{
		"Zeta": {Category: "malicious"}, "Alpha": {Category: "malicious"},
		"Mid": {Category: "malicious"}, "Clean": {Category: "harmless"},
	}}
	first := virusTotalResults("https://x.example/", d, true)[0].Message
	for range 20 {
		if got := virusTotalResults("https://x.example/", d, true)[0].Message; got != first {
			t.Fatalf("message is not stable between runs:\n  %q\n  %q", first, got)
		}
	}
	if !strings.Contains(first, "Alpha, Mid, Zeta") {
		t.Errorf("engines should be named in order: %q", first)
	}
}

func TestVirusTotalRateLimitDefaultsToTheFreeTier(t *testing.T) {
	s := NewVirusTotal().(virusTotalScanner)
	if got := s.RateLimit(nil); got != virusTotalFreeRate {
		t.Errorf("RateLimit(nil) = %+v, want the public allowance", got)
	}
	if got := s.RateLimit(plugin.Config{"requestsPerMinute": 1000}); got.Requests != 1000 {
		t.Errorf("a paid key's allowance was ignored: %+v", got)
	}
	// Nonsense does not become an unlimited rate.
	if got := s.RateLimit(plugin.Config{"requestsPerMinute": 0}); got != virusTotalFreeRate {
		t.Errorf("zero should fall back to the default, got %+v", got)
	}
	if got := virusTotalFreeRate.Interval(); got != 15*time.Second {
		t.Errorf("4/minute should space calls 15s apart, got %v", got)
	}
}

func TestVirusTotalRefusesWithoutAKeyAndOffline(t *testing.T) {
	s := fakeVT(virusTotalDomain{}, false, nil)
	s.key = func() string { return "" }
	_, err := s.Scan(context.Background(), plugin.HostTarget{URL: "https://x.example/"}, plugin.Config{})
	if err == nil || !strings.Contains(err.Error(), virusTotalKeyEnv) {
		t.Errorf("the error should name the variable: %v", err)
	}
	if !strings.Contains(err.Error(), "commercial") {
		t.Errorf("and the restriction that decides whether they may use it at all: %v", err)
	}
}

func TestVirusTotalInfoAndScan(t *testing.T) {
	info := NewVirusTotal().Info()
	if info.Name != "virustotal" || !strings.Contains(info.Origin, "Google") {
		t.Errorf("Info() = %+v", info)
	}
	// Naming Google matters: a reader deciding whether to enable this is weighing who receives
	// their hostnames, and "VirusTotal" alone does not answer that for everyone.
	if len(info.Effects) != 1 || info.Effects[0].Kind != plugin.EffectDisclosure {
		t.Fatalf("effects = %+v", info.Effects)
	}
	if !strings.Contains(info.Effects[0].Detail, "Google") {
		t.Errorf("the effect should say who receives it: %q", info.Effects[0].Detail)
	}
	if len(info.ConfigSchema) == 0 {
		t.Error("no config schema, so requestsPerMinute would be rejected as an unknown key")
	}

	s := fakeVT(virusTotalDomain{Stats: virusTotalStats{Malicious: 3, Harmless: 60}}, true, nil)
	if s.CacheVersion(context.Background()) == "" {
		t.Error("no cache version, so a Draugr upgrade would not invalidate cached verdicts")
	}
	rep, err := s.Scan(context.Background(), plugin.HostTarget{URL: "https://bad.example/x"}, plugin.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 1 || rep.Results[0].Level != sarif.LevelError {
		t.Fatalf("results = %+v", rep.Results)
	}
	if len(rep.Rules) == 0 {
		t.Error("no rule metadata, so a reader cannot follow the finding to its source")
	}
	if len(rep.Provenance) != 1 || !strings.Contains(rep.Provenance[0].Describe(), "3 malicious") {
		t.Errorf("provenance = %+v", rep.Provenance)
	}
}

func TestVirusTotalRejectsWhatItCannotAsk(t *testing.T) {
	s := fakeVT(virusTotalDomain{}, false, nil)
	for _, target := range []plugin.Target{
		plugin.HostTarget{URL: ""},
		plugin.RepositoryTarget{URL: "."},
	} {
		if _, err := s.Scan(context.Background(), target, plugin.Config{}); err == nil {
			t.Errorf("%+v was accepted", target)
		}
	}
}

func TestNamesOrCount(t *testing.T) {
	if got := namesOrCount(nil); !strings.Contains(got, "not named") {
		t.Errorf("got %q", got)
	}
	if got := namesOrCount([]string{"a", "b"}); got != "a, b" {
		t.Errorf("got %q", got)
	}
	// A domain can be flagged by dozens of engines; listing them all buries the count.
	got := namesOrCount([]string{"a", "b", "c", "d", "e", "f"})
	if !strings.Contains(got, "and 2 more") {
		t.Errorf("got %q", got)
	}
}

func TestVirusTotalLookupHandlesEachAnswer(t *testing.T) {
	const key = "super-secret-key-value"
	t.Setenv(virusTotalKeyEnv, key)

	cases := []struct {
		name      string
		status    int
		body      string
		wantKnown bool
		wantErr   string
		wantStats int
	}{
		{name: "known", status: 200, wantKnown: true, wantStats: 3,
			body: `{"data":{"attributes":{"last_analysis_stats":{"malicious":3}}}}`},
		// A 404 is an answer — "never seen it" — not a failure, and reporting it as one would
		// turn every unremarkable domain into a scan error.
		{name: "unknown", status: 404, wantKnown: false},
		{name: "rate limited", status: 429, wantErr: "4 requests a minute"},
		{name: "auth failure", status: 401, body: `{"error":"bad key ` + key + `"}`, wantErr: "401"},
		{name: "garbage", status: 200, body: `{not json`, wantErr: "decode"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var gotKeyHeader, gotPath string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotKeyHeader, gotPath = r.Header.Get("x-apikey"), r.URL.Path
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			orig := virusTotalEndpoint
			virusTotalEndpoint = srv.URL + "/api/v3/domains/"
			defer func() { virusTotalEndpoint = orig }()

			got, known, err := virusTotalLookup(context.Background(), "shop.example")
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want it to mention %q", err, tc.wantErr)
				}
				// The property that matters most here: an authentication failure can echo the
				// key back, and this string reaches the terminal and the report.
				if strings.Contains(err.Error(), key) {
					t.Error("the API key leaked into an error message")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if known != tc.wantKnown || got.Stats.Malicious != tc.wantStats {
				t.Errorf("known=%v stats=%d, want %v/%d", known, got.Stats.Malicious, tc.wantKnown, tc.wantStats)
			}
			if gotKeyHeader != key {
				t.Errorf("key sent as %q", gotKeyHeader)
			}
			if !strings.HasSuffix(gotPath, "/shop.example") {
				t.Errorf("path = %q", gotPath)
			}
		})
	}
}
