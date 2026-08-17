package scanners

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/draugr-dev/draugr/internal/netpolicy"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// urlhausAPI is abuse.ch's lookup endpoint. A POST, not a GET — their API rejects anything else
// with `http_post_expected`.
const urlhausAPI = "https://urlhaus-api.abuse.ch/v1/host/"

// urlhausEndpoint is the address actually called. A var so a test can point it at a local server.
var urlhausEndpoint = urlhausAPI

// urlhausKeyEnv holds the abuse.ch Auth-Key. Free, and required: abuse.ch made authentication
// mandatory, so this scanner cannot work without one and says so rather than failing at the
// network.
const urlhausKeyEnv = "URLHAUS_AUTH_KEY" //nolint:gosec // the name of a variable, not a credential

// urlhausScanner asks abuse.ch whether a component's own hosts are known to serve malware.
//
// Backwards compared to most controls: the others ask "is there something wrong inside this
// artifact". This asks "does the outside world already consider this host hostile" — which is a
// different question with a different failure mode. A hit means someone else has seen your
// infrastructure distributing malware, which is either a compromise you have not found yet or a
// name someone else abused before you had it.
type urlhausScanner struct {
	info   plugin.ScannerInfo
	lookup func(ctx context.Context, host string) (urlhausResponse, error)
	key    func() string
}

// NewURLhaus returns the abuse.ch URLhaus threat-intelligence scanner.
func NewURLhaus() plugin.Scanner {
	return urlhausScanner{
		info: plugin.ScannerInfo{
			Name:         "urlhaus",
			Origin:       "abuse.ch",
			Controls:     []string{"threats"},
			TargetKinds:  []plugin.TargetKind{plugin.TargetHost},
			ConfigSchema: json.RawMessage(noScannerOptions),
			// Disclosure rather than network: the packets do not go to the target at all. Every
			// other host scanner sends traffic to a host you own; this one tells a third party
			// that the host exists and that you are interested in it. Someone approving a scan
			// of an unannounced service deserves to know that before it runs, not after.
			Effects: []plugin.Effect{{
				Kind: plugin.EffectDisclosure,
				Detail: "sends each host's name to abuse.ch to ask whether it is known to " +
					"serve malware — a third party learns the hostname",
			}},
		},
		lookup: urlhausLookup,
		key:    func() string { return os.Getenv(urlhausKeyEnv) },
	}
}

// Info describes the scanner.
func (s urlhausScanner) Info() plugin.ScannerInfo { return s.info }

// CacheVersion ties cached results to this binary (implements plugin.CacheVersioner).
//
// There is no tool version to read, and the answer depends on a feed that changes constantly —
// which is what the cache TTL is for. This only has to invalidate when Draugr's own reading of
// the response changes.
func (s urlhausScanner) CacheVersion(context.Context) string { return draugrCacheVersion() }

// Scan asks URLhaus about the host and reports what it already knows.
func (s urlhausScanner) Scan(ctx context.Context, target plugin.Target, _ plugin.Config) (sarif.Report, error) {
	host, ok := target.(plugin.HostTarget)
	if !ok {
		return sarif.Report{}, fmt.Errorf("urlhaus: unsupported target %T (want host)", target)
	}
	name, err := hostnameOf(host.URL)
	if err != nil {
		return sarif.Report{}, fmt.Errorf("urlhaus: %w", err)
	}
	// Refused rather than attempted: this control's whole job is to ask somebody else, so there
	// is no degraded version of it to run. Saying which host would have been disclosed is the
	// point — an air-gapped operator needs to know what the scan would have sent.
	if netpolicy.Offline() {
		return sarif.Report{}, netpolicy.Refuse("the threats control", urlhausAPI+" (asking about "+name+")")
	}
	if s.key() == "" {
		return sarif.Report{}, fmt.Errorf(
			"urlhaus: no API key. abuse.ch requires one and issues them free at "+
				"https://auth.abuse.ch/ — put it in $%s", urlhausKeyEnv)
	}

	resp, err := s.lookup(ctx, name)
	if err != nil {
		return sarif.Report{}, fmt.Errorf("urlhaus: look up %s: %w", name, err)
	}
	return sarif.Report{
		Tool:       s.info.Name,
		Results:    urlhausResults(host.URL, resp),
		Rules:      urlhausRules(),
		Provenance: []sarif.Provenance{urlhausProvenance(name, resp)},
	}, nil
}

// hostnameOf extracts the host to ask about. URLhaus keys on the host, not the full URL, so a
// path would only narrow the question and miss malware served from elsewhere on the same host.
func hostnameOf(raw string) (string, error) {
	if raw == "" {
		return "", errors.New("host target has no url")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return "", fmt.Errorf("%q is not a URL a hostname can be read from", raw)
	}
	return u.Hostname(), nil
}

// urlhausResponse is the part of abuse.ch's answer Draugr reads.
type urlhausResponse struct {
	QueryStatus string `json:"query_status"`
	// Blacklists is abuse.ch's view of third-party lists for this host, e.g. spamhaus_dbl.
	Blacklists map[string]string `json:"blacklists"`
	URLs       []urlhausEntry    `json:"urls"`
}

// urlhausEntry is one malware URL abuse.ch has recorded on the host.
type urlhausEntry struct {
	URL       string   `json:"url"`
	Status    string   `json:"url_status"`
	Threat    string   `json:"threat"`
	DateAdded string   `json:"date_added"`
	Tags      []string `json:"tags"`
	Reference string   `json:"urlhaus_reference"`
}

// urlhausLookup posts the host to abuse.ch.
func urlhausLookup(ctx context.Context, host string) (urlhausResponse, error) {
	form := url.Values{"host": {host}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, urlhausEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return urlhausResponse{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Auth-Key", os.Getenv(urlhausKeyEnv))

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return urlhausResponse{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		// Never the body: an auth failure from abuse.ch can echo the key back, and this string
		// reaches the terminal and the report.
		return urlhausResponse{}, fmt.Errorf("abuse.ch returned %s", resp.Status)
	}
	var out urlhausResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&out); err != nil {
		return urlhausResponse{}, fmt.Errorf("decode response: %w", err)
	}
	switch out.QueryStatus {
	case "ok", "no_results":
		return out, nil
	case "invalid_host":
		return urlhausResponse{}, fmt.Errorf("abuse.ch could not read %q as a host", host)
	default:
		return urlhausResponse{}, fmt.Errorf("abuse.ch answered %q", out.QueryStatus)
	}
}

// Rule IDs. Stable, because a diff matches on them and a finding that renames itself between
// releases reads as one fixed and one new.
const (
	ruleMalwareHost     = "urlhaus/malware-host"
	ruleMalwareHostPast = "urlhaus/malware-host-historic"
	ruleHostBlacklisted = "urlhaus/blacklisted"
)

// urlhausResults turns abuse.ch's answer into findings.
//
// Two levels, and the distinction is the whole judgement here. A URL abuse.ch still marks
// `online` is malware being served from your host right now. One marked offline is a record that
// it once was — which is not nothing, because it means the host was compromised or abused before,
// but it is not an emergency and reporting it as one would make the control cry wolf on any
// domain with a history.
func urlhausResults(rawURL string, resp urlhausResponse) []sarif.Result {
	var out []sarif.Result
	var online, historic []urlhausEntry
	for _, u := range resp.URLs {
		if strings.EqualFold(u.Status, "online") {
			online = append(online, u)
			continue
		}
		historic = append(historic, u)
	}

	if len(online) > 0 {
		out = append(out, sarif.Result{
			Tool:   "urlhaus",
			RuleID: ruleMalwareHost,
			Level:  sarif.LevelError,
			Message: fmt.Sprintf(
				"abuse.ch is currently serving %s from this host as malware: %s. "+
					"Either the host is compromised, or the name was abused before you held it.",
				countOf(len(online), "URL"), summarizeEntries(online)),
			Location: sarif.Location{URI: rawURL},
		})
	}
	if len(historic) > 0 {
		out = append(out, sarif.Result{
			Tool:   "urlhaus",
			RuleID: ruleMalwareHostPast,
			Level:  sarif.LevelWarning,
			Message: fmt.Sprintf(
				"abuse.ch has %s recorded on this host as having served malware, now offline: %s. "+
					"Worth knowing when the host was compromised, and noise if the name changed hands.",
				countOf(len(historic), "URL"), summarizeEntries(historic)),
			Location: sarif.Location{URI: rawURL},
		})
	}
	for list, state := range resp.Blacklists {
		// abuse.ch reports every list it consulted, including the ones that came back clean.
		// Reporting "not listed" as a finding would be reporting good news as a problem.
		if strings.EqualFold(state, "not listed") || state == "" {
			continue
		}
		out = append(out, sarif.Result{
			Tool:     "urlhaus",
			RuleID:   ruleHostBlacklisted,
			Level:    sarif.LevelWarning,
			Message:  fmt.Sprintf("%s lists this host as %s (via abuse.ch)", list, state),
			Location: sarif.Location{URI: rawURL},
		})
	}
	return out
}

// countOf renders "1 URL" / "3 URLs". Local rather than shared: the plural helpers elsewhere
// live in packages this one should not depend on for a word.
func countOf(n int, noun string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", noun)
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

// summarizeEntries names a few URLs without pasting a hundred of them into a report.
func summarizeEntries(entries []urlhausEntry) string {
	const show = 3
	var parts []string
	for i, e := range entries {
		if i == show {
			parts = append(parts, fmt.Sprintf("and %d more", len(entries)-show))
			break
		}
		threat := e.Threat
		if threat == "" {
			threat = "unknown threat"
		}
		parts = append(parts, fmt.Sprintf("%s (%s)", e.URL, threat))
	}
	return strings.Join(parts, ", ")
}

// urlhausRules documents each rule, so a reader can follow the finding to the source that made
// the claim rather than taking Draugr's word for it.
func urlhausRules() map[string]sarif.Rule {
	const home = "https://urlhaus.abuse.ch/"
	return map[string]sarif.Rule{
		ruleMalwareHost: {
			Name:             "Host is serving malware",
			ShortDescription: "abuse.ch records malware currently being served from this host.",
			HelpURI:          home,
		},
		ruleMalwareHostPast: {
			Name:             "Host has served malware",
			ShortDescription: "abuse.ch records malware previously served from this host, now offline.",
			HelpURI:          home,
		},
		ruleHostBlacklisted: {
			Name:             "Host appears on a blocklist",
			ShortDescription: "A third-party blocklist consulted by abuse.ch lists this host.",
			HelpURI:          home,
		},
	}
}

// urlhausProvenance records who was asked and what they said, including when they said nothing.
//
// A control that reports no findings because a feed knows nothing is indistinguishable, in a
// report, from one that did not run — and this one is worth telling apart, because "abuse.ch has
// never heard of your host" is the answer you wanted.
func urlhausProvenance(host string, resp urlhausResponse) sarif.Provenance {
	answer := resp.QueryStatus
	if answer == "no_results" {
		answer = "no records for this host"
	}
	return sarif.Provenance{
		Tool: "urlhaus",
		Fields: []sarif.Field{
			{Key: "source", Value: "abuse.ch URLhaus"},
			{Key: "host", Value: host},
			{Key: "answer", Value: answer},
		},
	}
}
