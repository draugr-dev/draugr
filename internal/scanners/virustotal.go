package scanners

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/draugr-dev/draugr/internal/netpolicy"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// virusTotalAPI is the domain-report endpoint.
//
// Domain reports and nothing else. VirusTotal's terms attach sharing to "Sample submissions" —
// files and URLs sent for analysis — and their own documentation says reports are shared with the
// community and sample contents may reach premium customers. A domain report is a lookup of an
// aggregate they already maintain; there is no submitting a domain. Using any endpoint that
// accepts content would put a customer's data into that corpus, so this scanner has exactly one
// URL and a test that it has not grown another.
const virusTotalAPI = "https://www.virustotal.com/api/v3/domains/"

// virusTotalEndpoint is the address actually called. A var so a test can point it at a local
// server; the const above is what the scanner ships with and what its safety test asserts.
var virusTotalEndpoint = virusTotalAPI

// virusTotalKeyEnv holds the API key. VirusTotal asks that keys not be embedded "in scripts or
// software from which it can be easily retrieved", which is why it is read from the environment
// and never from a descriptor.
const virusTotalKeyEnv = "VIRUSTOTAL_API_KEY" //nolint:gosec // the name of a variable, not a credential

// virusTotalFreeRate is the published public-API allowance: 4 requests a minute.
//
// The conservative default on purpose. A paid key allows far more, and someone holding one raises
// it in configuration — a scanner that assumed the generous limit would earn a throttle, or worse
// a ban, for a user who never chose it.
var virusTotalFreeRate = plugin.Rate{Requests: 4, Per: time.Minute}

const virusTotalConfigSchema = `{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "requestsPerMinute": {
      "type": "integer",
      "description": "Override the assumed API allowance. Defaults to the public tier's 4. Raise it only to what your key actually permits — exceeding VirusTotal's limit risks losing access, and their stated penalty for terms violations is a permanent ban."
    }
  }
}`

// virusTotalScanner asks VirusTotal what its engines currently say about a host's domain.
type virusTotalScanner struct {
	info   plugin.ScannerInfo
	lookup func(ctx context.Context, domain string) (virusTotalDomain, bool, error)
	key    func() string
}

// NewVirusTotal returns the VirusTotal domain-reputation scanner.
func NewVirusTotal() plugin.Scanner {
	return virusTotalScanner{
		info: plugin.ScannerInfo{
			Name:        "virustotal",
			Origin:      "VirusTotal (Google)",
			Controls:    []string{"threats"},
			TargetKinds: []plugin.TargetKind{plugin.TargetHost},
			Effects: []plugin.Effect{{
				Kind: plugin.EffectDisclosure,
				Detail: "sends each host's domain to VirusTotal, a Google service, to read what " +
					"their engines already say about it",
			}},
			ConfigSchema: json.RawMessage(virusTotalConfigSchema),
		},
		lookup: virusTotalLookup,
		key:    func() string { return os.Getenv(virusTotalKeyEnv) },
	}
}

// Info describes the scanner.
func (s virusTotalScanner) Info() plugin.ScannerInfo { return s.info }

// RateLimit reports how often this scanner may be called (implements plugin.RateLimited).
func (s virusTotalScanner) RateLimit(cfg plugin.Config) plugin.Rate {
	if n, ok := configInt(cfg, "requestsPerMinute"); ok && n > 0 {
		return plugin.Rate{Requests: n, Per: time.Minute}
	}
	return virusTotalFreeRate
}

// CacheVersion ties cached results to this binary (implements plugin.CacheVersioner).
func (s virusTotalScanner) CacheVersion(context.Context) string { return draugrCacheVersion() }

// Scan reads VirusTotal's current verdict on the host's domain.
func (s virusTotalScanner) Scan(ctx context.Context, target plugin.Target, _ plugin.Config) (sarif.Report, error) {
	host, ok := target.(plugin.HostTarget)
	if !ok {
		return sarif.Report{}, fmt.Errorf("virustotal: unsupported target %T (want host)", target)
	}
	name, err := hostnameOf(host.URL)
	if err != nil {
		return sarif.Report{}, fmt.Errorf("virustotal: %w", err)
	}
	if netpolicy.Offline() {
		return sarif.Report{}, netpolicy.Refuse("the threats control",
			virusTotalAPI+" (asking about "+name+")")
	}
	if s.key() == "" {
		return sarif.Report{}, fmt.Errorf(
			"virustotal: no API key. Get one free at https://www.virustotal.com/gui/my-apikey "+
				"and put it in $%s — note their free tier forbids commercial use", virusTotalKeyEnv)
	}

	report, known, err := s.lookup(ctx, name)
	if err != nil {
		return sarif.Report{}, fmt.Errorf("virustotal: look up %s: %w", name, err)
	}
	return sarif.Report{
		Tool:       s.info.Name,
		Results:    virusTotalResults(host.URL, report, known),
		Rules:      virusTotalRules(),
		Provenance: []sarif.Provenance{virusTotalProvenance(name, report, known)},
	}, nil
}

// virusTotalDomain is the part of a domain report Draugr reads.
type virusTotalDomain struct {
	Stats      virusTotalStats `json:"last_analysis_stats"`
	Reputation int             `json:"reputation"`
	// Engines that flagged it, so a finding can name who rather than only how many.
	Results map[string]struct {
		Category string `json:"category"`
		Result   string `json:"result"`
	} `json:"last_analysis_results"`
}

// virusTotalStats is the tally across VirusTotal's engines.
type virusTotalStats struct {
	Malicious  int `json:"malicious"`
	Suspicious int `json:"suspicious"`
	Harmless   int `json:"harmless"`
	Undetected int `json:"undetected"`
}

// virusTotalLookup fetches a domain report. The bool reports whether VirusTotal knows the domain
// at all — a 404 is an answer ("never seen it"), not a failure.
func virusTotalLookup(ctx context.Context, domain string) (virusTotalDomain, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, virusTotalEndpoint+url.PathEscape(domain), nil)
	if err != nil {
		return virusTotalDomain{}, false, err
	}
	req.Header.Set("x-apikey", os.Getenv(virusTotalKeyEnv))

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return virusTotalDomain{}, false, err
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return virusTotalDomain{}, false, nil
	case http.StatusTooManyRequests:
		// Named, because the fix is a setting rather than a retry. Draugr already spaces calls to
		// the free allowance, so seeing this means either a paid key's higher limit was assumed
		// or something else is sharing it.
		return virusTotalDomain{}, false, fmt.Errorf(
			"rate limited (the public API allows 4 requests a minute; set " +
				"controllers.threats.virustotal.requestsPerMinute if your key allows more)")
	default:
		// Never the body: an auth failure can echo the key, and this string reaches the report.
		return virusTotalDomain{}, false, fmt.Errorf("VirusTotal returned %s", resp.Status)
	}

	var envelope struct {
		Data struct {
			Attributes virusTotalDomain `json:"attributes"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&envelope); err != nil {
		return virusTotalDomain{}, false, fmt.Errorf("decode response: %w", err)
	}
	return envelope.Data.Attributes, true, nil
}

// Rule IDs, stable so a diff matches on them across runs.
const (
	ruleVTMalicious  = "virustotal/malicious"
	ruleVTSuspicious = "virustotal/suspicious"
)

// vtMaliciousThreshold is how many engines must agree before it is an error rather than a warning.
//
// Two, not one. VirusTotal aggregates seventy-odd engines and a single detection on a legitimate
// domain is routine — newly registered domains, shared hosting, and anything a heuristic dislikes.
// Failing a build on one engine's opinion is how a control gets switched off. Two independent
// engines agreeing is a different claim.
const vtMaliciousThreshold = 2

// virusTotalResults turns a domain report into findings.
func virusTotalResults(rawURL string, d virusTotalDomain, known bool) []sarif.Result {
	// Never heard of it is a clean answer, and the commonest one for a domain nobody has reported.
	if !known {
		return nil
	}
	flagged := engineNames(d, "malicious")
	suspicious := engineNames(d, "suspicious")

	var out []sarif.Result
	switch {
	case d.Stats.Malicious >= vtMaliciousThreshold:
		out = append(out, sarif.Result{
			Tool:   "virustotal",
			RuleID: ruleVTMalicious,
			Level:  sarif.LevelError,
			Message: fmt.Sprintf("%d of VirusTotal's engines call this domain malicious (%s)",
				d.Stats.Malicious, namesOrCount(flagged)),
			Location: sarif.Location{URI: rawURL},
		})
	case d.Stats.Malicious == 1:
		out = append(out, sarif.Result{
			Tool:   "virustotal",
			RuleID: ruleVTSuspicious,
			Level:  sarif.LevelWarning,
			Message: fmt.Sprintf("one of VirusTotal's engines calls this domain malicious (%s). "+
				"A single detection is often a false positive — worth checking, not worth blocking on",
				namesOrCount(flagged)),
			Location: sarif.Location{URI: rawURL},
		})
	}
	if d.Stats.Suspicious > 0 {
		out = append(out, sarif.Result{
			Tool:   "virustotal",
			RuleID: ruleVTSuspicious,
			Level:  sarif.LevelWarning,
			Message: fmt.Sprintf("%d of VirusTotal's engines call this domain suspicious (%s)",
				d.Stats.Suspicious, namesOrCount(suspicious)),
			Location: sarif.Location{URI: rawURL},
		})
	}
	return out
}

// engineNames lists the engines that returned a category, sorted so a report is stable between
// runs — a map's order is not, and an unstable message makes every diff show the same finding as
// fixed and new.
func engineNames(d virusTotalDomain, category string) []string {
	var names []string
	for engine, r := range d.Results {
		if strings.EqualFold(r.Category, category) {
			names = append(names, engine)
		}
	}
	sort.Strings(names)
	return names
}

// namesOrCount lists a few engines, or says how many when there are too many to read.
func namesOrCount(names []string) string {
	const show = 4
	switch {
	case len(names) == 0:
		return "engines not named in the report"
	case len(names) <= show:
		return strings.Join(names, ", ")
	default:
		return fmt.Sprintf("%s and %d more", strings.Join(names[:show], ", "), len(names)-show)
	}
}

// virusTotalRules documents each rule so a reader can reach the source of the claim.
func virusTotalRules() map[string]sarif.Rule {
	return map[string]sarif.Rule{
		ruleVTMalicious: {
			Name:             "Domain flagged as malicious",
			ShortDescription: "Two or more of VirusTotal's engines currently classify this domain as malicious.",
			HelpURI:          "https://www.virustotal.com/",
		},
		ruleVTSuspicious: {
			Name:             "Domain flagged by a minority of engines",
			ShortDescription: "One engine calls it malicious, or some call it suspicious — often a false positive.",
			HelpURI:          "https://www.virustotal.com/",
		},
	}
}

// virusTotalProvenance records who was asked and what came back, including a clean answer.
func virusTotalProvenance(domain string, d virusTotalDomain, known bool) sarif.Provenance {
	answer := fmt.Sprintf("%d malicious, %d suspicious, %d harmless",
		d.Stats.Malicious, d.Stats.Suspicious, d.Stats.Harmless)
	if !known {
		answer = "no report for this domain"
	}
	return sarif.Provenance{
		Tool: "virustotal",
		Fields: []sarif.Field{
			{Key: "source", Value: "VirusTotal domain report"},
			{Key: "host", Value: domain},
			{Key: "answer", Value: answer},
		},
	}
}
