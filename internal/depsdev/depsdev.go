// Package depsdev asks deps.dev what is known about the packages a scan found.
//
// # What leaves the machine
//
// A list of package names and versions, and nothing else. No source, no findings, no descriptor.
// That is still a disclosure, and the control declares it, because a reader deciding whether to
// switch this on is entitled to know that their dependency list reaches a third party.
//
// # Why the cache is an hour
//
// The service permits caching in its own documentation and the Google API Terms of Service cap a
// cached copy at what the response's cache header allows. That header says `max-age=3600`, so an
// hour is the contract rather than a tuning choice, and a longer one would need a different source
// for the same data rather than a larger number here.
//
// An hour is enough for the case that matters: a developer running a scan repeatedly while fixing
// something pays for one lookup. It is not enough for an air-gapped run, which this signal
// therefore does not claim to support.
package depsdev

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/draugr-dev/draugr/pkg/dephealth"
)

// endpoint is the batch findings lookup. The single-version form exists and is not used: a scan
// knows every package it wants before it asks, and one request per package is a rate limit
// somebody else has to absorb.
const endpoint = "https://api.deps.dev/v3alpha/findingsbatch"

// pageSize is what the service returns per request, observed on 2026-09-19. Asking for more
// returns the first hundred and a page token, so the client batches to match rather than paging.
const pageSize = 100

// CacheTTL is how long a response may be kept. Set by the API's own cache header; see the package
// comment before changing it, because this is a term rather than a preference.
const CacheTTL = time.Hour

// Host is what the control declares it contacts.
const Host = "api.deps.dev"

// systems maps a purl type to the name deps.dev uses. A type absent here is one the service does
// not index, which is most of them: every operating-system package in a container image is a
// `deb`, `rpm` or `apk`, and none of those appear.
var systems = map[string]string{
	"npm":    "NPM",
	"pypi":   "PYPI",
	"golang": "GO",
	"cargo":  "CARGO",
	"maven":  "MAVEN",
	"nuget":  "NUGET",
	"gem":    "RUBYGEMS",
}

// Client looks packages up, through a cache.
type Client struct {
	HTTP *http.Client
	// Now is the clock, injectable so a test can age the cache without sleeping.
	Now func() time.Time
	// Endpoint overrides where requests go. Empty means the real service; a test points this at
	// its own server rather than at somebody else's, because a unit test that depends on a third
	// party is a test that fails when their week goes badly.
	Endpoint string

	cache map[string]entry
}

type entry struct {
	pkg     dephealth.Package
	fetched time.Time
}

// New returns a Client with the defaults a scan should use.
func New() *Client {
	return &Client{
		// Generous enough for a slow link and bounded, because a scan that hangs on an enrichment
		// nobody asked for is worse than one that reports it could not reach the data.
		HTTP:  &http.Client{Timeout: 30 * time.Second},
		Now:   time.Now,
		cache: map[string]entry{},
	}
}

// key identifies one package version to the service.
type key struct {
	System, Name, Version string
}

// Lookup answers for as many of these packages as the service indexes.
//
// A purl in an ecosystem deps.dev does not cover is skipped rather than reported as an error: a
// container image is mostly operating-system packages, and a run that failed because Debian is not
// indexed would fail every time on most projects.
//
// The error is returned only when the service could not be reached at all. A caller should report
// that and carry on: this signal never gates, so a lookup that did not happen must cost a reader a
// line of evidence rather than a verdict.
func (c *Client) Lookup(ctx context.Context, purls []string) (map[string]dephealth.Package, error) {
	out := map[string]dephealth.Package{}
	var want []string
	seen := map[string]bool{}

	for _, p := range purls {
		p = strings.TrimSpace(p)
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		if _, ok := Parse(p); !ok {
			continue // an ecosystem this service does not index
		}
		if e, ok := c.cache[p]; ok && c.Now().Sub(e.fetched) < CacheTTL {
			out[p] = e.pkg
			continue
		}
		want = append(want, p)
	}
	if len(want) == 0 {
		return out, nil
	}

	for i := 0; i < len(want); i += pageSize {
		end := min(i+pageSize, len(want))
		got, err := c.fetch(ctx, want[i:end])
		if err != nil {
			// What was already answered is still worth having, so the partial result travels with
			// the error rather than being discarded.
			return out, err
		}
		for purl, pkg := range got {
			out[purl] = pkg
			c.cache[purl] = entry{pkg: pkg, fetched: c.Now()}
		}
	}
	return out, nil
}

// fetch performs one batch request.
func (c *Client) fetch(ctx context.Context, purls []string) (map[string]dephealth.Package, error) {
	type versionKey struct {
		System  string `json:"system"`
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	type request struct {
		VersionKey versionKey `json:"versionKey"`
	}

	byKey := map[key]string{} // back to the purl that asked
	var reqs []request
	for _, p := range purls {
		k, ok := Parse(p)
		if !ok {
			continue
		}
		byKey[k] = p
		reqs = append(reqs, request{versionKey{k.System, k.Name, k.Version}})
	}
	if len(reqs) == 0 {
		return nil, nil
	}

	body, err := json.Marshal(struct {
		Requests []request `json:"requests"`
	}{reqs})
	if err != nil {
		return nil, fmt.Errorf("deps.dev: encoding the request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url(), strings.NewReader(string(body)))
	if err != nil {
		return nil, fmt.Errorf("deps.dev: building the request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("deps.dev: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("deps.dev: %s", resp.Status)
	}
	// Bounded, because an unbounded read of somebody else's endpoint is a memory-exhaustion bug
	// waiting for a bad day upstream. A hundred packages measured at roughly 350 KiB.
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, fmt.Errorf("deps.dev: reading the response: %w", err)
	}
	return decode(raw, byKey)
}

// endpointURL lets a test point the client at its own server.
func (c *Client) url() string {
	if c.Endpoint != "" {
		return c.Endpoint
	}
	return endpoint
}

// Parse turns a purl into the identifiers deps.dev wants, and reports whether it indexes that
// ecosystem at all.
//
// The name is everything between the type and the version, which for Go is a module path with
// slashes in it and for Maven is a group and an artifact the service joins with a colon.
func Parse(purl string) (key, bool) {
	rest, ok := strings.CutPrefix(strings.TrimSpace(purl), "pkg:")
	if !ok {
		return key{}, false
	}
	// Qualifiers and subpaths say where a package came from rather than which package it is.
	if i := strings.IndexAny(rest, "?#"); i >= 0 {
		rest = rest[:i]
	}
	typ, path, ok := strings.Cut(rest, "/")
	if !ok {
		return key{}, false
	}
	system, known := systems[strings.ToLower(typ)]
	if !known {
		return key{}, false
	}
	at := strings.LastIndex(path, "@")
	// A scoped npm name begins with @, which is not the version separator.
	if at <= 0 {
		return key{}, false
	}
	name, version := path[:at], path[at+1:]
	if name == "" || version == "" {
		return key{}, false
	}
	name, err := url.PathUnescape(name)
	if err != nil {
		return key{}, false
	}
	if system == "MAVEN" {
		// A purl carries the group as a namespace; deps.dev names the artifact group:artifact.
		if g, a, found := strings.Cut(name, "/"); found {
			name = g + ":" + a
		}
	}
	if v, err := url.PathUnescape(version); err == nil {
		version = v
	}
	return key{System: system, Name: name, Version: version}, true
}

// decode reads a batch response into what the ranking needs.
//
// The response nests three ways and only one of them is about the version that was asked for.
// `packageFindings` applies to every version of the package, which is how MALICIOUS arrives, and
// `recommendedVersions` is a suggestion rather than an instruction.
func decode(raw []byte, byKey map[key]string) (map[string]dephealth.Package, error) {
	type finding struct {
		Type              string `json:"type"`
		DeprecatedContext struct {
			Reason string `json:"reason"`
		} `json:"deprecatedContext"`
	}
	type versionKey struct {
		System, Name, Version string
	}
	type version struct {
		VersionKey versionKey `json:"versionKey"`
		Findings   []finding  `json:"findings"`
	}
	type result struct {
		RecommendedVersions []version `json:"recommendedVersions"`
		RequestedVersion    version   `json:"requestedVersion"`
		PackageFindings     []finding `json:"packageFindings"`
	}
	var body struct {
		Responses []struct {
			Request struct {
				VersionKey versionKey `json:"versionKey"`
			} `json:"request"`
			Findings result `json:"findings"`
		} `json:"responses"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, fmt.Errorf("deps.dev: reading the response: %w", err)
	}

	out := map[string]dephealth.Package{}
	for _, r := range body.Responses {
		k := key{r.Request.VersionKey.System, r.Request.VersionKey.Name, r.Request.VersionKey.Version}
		purl, asked := byKey[k]
		if !asked {
			continue // not something this batch requested
		}
		var pkg dephealth.Package
		for _, f := range append(r.Findings.PackageFindings, r.Findings.RequestedVersion.Findings...) {
			pkg.Findings = append(pkg.Findings, dephealth.Finding{
				Kind: f.Type, Reason: f.DeprecatedContext.Reason,
			})
		}
		// Only ever forwards. The service offered v1.5.1 against a deprecated v1.5.4, and a report
		// telling somebody to downgrade a working dependency is worse than one saying nothing.
		for _, rec := range r.Findings.RecommendedVersions {
			if newer, ok := dephealth.Newer(k.Version, rec.VersionKey.Version); ok && newer {
				pkg.Recommended = rec.VersionKey.Version
				break
			}
		}
		out[purl] = pkg
	}
	return out, nil
}
