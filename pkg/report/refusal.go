package report

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/draugr-dev/draugr/internal/english"
	"github.com/draugr-dev/draugr/internal/registry"
	"github.com/draugr-dev/draugr/pkg/engine"
)

// refusal is a registry declining to serve an image to the machine that ran the scan, in the words
// `draugr doctor` uses for the same answer.
type refusal struct {
	// host is the registry as a reader types it after `docker login`.
	host string
	// said is the registry's answer without the host: "401 unauthorized, no credential".
	said string
	// login is whether logging in is what changes the answer: no credential at all, or one the
	// registry did not accept.
	login bool
}

// registryRefusal reports whether a target is an image its registry refused to serve, and the
// refusal when it is. The run decided both, and whether this machine held a credential, where it
// ran; this only words it.
func registryRefusal(t engine.TargetOutcome) (refusal, bool) {
	r := t.Refusal
	if r == nil || t.Kind != "image" {
		return refusal{}, false
	}
	anonymous := r.Credential != nil && !*r.Credential
	said := (&registry.StatusError{Code: r.Status, Host: r.Registry, Anonymous: anonymous}).Error()
	said = strings.TrimSuffix(said, " for "+r.Registry)
	return refusal{host: r.Registry, said: said, login: anonymous || r.Status == http.StatusUnauthorized}, true
}

// loginCommand is the command that stores a credential for host where the scanners read it.
func loginCommand(host string) string {
	if host == "docker.io" {
		return "docker login"
	}
	return "docker login " + host
}

// refusedGroup is the images one registry refused, for the same reason.
type refusedGroup struct {
	refusal
	images []engine.TargetOutcome
}

// byRegistry divides targets no scanner could read into the images a registry refused, grouped by
// registry and its answer in the order each registry first appears, and the rest.
func byRegistry(missed []engine.TargetOutcome) (groups []*refusedGroup, rest []engine.TargetOutcome) {
	for _, m := range missed {
		r, ok := registryRefusal(m)
		if !ok {
			rest = append(rest, m)
			continue
		}
		var g *refusedGroup
		for _, x := range groups {
			if x.refusal == r {
				g = x
				break
			}
		}
		if g == nil {
			g = &refusedGroup{refusal: r}
			groups = append(groups, g)
		}
		g.images = append(g.images, m)
	}
	return groups, rest
}

// htmlUnreachedTargets names the targets no scanner could read as the console's errors block names
// them, every one of them, with the count the block's heading gives. A page has no terminal to fit,
// so nothing is capped; a digest is still shortened, with the whole reference behind it.
func htmlUnreachedTargets(d Data) (regs []htmlRegistry, rest []htmlUnreached, count string) {
	missed := notReached(d)
	if len(missed) == 0 {
		return nil, nil, ""
	}
	groups, others := byRegistry(missed)
	for _, g := range groups {
		r := htmlRegistry{Host: g.host, Said: g.said}
		if g.login {
			r.Login = loginCommand(g.host)
		}
		for _, m := range g.images {
			r.Images = append(r.Images, htmlUnreached{Kind: m.Kind, Name: inRegistry(m.Target, g.host), Full: m.Target,
				Components: componentsLabel(m.Components)})
		}
		regs = append(regs, r)
	}
	for _, m := range others {
		rest = append(rest, htmlUnreached{Kind: m.Kind, Name: shownTarget(m.Kind, m.Target), Full: m.Target,
			Components: componentsLabel(m.Components), Why: shortReason(m.Detail, whyWidth)})
	}
	return regs, rest, fmt.Sprintf("%d of %s not reached", len(missed), english.Count(len(d.Run.Targets), "target"))
}

// inRegistry is an image as it is named under its registry's heading: the repository, tag and
// shortened digest, without the host the heading already gives.
func inRegistry(target, host string) string {
	name := shownTarget("image", target)
	prefixes := []string{host + "/"}
	if host == "docker.io" {
		prefixes = append(prefixes, "index.docker.io/", "registry-1.docker.io/")
	}
	for _, prefix := range prefixes {
		if after, ok := strings.CutPrefix(name, prefix); ok {
			return after
		}
	}
	return name
}

// shownTarget is a target as a row names it, an image's digest shortened. --format json keeps the
// whole digest.
func shownTarget(kind, target string) string {
	if kind != "image" {
		return target
	}
	return registry.ShortDigest(target)
}
