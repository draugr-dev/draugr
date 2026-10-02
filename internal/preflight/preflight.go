// Package preflight checks that this machine can reach what a scan would read: each repository at
// its revision, the paths a component is scoped to, each image, each endpoint. With the
// credentials and the network the scan would have, and before the scan is started.
//
// Every check touches something outside the descriptor, a checkout, a registry, a network or a
// credential, which is why it lives in `doctor` rather than `validate`.
package preflight

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/draugr-dev/draugr/internal/git"
	"github.com/draugr-dev/draugr/internal/registry"
	"github.com/draugr-dev/draugr/pkg/plugin"
)

// Status is how a check ended.
type Status string

// The ways a check ends. NotChecked is neither of the others: a check that did not run has not
// passed, and it has not found anything wrong either.
const (
	Passed     Status = "passed"
	Failed     Status = "failed"
	NotChecked Status = "not-checked"
)

// Check is one target checked, and what came of it.
type Check struct {
	// Kind is what was checked: repository, paths, image, host or cluster.
	Kind string `json:"kind"`
	// Target names it, without credentials.
	Target string `json:"target"`
	Status Status `json:"status"`
	// Detail is the result in words: what resolved, or why it failed or was not checked.
	Detail string `json:"detail"`
}

// Probes are the checks themselves. A nil field is the real probe; tests replace them.
type Probes struct {
	// Revision resolves a repository's revision to a commit.
	Revision func(ctx context.Context, url, revision string) (string, error)
	// Paths checks a repository's paths at a revision and returns the commit it read.
	Paths func(ctx context.Context, url, revision string, paths []string) (string, error)
	// Image checks that an image can be read, and says from where.
	Image func(ctx context.Context, ref string, offline bool) (string, error)
	// Host opens a connection to an endpoint and says what it established.
	Host func(ctx context.Context, rawURL string) (string, error)
	// Cluster resolves a kubeconfig context, "" for the current one, asks its API server for its
	// version, and says what answered.
	Cluster func(ctx context.Context, kubeContext string) (string, error)
}

// Options shape a run.
type Options struct {
	// Offline skips every check that needs the network, and reports each as not checked.
	Offline bool
	// Timeout bounds each target's checks. Zero means 20 seconds.
	Timeout time.Duration
	// Concurrency bounds how many targets are checked at once. Zero means 8.
	Concurrency int
	Probes      Probes
}

// offlineReason is what a network check reports when --offline stopped it.
const offlineReason = "--offline"

// Run checks every distinct target once, in the order they are first named. Components sharing a
// repository or an image share its check.
func Run(ctx context.Context, targets []plugin.Target, opts Options) []Check {
	p := opts.Probes.withDefaults()
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	workers := opts.Concurrency
	if workers <= 0 {
		workers = 8
	}

	var units []func(context.Context) []Check
	repos := map[string]*repoUnit{}
	seen := map[string]bool{}
	for _, t := range targets {
		switch t := t.(type) {
		case plugin.RepositoryTarget:
			key := t.URL + "@" + t.Revision
			u, ok := repos[key]
			if !ok {
				u = &repoUnit{target: t, seen: map[string]bool{}}
				repos[key] = u
				units = append(units, func(ctx context.Context) []Check { return u.run(ctx, p, opts.Offline) })
			}
			if keep := git.Selected(t.Paths); keep != nil {
				if k := strings.Join(keep, "\x00"); !u.seen[k] {
					u.seen[k] = true
					u.paths = append(u.paths, keep)
				}
			}
		case plugin.ImageTarget:
			ref := t.PinnedRef()
			if seen["image:"+ref] {
				continue
			}
			seen["image:"+ref] = true
			units = append(units, func(ctx context.Context) []Check {
				return []Check{imageCheck(ctx, p, ref, opts.Offline)}
			})
		case plugin.HostTarget:
			u := plugin.SourceURL(t.URL)
			if seen["host:"+u] {
				continue
			}
			seen["host:"+u] = true
			raw := t.URL
			units = append(units, func(ctx context.Context) []Check {
				return []Check{hostCheck(ctx, p, raw, u, opts.Offline)}
			})
		case plugin.KubernetesTarget:
			// Once per cluster and context, however many components use it or how they scope it:
			// the namespaces narrow an audit, and reaching the cluster is the same question for all.
			key := "cluster:" + t.Cluster + "@" + t.Context
			if seen[key] {
				continue
			}
			seen[key] = true
			name, kubeCtx := t.Cluster, t.Context
			units = append(units, func(ctx context.Context) []Check {
				return []Check{clusterCheck(ctx, p, name, kubeCtx, opts.Offline)}
			})
		default:
			id := string(t.Kind()) + ":" + t.Identity()
			if seen[id] {
				continue
			}
			seen[id] = true
			units = append(units, func(context.Context) []Check {
				return []Check{{Kind: string(t.Kind()), Target: t.Identity(), Status: NotChecked,
					Detail: "doctor has no reachability check for this kind of target"}}
			})
		}
	}

	results := make([][]Check, len(units))
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for i, unit := range units {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer func() { <-sem; wg.Done() }()
			uctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			results[i] = unit(uctx)
		}()
	}
	wg.Wait()

	// Grouped by kind, in the order a scan meets them, and in the order they were named within one.
	// The planner visits controls by name, which would interleave hosts with repositories.
	var out []Check
	for _, kind := range kindOrder {
		for _, r := range results {
			if len(r) > 0 && r[0].Kind == kind {
				out = append(out, r...)
			}
		}
	}
	for _, r := range results {
		if len(r) > 0 && !slices.Contains(kindOrder, r[0].Kind) {
			out = append(out, r...)
		}
	}
	return out
}

// kindOrder is the order checks are listed in. A repository's paths follow it.
var kindOrder = []string{"repository", "image", "host"}

// FailedCount counts the checks that failed.
func FailedCount(checks []Check) int {
	n := 0
	for _, c := range checks {
		if c.Status == Failed {
			n++
		}
	}
	return n
}

// repoUnit is one repository at one revision, and every distinct set of paths components scope it
// to.
type repoUnit struct {
	target plugin.RepositoryTarget
	paths  [][]string
	seen   map[string]bool
}

func (u *repoUnit) run(ctx context.Context, p Probes, offline bool) []Check {
	t := u.target
	name := plugin.SourceURL(t.URL)
	if t.Revision != "" {
		name += "@" + t.Revision
	}
	ref := Check{Kind: "repository", Target: name}
	pathChecks := make([]Check, len(u.paths))
	for i, keep := range u.paths {
		pathChecks[i] = Check{Kind: "paths", Target: strings.Join(keep, ", ")}
	}
	notChecked := func(reason string) []Check {
		for i := range pathChecks {
			pathChecks[i].Status, pathChecks[i].Detail = NotChecked, reason
		}
		return append([]Check{ref}, pathChecks...)
	}

	if offline && !git.IsLocalPath(t.URL) {
		ref.Status, ref.Detail = NotChecked, offlineReason
		return notChecked(offlineReason)
	}
	commit, err := p.Revision(ctx, t.URL, t.Revision)
	if err != nil {
		ref.Status, ref.Detail = Failed, reason(err, t.URL)
		return notChecked("the revision did not resolve")
	}
	ref.Status, ref.Detail = Passed, "resolves to "+git.ShortRevision(commit)
	if git.IsCommitSHA(t.Revision) {
		// A full commit name resolves to itself without asking anybody, so whether the repository
		// holds it is a separate question.
		if _, err := p.Paths(ctx, t.URL, commit, nil); err != nil {
			ref.Status, ref.Detail = Failed, reason(err, t.URL)
			return notChecked("the revision did not resolve")
		}
		ref.Detail = "commit exists"
	}

	for i, keep := range u.paths {
		// The commit just resolved rather than the name, so every set of paths is read from the
		// one tree, whatever the branch does in between.
		read, err := p.Paths(ctx, t.URL, commit, keep)
		if err != nil {
			pathChecks[i].Status, pathChecks[i].Detail = Failed, reason(err, t.URL)
			continue
		}
		pathChecks[i].Status, pathChecks[i].Detail = Passed, "in the tree at "+git.ShortRevision(read)
	}
	return append([]Check{ref}, pathChecks...)
}

func imageCheck(ctx context.Context, p Probes, ref string, offline bool) Check {
	c := Check{Kind: "image", Target: ref}
	detail, err := p.Image(ctx, ref, offline)
	switch {
	case errors.Is(err, errNotChecked):
		c.Status, c.Detail = NotChecked, offlineReason
	case err != nil:
		c.Status, c.Detail = Failed, reason(err, "")
	default:
		c.Status, c.Detail = Passed, detail
	}
	return c
}

func hostCheck(ctx context.Context, p Probes, raw, name string, offline bool) Check {
	c := Check{Kind: "host", Target: name}
	if offline {
		c.Status, c.Detail = NotChecked, offlineReason
		return c
	}
	detail, err := p.Host(ctx, raw)
	if err != nil {
		c.Status, c.Detail = Failed, reason(err, raw)
		return c
	}
	c.Status, c.Detail = Passed, detail
	return c
}

func clusterCheck(ctx context.Context, p Probes, name, kubeCtx string, offline bool) Check {
	target := "kubernetes/" + name
	if name == "" {
		target = "kubernetes"
	}
	c := Check{Kind: "cluster", Target: target}
	if offline {
		c.Status, c.Detail = NotChecked, offlineReason
		return c
	}
	detail, err := p.Cluster(ctx, kubeCtx)
	if err != nil {
		c.Status, c.Detail = Failed, err.Error()
		return c
	}
	c.Status, c.Detail = Passed, detail
	return c
}

// errNotChecked is an image probe declining to go to the network under --offline.
var errNotChecked = errors.New("not checked")

func (p Probes) withDefaults() Probes {
	if p.Revision == nil {
		p.Revision = git.ResolveRevision
	}
	if p.Paths == nil {
		p.Paths = git.PathsAt
	}
	if p.Image == nil {
		client := &registry.Client{}
		p.Image = func(ctx context.Context, ref string, offline bool) (string, error) {
			return probeImage(ctx, ref, offline, localImage, client.Check)
		}
	}
	if p.Host == nil {
		p.Host = dialHost
	}
	if p.Cluster == nil {
		p.Cluster = reachCluster
	}
	return p
}

// probeImage looks for the image in the local Docker daemon first and asks its registry second, the
// order Trivy and Grype read an image in. An image built on this machine and never pushed is one a
// scan here can read.
func probeImage(ctx context.Context, ref string, offline bool,
	local func(context.Context, string) bool, remote func(context.Context, string) error,
) (string, error) {
	if local(ctx, ref) {
		return "in the local Docker daemon", nil
	}
	if offline {
		return "", errNotChecked
	}
	if err := remote(ctx, ref); err != nil {
		return "", err
	}
	return "manifest readable", nil
}

// localImage reports whether the local Docker daemon holds ref. No daemon, or no docker, is a no.
func localImage(ctx context.Context, ref string) bool {
	if _, err := exec.LookPath("docker"); err != nil {
		return false
	}
	return exec.CommandContext(ctx, "docker", "image", "inspect", "--format", "{{.Id}}", ref).Run() == nil // #nosec G204 -- the descriptor's own image reference, passed as one argument
}

// dialHost opens a TCP connection to an endpoint, completing the TLS handshake for https, and
// sends nothing else. Anything a scanner would send is traffic its control declares and asks
// approval for.
func dialHost(ctx context.Context, raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("not a URL: %w", err)
	}
	port := u.Port()
	if port == "" {
		port = map[string]string{"https": "443", "http": "80"}[u.Scheme]
	}
	if u.Hostname() == "" || port == "" {
		return "", fmt.Errorf("names no host and port to connect to")
	}
	addr := net.JoinHostPort(u.Hostname(), port)

	if u.Scheme != "https" {
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
		if err != nil {
			return "", err
		}
		_ = conn.Close()
		return "connects", nil
	}
	d := &tls.Dialer{Config: &tls.Config{ServerName: u.Hostname(), MinVersion: tls.VersionTLS12}}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err == nil {
		_ = conn.Close()
		return "TLS handshake completes", nil
	}
	var cert *tls.CertificateVerificationError
	if !errors.As(err, &cert) {
		return "", err
	}
	// Reachable, with a certificate this machine does not trust. The scanners that probe an
	// endpoint do not verify it either, so the scan will run; the reader should still know.
	return "connects, certificate not trusted: " + cert.Err.Error(), nil
}

// userinfo matches the credentials in a URL.
var userinfo = regexp.MustCompile(`://[^/@\s]+@`)

// reason turns an error into the detail a check shows: its first line, with the fetch URL replaced
// by its credential-free form. git and the registry both repeat the URL they were given, and a CI
// clone URL carries a token.
func reason(err error, rawURL string) string {
	// The innermost cause a reader can act on: "lookup x: no such host" rather than the request
	// that failed and the dialer that failed inside it.
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	var dns *net.DNSError
	if errors.As(err, &dns) {
		return "lookup " + dns.Name + ": " + dns.Err
	}
	var op *net.OpError
	if errors.As(err, &op) && op.Err != nil {
		err = op.Err
	}
	msg := err.Error()
	var exit *exec.ExitError
	if errors.As(err, &exit) && len(exit.Stderr) > 0 {
		msg = string(exit.Stderr)
	}
	if rawURL != "" {
		msg = strings.ReplaceAll(msg, rawURL, plugin.SourceURL(rawURL))
	}
	msg = userinfo.ReplaceAllString(msg, "://")
	if errors.Is(err, context.DeadlineExceeded) {
		return "no answer before the timeout"
	}
	line, _, _ := strings.Cut(strings.TrimSpace(msg), "\n")
	return strings.TrimPrefix(line, "fatal: ")
}
