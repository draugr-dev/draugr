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
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/draugr-dev/draugr/internal/git"
	"github.com/draugr-dev/draugr/internal/registry"
	"github.com/draugr-dev/draugr/internal/scanners"
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
	// Kind is what was checked: repository, paths, image, host, cluster or account.
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
	// Account asks a cloud whether the credentials in the environment can read an account, and
	// says what answered.
	Account func(ctx context.Context, provider, id string) (string, error)
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
		case plugin.AccountTarget:
			// Once per account, however many components name it or which regions they claim.
			key := "account:" + t.Provider + "/" + t.ID
			if seen[key] {
				continue
			}
			seen[key] = true
			provider, id := t.Provider, t.ID
			units = append(units, func(ctx context.Context) []Check {
				return []Check{accountCheck(ctx, p, provider, id, opts.Offline)}
			})
		case plugin.FileTarget:
			if t.Source != "" {
				// A service's alerts: whether the token is there to send. The alerts themselves are
				// read by the scan, which names what GitHub refused.
				key := "source:" + t.Identity() + ":" + t.TokenEnv
				if seen[key] {
					continue
				}
				seen[key] = true
				target := t
				units = append(units, func(context.Context) []Check { return []Check{sourceCheck(target)} })
				continue
			}
			// A file read in place: whether it is there, reads as its format, and is the commit's the
			// scan holds it to. Once per file, format and what binds it, as one file imported twice is
			// read by each import's reader, and two components can hold it to two repositories.
			key := "file:" + t.Format + ":" + t.Path + ":" + t.Component + ":" + t.Commit + ":" + t.CommitUnset
			if t.Converter != nil {
				key += ":" + t.Converter.Name + ":" + strings.Join(t.Converter.Sets, ",")
			}
			if seen[key] {
				continue
			}
			seen[key] = true
			target := t
			units = append(units, func(ctx context.Context) []Check { return []Check{fileCheck(ctx, p, target, opts.Offline)} })
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

func accountCheck(ctx context.Context, p Probes, provider, id string, offline bool) Check {
	c := Check{Kind: "account", Target: provider + "/" + id}
	if offline {
		c.Status, c.Detail = NotChecked, offlineReason
		return c
	}
	detail, err := p.Account(ctx, provider, id)
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
			return probeImage(ctx, ref, offline, LocalImage, client.Check)
		}
	}
	if p.Host == nil {
		p.Host = dialHost
	}
	if p.Cluster == nil {
		p.Cluster = reachCluster
	}
	if p.Account == nil {
		p.Account = reachAccount
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

// LocalImage reports whether the local Docker daemon holds ref. No daemon, or no docker, is a no.
func LocalImage(ctx context.Context, ref string) bool {
	held, _ := LookInDaemon(ctx, ref)
	return held
}

// LookInDaemon asks the local Docker daemon whether it holds ref, and says whether any daemon
// answered. With docker on PATH the CLI asks, so its context and DOCKER_HOST apply. Without it the
// daemon's API is asked on its socket, the way Trivy reads an image from a daemon in a container
// with the socket mounted and no docker CLI installed.
//
// reachable is false only when no daemon answered where one is looked for. A daemon that cannot be
// asked from here, such as one behind TLS with no docker CLI to hold its certificates, counts as
// reachable, so a refusal is never blamed on a daemon that may well be there.
func LookInDaemon(ctx context.Context, ref string) (held, reachable bool) {
	return daemonProbe{lookPath: exec.LookPath, run: runQuiet, getenv: os.Getenv, api: daemonAPI}.look(ctx, ref)
}

// daemonProbe is LookInDaemon with what it runs and reads passed in, so each answer can be tested
// without a daemon.
type daemonProbe struct {
	lookPath func(string) (string, error)
	run      func(ctx context.Context, args ...string) error
	getenv   func(string) string
	// api sends a GET to the daemon at host (DOCKER_HOST's form) and returns the status.
	api func(ctx context.Context, host, path string) (int, error)
}

func (p daemonProbe) look(ctx context.Context, ref string) (held, reachable bool) {
	if _, err := p.lookPath("docker"); err == nil {
		if p.run(ctx, "docker", "image", "inspect", "--format", "{{.Id}}", ref) == nil {
			return true, true
		}
		// `docker version` exits non-zero when no daemon answers, and prints the server's
		// version when one does.
		return false, p.run(ctx, "docker", "version", "--format", "{{.Server.Version}}") == nil
	}
	host := p.getenv("DOCKER_HOST")
	if host == "" {
		host = "unix:///var/run/docker.sock"
	}
	if strings.HasPrefix(host, "tcp://") && (p.getenv("DOCKER_TLS_VERIFY") != "" || p.getenv("DOCKER_CERT_PATH") != "") {
		return false, true
	}
	if !strings.HasPrefix(host, "unix://") && !strings.HasPrefix(host, "tcp://") {
		return false, true
	}
	if code, err := p.api(ctx, host, "/_ping"); err != nil || code != http.StatusOK {
		return false, false
	}
	code, err := p.api(ctx, host, "/images/"+ref+"/json")
	return err == nil && code == http.StatusOK, true
}

// runQuiet runs a command and reports only whether it succeeded.
func runQuiet(ctx context.Context, args ...string) error {
	return exec.CommandContext(ctx, args[0], args[1:]...).Run() // #nosec G204 -- docker, with the descriptor's own image reference as one argument
}

// daemonAPI sends a GET to the Docker daemon's API at host, a unix:// socket or a plain tcp://
// address, and returns the status. Two seconds is long for a socket on this machine and short
// enough that a scan's account of its targets does not wait on a daemon that never answers.
func daemonAPI(ctx context.Context, host, path string) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	base := "http://docker"
	transport := &http.Transport{}
	if sock, ok := strings.CutPrefix(host, "unix://"); ok {
		transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		}
	} else {
		base = "http://" + strings.TrimPrefix(host, "tcp://")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
	if err != nil {
		return 0, err
	}
	resp, err := (&http.Client{Transport: transport}).Do(req)
	if err != nil {
		return 0, err
	}
	_ = resp.Body.Close()
	return resp.StatusCode, nil
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

// sourceCheck is whether an import of a service's alerts has a token to send: the variable it names is
// one it may read, and is set. The scan stops on either, so the preflight says so first.
func sourceCheck(t plugin.FileTarget) Check {
	// "alerts" rather than the target's kind, file: what is read is a service's alerts, not a file.
	c := Check{Kind: "alerts", Target: t.Identity()}
	detail, ok := scanners.SourceCheck(t)
	c.Status, c.Detail = Failed, detail
	if ok {
		c.Status = Passed
	}
	return c
}

// fileCheck is whether an imported file is there to read, whether it is the format the import names,
// SARIF 2.1.0 where it names none, and whether it was written for the commit the scan reads, from its
// own provenance or the descriptor's commit: the scan stops on each, so the preflight says so first.
//
// The commit is worked out by the scan's own rule, so a file it would refuse fails here in its words
// and a file nothing binds is reported as the scan reports it. Under --offline a revision that only
// the network can resolve is not resolved, and the check says the commit was not checked.
func fileCheck(ctx context.Context, p Probes, t plugin.FileTarget, offline bool) Check {
	c := Check{Kind: string(plugin.TargetFile), Target: t.Path}
	if t.Component != "" {
		// One file imported by two components is checked for each, against its own repositories.
		c.Target += " · " + t.Component
	}
	data, err := os.ReadFile(t.Path) // #nosec G304 -- a file the descriptor names for import
	if err != nil {
		c.Status, c.Detail = Failed, err.Error()
		return c
	}
	resolve := func(ctx context.Context, url, revision string) (string, error) {
		if offline && !git.IsLocalPath(url) && !git.IsCommitSHA(revision) {
			return "", errNotChecked
		}
		return p.Revision(ctx, url, revision)
	}
	detail, err := scanners.DescribeBound(ctx, data, t, resolve)
	if errors.Is(err, errNotChecked) {
		// The file read; only its commit is left, and that needs the network.
		detail, err = scanners.DescribeFile(data, t)
		if err == nil {
			c.Status, c.Detail = NotChecked, detail+", commit not checked under "+offlineReason
			return c
		}
	}
	if err != nil {
		// The scan's message opens with the file, which the row already names.
		c.Status, c.Detail = Failed, strings.TrimPrefix(err.Error(), t.Path+": ")
		return c
	}
	c.Status, c.Detail = Passed, detail
	return c
}
