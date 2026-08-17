package plugin

import (
	"slices"
	"strings"
)

// TargetKind identifies the sort of surface a scanner acts on.
type TargetKind string

// The kinds of target a scanner may accept.
const (
	TargetRepository TargetKind = "repository"
	TargetImage      TargetKind = "image"
	TargetHost       TargetKind = "host"
	TargetInfra      TargetKind = "infrastructure"
)

// Target is something a scanner can act on. Identity returns a stable string that
// uniquely identifies the target for cache keying (a commit, an image digest, a
// normalized endpoint) — two targets with the same Identity are considered the same
// scan input.
type Target interface {
	Kind() TargetKind
	Identity() string
}

// RepositoryTarget is a source repository at a revision, optionally scoped to part of its tree.
type RepositoryTarget struct {
	URL      string
	Revision string
	// Paths restricts the scan to these directories; the repository root is always included.
	Paths []string
	// Ignore removes matching paths, applied after Paths.
	Ignore []string
	// Remote is the repository this checkout came from, resolved from its git remote when URL is
	// a local path. Empty when URL is already remote, or when the checkout has no remote — a
	// repository that exists only on one machine is legitimate, and then the path is all there is.
	//
	// Set by the engine rather than by each controller, so a controller written next cannot
	// forget it.
	Remote string
	// WorkingTree scans the checkout as it is on disk, uncommitted work included, instead of the
	// committed revision. Set only by `draugr scan --working-tree`, and only meaningful for a
	// local path.
	//
	// It exists for the loop of fixing a finding — edit, scan, see whether it went away — which
	// otherwise needs a commit per iteration. The result is deliberately not reproducible, and
	// says so in the report.
	WorkingTree bool
}

// Kind returns TargetRepository.
func (RepositoryTarget) Kind() TargetKind { return TargetRepository }

// Identity returns the URL, revision and scope, e.g. "https://git/x@1.0".
//
// The scope belongs in the identity because it changes what is scanned. Two components pointing
// at different subtrees of one repository are two different scans; leaving the scope out gave
// them the same identity, so they shared a cache entry and collapsed into a single run whose
// findings both then received.
func (t RepositoryTarget) Identity() string {
	// Source rather than URL: credentials are how a repository is fetched, not which repository
	// it is. Including them would give two people scanning one repository different identities,
	// so they would miss each other's cache entries and appear as two sources in a report.
	id := t.Source() + "@" + t.Revision
	if t.WorkingTree {
		// A different scan input from the commit it sits on, and one whose content changes
		// between two runs at the same revision. Sharing an identity with the committed scan
		// would let one serve the other from cache.
		id += "+worktree"
	}
	if s := scopeKey(t.Paths, t.Ignore); s != "" {
		id += "#" + s
	}
	return id
}

// scopeKey renders a repository scope for an identity. Empty when nothing is restricted, so an
// unscoped target keeps the identity it always had.
func scopeKey(paths, ignore []string) string {
	if len(paths) == 0 && len(ignore) == 0 {
		return ""
	}
	return "paths=" + strings.Join(paths, ",") + ";ignore=" + strings.Join(ignore, ",")
}

// ImageTarget is a container image. Identity prefers the immutable digest.
type ImageTarget struct {
	Ref    string
	Digest string
	// BuiltUpstream marks an image this component runs and somebody else publishes, so a
	// package inside it is not the reader's to upgrade — the fix is a newer image.
	BuiltUpstream bool
}

// Kind returns TargetImage.
func (ImageTarget) Kind() TargetKind { return TargetImage }

// Identity returns the digest when set, otherwise the ref. Keying on the immutable digest
// makes the cache content-addressed: a rebuilt image under the same tag has a new digest and
// so a new key, while an unchanged image reuses its result.
func (t ImageTarget) Identity() string {
	if t.Digest != "" {
		return t.Digest
	}
	return t.Ref
}

// ContentAddressable is an optional interface a Target may implement to say whether its identity
// is its content. A target that does not implement it is treated as content-addressed, which is
// the honest default: a repository at a revision and a host at a URL both are.
//
// It exists because the cache's correctness rests on that property, and one target kind cannot
// guarantee it. Rather than let the engine keep a list of the kinds it should distrust — a list
// that goes stale the moment a target is added — the target says so itself.
type ContentAddressable interface {
	ContentAddressed() bool
}

// ContentAddressed reports whether a target's identity is its content, for targets that say.
func ContentAddressed(t Target) bool {
	ca, ok := t.(ContentAddressable)
	return !ok || ca.ContentAddressed()
}

// ContentAddressed reports whether this target's identity really is its content.
//
// It is when a digest is known, either declared or already written into the ref. A tag alone is
// not: `alpine:3.19` is a name someone can repoint at different bytes, so a cache entry keyed on
// it is right about the key and possibly wrong about the image.
//
// Draugr cannot tell the difference without asking the registry, which is a network call and a
// credential the run may not have. So the answer here is what the descriptor says, and a false
// means the result has to be reported as one that could not be content-addressed rather than
// quietly presented as though it had been.
func (t ImageTarget) ContentAddressed() bool {
	return t.Digest != "" || strings.Contains(t.Ref, "@")
}

// PinnedRef returns the reference a scanner should actually pull: the ref pinned to the
// digest (e.g. "repo:tag@sha256:…") when a digest is known, so the bytes scanned match the
// digest the result is cached under. The tag is kept for readable scanner output. Falls back
// to the ref alone (or a repo-less digest) when either part is missing or the ref is already
// digest-pinned.
func (t ImageTarget) PinnedRef() string {
	switch {
	case t.Digest == "":
		return t.Ref
	case t.Ref == "":
		return t.Digest
	case strings.Contains(t.Ref, "@"):
		return t.Ref
	default:
		return t.Ref + "@" + t.Digest
	}
}

// HostTarget is a running endpoint. Type is "browser" or "api".
type HostTarget struct {
	Name string
	URL  string
	Type string
	// Auth is how a scanner should authenticate to this endpoint, or nil to probe it anonymously.
	Auth *HostAuth
	// Spec drives the scan from an OpenAPI document instead of crawling, or nil to crawl.
	Spec *HostSpec
}

// HostSpec points a dynamic scan at an OpenAPI document, and says which methods it may exercise.
type HostSpec struct {
	// Path is the document, resolved relative to where Draugr runs.
	Path string
	// Methods are the HTTP methods to exercise. Empty means read-only.
	Methods []string
}

// ReadMethods are what a spec-driven scan exercises when the descriptor names none. A
// specification lists POST, PUT and DELETE too, and a scanner handed one will exercise them.
var ReadMethods = []string{"get", "head"}

// specMethods are the methods a spec-driven scan may be told to exercise.
var specMethods = []string{"get", "head", "options", "trace", "post", "put", "patch", "delete"}

// NormalizeMethods lower-cases, de-duplicates and orders a descriptor's method list, defaulting to
// read-only.
//
// Here rather than in the scanner because the cache key is built from it: "GET" and "get" describe
// the same scan, and a key telling them apart would re-run one having already answered the other.
func NormalizeMethods(methods []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(methods))
	for _, m := range methods {
		m = strings.ToLower(strings.TrimSpace(m))
		if m == "" || seen[m] || !slices.Contains(specMethods, m) {
			continue
		}
		seen[m] = true
		out = append(out, m)
	}
	if len(out) == 0 {
		return slices.Clone(ReadMethods)
	}
	slices.Sort(out)
	return out
}

// Marker describes a spec-driven scan without reading the document — the file, and the methods it
// may use. Safe for a cache key: two scans of one endpoint exercising different methods are not
// the same scan and must not share a result.
func (s *HostSpec) Marker() string {
	if s == nil {
		return ""
	}
	return "spec=" + s.Path + " methods=" + strings.Join(NormalizeMethods(s.Methods), ",")
}

// HostAuth says how to authenticate, and deliberately cannot say what the credential is.
//
// It carries the *name* of an environment variable, never a value. A descriptor is committed, so
// a token written into one is a leaked token — and the value must not reach a cache key, a report
// or a process list either. Resolution happens in the scanner, at the moment of the scan.
type HostAuth struct {
	// Kind is "bearer" (an Authorization: Bearer header) or "header" (a named header).
	Kind string
	// Header is the header name, for Kind "header".
	Header string
	// TokenEnv is the environment variable holding the credential.
	TokenEnv string
}

// Marker describes this authentication without disclosing it — the kind, the header it sets, and
// the variable it reads. Safe to put in a cache key or a report; there is nothing secret in it.
func (a *HostAuth) Marker() string {
	if a == nil {
		return ""
	}
	return "auth=" + a.Kind + ":" + a.Header + ":" + a.TokenEnv
}

// Kind returns TargetHost.
func (HostTarget) Kind() TargetKind { return TargetHost }

// Identity returns the host URL without credentials, plus a marker when the scan authenticates.
//
// Two different things are at play and only one is stripped. Credentials embedded in the URL are
// how a target is *reached* and not which target it is, so they go — same rule as a repository's.
// A declared `auth:` block is not that: an authenticated scan sees a different application from an
// anonymous one, and the two results are not interchangeable. Identity feeds the cache key, so
// leaving it out would let a scan run before the credential was configured answer for one run
// after.
//
// The marker names the variable rather than reading it. A variable name is not a secret; its
// value must never reach a cache key on disk.
func (t HostTarget) Identity() string {
	id := SourceURL(t.URL)
	for _, marker := range []string{t.Auth.Marker(), t.Spec.Marker()} {
		if marker != "" {
			id += " " + marker
		}
	}
	return id
}

// InfraTarget is an infrastructure surface (e.g. a Kubernetes cluster). Platform is the
// kind of infrastructure (e.g. "kubernetes"); Ref names the concrete instance.
type InfraTarget struct {
	Platform string
	Ref      string
	// Namespaces narrows the audit to part of the cluster. Empty means all of it.
	Namespaces []string
	// ProviderOperated says the surface is a managed service, so part of it is not reachable by
	// the team that owns the workloads on it. Carried from the descriptor, because a scanner
	// cannot see a support contract.
	ProviderOperated bool
}

// Kind returns TargetInfra.
func (InfraTarget) Kind() TargetKind { return TargetInfra }

// Identity returns the platform and ref, e.g. "kubernetes/prod".
// Identity names what was assessed, and therefore what a cached result may be reused for.
//
// The namespaces belong in it: two components auditing the same cluster with different scopes
// are asking different questions, and a cache keyed on the cluster alone would answer the second
// with the first one's findings.
func (t InfraTarget) Identity() string {
	id := t.Platform + "/" + t.Ref
	if len(t.Namespaces) == 0 {
		return id
	}
	ns := slices.Clone(t.Namespaces)
	slices.Sort(ns)
	return id + "[" + strings.Join(ns, ",") + "]"
}
