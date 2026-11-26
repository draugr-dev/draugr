package plugin

import (
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// TargetKind identifies the sort of surface a scanner acts on.
type TargetKind string

// The kinds of target a scanner may accept.
const (
	TargetRepository TargetKind = "repository"
	TargetImage      TargetKind = "image"
	TargetHost       TargetKind = "host"
	TargetKubernetes TargetKind = "kubernetes"
	TargetAccount    TargetKind = "account"
	TargetFile       TargetKind = "file"
)

// Target is something a scanner can act on. Identity returns a stable string that uniquely
// identifies the target for cache keying (a commit, an image digest, a normalized endpoint), two
// targets with the same Identity are considered the same scan input.
type Target interface {
	Kind() TargetKind
	Identity() string
}

// RepositoryTarget is a source repository at a revision, optionally scoped to part of its tree.
type RepositoryTarget struct {
	URL      string
	Revision string
	// Paths restricts the scan to these directories and files. A root file is in scope only when
	// an entry names it, apart from the scanners' own configuration.
	Paths []string
	// Ignore removes matching paths, applied after Paths.
	Ignore []string
	// Remote is the repository this checkout came from, resolved from its git remote when URL is a
	// local path. Empty when URL is already remote, or when the checkout has no remote, a repository
	// that exists only on one machine is legitimate, and then the path is all there is.
	//
	// Set by the engine rather than by each controller, so a controller written next cannot
	// forget it.
	Remote string
	// Upstream marks a repository this component uses and somebody else publishes, so a finding
	// inside it is not the reader's to fix where it is, a denied license in its dependency tree is
	// not one they chose, and telling them to change the code is advice they cannot take.
	Upstream bool
	// WorkingTree scans the checkout as it is on disk, uncommitted work included, instead of the
	// committed revision. Set only by `draugr scan --working-tree`, and only meaningful for a
	// local path.
	//
	// It exists for the loop of fixing a finding, edit, scan, see whether it went away. Which
	// otherwise needs a commit per iteration. The result is deliberately not reproducible, and says
	// so in the report.
	WorkingTree bool
	// Entry is where a call-graph analysis of a widened target starts: the paths the component
	// itself declares, inside the modules Paths was widened to. Empty for a target nobody widened.
	//
	// Not part of the identity, which says what is checked out. Components carved out of one
	// module share that checkout, and each is analyzed from its own code, so Entry is part of the
	// cache and dedupe key instead (see CacheDetail).
	Entry []string
}

// Kind returns TargetRepository.
func (RepositoryTarget) Kind() TargetKind { return TargetRepository }

// CacheDetail is where a call-graph analysis starts, for a target that names one. Two components
// sharing a widened checkout are two analyses, and the one that calls a function must not answer
// for the one that does not. Empty for every other target, so their keys are the ones they had.
func (t RepositoryTarget) CacheDetail() string {
	if len(t.Entry) == 0 {
		return ""
	}
	entry := slices.Clone(t.Entry)
	slices.Sort(entry)
	return "entry=" + strings.Join(entry, ",")
}

// Identity returns the URL, revision and scope, e.g. "https://git/x@1.0".
//
// The scope belongs in the identity because it changes what is scanned. Two components pointing
// at different subtrees of one repository are two different scans. Without the scope they would
// share an identity, and with it a cache entry and a single run whose findings both receive.
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

// Pinned reports whether this target's revision names one commit for good.
//
// A branch or a tag is a name for whatever it points at now, and an empty revision is the same
// problem with nothing written down. Anything that has to stay true across runs, a cache entry
// above all, is keyed on a moving name only if somebody resolves it first.
func (t RepositoryTarget) Pinned() bool { return commitSHA.MatchString(t.Revision) }

// commitSHA matches a full 40-character object name.
var commitSHA = regexp.MustCompile(`^[0-9a-f]{40}$`)

// BuiltUpstream reports who publishes this repository.
func (t RepositoryTarget) BuiltUpstream() bool { return t.Upstream }

// scopeKey renders a repository scope for an identity. Empty when nothing is restricted, so an
// unscoped target keeps the identity it always had.
func scopeKey(paths, ignore []string) string {
	if len(paths) == 0 && len(ignore) == 0 {
		return ""
	}
	return "paths=" + strings.Join(paths, ",") + ";ignore=" + strings.Join(ignore, ",")
}

// UpstreamPublished is an optional interface a Target implements when the descriptor may declare
// that somebody else publishes it.
//
// An interface rather than a field on every target, because it is not true of every kind: a host
// is somebody's endpoint and a cluster has `operatedBy`, which answers the same question in the
// vocabulary that surface uses. The engine asks; a target that cannot answer is the reader's own.
type UpstreamPublished interface {
	// BuiltUpstream reports whether somebody else publishes this target, so a finding inside it
	// is not the reader's to fix where it is.
	BuiltUpstream() bool
}

// ImageTarget is a container image. Identity prefers the immutable digest.
type ImageTarget struct {
	Ref    string
	Digest string
	// Upstream marks an image this component runs and somebody else publishes, so a package inside it
	// is not the reader's to upgrade. The fix is a newer image.
	Upstream bool
}

// BuiltUpstream reports who publishes this image.
func (t ImageTarget) BuiltUpstream() bool { return t.Upstream }

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
// guarantee it. Rather than let the engine keep a list of the kinds it should distrust. A list
// that goes stale the moment a target is added. The target says so itself.
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
	// Environment is which environment this endpoint is in, or "" when the descriptor did not say.
	Environment string
	// CertificateReported says another job in the same run verifies this endpoint's certificate and
	// reports a failure as a finding: a control whose ControllerInfo.VerifiesCertificates is set
	// planned a job for the same URL in the same component. Set by the engine after planning.
	//
	// A scanner that only reads what the endpoint answers, and sends it nothing secret, may then read
	// it over a certificate that fails verification, rather than ending in an error about a fact the
	// run already reports with its fix.
	CertificateReported bool
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

// Marker describes a spec-driven scan without reading the document, the file, and the methods it
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
// It carries the *name* of an environment variable, never a value. A descriptor is committed, so a
// token written into one is a leaked token. And the value must not reach a cache key, a report or
// a process list either. Resolution happens in the scanner, at the moment of the scan.
type HostAuth struct {
	// Kind is "bearer" (an Authorization: Bearer header) or "header" (a named header).
	Kind string
	// Header is the header name, for Kind "header".
	Header string
	// TokenEnv is the environment variable holding the credential.
	TokenEnv string
}

// Marker describes this authentication without disclosing it, the kind, the header it sets, and
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
// how a target is *reached* and not which target it is, so they go, same rule as a repository's. A
// declared `auth:` block is not that: an authenticated scan sees a different application from an
// anonymous one, and the two results are not interchangeable. Identity feeds the cache key, so
// leaving it out would let a scan run before the credential was configured answer for one run
// after.
//
// The marker names the variable rather than reading it. A variable name is not a secret; its
// value must never reach a cache key on disk.
//
// CertificateReported is marked too: a scan that may read past a failed certificate can answer
// where one that may not ends in an error, so the two do not share a cached result.
func (t HostTarget) Identity() string {
	id := SourceURL(t.URL)
	certificate := ""
	if t.CertificateReported {
		certificate = "certificate=reported"
	}
	for _, marker := range []string{t.Auth.Marker(), t.Spec.Marker(), certificate} {
		if marker != "" {
			id += " " + marker
		}
	}
	return id
}

// KubernetesTarget is a Kubernetes cluster, as the descriptor's `clusters:` declares it.
type KubernetesTarget struct {
	// Cluster is the cluster's name in the descriptor, which reports and identities use.
	Cluster string
	// Context is the kubeconfig context that reaches the cluster, or "" for the current one.
	Context string
	// Namespaces narrows the audit to part of the cluster. Empty means all of it.
	Namespaces []string
	// Benchmark and Version select the CIS benchmark a tool audits against, for a tool that takes
	// one. Empty lets the tool choose from the cluster.
	Benchmark, Version string
	// ProviderOperated says the surface is a managed service, so part of it is not reachable by
	// the team that owns the workloads on it. Carried from the descriptor, because a scanner
	// cannot see a support contract.
	ProviderOperated bool
	// Environment is which environment this surface is in, or "" when the descriptor did not say.
	Environment string
}

// Kind returns TargetKubernetes.
func (KubernetesTarget) Kind() TargetKind { return TargetKubernetes }

// Identity returns the cluster's name and scope, e.g. "kubernetes/prod[payments]".
//
// The namespaces belong in it: two components auditing the same cluster with different scopes
// are asking different questions, and a cache keyed on the cluster alone would answer the second
// with the first one's findings. The context and the benchmark do not: they decide the result too,
// and CacheDetail carries them into the cache key, but the identity is what a report shows and it
// stays the same on a machine whose contexts are named differently.
func (t KubernetesTarget) Identity() string {
	id := "kubernetes/" + t.Cluster
	if len(t.Namespaces) == 0 {
		return id
	}
	ns := slices.Clone(t.Namespaces)
	slices.Sort(ns)
	return id + "[" + strings.Join(ns, ",") + "]"
}

// CacheDetail is what decides a cluster's result beyond its identity: the context that reached
// it and the benchmark it was measured against. Part of the cache and dedupe key, so a run
// through another context, or against another benchmark, is never answered with an earlier one.
func (t KubernetesTarget) CacheDetail() string {
	return "context=" + t.Context + ";benchmark=" + t.Benchmark + ";version=" + t.Version
}

// AccountTarget is a cloud account, as the descriptor's `accounts:` declares it.
type AccountTarget struct {
	// Account is the account's name in the descriptor.
	Account string
	// Provider is the cloud, "gcp", "aws" or "azure", and ID the account's identifier there: a project
	// ID on Google Cloud, a 12-digit account ID on AWS, a subscription's GUID on Azure.
	Provider, ID string
	// Regions narrows the findings to resources in these regions. Empty means all of the account.
	Regions []string
}

// Kind returns TargetAccount.
func (AccountTarget) Kind() TargetKind { return TargetAccount }

// Identity returns the provider, the account's ID and the regions, e.g.
// "gcp/shop-prod-4821[us-central1]".
//
// The provider's ID rather than the descriptor's name: the ID is what a scan reads and what a
// cached result was read from, and two descriptors naming one project differently are one account.
// The regions belong in it for the reason a cluster's namespaces do.
func (t AccountTarget) Identity() string {
	id := t.Provider + "/" + t.ID
	if len(t.Regions) == 0 {
		return id
	}
	regions := slices.Clone(t.Regions)
	slices.Sort(regions)
	return id + "[" + strings.Join(regions, ",") + "]"
}

// CacheDetailer is an optional interface a Target implements when something other than its
// identity decides what a scan of it returns.
type CacheDetailer interface {
	CacheDetail() string
}

// ImportScanner is the scanner that reads a file another tool wrote, the one every import is
// planned for. The name is sarif's, which reads it to tell an imported finding from a native one
// (sarif.Result.Reporter).
const ImportScanner = sarif.ImportScanner

// FileTarget is a file another tool wrote, read in place of running a scanner: a SARIF file, or a
// tool's own JSON, a component imports.
type FileTarget struct {
	// Path is the file, relative to where Draugr runs.
	Path string
	// Component is the component that imports it, which a caveat about the file names.
	Component string
	// Digest is the SHA-256 of the file when the run was planned, empty when it could not be read.
	// Part of the cache key, so a file rewritten under the same name is read again rather than
	// answered with what the old one said.
	Digest string
	// Repositories are the component's repositories, which the file has to describe: one that
	// states the revision it scanned is held to the revision this run reads. Each carries its paths
	// and ignore, which leave out of the component a finding placed in it whose file they exclude.
	Repositories []RepositoryTarget
	// Severity is the descriptor's mapping of the tool's own rating, nil where it gives none.
	Severity *saga.ImportSeverity
	// Commit is the commit the descriptor says the file describes, held to the one this run reads as
	// a commit the file names itself is. Empty where the descriptor names none.
	Commit string
	// CommitUnset is the variable the descriptor's commit references where the environment does not
	// set it, so the file is read unbound and the report can say why. Commit is then empty.
	CommitUnset string
	// Format is what the file is, one of saga.ImportFormats. Empty is SARIF.
	Format string
	// Control is the control the descriptor imports the file into. A format that holds several
	// controls' results (saga.ImportFormatSplitsByControl) reads that control's from it and leaves the
	// rest to the file's other imports.
	Control string
	// CountSuppressed counts the findings the file's tool suppressed, as the descriptor's
	// imports[].suppressions: count asks, rather than setting them aside.
	CountSuppressed bool
	// Source is the service whose alerts are read in place of a file, one of saga.ImportSources, and
	// empty for a file. Path is then empty.
	Source string
	// TokenEnv is the variable the descriptor names for the source's token, empty for the source's
	// own. The token is read when the scan runs and kept nowhere else.
	TokenEnv string
	// Repository is the repository the descriptor names for the source as owner/name, empty where the
	// component's one repository names it.
	Repository string
	// Converter is the converter the descriptor declares for a draugr-converter file: the name the
	// file has to state, and the properties it may set. Nil for every other format.
	Converter *saga.ImportConverter
}

// Kind returns TargetFile.
func (FileTarget) Kind() TargetKind { return TargetFile }

// Identity returns the path, e.g. "reports/checkmarx.sarif", or for a source the source and the
// repository it names, "github-code-scanning acme/api". The kind is beside it wherever the two are
// shown or keyed together, as for every other target.
func (t FileTarget) Identity() string {
	if t.Source != "" {
		return strings.TrimSpace(t.Source + " " + t.Repository)
	}
	return t.Path
}

// CacheDetail is the file's content, so the same path holding different findings is a different
// scan; the repositories it is read against, because what the import makes of a file depends on
// them, the revision it is held to, the repository its findings are placed in and the scope that
// keeps or leaves out each one; the component it is read for, which its account names; the commit
// the descriptor holds it to, or the variable that left it
// unbound; the format it is read as, since one file read by two readers is two answers, and for a
// format that reads one control's results the control; whether
// the tool's own suppressions are counted; the converter and what it may set; and the descriptor's
// mapping of its tool's rating where it gives one.
//
// A source's alerts are never served from the cache (the engine does not cache a source), so its
// detail keeps it apart from a file's, and two reads of one source that make different findings
// of it apart from each other.
func (t FileTarget) CacheDetail() string {
	if t.Source != "" {
		detail := "source=" + t.Identity()
		for _, r := range t.Repositories {
			detail += " repo=" + r.Identity()
		}
		if t.CountSuppressed {
			detail += " suppressions=count"
		}
		return detail
	}
	detail := "sha256=" + t.Digest
	// A SARIF file's key is as it was before formats existed, so its cached reads stay valid.
	if t.Format != "" && t.Format != saga.ImportFormatSARIF {
		detail += " format=" + t.Format
	}
	// One file read into two controls by a format that reads each control's results is two answers.
	// Other formats read the file whole, and their keys stay as they were.
	if saga.ImportFormatSplitsByControl(t.Format) {
		detail += " control=" + t.Control
	}
	for _, r := range t.Repositories {
		detail += " repo=" + r.Identity()
	}
	// The import's account of the file names the component it was read for, so two components
	// importing one file are two reads, each answered from the cache with its own name.
	if t.Component != "" {
		detail += " component=" + t.Component
	}
	if t.Commit != "" {
		detail += " commit=" + t.Commit
	}
	if t.CommitUnset != "" {
		detail += " commit-unset=" + t.CommitUnset
	}
	if t.CountSuppressed {
		detail += " suppressions=count"
	}
	// What the converter may set decides what is read, so narrowing it reads the file again.
	if c := t.Converter; c != nil {
		detail += " converter=" + c.Name + "@" + strconv.Itoa(c.Contract) + ":" + strings.Join(c.Sets, ",")
	}
	if t.Severity == nil {
		return detail
	}
	values := make([]string, 0, len(t.Severity.Values))
	for _, k := range slices.Sorted(maps.Keys(t.Severity.Values)) {
		values = append(values, strconv.Quote(k)+"="+strconv.Quote(t.Severity.Values[k]))
	}
	return detail + " severity=" + strconv.Quote(t.Severity.Property) + ":" + strings.Join(values, ",")
}
