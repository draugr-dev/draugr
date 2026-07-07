package plugin

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

// RepositoryTarget is a source repository at a revision, optionally scoped to paths.
type RepositoryTarget struct {
	URL      string
	Revision string
	Paths    []string
}

// Kind returns TargetRepository.
func (RepositoryTarget) Kind() TargetKind { return TargetRepository }

// Identity returns the URL and revision, e.g. "https://git/x@1.0".
func (t RepositoryTarget) Identity() string { return t.URL + "@" + t.Revision }

// ImageTarget is a container image. Identity prefers the immutable digest.
type ImageTarget struct {
	Ref    string
	Digest string
}

// Kind returns TargetImage.
func (ImageTarget) Kind() TargetKind { return TargetImage }

// Identity returns the digest when set, otherwise the ref.
func (t ImageTarget) Identity() string {
	if t.Digest != "" {
		return t.Digest
	}
	return t.Ref
}

// HostTarget is a running endpoint. Type is "api" or "web".
type HostTarget struct {
	Name string
	URL  string
	Type string
}

// Kind returns TargetHost.
func (HostTarget) Kind() TargetKind { return TargetHost }

// Identity returns the host URL.
func (t HostTarget) Identity() string { return t.URL }

// InfraTarget is an infrastructure surface (e.g. a Kubernetes cluster). Platform is the
// kind of infrastructure (e.g. "kubernetes"); Ref names the concrete instance.
type InfraTarget struct {
	Platform string
	Ref      string
}

// Kind returns TargetInfra.
func (InfraTarget) Kind() TargetKind { return TargetInfra }

// Identity returns the platform and ref, e.g. "kubernetes/prod".
func (t InfraTarget) Identity() string { return t.Platform + "/" + t.Ref }
