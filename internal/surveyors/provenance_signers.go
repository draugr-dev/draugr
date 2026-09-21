package surveyors

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"

	"github.com/draugr-dev/draugr/internal/scanners"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// ProvenanceImagesKey carries the images to ask about, and ProvenanceTrustRootKey the Sigstore
// root to ask against.
//
// Scope config rather than fields on SurveyScope, the same channel ProposeExposureKey uses: this
// is one surveyor's input, and every other surveyor discovers from a system it can name with a
// Ref. This one discovers from the descriptor, which the command has already read.
const (
	ProvenanceImagesKey    = "images"
	ProvenanceTrustRootKey = "trustRoot"
)

// ProvenanceSigners reads the signature on each image a descriptor declares and proposes the
// `signers:` that would accept it.
//
// Writing a signer means knowing the identity a build signs with, and there are two situations
// where nobody does. A job that calls a reusable workflow is signed as that workflow's repository
// rather than as the caller, so the obvious value is the wrong one and it fails as a mismatch
// rather than as a syntax error. And a third-party image can only be pinned to whatever actually
// signed it. Both are the same job: read the signature, and turn it into a signer.
type ProvenanceSigners struct {
	// whoSigned asks a registry what signed an image; injectable so tests need neither cosign nor
	// a network.
	whoSigned func(ctx context.Context, ref, trustRoot string) (scanners.Signature, error)
}

// NewProvenanceSigners returns the provenance-signers surveyor, reading through cosign.
func NewProvenanceSigners() *ProvenanceSigners {
	return &ProvenanceSigners{whoSigned: scanners.WhoSigned}
}

// Info identifies the surveyor.
func (ProvenanceSigners) Info() plugin.SurveyorInfo {
	return plugin.SurveyorInfo{Name: "provenance-signers"}
}

// Survey asks each image what signed it and returns the signers that would accept those answers.
//
// Sigstore only. A Notary Project signature records nothing observable here, and reading a
// certificate subject through `notation inspect` is its own step rather than a variation on this
// one. An image it cannot read is warned about and does not stop the rest, and a run where none
// of them could be read is a failure rather than an empty answer.
func (p ProvenanceSigners) Survey(ctx context.Context, scope plugin.SurveyScope) (saga.Fragment, error) {
	images := stringList(scope.Config[ProvenanceImagesKey])
	if len(images) == 0 {
		return saga.Fragment{}, fmt.Errorf("provenance-signers: no images to ask about; " +
			"declare images on a component, or survey a cluster first")
	}
	trustRoot, _ := scope.Config[ProvenanceTrustRootKey].(string)

	found := map[identity][]string{}
	var unreadable []string
	for _, ref := range images {
		sig, err := p.whoSigned(ctx, ref, trustRoot)
		if err != nil {
			// Named and skipped. A registry that did not answer is a gap in the survey, and
			// stopping on the first one would make an inventory of fourteen depend on all
			// fourteen being reachable at once.
			//
			// Warned rather than returned, because the registry returns a fragment only from a
			// surveyor that returned no error, so an error here would throw away every image that
			// did answer. It cannot go unsaid either: an image nobody could read must not look
			// like an image nobody signed.
			unreadable = append(unreadable, ref)
			slog.Warn("could not read the signature", "image", ref, "error", err)
			continue
		}
		// An unsigned image is not an error and produces no signer. Most of what a project runs
		// is published by somebody else, and a signer proposed for an image nobody signed is a
		// policy that can only fail.
		if !sig.Signed || sig.Identity == "" {
			continue
		}
		key := identity{Identity: sig.Identity, Issuer: sig.Issuer}
		found[key] = append(found[key], ref)
	}

	frag := saga.Fragment{SignerReasons: map[string]string{}}
	signers := make([]any, 0, len(found))
	for _, key := range sortedIdentities(found) {
		refs := found[key]
		sort.Strings(refs)
		name := signerName(key.Identity, refs[0])
		signers = append(signers, map[string]any{
			"name":   name,
			"images": toAnyList(refs),
			"keyless": map[string]any{
				"issuer":   key.Issuer,
				"identity": key.Identity,
			},
		})
		frag.SignerReasons[name] = reason(refs)
	}
	if len(signers) > 0 {
		frag.Config.Controls = map[string]saga.ControllerSettings{
			"provenance": {"signers": signers},
		}
	}
	// Every image unreadable is a different answer from every image unsigned, and only the second
	// is a survey that ran. Reported as a failure so nobody reads an empty result as "nothing here
	// is signed" when the truth is that nothing here could be reached.
	if len(unreadable) == len(images) {
		return saga.Fragment{}, fmt.Errorf(
			"provenance-signers: could not read the signature on any of %s; "+
				"the log above names each one", strings.Join(unreadable, ", "))
	}
	return frag, nil
}

// identity is one signing identity, which is what groups images into a signer.
type identity struct{ Identity, Issuer string }

// sortedIdentities orders the signers so two runs over the same registry write the same file.
func sortedIdentities(found map[identity][]string) []identity {
	out := make([]identity, 0, len(found))
	for key := range found {
		out = append(out, key)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Identity != out[j].Identity {
			return out[i].Identity < out[j].Identity
		}
		return out[i].Issuer < out[j].Issuer
	})
	return out
}

// reason records what this signer was read from, for the line beside the value when it is
// reviewed. A proposal a reader cannot trace is one they have to take on trust, which is the
// opposite of what proposing a trust policy should ask of them.
func reason(refs []string) string {
	return "read from the signature on " + strings.Join(refs, ", ")
}

// signerName is what to call the signer in the descriptor.
//
// Derived from the workflow or repository in the identity where there is one, because a reader
// reviewing `signers:` is deciding about a thing they recognize, and "signer-1" asks them to
// follow a URL to find out what they are being asked to trust. Falls back to the image, which is
// the other thing they recognize.
func signerName(id, ref string) string {
	if rest, ok := strings.CutPrefix(id, "https://github.com/"); ok {
		if owner, tail, ok := strings.Cut(rest, "/"); ok {
			repo, _, _ := strings.Cut(tail, "/")
			if repo != "" {
				return slug(owner + "-" + repo)
			}
		}
	}
	name, _, _ := strings.Cut(ref, ":")
	if i := strings.LastIndex(name, "/"); i >= 0 {
		name = name[i+1:]
	}
	if name == "" {
		return "observed"
	}
	return slug(name)
}

// slug keeps a name to what a descriptor reads back cleanly.
func slug(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '.' || r == '_':
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "observed"
	}
	return out
}

func stringList(v any) []string {
	switch t := v.(type) {
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func toAnyList(in []string) []any {
	out := make([]any, len(in))
	for i, s := range in {
		out[i] = s
	}
	return out
}
