package surveyors

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/scanners"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// signed scripts an answer per image, so a test says what each registry replied and nothing else.
func signed(answers map[string]scanners.Signature, fails map[string]error) *ProvenanceSigners {
	return &ProvenanceSigners{
		whoSigned: func(_ context.Context, ref, _ string) (scanners.Signature, error) {
			if err, bad := fails[ref]; bad {
				return scanners.Signature{}, err
			}
			return answers[ref], nil
		},
	}
}

func surveyImages(t *testing.T, p *ProvenanceSigners, images ...string) (saga.Fragment, error) {
	t.Helper()
	return p.Survey(context.Background(), plugin.SurveyScope{
		Config: plugin.Config{ProvenanceImagesKey: images},
	})
}

// signersIn pulls the proposed signers out of the fragment, as the descriptor will hold them.
func signersIn(t *testing.T, frag saga.Fragment) []map[string]any {
	t.Helper()
	raw, _ := frag.Config.Controls["provenance"]["signers"].([]any)
	out := make([]map[string]any, 0, len(raw))
	for _, e := range raw {
		m, ok := e.(map[string]any)
		if !ok {
			t.Fatalf("a signer is %T, not a mapping", e)
		}
		out = append(out, m)
	}
	return out
}

// TestImagesSharingAnIdentityBecomeOneSigner. The alternative is a pattern, and a pattern means
// guessing how broad to be: one too wide accepts signatures from people the reader did not mean to
// trust, and it passes validation, because the schema can refuse a signer that recognizes nobody
// and cannot refuse one that recognizes too many.
func TestImagesSharingAnIdentityBecomeOneSigner(t *testing.T) {
	t.Parallel()
	const id = "https://github.com/acme/ci/.github/workflows/release.yml@refs/tags/v3"
	const issuer = "https://token.actions.githubusercontent.com"
	p := signed(map[string]scanners.Signature{
		"ghcr.io/acme/api:1.0":   {Identity: id, Issuer: issuer, Signed: true},
		"ghcr.io/acme/web:2.0":   {Identity: id, Issuer: issuer, Signed: true},
		"ghcr.io/other/tool:1.0": {Identity: "https://github.com/other/build/.github/workflows/p.yml@refs/heads/main", Issuer: issuer, Signed: true},
	}, nil)

	frag, err := surveyImages(t, p, "ghcr.io/acme/web:2.0", "ghcr.io/acme/api:1.0", "ghcr.io/other/tool:1.0")
	if err != nil {
		t.Fatal(err)
	}
	got := signersIn(t, frag)
	if len(got) != 2 {
		t.Fatalf("got %d signers, want one per identity: %+v", len(got), got)
	}

	var acme map[string]any
	for _, s := range got {
		if s["name"] == "acme-ci" {
			acme = s
		}
	}
	if acme == nil {
		t.Fatalf("no signer named for the workflow that signed: %+v", got)
	}
	images, _ := acme["images"].([]any)
	if len(images) != 2 || images[0] != "ghcr.io/acme/api:1.0" || images[1] != "ghcr.io/acme/web:2.0" {
		t.Errorf("images = %v, want both, sorted, and exact", images)
	}
	keyless, _ := acme["keyless"].(map[string]any)
	if keyless["identity"] != id || keyless["issuer"] != issuer {
		t.Errorf("keyless = %v, want the exact identity and issuer observed", keyless)
	}
}

// TestNothingIsWidenedIntoAPattern. The generated block is the narrowest thing that works, so
// widening it is the reader's deliberate act rather than a default they have to notice and undo.
func TestNothingIsWidenedIntoAPattern(t *testing.T) {
	t.Parallel()
	p := signed(map[string]scanners.Signature{
		"ghcr.io/acme/api:1.0": {Identity: "https://github.com/acme/ci/.github/workflows/release.yml@refs/tags/v3", Issuer: "i", Signed: true},
	}, nil)
	frag, err := surveyImages(t, p, "ghcr.io/acme/api:1.0")
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range signersIn(t, frag) {
		keyless, _ := s["keyless"].(map[string]any)
		if _, widened := keyless["identityRegexp"]; widened {
			t.Error("a pattern was proposed where an exact identity was observed")
		}
		for _, img := range s["images"].([]any) {
			if strings.Contains(img.(string), "*") {
				t.Errorf("an image pattern was proposed: %v", img)
			}
		}
	}
}

// TestAnUnsignedImageProducesNoSigner. Most of what a project runs is published by somebody else.
// A signer proposed for an image nobody signed is a policy that can only fail.
func TestAnUnsignedImageProducesNoSigner(t *testing.T) {
	t.Parallel()
	p := signed(map[string]scanners.Signature{
		"docker.io/library/python:3.8-slim": {},
		"ghcr.io/acme/api:1.0":              {Identity: "https://github.com/acme/ci/.github/workflows/r.yml@refs/tags/v1", Issuer: "i", Signed: true},
	}, nil)
	frag, err := surveyImages(t, p, "docker.io/library/python:3.8-slim", "ghcr.io/acme/api:1.0")
	if err != nil {
		t.Fatalf("an unsigned image is not an error: %v", err)
	}
	got := signersIn(t, frag)
	if len(got) != 1 {
		t.Fatalf("got %d signers, want only the signed image's: %+v", len(got), got)
	}
	for _, img := range got[0]["images"].([]any) {
		if img == "docker.io/library/python:3.8-slim" {
			t.Error("the unsigned image was written into a signer")
		}
	}
}

// TestASignatureWhoseIdentityIsUnreadableProposesNothing. A signer needs an identity to check
// against, and "signed by somebody" is not one. Recording the image as covered by a signer with no
// identity would be a policy that accepts anything.
func TestASignatureWhoseIdentityIsUnreadableProposesNothing(t *testing.T) {
	t.Parallel()
	p := signed(map[string]scanners.Signature{
		"ghcr.io/acme/api:1.0": {Signed: true},
	}, nil)
	frag, err := surveyImages(t, p, "ghcr.io/acme/api:1.0")
	if err != nil {
		t.Fatal(err)
	}
	if got := signersIn(t, frag); len(got) != 0 {
		t.Errorf("a signer was proposed with no identity to check: %+v", got)
	}
}

// TestOneUnreadableImageDoesNotDiscardTheRest. The registry hands back a fragment only from a
// surveyor that returned no error, so failing here would throw away every image that did answer,
// and an inventory of fourteen would depend on all fourteen being reachable at once.
func TestOneUnreadableImageDoesNotDiscardTheRest(t *testing.T) {
	t.Parallel()
	p := signed(
		map[string]scanners.Signature{
			"ghcr.io/acme/api:1.0": {Identity: "https://github.com/acme/ci/.github/workflows/r.yml@refs/tags/v1", Issuer: "i", Signed: true},
		},
		map[string]error{"ghcr.io/acme/down:1.0": errors.New("registry timed out")},
	)
	frag, err := surveyImages(t, p, "ghcr.io/acme/api:1.0", "ghcr.io/acme/down:1.0")
	if err != nil {
		t.Fatalf("one unreachable image failed the whole survey: %v", err)
	}
	if got := signersIn(t, frag); len(got) != 1 {
		t.Errorf("the readable image's signer was lost: %+v", got)
	}
}

// TestNoImageReadableIsAFailureRatherThanAnEmptyAnswer. Every image unreadable and every image
// unsigned produce the same empty result, and only the second is a survey that ran. Reported as
// success, the first reads as "nothing here is signed".
func TestNoImageReadableIsAFailureRatherThanAnEmptyAnswer(t *testing.T) {
	t.Parallel()
	p := signed(nil, map[string]error{
		"ghcr.io/acme/a:1": errors.New("registry timed out"),
		"ghcr.io/acme/b:1": errors.New("registry timed out"),
	})
	frag, err := surveyImages(t, p, "ghcr.io/acme/a:1", "ghcr.io/acme/b:1")
	if err == nil {
		t.Fatal("a survey that read nothing reported success")
	}
	if len(signersIn(t, frag)) != 0 {
		t.Error("a failed survey still proposed signers")
	}
}

// TestTheReasonSaysWhichImageItCameFrom. A signer is a statement about who is trusted, so a reader
// reviewing one is accepting a policy rather than correcting an inventory, and the question they
// have is which image this came off.
func TestTheReasonSaysWhichImageItCameFrom(t *testing.T) {
	t.Parallel()
	p := signed(map[string]scanners.Signature{
		"ghcr.io/acme/api:1.0": {Identity: "https://github.com/acme/ci/.github/workflows/r.yml@refs/tags/v1", Issuer: "i", Signed: true},
	}, nil)
	frag, err := surveyImages(t, p, "ghcr.io/acme/api:1.0")
	if err != nil {
		t.Fatal(err)
	}
	got := frag.SignerReasons["acme-ci"]
	if !strings.Contains(got, "ghcr.io/acme/api:1.0") {
		t.Errorf("reason = %q, want the image it was read from", got)
	}
}

// TestSurveyingNoImagesSaysWhatToDo. The common first encounter: a descriptor with no images yet.
// An empty result would read as "nothing signed", which is a different and wrong answer.
func TestSurveyingNoImagesSaysWhatToDo(t *testing.T) {
	t.Parallel()
	_, err := surveyImages(t, signed(nil, nil))
	if err == nil || !strings.Contains(err.Error(), "declare images") {
		t.Errorf("err = %v, want a message naming what to do about it", err)
	}
}

// TestASignerIsNamedForWhatTheReaderRecognizes. `signer-1` asks somebody reviewing a trust policy
// to follow a URL to find out what they are being asked to trust.
func TestASignerIsNamedForWhatTheReaderRecognizes(t *testing.T) {
	t.Parallel()
	for _, c := range []struct{ id, ref, want string }{
		{"https://github.com/acme/ci/.github/workflows/release.yml@refs/tags/v3", "ghcr.io/acme/api:1.0", "acme-ci"},
		{"https://gitlab.com/acme/build//.gitlab-ci.yml@refs/heads/main", "registry.gitlab.com/acme/api:1.0", "api"},
		{"", "ghcr.io/acme/api:1.0", "api"},
	} {
		if got := signerName(c.id, c.ref); got != c.want {
			t.Errorf("signerName(%q, %q) = %q, want %q", c.id, c.ref, got, c.want)
		}
	}
}

// TestTwoRunsWriteTheSameFile. A descriptor that changes when nothing changed is a diff somebody
// has to read before they can see the one that matters.
func TestTwoRunsWriteTheSameFile(t *testing.T) {
	t.Parallel()
	answers := map[string]scanners.Signature{
		"ghcr.io/acme/a:1": {Identity: "https://github.com/acme/z/.github/workflows/r.yml@refs/tags/v1", Issuer: "i", Signed: true},
		"ghcr.io/acme/b:1": {Identity: "https://github.com/acme/a/.github/workflows/r.yml@refs/tags/v1", Issuer: "i", Signed: true},
		"ghcr.io/acme/c:1": {Identity: "https://github.com/acme/m/.github/workflows/r.yml@refs/tags/v1", Issuer: "i", Signed: true},
	}
	var first []string
	for run := range 5 {
		frag, err := surveyImages(t, signed(answers, nil), "ghcr.io/acme/c:1", "ghcr.io/acme/a:1", "ghcr.io/acme/b:1")
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, s := range signersIn(t, frag) {
			names = append(names, s["name"].(string))
		}
		if run == 0 {
			first = names
			continue
		}
		if strings.Join(names, ",") != strings.Join(first, ",") {
			t.Fatalf("run %d ordered the signers %v, first run %v", run, names, first)
		}
	}
}

// TestAnOwnerThatAlreadyNamesTheRepositoryDoesNotStutter. `chainguard-images/images` is a real
// one, and joined blindly it reads as a fault in the tool rather than as a name.
func TestAnOwnerThatAlreadyNamesTheRepositoryDoesNotStutter(t *testing.T) {
	t.Parallel()
	for _, c := range []struct{ id, want string }{
		{"https://github.com/chainguard-images/images/.github/workflows/release.yaml@refs/heads/main", "chainguard-images"},
		{"https://github.com/acme/acme/.github/workflows/r.yml@refs/tags/v1", "acme"},
		{"https://github.com/acme/ci/.github/workflows/r.yml@refs/tags/v1", "acme-ci"},
	} {
		if got := signerName(c.id, "ghcr.io/x/y:1"); got != c.want {
			t.Errorf("signerName(%q) = %q, want %q", c.id, got, c.want)
		}
	}
}
