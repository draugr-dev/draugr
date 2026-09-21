package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/saga"
)

// TestTheSignatureIsReadAgainstWhatTheDescriptorPinned. A tag can be repointed after the read, so
// a signer adopted from one says less than the same signer adopted from a digest. Where the
// descriptor pinned a digest, that is what the registry is asked about.
func TestTheSignatureIsReadAgainstWhatTheDescriptorPinned(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name string
		img  saga.Image
		want string
	}{
		{"a tag is asked about as a tag", saga.Image{Image: "ghcr.io/acme/api:1.0"}, "ghcr.io/acme/api:1.0"},
		{
			name: "a pinned digest wins over the tag beside it",
			img:  saga.Image{Image: "ghcr.io/acme/api:1.0", Digest: "sha256:abc"},
			want: "ghcr.io/acme/api@sha256:abc",
		},
		{
			name: "a digest with no tag on the reference",
			img:  saga.Image{Image: "ghcr.io/acme/api", Digest: "sha256:abc"},
			want: "ghcr.io/acme/api@sha256:abc",
		},
		// A registry port is a colon that is not a tag separator, and cutting at the first one
		// would ask about a host.
		{
			name: "a digest on a reference carrying a port",
			img:  saga.Image{Image: "registry.local:5000/acme/api:1.0", Digest: "sha256:abc"},
			want: "registry.local:5000/acme/api@sha256:abc",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if got := imageRef(c.img); got != c.want {
				t.Errorf("imageRef = %q, want %q", got, c.want)
			}
		})
	}
}

// TestTheImagesAskedAboutAreTheOnesDeclared, deduplicated and ordered, so two runs over one
// descriptor ask the same questions in the same order.
func TestTheImagesAskedAboutAreTheOnesDeclared(t *testing.T) {
	t.Parallel()
	opts := surveyOptions{output: writeSaga(t, `project: p
release:
  version: "1.0"
components:
  - name: b
    images:
      - image: ghcr.io/acme/z:1
      - image: ghcr.io/acme/a:1
  - name: a
    images:
      - image: ghcr.io/acme/a:1
`)}
	got, err := declaredImages(opts)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"ghcr.io/acme/a:1", "ghcr.io/acme/z:1"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("images = %v, want %v, deduplicated across components and sorted", got, want)
	}
}

// TestADescriptorWithNothingToAskAboutSaysWhatToDo. Both of these would otherwise reach the
// surveyor as an empty list and come back as "nothing here is signed", which is a different and
// wrong answer.
func TestADescriptorWithNothingToAskAboutSaysWhatToDo(t *testing.T) {
	t.Parallel()

	t.Run("no descriptor at all", func(t *testing.T) {
		t.Parallel()
		_, err := declaredImages(surveyOptions{output: filepath.Join(t.TempDir(), "absent.saga.yaml")})
		if err == nil || !strings.Contains(err.Error(), "already exists") {
			t.Errorf("err = %v, want it to say the file has to exist first", err)
		}
	})

	t.Run("a descriptor declaring no images", func(t *testing.T) {
		t.Parallel()
		opts := surveyOptions{output: writeSaga(t, `project: p
release:
  version: "1.0"
components:
  - name: a
`)}
		_, err := declaredImages(opts)
		if err == nil || !strings.Contains(err.Error(), "declares no images") {
			t.Errorf("err = %v, want it to name what is missing", err)
		}
	})
}

// TestTheAdoptionIsSaidOutLoud is the safety property of the whole surveyor. A signer derived from
// what signs an image today cannot fail the check it was derived from, so the moment it is adopted
// is the moment somebody can still disagree, and the note is the only place that happens.
func TestTheAdoptionIsSaidOutLoud(t *testing.T) {
	t.Parallel()
	frag := saga.Fragment{
		Config: saga.FragmentConfig{Controls: map[string]saga.ControllerSettings{
			"provenance": {"signers": []any{map[string]any{
				"name":   "acme-ci",
				"images": []any{"ghcr.io/acme/api:1.0"},
				"keyless": map[string]any{
					"identity": "https://github.com/acme/ci/.github/workflows/release.yml@refs/tags/v3",
					"issuer":   "https://token.actions.githubusercontent.com",
				},
			}}},
		}},
		SignerReasons: map[string]string{"acme-ci": "read from the signature on ghcr.io/acme/api:1.0"},
	}

	got := adoptedSignerNote(frag)
	for _, want := range []string{
		"not confirmed",
		"acme-ci",
		"https://github.com/acme/ci/.github/workflows/release.yml@refs/tags/v3",
		"read from the signature on ghcr.io/acme/api:1.0",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the adoption note does not carry %q:\n%s", want, got)
		}
	}
}

// A survey that proposed nothing says nothing. A heading over an empty list reads as a thing that
// happened, and this one would read as a trust decision that happened.
func TestNoSignersMeansNoAdoptionNote(t *testing.T) {
	t.Parallel()
	if got := adoptedSignerNote(saga.Fragment{}); got != "" {
		t.Errorf("a survey that adopted nothing announced an adoption:\n%s", got)
	}
}
