package sbom

import (
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
)

func TestSlug(t *testing.T) {
	for in, want := range map[string]string{
		"web":                       "web",
		"API Gateway":               "api-gateway",
		"python:3.8-slim":           "python-3-8-slim",
		"https://github.com/a/b":    "https-github-com-a-b",
		"ghcr.io/org/img@sha256:ab": "ghcr-io-org-img-sha256-ab",
		"---":                       "",
		"":                          "",
	} {
		if got := slug(in); got != want {
			t.Errorf("slug(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestEveryFormatHasAFileExtension(t *testing.T) {
	// A format the Saga accepts but that has no extension here would silently produce
	// "sbom-x-y.json", readable, but not what a consumer keying on the suffix expects.
	for _, f := range saga.SBOMFormats {
		meta, ok := fileTypes[f]
		if !ok {
			t.Errorf("format %q has no file extension or media type mapped", f)
			continue
		}
		// An XML or tag-value document labeled application/json would be a lie the moment a
		// publisher acts on the media type.
		if meta.ext == "" || meta.mediaType == "" {
			t.Errorf("format %q has an incomplete mapping: %+v", f, meta)
		}
		if strings.HasSuffix(string(f), "-xml") && !strings.Contains(meta.mediaType, "xml") {
			t.Errorf("format %q should not claim %q", f, meta.mediaType)
		}
	}
	if got := MediaType("future-format"); got != "application/octet-stream" {
		t.Errorf("an unmapped format is delivered as %q, want application/octet-stream", got)
	}
}

func TestFilenamesNameEachDocumentOnce(t *testing.T) {
	docs := []Document{
		{Component: "web", Target: "https://github.com/acme/web", Format: saga.SBOMCycloneDXJSON},
		// The same repository scoped to a second path of the same component: a second inventory
		// under the same component and source, which must not overwrite the first.
		{Component: "web", Target: "https://github.com/acme/web", Format: saga.SBOMCycloneDXJSON},
		{Component: "api", Target: "ghcr.io/acme/api@sha256:ab", Format: saga.SBOMSPDXJSON},
		{Project: true, Format: saga.SBOMCycloneDXJSON},
	}
	want := []string{
		"sbom-web-https-github-com-acme-web.cdx.json",
		"sbom-web-https-github-com-acme-web-2.cdx.json",
		"sbom-api-ghcr-io-acme-api-sha256-ab.spdx.json",
		"sbom-project.cdx.json",
	}
	got := Filenames(docs)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("Filenames = %v\nwant        %v", got, want)
	}
	if len(Filenames(nil)) != 0 {
		t.Error("no documents name no files")
	}
}

func TestDigestIsOverTheBytesWritten(t *testing.T) {
	d := Document{Bytes: []byte("{}")}
	// sha256 of "{}".
	const want = "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
	if got := d.Digest(); got != want {
		t.Errorf("Digest = %q, want %q", got, want)
	}
}

func TestTargetNameIsWhatTheDocumentIsNamedAfter(t *testing.T) {
	for _, tc := range []struct {
		target plugin.Target
		want   string
	}{
		// #nosec G101 -- placeholder credentials, there to prove they are left out of the name.
		{plugin.RepositoryTarget{URL: "https://x-access-token:secret@github.com/acme/web.git", Revision: "main"}, "https://github.com/acme/web"},
		{plugin.ImageTarget{Ref: "ghcr.io/acme/api:1", Digest: "sha256:ab"}, "ghcr.io/acme/api:1@sha256:ab"},
		{plugin.HostTarget{URL: "https://api.example.com"}, plugin.HostTarget{URL: "https://api.example.com"}.Identity()},
	} {
		if got := TargetName(tc.target); got != tc.want {
			t.Errorf("TargetName(%T) = %q, want %q", tc.target, got, tc.want)
		}
	}
}
