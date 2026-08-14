package tools

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// registerVersionedTool injects an installable whose URLs carry a {version} placeholder, so a
// test can ask for a version other than the pinned one.
func registerVersionedTool(t *testing.T, name, base, sha, checksums string) {
	t.Helper()
	installable[name] = InstallSpec{
		Binary:               name,
		Version:              "9.9.9",
		ChecksumsURLTemplate: checksums,
		Assets: map[string]Asset{platformKey(): {
			URL:             base + "/9.9.9/" + name,
			URLTemplate:     base + "/{version}/" + name,
			SHA256:          sha,
			BinaryInArchive: "",
		}},
	}
	t.Cleanup(func() { delete(installable, name) })
}

func TestSpecForShippedVersionIsUnchanged(t *testing.T) {
	// The pinned version keeps its recorded SHA, which is what lets an install verify without
	// reaching the network for metadata — the property air-gapped runners depend on.
	registerVersionedTool(t, "vtool", "https://example.test", "abc", "")
	for _, v := range []string{"", "9.9.9", "v9.9.9", " 9.9.9 "} {
		spec, err := SpecFor("vtool", v)
		if err != nil {
			t.Fatalf("SpecFor(%q): %v", v, err)
		}
		if spec.Assets[platformKey()].SHA256 != "abc" {
			t.Errorf("SpecFor(%q) dropped the recorded checksum", v)
		}
	}
}

func TestSpecForOtherVersionRendersURLsAndDropsTheSHA(t *testing.T) {
	registerVersionedTool(t, "vtool", "https://example.test", "abc",
		"https://example.test/{version}/checksums.txt")
	spec, err := SpecFor("vtool", "1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	a := spec.Assets[platformKey()]
	if a.URL != "https://example.test/1.2.3/vtool" {
		t.Errorf("URL not rendered: %q", a.URL)
	}
	// The absence of a recorded hash is the signal that verification has to come from upstream.
	// Carrying the shipped version's hash forward would fail every install of every other one.
	if a.SHA256 != "" {
		t.Errorf("a version Draugr does not ship cannot have a recorded checksum: %q", a.SHA256)
	}
	if spec.Version != "1.2.3" {
		t.Errorf("Version = %q", spec.Version)
	}
	if spec.ChecksumsURLTemplate != "https://example.test/1.2.3/checksums.txt" {
		t.Errorf("checksums URL not rendered: %q", spec.ChecksumsURLTemplate)
	}
}

func TestSpecForRefusesWhenItCannotBuildAURL(t *testing.T) {
	// Without a template Draugr has no idea what the upstream's URLs look like, and guessing at
	// one downloads whatever happens to answer. Saying so is better than a 404 the user has to
	// interpret, and it names the escape hatch.
	installable["notmpl"] = InstallSpec{
		Binary: "notmpl", Version: "9.9.9",
		Assets: map[string]Asset{platformKey(): {URL: "https://example.test/x", SHA256: "abc"}},
	}
	t.Cleanup(func() { delete(installable, "notmpl") })

	_, err := SpecFor("notmpl", "1.2.3")
	if err == nil {
		t.Fatal("expected a refusal")
	}
	if !strings.Contains(err.Error(), "external") {
		t.Errorf("the message should point at the way round it: %v", err)
	}
}

func TestSpecForUnknownTool(t *testing.T) {
	if _, err := SpecFor("nope", "1.0.0"); err == nil {
		t.Fatal("expected an error for an unknown tool")
	}
}

func TestEveryInstallableCanResolveAnotherVersion(t *testing.T) {
	// A template missing from the table is invisible until somebody pins that tool, at which
	// point the feature simply does not work for it.
	for _, name := range Installable() {
		// A tool obtained as a Python package has no per-version asset table to template: pip
		// resolves the version, and only the pinned one has hashes built in. That difference is
		// the subject of TestEveryPythonToolHasPinsAtItsVersion rather than this.
		if _, isPython := PythonTool(name); isPython {
			continue
		}
		spec, err := SpecFor(name, "1.2.3")
		if err != nil {
			t.Errorf("%s cannot resolve another version: %v", name, err)
			continue
		}
		for platform, a := range installable[name].Assets {
			got, ok := spec.Assets[platform]
			if !ok {
				t.Errorf("%s: no %s asset at another version", name, platform)
				continue
			}
			if strings.Contains(got.URL, "{version}") || !strings.Contains(got.URL, "1.2.3") {
				t.Errorf("%s/%s: URL did not render: %q", name, platform, got.URL)
			}
			if a.BinaryInArchive != got.BinaryInArchive {
				t.Errorf("%s/%s: lost the path inside the archive", name, platform)
			}
		}
	}
}

func TestInstallVersionWarnsRatherThanRefusingWithNothingToCheckAgainst(t *testing.T) {
	// Draugr does not gatekeep an install it cannot verify. An operator asking for a version has
	// a reason Draugr does not know — a fork, a release candidate, a build newer than this one.
	// The answer is to install it and label it, not to refuse.
	content := []byte("#!/bin/sh\necho v\n")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(content)
	}))
	defer srv.Close()
	registerVersionedTool(t, "vtool", srv.URL, sha256Hex(content), "")

	dest := t.TempDir()
	got, err := InstallVersion(context.Background(), "vtool", "1.2.3", dest, srv.Client(), false)
	if err != nil {
		t.Fatalf("InstallVersion: %v", err)
	}
	if got.Version != "1.2.3" {
		t.Errorf("Version = %q", got.Version)
	}
	// And the label survives the install, because a warning in the logs of the run that installed
	// it is not where anyone looks six weeks later.
	if lvl := loadManifest(dest)["vtool"].Verified; lvl != LevelUnverified {
		t.Errorf("recorded level = %q, want %q", lvl, LevelUnverified)
	}
	if a := Attest("vtool", got.Path, "", dest); a.Level != LevelUnverified || a.Reason == "" {
		t.Errorf("attestation does not carry the level: %+v", a)
	}
}

func TestInstallVersionMatchesUpstreamChecksums(t *testing.T) {
	// An unsigned checksums file over HTTPS proves the download was not corrupted or truncated.
	// It does not prove the upstream published it, so it is its own level rather than "signed".
	content := []byte("#!/bin/sh\necho v\n")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "checksums.txt") {
			_, _ = w.Write([]byte("deadbeef  someother\n" + sha256Hex(content) + "  vtool\n"))
			return
		}
		_, _ = w.Write(content)
	}))
	defer srv.Close()
	registerVersionedTool(t, "vtool", srv.URL, "unused", srv.URL+"/{version}/checksums.txt")

	dest := t.TempDir()
	if _, err := InstallVersion(context.Background(), "vtool", "1.2.3", dest, srv.Client(), false); err != nil {
		t.Fatalf("InstallVersion: %v", err)
	}
	if lvl := loadManifest(dest)["vtool"].Verified; lvl != LevelChecksum {
		t.Errorf("recorded level = %q, want %q", lvl, LevelChecksum)
	}
}

func TestInstallVersionRefusesAPublishedChecksumThatDisagrees(t *testing.T) {
	// Missing is not the same as mismatched. Nothing published is unknown; a published checksum
	// that disagrees says the download was corrupted or substituted, and installing past it would
	// be ignoring evidence rather than lacking it.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "checksums.txt") {
			_, _ = w.Write([]byte("0000000000000000000000000000000000000000000000000000000000000000  vtool\n"))
			return
		}
		_, _ = w.Write([]byte("#!/bin/sh\necho v\n"))
	}))
	defer srv.Close()
	registerVersionedTool(t, "vtool", srv.URL, "unused", srv.URL+"/{version}/checksums.txt")

	dest := t.TempDir()
	_, err := InstallVersion(context.Background(), "vtool", "1.2.3", dest, srv.Client(), false)
	if err == nil {
		t.Fatal("a download that contradicts the published checksum was installed")
	}
	if !strings.Contains(err.Error(), "published") {
		t.Errorf("the message should say what disagreed: %v", err)
	}
}

func TestInstallVersionTreatsAnUnreachableChecksumsFileAsUnknown(t *testing.T) {
	// The upstream being down is not evidence the download is wrong.
	content := []byte("#!/bin/sh\necho v\n")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "checksums.txt") {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(content)
	}))
	defer srv.Close()
	registerVersionedTool(t, "vtool", srv.URL, "unused", srv.URL+"/{version}/checksums.txt")

	dest := t.TempDir()
	if _, err := InstallVersion(context.Background(), "vtool", "1.2.3", dest, srv.Client(), false); err != nil {
		t.Fatalf("an unreachable checksums file blocked the install: %v", err)
	}
	if lvl := loadManifest(dest)["vtool"].Verified; lvl != LevelUnverified {
		t.Errorf("recorded level = %q, want %q", lvl, LevelUnverified)
	}
}

func TestAssetFileName(t *testing.T) {
	if got := assetFileName("https://example.test/a/b/tool_1.2.3.tar.gz"); got != "tool_1.2.3.tar.gz" {
		t.Errorf("assetFileName = %q", got)
	}
	if got := assetFileName("tool"); got != "tool" {
		t.Errorf("assetFileName = %q", got)
	}
}

func TestInstallVersionFallsBackWhenCosignIsNotInstalled(t *testing.T) {
	// An upstream that signs its checksums is still checked against them when the cosign CLI is
	// absent — the signature could not be read, which says nothing about the download. Refusing
	// here would make every install of another version depend on a tool the user may not have.
	t.Setenv("PATH", t.TempDir()) // no cosign
	content := []byte("#!/bin/sh\necho v\n")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "checksums.txt") {
			_, _ = w.Write([]byte(sha256Hex(content) + "  vtool\n"))
			return
		}
		_, _ = w.Write(content)
	}))
	defer srv.Close()
	registerVersionedTool(t, "vtool", srv.URL, "unused", "")
	spec := installable["vtool"]
	spec.Cosign = &CosignSpec{
		ChecksumsURL:         srv.URL + "/9.9.9/checksums.txt",
		ChecksumsURLTemplate: srv.URL + "/{version}/checksums.txt",
		BundleURLTemplate:    srv.URL + "/{version}/checksums.txt.sigstore.json",
	}
	installable["vtool"] = spec

	dest := t.TempDir()
	if _, err := InstallVersion(context.Background(), "vtool", "1.2.3", dest, srv.Client(), false); err != nil {
		t.Fatalf("InstallVersion: %v", err)
	}
	// Matched against the upstream's checksums, but nothing verified who published them.
	if lvl := loadManifest(dest)["vtool"].Verified; lvl != LevelChecksum {
		t.Errorf("recorded level = %q, want %q", lvl, LevelChecksum)
	}
}

func TestLevelDescribeCoversEveryLevel(t *testing.T) {
	// These are what a reader sees next to a scanner in their report, so an empty or duplicated
	// one is a line that explains nothing.
	seen := map[string]bool{}
	for _, l := range []Level{LevelPinned, LevelSigned, LevelChecksum, LevelUnverified, LevelExternal, ""} {
		d := l.Describe()
		if d == "" {
			t.Errorf("%q describes itself as nothing", l)
		}
		if l != "" && seen[d] {
			t.Errorf("%q reuses another level's description: %q", l, d)
		}
		seen[d] = true
	}
	if !LevelUnverified.Vouched() {
		t.Error("Draugr did install an unverified build, and saying otherwise loses that")
	}
	if LevelExternal.Vouched() || Level("").Vouched() {
		t.Error("a binary Draugr never installed is not vouched for")
	}
}
