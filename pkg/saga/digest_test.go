package saga

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writePair puts a descriptor and a fragment on disk and returns the descriptor's path.
func writePair(t *testing.T, root, fragment string) string {
	t.Helper()
	dir := t.TempDir()
	if fragment != "" {
		if err := os.WriteFile(filepath.Join(dir, "f.saga-fragment.yaml"), []byte(fragment), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(dir, "draugr.saga.yaml")
	if err := os.WriteFile(path, []byte(root), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

const rootWithFragment = `
project: p
release: {version: "1"}
fragments:
  - path: f.saga-fragment.yaml
components:
  - name: c
    repositories: [{url: "."}]
`

// The digest has to answer "were these two runs asked the same question", and a fragment is part
// of the question. A digest over the root file alone says yes here, which is the whole reason it
// is computed over the merged model instead.
func TestDigestFollowsTheFragments(t *testing.T) {
	one, err := ResolveFile(writePair(t, rootWithFragment, "config: {exclude: [{rules: [a], reason: r}]}"), nil)
	if err != nil {
		t.Fatal(err)
	}
	two, err := ResolveFile(writePair(t, rootWithFragment, "config: {exclude: [{rules: [b], reason: r}]}"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if one.Digest() == two.Digest() {
		t.Error("a changed fragment left the descriptor digest identical")
	}
	if one.Sources[0].Digest != two.Sources[0].Digest {
		t.Error("the root file was not touched, so its own digest must not have moved")
	}
}

// Comments and key order are not the descriptor. Two documents that mean the same thing must not
// look like a change to anything comparing runs.
func TestDigestIgnoresWhatDoesNotChangeTheMeaning(t *testing.T) {
	plain := "project: p\nrelease: {version: \"1\"}\ncomponents: [{name: c, repositories: [{url: \".\"}]}]"
	noisy := "# a comment\ncomponents: [{name: c, repositories: [{url: \".\"}]}]\nrelease:\n  version: \"1\"\nproject: p\n"
	a, err := ResolveFile(writePair(t, plain, ""), nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ResolveFile(writePair(t, noisy, ""), nil)
	if err != nil {
		t.Fatal(err)
	}
	if a.Digest() != b.Digest() {
		t.Errorf("the same descriptor written twice produced two digests:\n%s\n%s", a.Digest(), b.Digest())
	}
	if a.Sources[0].Digest == b.Sources[0].Digest {
		t.Error("two different files must have different file digests")
	}
}

// Every source carries one, root included: an exclusion arriving from a fragment nobody can pin is
// a decision with no author.
func TestEverySourceIsDigested(t *testing.T) {
	res, err := ResolveFile(writePair(t, rootWithFragment, "config: {exclude: [{rules: [a], reason: r}]}"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Sources) != 2 {
		t.Fatalf("got %d sources, want 2", len(res.Sources))
	}
	for _, s := range res.Sources {
		if s.Digest == "" {
			t.Errorf("source %q has no digest", s.Path)
		}
	}
}

// A nil resolution has no digest to give, and must not answer with the digest of nothing — which
// is a real, constant, entirely wrong sha256.
func TestNoModelNoDigest(t *testing.T) {
	var nilRes *Resolved
	if got := nilRes.Digest(); got != "" {
		t.Errorf("nil.Digest() = %q, want empty", got)
	}
	if got := (&Resolved{}).Digest(); got != "" {
		t.Errorf("empty.Digest() = %q, want empty", got)
	}
}

// A file that cannot be read has no digest, and losing one is not a reason to fail a scan.
func TestUnreadableFileHasNoDigest(t *testing.T) {
	if got := digestFile(filepath.Join(t.TempDir(), "absent.yaml")); got != "" {
		t.Errorf("digestFile(absent) = %q, want empty", got)
	}
}

// The digest is only worth something to somebody who can reproduce it. Shipping the bytes it is
// taken over is what makes it checkable rather than a number a reader has to trust.
func TestTheDigestIsReproducibleFromTheEffectiveDescriptor(t *testing.T) {
	res, err := ResolveFile(writePair(t, rootWithFragment, "config: {exclude: [{rules: [a], reason: r}]}"), nil)
	if err != nil {
		t.Fatal(err)
	}
	effective := res.Effective()
	if effective == "" {
		t.Fatal("no effective descriptor")
	}
	sum := sha256.Sum256([]byte(effective))
	if want := "sha256:" + hex.EncodeToString(sum[:]); res.Digest() != want {
		t.Errorf("the digest does not describe the bytes shipped beside it:\n got %s\nwant %s",
			res.Digest(), want)
	}
}

// It is the merged form, so it carries what the fragments contributed. A reader asking why a
// finding was suppressed is asking about a rule that may not be in the file they have open.
func TestTheEffectiveDescriptorCarriesTheFragments(t *testing.T) {
	res, err := ResolveFile(writePair(t, rootWithFragment,
		"config: {exclude: [{rules: [CVE-2024-9999], reason: waiting on upstream}]}"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Effective(), "CVE-2024-9999") {
		t.Errorf("a fragment's exclusion is not in the effective descriptor:\n%s", res.Effective())
	}
}

// A descriptor never carries a credential — the schema has a field for the name of an environment
// variable and none for a value. This is the assertion that keeps that true of what is published.
func TestTheEffectiveDescriptorCarriesNoCredential(t *testing.T) {
	const withAuth = `
project: p
release: {version: "1"}
components:
  - name: c
    hosts:
      - name: api
        url: https://api.example.com
        auth: {type: bearer, tokenEnv: SECRET_TOKEN}
`
	t.Setenv("SECRET_TOKEN", "a-real-looking-credential-value")
	res, err := ResolveFile(writePair(t, withAuth, ""), nil)
	if err != nil {
		t.Fatal(err)
	}
	effective := res.Effective()
	if strings.Contains(effective, "a-real-looking-credential-value") {
		t.Errorf("the credential reached the effective descriptor:\n%s", effective)
	}
	if !strings.Contains(effective, "SECRET_TOKEN") {
		t.Error("the variable's name should survive: it says where the credential came from")
	}
}

// Two spaces, because that is what every descriptor anybody writes uses and what the reference
// shows. The effective text is the copy a reader is asked to compare against the file they have
// open, and four-space output does not look like that file.
func TestTheEffectiveDescriptorIsIndentedLikeADescriptor(t *testing.T) {
	res, err := ResolveFile(writePair(t, rootWithFragment, "config: {exclude: [{rules: [a], reason: r}]}"), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(res.Effective(), "\n") {
		trimmed := strings.TrimLeft(line, " ")
		if trimmed == "" {
			continue
		}
		if indent := len(line) - len(trimmed); indent%2 != 0 {
			t.Errorf("line indented by %d, which is not a multiple of two: %q", indent, line)
		}
	}
	// The nesting every descriptor has, at the depth it should be.
	if !strings.Contains(res.Effective(), "\n  - name: c") {
		t.Errorf("a component is not indented two spaces:\n%s", res.Effective())
	}
}
