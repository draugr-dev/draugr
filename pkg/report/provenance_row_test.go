package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/tui"
)

// An image signed by an identity no signer names: the title line ends with the signer that was
// expected, whole, and the line beneath gives the identity under the keys a GitHub signer takes, in
// the descriptor's own values where they fit, so each pastes into the signer, and shortened where not.
func TestAnUnexpectedSignerRowNamesTheIdentityByTheSignersKeys(t *testing.T) {
	f := finding{
		priority: "P1", severity: "critical", ruleID: "provenance-unexpected-identity",
		message: "Signed by chainguard-images/images/.github/workflows/release.yaml@refs/heads/main, not our-ci.",
	}
	for _, c := range []struct {
		width int
		want  string
	}{
		{160, "      repository chainguard-images/images · workflow .github/workflows/release.yaml · ref refs/heads/main\n"},
		{80, "      repository chainguard-images/images · workflow release.yaml · ref main\n"},
	} {
		var b bytes.Buffer
		writeBlockHead(&b, tui.Plain(), f, c.width)
		got := b.String()
		if !strings.Contains(got, "provenance-unexpected-identity · not our-ci\n") || !strings.Contains(got, c.want) {
			t.Errorf("at %d columns:\n%s\nwant the signer on the title line and %q", c.width, got, c.want)
		}
		for _, line := range strings.Split(strings.TrimSuffix(got, "\n"), "\n") {
			if len([]rune(line)) > c.width {
				t.Errorf("at %d columns a line is %d wide: %q", c.width, len([]rune(line)), line)
			}
		}
	}
}

// An identity that is not a GitHub workflow's is printed as it is, and a message in another form,
// such as Notation's, keeps the row it always had.
func TestOtherSignersKeepTheirOwnWords(t *testing.T) {
	email := finding{priority: "P1", severity: "critical", ruleID: "provenance-unexpected-identity",
		message: "Signed by release-bot@example.com, not our-ci."}
	var b bytes.Buffer
	writeBlockHead(&b, tui.Plain(), email, 80)
	if !strings.Contains(b.String(), "      signed by release-bot@example.com\n") {
		t.Errorf("an email identity reads:\n%s", b.String())
	}
	notation := finding{priority: "P1", severity: "critical", ruleID: "provenance-unexpected-identity",
		message: "Signed by a certificate whose subject is not the x509.subject of signer our-ci."}
	if _, _, ok := unexpectedSigner(notation); ok {
		t.Error("a Notation message was read as a signer and an identity")
	}
	if _, _, ok := unexpectedSigner(finding{ruleID: "provenance-unsigned", message: "Signed by x, not y."}); ok {
		t.Error("another rule's message was read as an unexpected signer")
	}
}
