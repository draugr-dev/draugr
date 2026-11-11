package scanners

import (
	"context"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/credential"
	"github.com/draugr-dev/draugr/pkg/plugin"
)

// loginSpec is the document from https://github.com/draugr-dev/draugr/issues/1959: one POST whose
// response is JSON.
const loginSpec = `openapi: 3.0.3
info: {title: login, version: '1'}
paths:
  /rest/user/login:
    post:
      requestBody:
        content:
          application/json:
            schema: {type: object}
      responses:
        '200':
          description: ok
          content:
            application/json:
              schema: {type: object}
`

func TestDeclaresJSONResponse(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name, media string
		want        bool
	}{
		{"application/json", "application/json", true},
		{"a parameter after the type", "application/json; charset=utf-8", true},
		{"a +json type", "application/problem+json", true},
		{"HTML", "text/html", false},
	} {
		doc := strings.ReplaceAll(loginSpec, "            application/json:\n              schema: {type: object}\n",
			"            "+c.media+":\n              schema: {type: object}\n")
		got, err := prepareSpec(writeSpec(t, doc), "https://api.example.com", []string{"post"})
		if err != nil {
			t.Fatal(err)
		}
		got.Cleanup()
		if got.JSON != c.want {
			t.Errorf("%s: JSON = %v, want %v", c.name, got.JSON, c.want)
		}
	}
	// An operation the scan leaves out does not decide what the scan asks for.
	got, err := prepareSpec(writeSpec(t, loginSpec), "https://api.example.com", []string{"get"})
	if err == nil {
		got.Cleanup()
		t.Fatal("a document with no allowed operation should be refused")
	}
}

// headersOf runs a spec scan and returns, for each Nuclei run, the header file's lines, read while
// the run is going (Scan removes the file when it returns).
func headersOf(t *testing.T, target plugin.HostTarget) [][]string {
	t.Helper()
	var got [][]string
	s := nucleiScanner{
		info: plugin.ScannerInfo{Name: "nuclei"},
		run: func(_ context.Context, argv []string) ([]byte, error) {
			var lines []string
			if i := slices.Index(argv, "-H"); i >= 0 {
				body, err := os.ReadFile(argv[i+1])
				if err != nil {
					t.Fatal(err)
				}
				lines = strings.Split(strings.TrimSpace(string(body)), "\n")
			}
			got = append(got, lines)
			return nil, nil
		},
	}
	if _, err := s.Scan(context.Background(), target, nil); err != nil {
		t.Fatal(err)
	}
	return got
}

// The spec run asks for JSON when the document declares it; the default templates' run does not.
func TestASpecScanAsksForTheJSONItsDocumentDeclares(t *testing.T) {
	target := plugin.HostTarget{URL: "https://api.example.com",
		Spec: &plugin.HostSpec{Path: writeSpec(t, loginSpec), Methods: []string{"post"}}}
	got := headersOf(t, target)
	if len(got) != 2 || len(got[0]) != 0 || !slices.Equal(got[1], []string{specAccept}) {
		t.Errorf("headers per run = %q, want none on the default run and Accept on the spec run", got)
	}

	// A credential travels on both runs, and the spec run carries Accept beside it.
	t.Setenv("DRAUGR_TEST_ACCEPT_TOKEN", "aaaaaaaa")
	t.Setenv(credential.TokenEnvsVar, "DRAUGR_TEST_ACCEPT_TOKEN")
	target.Auth = &plugin.HostAuth{Kind: "bearer", TokenEnv: "DRAUGR_TEST_ACCEPT_TOKEN"} // #nosec G101 -- the name of an environment variable
	got = headersOf(t, target)
	if len(got) != 2 || len(got[0]) != 1 || !strings.HasPrefix(got[0][0], "Authorization: ") ||
		len(got[1]) != 2 || got[1][0] != got[0][0] || got[1][1] != specAccept {
		t.Errorf("headers per run = %q, want the credential on both and Accept beside it on the spec run", got)
	}

	// A document that declares no JSON leaves the spec run's request as it was.
	html := strings.ReplaceAll(loginSpec, "            application/json:\n              schema: {type: object}\n",
		"            text/html:\n              schema: {type: string}\n")
	target = plugin.HostTarget{URL: "https://api.example.com",
		Spec: &plugin.HostSpec{Path: writeSpec(t, html), Methods: []string{"post"}}}
	if got := headersOf(t, target); len(got) != 2 || len(got[1]) != 0 {
		t.Errorf("headers per run = %q, want no Accept for a document declaring no JSON", got)
	}
}
