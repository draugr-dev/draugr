package credential

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/draugr-dev/draugr/pkg/saga"
)

func TestADescriptorNamesOnlyTheOwnVariableOrAListedOne(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "own")
	t.Setenv("GH_ISSUES", "listed")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "aws-secret")
	t.Setenv(TokenEnvsVar, " ,STAGING_TOKEN, GH_ISSUES ,")

	for _, tc := range []struct {
		named, def, wantName, wantValue string
		refused                         bool
	}{
		{"", "GITHUB_TOKEN", "GITHUB_TOKEN", "own", false},
		{"  ", "GITHUB_TOKEN", "GITHUB_TOKEN", "own", false},
		{"GITHUB_TOKEN", "GITHUB_TOKEN", "GITHUB_TOKEN", "own", false},
		{"GH_ISSUES", "GITHUB_TOKEN", "GH_ISSUES", "listed", false},
		{"GH_ISSUES", "", "GH_ISSUES", "listed", false},
		{"AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "AWS_SECRET_ACCESS_KEY", "", true},
		{"AWS_SECRET_ACCESS_KEY", "", "AWS_SECRET_ACCESS_KEY", "", true},
	} {
		name, value, err := Token(tc.named, tc.def)
		var refused *RefusedVariableError
		if got := errors.As(err, &refused); got != tc.refused {
			t.Errorf("Token(%q, %q) err = %v, want refused: %v", tc.named, tc.def, err, tc.refused)
		}
		if name != tc.wantName || value != tc.wantValue {
			t.Errorf("Token(%q, %q) = %q, %q, want %q, %q", tc.named, tc.def, name, value, tc.wantName, tc.wantValue)
		}
		if err != nil && strings.Contains(err.Error(), "aws-secret") {
			t.Errorf("the refusal printed the value: %v", err)
		}
	}
}

func TestARefusalSaysWhatToSet(t *testing.T) {
	t.Setenv(TokenEnvsVar, "")
	_, err := Variable("AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN")
	want := "tokenEnv: $AWS_SECRET_ACCESS_KEY is neither $GITHUB_TOKEN, this publisher's own variable, nor listed in " +
		"$DRAUGR_TOKEN_ENVS. Set DRAUGR_TOKEN_ENVS=AWS_SECRET_ACCESS_KEY in the pipeline's environment (comma-separated for several)"
	if err == nil || err.Error() != want {
		t.Errorf("err = %v\nwant  %s", err, want)
	}
	_, err = Variable("STAGING_TOKEN", "")
	want = "tokenEnv: $STAGING_TOKEN is not listed in $DRAUGR_TOKEN_ENVS. " +
		"Set DRAUGR_TOKEN_ENVS=STAGING_TOKEN in the pipeline's environment (comma-separated for several)"
	if err == nil || err.Error() != want {
		t.Errorf("an integration with no variable of its own: %v\nwant  %s", err, want)
	}
}

func TestAnAddressInClearTextSaysWhatToUse(t *testing.T) {
	err := RequireTLS("http://user:pw@draugr.example/v1")
	want := "http://user:xxxxx@draugr.example/v1 is not https. A credential is sent only over https, or http to " +
		"localhost, 127.0.0.0/8 or ::1; use an https address"
	if err == nil || err.Error() != want || !errors.Is(err, ErrInsecure) {
		t.Errorf("err = %v\nwant  %s", err, want)
	}
}

func TestOrigin(t *testing.T) {
	for raw, want := range map[string]string{
		"https://Draugr.Example/v1/runs?x=1": "https://draugr.example",
		"https://draugr.example:443/":        "https://draugr.example",
		"http://draugr.example:80":           "http://draugr.example",
		"https://draugr.example:8443/path":   "https://draugr.example:8443",
		"http://[::1]:8080/":                 "http://[::1]:8080",
		"https://[2001:db8::1]/":             "https://[2001:db8::1]",
		" https://draugr.example ":           "https://draugr.example",
	} {
		got, err := Origin(raw)
		if err != nil || got != want {
			t.Errorf("Origin(%q) = %q, %v, want %q", raw, got, err, want)
		}
	}
	for _, raw := range []string{"ftp://draugr.example", "draugr.example", "https://", "https://%zz", ":"} {
		if got, err := Origin(raw); err == nil {
			t.Errorf("Origin(%q) = %q, want an error", raw, got)
		}
	}
}

func TestRequireTLS(t *testing.T) {
	for raw, ok := range map[string]bool{
		"https://draugr.example":     true,
		"HTTPS://draugr.example":     true,
		"http://localhost:8080":      true,
		"http://LOCALHOST":           true,
		"http://127.0.0.1:8080":      true,
		"http://127.8.9.10":          true,
		"http://[::1]:8080":          true,
		"http://draugr.example":      false,
		"http://10.0.0.1":            false,
		"http://localhost.attacker.": false,
		"ftp://localhost":            false,
		"https://%zz":                false,
	} {
		err := RequireTLS(raw)
		if (err == nil) != ok {
			t.Errorf("RequireTLS(%q) = %v, want allowed: %v", raw, err, ok)
		}
		if err != nil && !strings.Contains(raw, "%") && !errors.Is(err, ErrInsecure) {
			t.Errorf("RequireTLS(%q) = %v, want ErrInsecure", raw, err)
		}
	}
}

func TestGuardRefusesOnlyACredentialInClearText(t *testing.T) {
	req := func(raw string, header ...string) *http.Request {
		r, err := http.NewRequest(http.MethodGet, raw, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(header) == 2 {
			r.Header.Set(header[0], header[1])
		}
		return r
	}
	for _, tc := range []struct {
		req     *http.Request
		refused bool
	}{
		{req("http://storage.example/bucket?X-Amz-Signature=abc"), false},
		{req("http://draugr.example/v1/runs", "Authorization", "Bearer x"), true},
		{req("http://gitlab.example/api/v4", "PRIVATE-TOKEN", "x"), true},
		{req("https://draugr.example/v1/runs", "Authorization", "Bearer x"), false},
		{req("http://127.0.0.1:9/v1/runs", "Authorization", "Bearer x"), false},
		{&http.Request{Header: http.Header{"Authorization": {"x"}}}, false},
	} {
		if err := Guard(tc.req); (err != nil) != tc.refused {
			t.Errorf("Guard(%v %v) = %v, want refused: %v", tc.req.URL, tc.req.Header, err, tc.refused)
		}
	}
}

func TestCheckRedirect(t *testing.T) {
	at := func(raw string, auth bool) *http.Request {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		r := &http.Request{URL: u, Header: http.Header{}}
		if auth {
			r.Header.Set("Authorization", "Bearer x")
		}
		return r
	}
	for name, tc := range map[string]struct {
		next    string
		first   *http.Request
		refused bool
	}{
		"no credential, another origin": {"https://storage.example/b", at("https://draugr.example/v1", false), false},
		"a credential, the same origin": {"https://draugr.example:443/v1/", at("https://draugr.example/v1", true), false},
		"a credential, another host":    {"https://attacker.example/v1", at("https://draugr.example/v1", true), true},
		"a credential, another port":    {"https://draugr.example:8443/v1", at("https://draugr.example/v1", true), true},
		"a credential, another scheme":  {"http://draugr.example/v1", at("https://draugr.example/v1", true), true},
		"a credential, an odd scheme":   {"ftp://draugr.example/v1", at("https://draugr.example/v1", true), true},
	} {
		err := CheckRedirect(at(tc.next, false), []*http.Request{tc.first})
		if (err != nil) != tc.refused {
			t.Errorf("%s: err = %v, want refused: %v", name, err, tc.refused)
		}
	}
	via := make([]*http.Request, maxRedirects)
	for i := range via {
		via[i] = at("https://draugr.example/v1", false)
	}
	if err := CheckRedirect(at("https://draugr.example/v1", false), via); err == nil {
		t.Error("an eleventh redirect was followed")
	}
}

// Through a real client, both ways: a request carrying a token is refused where the redirect leaves
// its origin, and the other server is never asked; one carrying none follows it as before.
func TestAClientKeepsATokenToItsOrigin(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	elsewhere := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Header.Get("Authorization"))
		mu.Unlock()
	}))
	t.Cleanup(elsewhere.Close)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+"/upload", http.StatusTemporaryRedirect)
	}))
	t.Cleanup(origin.Close)

	client := Client(nil)
	withToken, _ := http.NewRequest(http.MethodGet, origin.URL, nil)
	withToken.Header.Set("Authorization", "Bearer secret")
	if resp, err := client.Do(withToken); err == nil {
		_ = resp.Body.Close()
		t.Fatal("a redirect to another origin was followed with the token")
	}
	mu.Lock()
	if len(seen) != 0 {
		t.Errorf("the other origin got %v", seen)
	}
	mu.Unlock()

	plain, _ := http.NewRequest(http.MethodGet, origin.URL, nil)
	resp, err := client.Do(plain)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 1 || seen[0] != "" {
		t.Errorf("a request with no token should follow the redirect: %v", seen)
	}
}

func TestClientKeepsTheCallersSettings(t *testing.T) {
	base := &http.Client{Timeout: 42}
	got := Client(base)
	if got == base || got.Timeout != 42 || got.CheckRedirect == nil || base.CheckRedirect != nil {
		t.Errorf("Client = %+v from %+v", got, base)
	}
}

// credentialFields are the descriptor fields that name an environment variable holding a
// credential, and where each is read.
//
// A new one fails TestEveryCredentialFieldIsKnown until it is added here, and its Go name has to
// be TokenEnv so TestEveryTokenEnvIsReadThroughHere sees every read of it.
//
// #nosec G101 -- descriptor field names and where they are read, not credentials.
var credentialFields = map[string]string{
	"PublisherConfig.tokenEnv": "pkg/publish tokenFor and ResolveAPI",
	"HostAuth.tokenEnv":        "internal/scanners authHeader",
}

func TestEveryCredentialFieldIsKnown(t *testing.T) {
	found := map[string]string{}
	seen := map[reflect.Type]bool{}
	var walk func(reflect.Type)
	walk = func(t reflect.Type) {
		for t.Kind() == reflect.Pointer || t.Kind() == reflect.Slice || t.Kind() == reflect.Array || t.Kind() == reflect.Map {
			t = t.Elem()
		}
		if t.Kind() != reflect.Struct || seen[t] {
			return
		}
		seen[t] = true
		for i := range t.NumField() {
			f := t.Field(i)
			key, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
			if strings.HasSuffix(key, "Env") {
				found[t.Name()+"."+key] = f.Name
			}
			walk(f.Type)
		}
	}
	walk(reflect.TypeOf(saga.Model{}))
	walk(reflect.TypeOf(saga.Fragment{}))

	for field, goName := range found {
		if _, ok := credentialFields[field]; !ok {
			t.Errorf("%s names an environment variable and is not in credentialFields. Read it through "+
				"credential.Token so %s applies to it, and add it there", field, TokenEnvsVar)
		}
		if goName != "TokenEnv" {
			t.Errorf("%s is the Go field %s; name it TokenEnv so TestEveryTokenEnvIsReadThroughHere checks its reads", field, goName)
		}
	}
	for field := range credentialFields {
		if _, ok := found[field]; !ok {
			t.Errorf("credentialFields lists %s, which the descriptor no longer has", field)
		}
	}
}

// carriesTheName are the functions that read a TokenEnv field for its name alone, never to look the
// variable up. Every other read must be an argument to Token or Variable.
var carriesTheName = map[string]string{
	"pkg/saga/validate.go validateHostAuth":        "requires the field to be written",
	"pkg/plugin/target.go Marker":                  "keys two jobs against one endpoint apart",
	"internal/controllers/dast.go hostAuth":        "copies the descriptor's block into the scanner's",
	"internal/scanners/nuclei.go nucleiProvenance": "records which variable authenticated the scan",
}

func TestEveryTokenEnvIsReadThroughHere(t *testing.T) {
	root := filepath.Join("..", "..")
	used := map[string]bool{}
	for _, dir := range []string{"pkg", "internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					return fs.SkipDir
				}
				return err
			}
			if d.IsDir() && d.Name() == "testdata" {
				return fs.SkipDir
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			rel, _ := filepath.Rel(root, path)
			rel = filepath.ToSlash(rel)
			for _, at := range tokenEnvReads(t, path) {
				if at.inLookup {
					continue
				}
				key := rel + " " + at.fn
				if _, ok := carriesTheName[key]; ok {
					used[key] = true
					continue
				}
				t.Errorf("%s:%d reads a TokenEnv field outside credential.Token. Pass it to credential.Token "+
					"so %s applies, or add %q to carriesTheName if it only carries the name", rel, at.line, TokenEnvsVar, key)
			}
			return nil
		})
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			t.Fatal(err)
		}
	}
	for key := range carriesTheName {
		if !used[key] {
			t.Errorf("carriesTheName lists %q, which reads no TokenEnv field any more", key)
		}
	}
}

type tokenEnvRead struct {
	fn       string
	line     int
	inLookup bool
}

// tokenEnvReads finds every `x.TokenEnv` in a file, the function it is in, and whether it is an
// argument to a call of Token or Variable.
func tokenEnvReads(t *testing.T, path string) []tokenEnvRead {
	t.Helper()
	src, err := os.ReadFile(path) // #nosec G304 -- a file in this repository
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, src, 0)
	if err != nil {
		t.Fatal(err)
	}
	var out []tokenEnvRead
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		lookups := map[ast.Expr]bool{}
		ast.Inspect(fn, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if ok && slices.Contains([]string{"Token", "Variable"}, calleeName(call.Fun)) {
				for _, arg := range call.Args {
					lookups[arg] = true
				}
			}
			return true
		})
		ast.Inspect(fn, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if ok && sel.Sel.Name == "TokenEnv" {
				out = append(out, tokenEnvRead{fn: fn.Name.Name, line: fset.Position(sel.Pos()).Line, inLookup: lookups[sel]})
			}
			return true
		})
	}
	return out
}

func calleeName(fun ast.Expr) string {
	switch f := fun.(type) {
	case *ast.Ident:
		return f.Name
	case *ast.SelectorExpr:
		if pkg, ok := f.X.(*ast.Ident); ok && pkg.Name == "credential" {
			return f.Sel.Name
		}
	}
	return ""
}
