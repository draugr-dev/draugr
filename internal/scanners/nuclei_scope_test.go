package scanners

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/netpolicy"
	"github.com/draugr-dev/draugr/pkg/plugin"
)

// Each case holds the lines that decide it, from community templates v10.5.1: rdap-whois,
// azure-domain-tenant, github-personal-access, CVE-2024-6396, apache-mesos-panel, CVE-2025-12101 and
// CVE-2026-73570 on one side.
func TestNucleiTemplateReaches(t *testing.T) {
	for _, c := range []struct {
		name, text string
		want       bool
	}{
		{"a fixed outside host carrying the target", "http:\n  - method: GET\n    path:\n      - \"https://www.rdap.net/domain/{{Host}}\"\n", true},
		{"a raw request to a fixed outside host", "http:\n  - raw:\n      - |\n        @Host: https://login.microsoftonline.com:443\n        GET /{{Host}}/v2.0/.well-known/openid-configuration HTTP/1.1\n", true},
		{"a credential found on the target, checked outside", "http:\n  - method: GET\n    path:\n      - \"{{BaseURL}}\"\n  - raw:\n      - |\n        @Host: https://api.github.com:443\n        GET /user HTTP/1.1\n", true},
		{"a raw request to another port", "http:\n  - raw:\n      - |\n        @Host: http://{{Host}}:43800\n        GET / HTTP/1.1\n", true},
		{"a path on another port", "http:\n  - method: GET\n    path:\n      - \"http://{{Hostname}}:5050\"\n", true},
		{"a raw request to this machine", "http:\n  - raw:\n      - |\n        @Host: localhost\n        GET /nginx_status HTTP/1.1\n", true},

		{"a JavaScript block beside an HTTP one, which -ept passes", "javascript:\n  - args:\n      Host: \"{{Host}}\"\n      Port: 443\nhttp:\n  - raw:\n      - |\n        GET / HTTP/1.1\n        Host: {{Hostname}}\n", true},
		{"a tcp block beside an HTTP one", "http:\n  - raw:\n      - |\n        GET / HTTP/1.1\ntcp:\n  - host:\n      - \"{{Hostname}}\"\n", true},

		{"a JavaScript template alone, which -ept leaves out", "javascript:\n  - args:\n      Port: 6379\n", false},
		{"the URL", "http:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/admin\"\n      - \"{{RootURL}}/admin\"\n", false},
		{"the URL's own port", "http:\n  - raw:\n      - |\n        @Host: {{Hostname}}\n        GET / HTTP/1.1\n", false},
		{"a reference, which is a link and no request", "info:\n  reference:\n    - https://www.rdap.net/about\nhttp:\n  - method: GET\n    path:\n      - \"{{BaseURL}}\"\n", false},
		{"a reference after a path", "http:\n  - method: GET\n    path:\n      - \"{{BaseURL}}\"\n    matchers:\n      - type: word\nreference:\n  - https://example.com\n", false},
		{"self-contained, which is not loaded", "self-contained: true\nhttp:\n  - raw:\n      - |\n        @Host: https://api.abuseipdb.com:443\n        GET / HTTP/1.1\n", false},
	} {
		if got := nucleiTemplateReaches([]byte(c.text)); got != c.want {
			t.Errorf("%s = %v, want %v", c.name, got, c.want)
		}
	}
}

func writeTemplates(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, text := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil { // #nosec G703 -- under the test's own temp directory
			t.Fatal(err)
		}
	}
	return dir
}

const (
	reachingTemplate = "id: rdap-whois\nhttp:\n  - path:\n      - \"https://www.rdap.net/domain/{{Host}}\"\n"
	localTemplate    = "id: exposed-admin\nhttp:\n  - path:\n      - \"{{BaseURL}}/admin\"\n"
)

// The list is the set's, sorted and once each, so the same set gives the same command line. Only a
// template is read: the hidden directories and other files in the set are not.
func TestNucleiReachingTemplatesListsTheSet(t *testing.T) {
	dir := writeTemplates(t, map[string]string{
		"http/z.yaml":         reachingTemplate,
		"http/a.yaml":         "id: another\nhttp:\n  - raw:\n      - |\n        @Host: https://example.com:443\n",
		"http/copy.yaml":      reachingTemplate,
		"http/local.yaml":     localTemplate,
		"http/no-id.yaml":     "http:\n  - raw:\n      - |\n        @Host: https://example.com:443\n",
		"http/readme.md":      reachingTemplate,
		".github/action.yaml": "id: hidden\nhttp:\n  - raw:\n      - |\n        @Host: https://example.com:443\n",
	})
	got, err := nucleiReachingTemplates(dir)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"another", "rdap-whois"}; !slices.Equal(got, want) {
		t.Errorf("ids = %v, want %v", got, want)
	}
	if _, err := nucleiReachingTemplates(filepath.Join(dir, "missing")); err == nil {
		t.Error("a missing directory reads as no templates")
	}
}

// templatesVersionOutput is `nuclei -templates-version`, as internal/tools reads it.
func templatesVersionOutput(dir string) []byte {
	return []byte("[INF] Public nuclei-templates version: v10.5.1 (" + dir + ")\n")
}

// A default scan leaves out what reaches past the URL, by the types and by the installed set, asks the
// machine's resolvers, and says what it left out. The second host of a run reads the set once.
func TestNucleiScanStaysOnTheURL(t *testing.T) {
	dir := writeTemplates(t, map[string]string{"a.yaml": reachingTemplate, "b.yaml": localTemplate})
	resolv := filepath.Join(t.TempDir(), "resolv.conf")
	if err := os.WriteFile(resolv, []byte("# stub\nnameserver 10.0.0.2\nnameserver fd00::1\noptions edns0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	asked := 0
	var resolvers string
	var argv []string
	s := nucleiScanner{
		info: plugin.ScannerInfo{Name: "nuclei"},
		run: func(_ context.Context, a []string) ([]byte, error) {
			argv = a
			if i := slices.Index(a, "-r"); i >= 0 {
				data, err := os.ReadFile(a[i+1])
				if err != nil {
					t.Fatal(err)
				}
				resolvers = string(data)
			}
			return nil, nil
		},
		templates: &nucleiTemplateWarmer{run: func(context.Context, []string) ([]byte, error) {
			asked++
			return templatesVersionOutput(dir), nil
		}},
		resolvConf: resolv,
	}
	report, err := s.Scan(context.Background(), plugin.HostTarget{URL: "http://app.internal:8080/"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := flagValue(argv, "-ept"); got != "javascript,tcp" {
		t.Errorf("-ept = %q: %v", got, argv)
	}
	if got, _ := flagValue(argv, "-eid"); got != "rdap-whois" {
		t.Errorf("-eid = %q: %v", got, argv)
	}
	if want := "10.0.0.2:53\n[fd00::1]:53\n"; resolvers != want {
		t.Errorf("resolvers = %q, want %q", resolvers, want)
	}
	if path, _ := flagValue(argv, "-r"); path != "" {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("the resolver file stayed behind: %v", err)
		}
	}
	got := report.Provenance[0].Describe()
	if !strings.Contains(got, "left out: javascript and tcp templates; 1 template naming another host or port") {
		t.Errorf("provenance = %q", got)
	}
	if _, err := s.Scan(context.Background(), plugin.HostTarget{URL: "http://other.internal:8080/"}, nil); err != nil {
		t.Fatal(err)
	}
	if asked != 1 {
		t.Errorf("the set was read %d times", asked)
	}
}

// A template the descriptor names runs as written: -ept and -eid would drop it with nothing said, and
// the report does not claim anything was left out.
func TestNucleiNamedTemplatesRunAsWritten(t *testing.T) {
	var argv []string
	s := nucleiScanner{
		info: plugin.ScannerInfo{Name: "nuclei"},
		run:  func(_ context.Context, a []string) ([]byte, error) { argv = a; return nil, nil },
		templates: &nucleiTemplateWarmer{run: func(context.Context, []string) ([]byte, error) {
			t.Error("the community set was read")
			return nil, nil
		}},
	}
	report, err := s.Scan(context.Background(), plugin.HostTarget{URL: "https://x.example.com"},
		plugin.Config{"templates": []any{"mine.yaml"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, flag := range []string{"-ept", "-eid"} {
		if slices.Contains(argv, flag) {
			t.Errorf("%s is on the command line: %v", flag, argv)
		}
	}
	if got := report.Provenance[0].Describe(); strings.Contains(got, "left out") {
		t.Errorf("provenance = %q", got)
	}
}

// A set that cannot be read stops the scan before a request, because the alternative is a scan that
// reaches further than it says.
func TestNucleiStopsWhenItCannotReadTheSet(t *testing.T) {
	for name, answer := range map[string]func(context.Context, []string) ([]byte, error){
		"nuclei fails":  func(context.Context, []string) ([]byte, error) { return nil, errors.New("boom") },
		"no directory":  func(context.Context, []string) ([]byte, error) { return []byte("nothing useful"), nil },
		"a missing dir": func(context.Context, []string) ([]byte, error) { return templatesVersionOutput("/does/not/exist"), nil },
	} {
		ran := false
		s := nucleiScanner{
			info:      plugin.ScannerInfo{Name: "nuclei"},
			run:       func(context.Context, []string) ([]byte, error) { ran = true; return nil, nil },
			templates: &nucleiTemplateWarmer{run: answer},
		}
		_, err := s.Scan(context.Background(), plugin.HostTarget{URL: "https://x.example.com"}, nil)
		if err == nil || !strings.Contains(err.Error(), "could not read the template set") {
			t.Errorf("%s: err = %v", name, err)
		}
		if ran {
			t.Errorf("%s: nuclei ran", name)
		}
	}
}

// With no resolver to name, an ordinary run says it used Nuclei's list, and an offline run refuses,
// because it promises to contact nothing besides its targets.
func TestNucleiWithNoResolverToName(t *testing.T) {
	var argv []string
	s := nucleiScanner{
		info:       plugin.ScannerInfo{Name: "nuclei"},
		run:        func(_ context.Context, a []string) ([]byte, error) { argv = a; return nil, nil },
		resolvConf: filepath.Join(t.TempDir(), "missing"),
	}
	report, err := s.Scan(context.Background(), plugin.HostTarget{URL: "https://x.example.com"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(argv, "-r") {
		t.Errorf("argv = %v", argv)
	}
	if got := report.Provenance[0].Describe(); !strings.Contains(got, "resolvers: Nuclei's built-in public servers") {
		t.Errorf("provenance = %q", got)
	}

	netpolicy.SetOffline(true)
	defer netpolicy.SetOffline(false)
	argv = nil
	_, err = s.Scan(context.Background(), plugin.HostTarget{URL: "https://x.example.com"}, nil)
	if err == nil || !strings.Contains(err.Error(), "names no DNS resolver") {
		t.Errorf("offline = %v", err)
	}
	if argv != nil {
		t.Errorf("nuclei ran offline: %v", argv)
	}
}

func TestNewNucleiReadsTheMachinesResolvers(t *testing.T) {
	if s := NewNuclei().(nucleiScanner); s.resolvConf != nucleiResolvConf {
		t.Errorf("resolvConf = %q", s.resolvConf)
	}
}

// Against the installed set, where there is one: what the search found on v10.5.1 is on the list, and
// the template every scan needs is not. Nothing here reaches the network.
func TestNucleiReachingTemplatesOnTheInstalledSet(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip(err)
	}
	dir := filepath.Join(home, "nuclei-templates")
	if _, err := os.Stat(filepath.Join(dir, "http")); err != nil {
		t.Skip("no template set installed")
	}
	got, err := nucleiReachingTemplates(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%d templates: %s", len(got), strings.Join(got, " "))
	for _, id := range []string{"rdap-whois", "azure-domain-tenant", "github-personal-access", "CVE-2024-6396", "CVE-2025-12101", "CVE-2020-2883"} {
		if !slices.Contains(got, id) {
			t.Errorf("%s is not on the list", id)
		}
	}
	if slices.Contains(got, "tech-detect") {
		t.Error("tech-detect is on the list")
	}
}
