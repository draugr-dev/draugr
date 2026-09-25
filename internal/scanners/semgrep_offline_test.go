package scanners

import (
	"context"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
)

// semgrepOver is the real Semgrep scanner with the checkout and the exec replaced, recording the
// ruleset of every invocation.
func semgrepOver(t *testing.T) (repoScanner, *[]string) {
	t.Helper()
	s := NewSemgrep().(repoScanner)
	s.checkout = fakeCheckout
	var ran []string
	s.run = func(_ context.Context, _ string, argv []string) ([]byte, error) {
		for i, a := range argv {
			if a == "--config" && i+1 < len(argv) {
				ran = append(ran, argv[i+1])
			}
		}
		return []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"semgrep"}},"results":[]}]}`), nil
	}
	return s, &ran
}

var twoRepositories = []plugin.RepositoryTarget{
	{URL: "https://example.com/api.git"},
	{URL: "https://example.com/worker.git"},
}

func TestSemgrepRefusesARemoteRulesetOffline(t *testing.T) {
	t.Setenv("SEMGREP_URL", "")
	for _, c := range []struct {
		name string
		cfg  plugin.Config
		want string
	}{
		{"default", nil, "semgrep: cannot run offline: config.controls.sast.semgrep.config is unset, " +
			"and Semgrep fetches its default, p/default, from semgrep.dev; set it to a rules file or directory on disk"},
		{"empty", plugin.Config{"config": ""}, "semgrep: cannot run offline: config.controls.sast.semgrep.config " +
			"is unset, and Semgrep fetches its default, p/default, from semgrep.dev; set it to a rules file or " +
			"directory on disk"},
		{"registry pack", plugin.Config{"config": "p/owasp-top-ten"}, "semgrep: cannot run offline: " +
			"config.controls.sast.semgrep.config is p/owasp-top-ten, which Semgrep fetches from semgrep.dev; " +
			"set it to a rules file or directory on disk"},
		{"url", plugin.Config{"config": "https://rules.example.com/team.yaml"}, "semgrep: cannot run offline: " +
			"config.controls.sast.semgrep.config is https://rules.example.com/team.yaml, which Semgrep fetches " +
			"from rules.example.com; set it to a rules file or directory on disk"},
	} {
		t.Run(c.name, func(t *testing.T) {
			offline(t)
			s, ran := semgrepOver(t)
			for _, repo := range twoRepositories {
				_, err := s.Scan(context.Background(), repo, c.cfg)
				if err == nil {
					t.Fatalf("%s: scanned offline with a ruleset Semgrep fetches", repo.URL)
				}
				if err.Error() != c.want {
					t.Errorf("%s: err = %q\nwant %q", repo.URL, err, c.want)
				}
			}
			if len(*ran) != 0 {
				t.Errorf("semgrep ran %v, want no invocation offline", *ran)
			}
		})
	}
}

func TestSemgrepNamesTheConfiguredRegistryHost(t *testing.T) {
	offline(t)
	t.Setenv("SEMGREP_URL", "https://semgrep.internal.example:8443")
	s, _ := semgrepOver(t)
	_, err := s.Scan(context.Background(), twoRepositories[0], plugin.Config{"config": "r/python.lang.security"})
	want := "semgrep: cannot run offline: config.controls.sast.semgrep.config is r/python.lang.security, " +
		"which Semgrep fetches from semgrep.internal.example:8443; set it to a rules file or directory on disk"
	if err == nil || err.Error() != want {
		t.Errorf("err = %v\nwant %s", err, want)
	}
}

func TestSemgrepRunsALocalRulesetOffline(t *testing.T) {
	offline(t)
	s, ran := semgrepOver(t)
	for _, repo := range twoRepositories {
		if _, err := s.Scan(context.Background(), repo, plugin.Config{"config": "/opt/rules/semgrep"}); err != nil {
			t.Fatalf("%s: %v", repo.URL, err)
		}
	}
	if len(*ran) != 2 || (*ran)[0] != "/opt/rules/semgrep" || (*ran)[1] != "/opt/rules/semgrep" {
		t.Errorf("ran %v, want the local ruleset once per repository", *ran)
	}
}

func TestSemgrepFetchesItsDefaultOnline(t *testing.T) {
	s, ran := semgrepOver(t)
	for _, repo := range twoRepositories {
		if _, err := s.Scan(context.Background(), repo, nil); err != nil {
			t.Fatalf("%s: %v", repo.URL, err)
		}
	}
	if len(*ran) != 2 || (*ran)[0] != "p/default" || (*ran)[1] != "p/default" {
		t.Errorf("ran %v, want p/default once per repository", *ran)
	}
}

// The classification is Semgrep's own config resolver's, so every form it fetches is refused and
// every form it reads from disk runs.
func TestSemgrepRemoteHost(t *testing.T) {
	t.Setenv("SEMGREP_URL", "")
	for _, c := range []struct {
		config string
		host   string
		remote bool
	}{
		{"p/default", "semgrep.dev", true},
		{"r/python.lang.security.audit.eval", "semgrep.dev", true},
		{"s/abc123", "semgrep.dev", true},
		{"auto", "semgrep.dev", true},
		{"r2c", "semgrep.dev", true},
		{"code", "semgrep.dev", true},
		{"code,secrets,supply-chain", "semgrep.dev", true},
		{"policy", "semgrep.dev", true},
		{"https://rules.example.com/x.yaml", "rules.example.com", true},
		{"http://127.0.0.1:18080/rules", "127.0.0.1:18080", true},
		{"rules/semgrep.yaml", "", false},
		{"/opt/rules", "", false},
		{"./p/rules.yaml", "", false},
		{"~/rules.yaml", "", false},
		{"code,rules", "", false},
		{"C:/rules/semgrep.yaml", "", false},
	} {
		host, remote := semgrepRemoteHost(c.config)
		if host != c.host || remote != c.remote {
			t.Errorf("semgrepRemoteHost(%q) = %q, %v, want %q, %v", c.config, host, remote, c.host, c.remote)
		}
	}
}
