package report

import (
	"testing"

	"github.com/draugr-dev/draugr/pkg/sarif"
	"github.com/draugr-dev/draugr/pkg/skald"
)

// keyFindings are a private key at app/config.example.pem:1, as a secrets rule and a code rule both
// report it on draugr-demo, at the band given to each, in the repository given.
func keyFindings(repository, secretsBand, codeBand string) (secret, code finding) {
	secret = finding{control: "secrets", tool: "gitleaks", ruleID: "private-key", priority: secretsBand,
		level: sarif.LevelError, component: "api", repository: repository, location: "app/config.example.pem:1",
		message:     "Identified a Private Key, which may compromise cryptographic security and sensitive data encryption",
		fingerprint: "gitleaks|private-key|" + repository}
	code = finding{control: "sast", tool: "Semgrep OSS", ruleID: "generic.secrets.security.detected-private-key.detected-private-key",
		priority: codeBand, level: sarif.LevelError, component: "api", repository: repository,
		location: "app/config.example.pem:1", fingerprint: "semgrep|detected-private-key|" + repository}
	return secret, code
}

// One key flagged by a secrets rule and a code rule is one change, so it is one action: in the
// credential list, because rotating the key is the part a code row would leave out, at the more
// urgent band of the two, clearing both findings. Either band may be the more urgent one.
func TestASecretAndACodeRuleAtOneLineAreOneAction(t *testing.T) {
	for _, tc := range []struct {
		name        string
		first, then string
	}{
		{"the secret more urgent", "secrets", "sast"},
		{"the code rule more urgent", "sast", "secrets"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			secret, code := keyFindings(demoRepository, "P1", "P3")
			fs := []finding{secret, code}
			if tc.first == "sast" {
				secret.priority, code.priority = "P3", "P1"
				fs = []finding{code, secret}
			}
			actions, _ := groupActions(fs, nil)
			if len(actions) != 1 {
				t.Fatalf("got %d actions, want one: %+v", len(actions), actions)
			}
			a := actions[0]
			if a.kind != skald.KindCredential || a.control != "secrets" || a.priority != "P1" || a.count() != 2 {
				t.Errorf("got kind %s, control %s, %s, %d findings; want credential, secrets, P1, 2",
					a.kind, a.control, a.priority, a.count())
			}
			if a.title != "Remove and rotate the private key if it is real" {
				t.Errorf("title %q", a.title)
			}
		})
	}
}

// Two rules at one line asking for different changes are two flaws, and keep an action each.
func TestASecretAndADifferentCodeRuleAtOneLineStayApart(t *testing.T) {
	secret, _ := keyFindings(demoRepository, "P1", "P3")
	other := codeFinding("Semgrep OSS", "python.lang.security.audit.eval-detected.eval-detected", "P3",
		sarif.LevelWarning, "app/config.example.pem:1", "")
	actions, _ := groupActions([]finding{secret, other}, nil)
	if len(actions) != 2 {
		t.Fatalf("got %d actions, want two: %+v", len(actions), actions)
	}
}

// The same path in two repositories is two files. A key in one does not take in a code finding at
// that path in the other.
func TestASecretJoinsOnlyTheCodeFindingInItsOwnRepository(t *testing.T) {
	secretA, codeA := keyFindings("https://github.com/acme/a", "P1", "P3")
	_, codeB := keyFindings("https://github.com/acme/b", "P1", "P3")
	actions, _ := groupActions([]finding{secretA, codeA, codeB}, nil)
	if len(actions) != 2 {
		t.Fatalf("got %d actions, want two: %+v", len(actions), actions)
	}
	for _, a := range actions {
		switch a.kind {
		case skald.KindCredential:
			if a.count() != 2 {
				t.Errorf("the credential action clears %d findings, want 2", a.count())
			}
		case skald.KindCode:
			if a.count() != 1 || a.findings[0].repository != "https://github.com/acme/b" {
				t.Errorf("the code action is %+v, want b's finding alone", a.findings)
			}
		default:
			t.Errorf("unexpected kind %s", a.kind)
		}
	}
}
