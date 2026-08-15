package sarif

import "testing"

// TestRemediationClassifiesWhatCanBeDone covers the question a reader has after the severity:
// can I do something about this, and what kind of thing.
func TestRemediationClassifiesWhatCanBeDone(t *testing.T) {
	for _, c := range []struct {
		name string
		res  Result
		want Remediation
	}{
		{
			name: "a fixed version exists",
			res:  Result{Package: &Package{Name: "jinja2", Version: "2.10", FixedVersion: "3.1.5"}},
			want: RemediationUpgrade,
		},
		{
			name: "no fix here, but the release underneath can move",
			res:  Result{Package: &Package{Name: "apt", Version: "2.2.4"}, OSEndOfLife: true},
			want: RemediationUpstream,
		},
		{
			// The whole point of the tier: telling somebody to chmod a control-plane file they
			// cannot reach is worse than saying nothing.
			name: "somebody else operates it",
			res:  Result{ProviderOperated: true},
			want: RemediationExternal,
		},
		{
			// Operated by somebody else wins even where a fix exists, because the reader still
			// cannot apply it — the fix is the provider's to ship.
			name: "operated elsewhere, and a fix exists there",
			res: Result{ProviderOperated: true,
				Package: &Package{Name: "etcd", Version: "3.5.0", FixedVersion: "3.5.9"}},
			want: RemediationExternal,
		},
		{
			name: "no fix published, and it is the reader's",
			res:  Result{Package: &Package{Name: "libdb5.3", Version: "5.3.28"}},
			want: RemediationNone,
		},
		{
			// A SAST finding has no package and no upgrade; it is changed in the code.
			name: "nothing packaged",
			res:  Result{RuleID: "tainted-sql-string"},
			want: RemediationNone,
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := c.res.Remediation(); got != c.want {
				t.Errorf("Remediation() = %q, want %q", got, c.want)
			}
		})
	}
}
