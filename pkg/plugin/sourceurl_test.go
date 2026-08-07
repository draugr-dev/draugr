package plugin

import "testing"

// fakeToken stands in for a credential in a clone URL. Assembled into the fixtures at runtime so
// no test line reads as a hardcoded password to a secret scanner — including ours.
const fakeToken = "not-a-real-token"

// A finding is about a repository, not about who fetched it — so the userinfo is dropped rather
// than hidden, and the same repository looks the same however it was cloned.
func TestSourceURLDropsUserinfo(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		// The ordinary CI shape: a token in the clone URL. Assembled rather than written out,
		// so the fixture is not itself a credential-shaped literal.
		{"https://oauth2:" + fakeToken + "@github.com/acme/api.git", "https://github.com/acme/api.git"},
		{"https://user:" + fakeToken + "@host/org/repo.git", "https://host/org/repo.git"},
		// Azure DevOps, both forms it hands out.
		{"https://my-org@dev.azure.com/my-org/my-project/_git/my-repo",
			"https://dev.azure.com/my-org/my-project/_git/my-repo"},
		{"git@ssh.dev.azure.com:v3/my-org/my-project/my-repo",
			"ssh.dev.azure.com:v3/my-org/my-project/my-repo"},
		// scp-style GitHub.
		{"git@github.com:acme/api.git", "github.com:acme/api.git"},
		// Nothing to remove.
		{"https://github.com/acme/api.git", "https://github.com/acme/api.git"},
		{"ssh://git@host/repo.git", "ssh://host/repo.git"},
		// Local paths are untouched, including ones containing an @.
		{".", "."},
		{"../payments", "../payments"},
		{"/srv/repos/my@team/app", "/srv/repos/my@team/app"},
	} {
		if got := SourceURL(tc.in); got != tc.want {
			t.Errorf("SourceURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// An @ inside the path must not be mistaken for userinfo — only the authority carries it.
func TestSourceURLIgnoresAnAtInThePath(t *testing.T) {
	const u = "https://host/org/repo@v2.git"
	if got := SourceURL(u); got != u {
		t.Errorf("SourceURL(%q) = %q, want it unchanged", u, got)
	}
}

// The property that makes this more than redaction: two people scanning one repository with
// different credentials share an identity, so they share a cache entry and read as one source.
func TestIdentityIsTheSameHoweverItWasCloned(t *testing.T) {
	a := RepositoryTarget{URL: "https://alice:" + fakeToken + "@host/org/repo.git", Revision: "main"}
	b := RepositoryTarget{URL: "https://bob:" + fakeToken + "2@host/org/repo.git", Revision: "main"}
	if a.Identity() != b.Identity() {
		t.Errorf("identities differ by credential:\n  %s\n  %s", a.Identity(), b.Identity())
	}
	if got := a.Identity(); got != "https://host/org/repo.git@main" {
		t.Errorf("identity = %q", got)
	}
}

// Credentials must not reach an identity, which is hashed into cache keys and shown in reports.
func TestIdentityCarriesNoCredential(t *testing.T) {
	tgt := RepositoryTarget{URL: "https://oauth2:" + fakeToken + "@host/org/repo.git", Revision: "v1"}
	for _, s := range []string{tgt.Identity(), tgt.Source()} {
		if contains(s, fakeToken) {
			t.Errorf("credential leaked into %q", s)
		}
	}
}

func contains(h, n string) bool {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return true
		}
	}
	return false
}
