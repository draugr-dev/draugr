package sarif

import "testing"

// Every spelling of one repository comes to one identity, and two repositories never come to one.
// The second half is the one that matters more: merging two repositories' findings is silent and
// cannot be undone by a later scan, where splitting one is loud and heals on the next.
func TestEverySpellingOfARepositoryIsOneIdentity(t *testing.T) {
	for want, spellings := range map[string][]string{
		"https://github.com/acme/api": {
			"https://github.com/acme/api",
			"https://github.com/acme/api.git",
			"https://github.com/acme/api/",
			"https://github.com/acme/api.git/",
			"http://github.com/acme/api",
			"https://GitHub.com/acme/api",
			"https://github.com:443/acme/api",
			"https://x-access-token:ghs_secret@github.com/acme/api.git",
			"git@github.com:acme/api.git",
			"git@github.com:acme/api",
			"github.com:acme/api.git",
			"ssh://git@github.com/acme/api.git",
			"ssh://git@github.com:22/acme/api.git",
			"git://github.com/acme/api.git",
			"  https://github.com/acme/api  ",
		},
		// The second repository in the same organization, so a rule that kept too little of the path
		// would show up as these two colliding.
		"https://github.com/acme/web": {
			"https://github.com/acme/web.git",
			"git@github.com:acme/web.git",
		},
		"https://gitlab.com/acme/platform/backend/api": {
			"https://gitlab.com/acme/platform/backend/api.git",
			"git@gitlab.com:acme/platform/backend/api.git",
		},
		"https://dev.azure.com/acme/platform/_git/api": {
			"https://dev.azure.com/acme/platform/_git/api",
			"https://acme@dev.azure.com/acme/platform/_git/api",
			"https://anything:eyJ0eXAi@dev.azure.com/acme/platform/_git/api",
			"git@ssh.dev.azure.com:v3/acme/platform/api",
			"ssh://git@ssh.dev.azure.com/v3/acme/platform/api",
			"https://acme.visualstudio.com/platform/_git/api",
			"https://acme.visualstudio.com/DefaultCollection/platform/_git/api",
			"acme@vs-ssh.visualstudio.com:v3/acme/platform/api",
		},
		// A self-hosted forge on its own HTTPS port keeps it: that port is part of where the
		// repository is, not how it was reached.
		"https://ghe.internal:8443/acme/api": {
			"https://ghe.internal:8443/acme/api.git",
		},
	} {
		for _, s := range spellings {
			if got := RepositoryIdentity(s); got != want {
				t.Errorf("RepositoryIdentity(%q) = %q, want %q", s, got, want)
			}
		}
	}
}

// Two repositories stay two. Path case is kept because some forges are case-sensitive, and folding
// it would merge two repositories into one on those.
func TestTwoRepositoriesStayTwo(t *testing.T) {
	for _, pair := range [][2]string{
		{"https://github.com/acme/api", "https://gitlab.com/acme/api"},
		{"https://github.com/acme/api", "https://github.com/acme/web"},
		{"https://github.com/payments/backend/api", "https://github.com/platform/backend/api"},
		{"https://git.internal/Acme/API", "https://git.internal/acme/api"},
		{"https://dev.azure.com/acme/platform/_git/api", "https://dev.azure.com/acme/billing/_git/api"},
	} {
		if a, b := RepositoryIdentity(pair[0]), RepositoryIdentity(pair[1]); a == b {
			t.Errorf("%q and %q both became %q", pair[0], pair[1], a)
		}
	}
}

// What names no forge is a place on one machine, and is left as it was written.
func TestAReferenceToNoForgeIsLeftAsWritten(t *testing.T) {
	for _, s := range []string{
		".",
		"./services/api",
		"/srv/checkouts/api",
		`C:\src\api`,
		"C:/src/api",
		"file:///srv/mirror/api.git",
		"",
	} {
		if got := RepositoryIdentity(s); got != s {
			t.Errorf("RepositoryIdentity(%q) = %q, want it unchanged", s, got)
		}
	}
}

// Applying it twice changes nothing, which is what lets a store be rewritten with it and a report
// already carrying an identity pass through it again.
func TestRepositoryIdentityIsIdempotent(t *testing.T) {
	for _, s := range []string{
		"git@github.com:acme/api.git",
		"git@ssh.dev.azure.com:v3/acme/platform/api",
		"https://acme.visualstudio.com/DefaultCollection/platform/_git/api",
		"https://ghe.internal:8443/acme/api.git",
		"./services/api",
	} {
		once := RepositoryIdentity(s)
		if twice := RepositoryIdentity(once); twice != once {
			t.Errorf("%q: once %q, twice %q", s, once, twice)
		}
	}
}
