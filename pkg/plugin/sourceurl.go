package plugin

import "strings"

// SourceURL returns a repository URL as the *source* it names, with any credentials or username
// removed.
//
// A finding is about a repository, not about who fetched it. Two people cloning one repository
// with different credentials are looking at the same source and should get the same finding, the
// same cache entry and the same name in a report — so the userinfo is not part of a repository's
// identity and is dropped rather than merely hidden.
//
// That it also stops a token reaching places it should never be is a consequence rather than the
// argument. A clone URL of the form https://oauth2:TOKEN@host/repo is the ordinary shape in CI,
// and the raw string is otherwise carried into reports, SBOM filenames and anything a scanner
// hands to a third party.
//
// The URL used to *fetch* is untouched: credentials are needed for that, and only for that.
func SourceURL(raw string) string {
	scheme, rest, ok := strings.Cut(raw, "://")
	if !ok {
		// An scp-style address — git@host:org/repo. The part before "@" is the transport user
		// ("git"), which is equally not part of the source.
		if at := strings.Index(raw, "@"); at >= 0 && !strings.ContainsAny(raw[:at], "/\\") {
			return raw[at+1:]
		}
		return raw
	}
	// Userinfo runs to the last "@" before the first "/" of the path.
	host := rest
	if slash := strings.Index(rest, "/"); slash >= 0 {
		host = rest[:slash]
	}
	if at := strings.LastIndex(host, "@"); at >= 0 {
		rest = rest[at+1:]
	}
	return scheme + "://" + rest
}

// Source is the repository this target names, without credentials — what a report should show
// and what identifies the scan.
//
// A resolved remote wins over the URL, because a local path describes where a checkout sits on
// one machine rather than which repository it is. That is what lets a scan on a laptop and a scan
// in a pipeline recognize each other as the same source.
func (t RepositoryTarget) Source() string {
	if t.Remote != "" {
		return SourceURL(t.Remote)
	}
	return SourceURL(t.URL)
}
