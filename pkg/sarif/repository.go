package sarif

import "strings"

// RepositoryIdentity is a repository reference spelled one way per repository.
//
// A repository's URL is part of a finding's identity: the report carries it, `draugr diff` keys on
// it, and anything that keeps a finding's history across runs hashes it. Written verbatim, one
// repository has several spellings, `https://github.com/acme/api`, `https://github.com/acme/api.git`
// and `git@github.com:acme/api.git` among them, and each spelling is a different repository to all
// three. A team that moves CI from an HTTPS clone to a deploy key then sees every finding reported
// as new and every existing one as fixed, with nothing changed.
//
// So a reference that names a forge is reduced to `https://host/path`:
//
//   - credentials and the transport user are dropped, as they are everywhere a source is named;
//   - the host is lowercased, and a port dropped where it is the transport's rather than the
//     repository's: an SSH port or the default HTTPS one;
//   - scp-style `host:path`, `ssh://`, `git://` and `http://` are read as the same repository as
//     `https://` on that host;
//   - a trailing `.git` and trailing slashes go;
//   - Azure DevOps SSH and legacy `visualstudio.com` addresses are mapped onto
//     `dev.azure.com/{org}/{project}/_git/{repo}`, which is the one spelling the others share
//     nothing with textually.
//
// The path keeps its case. Some forges treat it case-insensitively and some do not, and folding a
// case-sensitive path would make two repositories one, which is the worse of the two mistakes.
//
// Anything that names no forge is returned as written, trimmed: a local path, `.`, a `file://`
// URL. Those are places on one machine, and no rule here would make them more one thing.
//
// A pure function of the string, so a store holding references written before this existed can be
// rewritten with it and arrive at exactly what a new scan reports.
func RepositoryIdentity(ref string) string {
	s := strings.TrimSpace(ref)
	scheme, rest, hasScheme := strings.Cut(s, "://")
	var host, path string
	transport := false // the port, if any, belongs to the transport rather than the repository
	switch {
	case hasScheme:
		switch strings.ToLower(scheme) {
		case "https", "http":
		case "ssh", "git", "git+ssh", "ssh+git":
			transport = true
		default:
			return s
		}
		host, path, _ = strings.Cut(rest, "/")
		if at := strings.LastIndex(host, "@"); at >= 0 {
			host = host[at+1:]
		}
	case scpStyle(s):
		transport = true
		addr, p, _ := strings.Cut(s, ":")
		if at := strings.LastIndex(addr, "@"); at >= 0 {
			addr = addr[at+1:]
		}
		host, path = addr, p
	default:
		return s
	}

	host = strings.ToLower(host)
	if name, port, ok := strings.Cut(host, ":"); ok {
		if transport || port == "443" || port == "80" {
			host = name
		}
	}
	path = strings.Trim(path, "/")
	path = strings.TrimSuffix(path, ".git")
	path = strings.TrimRight(path, "/")
	if host == "" || path == "" {
		return s
	}
	host, path = azureDevOps(host, path)
	return "https://" + host + "/" + path
}

// scpStyle reports whether s is `[user@]host:path`, git's shorthand for SSH.
//
// A colon before the first slash, and more than one character before it. That excludes a Windows
// drive letter (`C:\src`), which is the one other string shaped like it.
func scpStyle(s string) bool {
	colon := strings.Index(s, ":")
	if colon < 0 {
		return false
	}
	if slash := strings.IndexAny(s, `/\`); slash >= 0 && slash < colon {
		return false
	}
	addr := s[:colon]
	if at := strings.LastIndex(addr, "@"); at >= 0 {
		addr = addr[at+1:]
	}
	return len(addr) > 1
}

// azureDevOps maps every Azure DevOps address onto dev.azure.com/{org}/{project}/_git/{repo}.
//
// SSH is `ssh.dev.azure.com:v3/{org}/{project}/{repo}`, the legacy SSH host is
// `vs-ssh.visualstudio.com`, and the legacy HTTPS form carries the organization in the host:
// `{org}.visualstudio.com[/DefaultCollection]/{project}/_git/{repo}`. Anything that does not have
// the shape its host promises is left alone rather than guessed at.
func azureDevOps(host, path string) (string, string) {
	const canonical = "dev.azure.com"
	parts := strings.Split(path, "/")
	switch {
	case host == "ssh.dev.azure.com" || host == "vs-ssh.visualstudio.com":
		if len(parts) == 4 && parts[0] == "v3" {
			return canonical, parts[1] + "/" + parts[2] + "/_git/" + parts[3]
		}
	case strings.HasSuffix(host, ".visualstudio.com"):
		org := strings.TrimSuffix(host, ".visualstudio.com")
		if len(parts) > 0 && strings.EqualFold(parts[0], "DefaultCollection") {
			parts = parts[1:]
		}
		if len(parts) == 3 && parts[1] == "_git" {
			return canonical, org + "/" + strings.Join(parts, "/")
		}
	}
	return host, path
}
