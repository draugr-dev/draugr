package registry

import (
	"context"
	"net/http"
	"regexp"
	"slices"
	"strings"
)

// Trivy, Grype and Cosign all reach a registry through go-containerregistry, which words a
// refusal as the request and the registry's answer:
//
//	GET https://ghcr.io/token?scope=…&service=ghcr.io: DENIED: requested access to the resource is denied
//
// The answer is an error code from the distribution specification where the registry sent one, and
// `unexpected status code 401 Unauthorized: <body>` where the body was plain text, as ECR's is.
var (
	// unauthorized is a registry asking for a credential. The codes are upper case so a socket's
	// "unauthorized" elsewhere in a tool's output is not read as the registry's answer.
	unauthorized = regexp.MustCompile(`\bUNAUTHORIZED\b|(?i:\b401 unauthorized\b)`)
	// forbidden is a registry declining the request it was given. Artifact Registry, which serves
	// gcr.io and *-docker.pkg.dev, ends its denial by naming the resource "(or it may not exist)",
	// and that ending survives a message shortened past its code.
	forbidden = regexp.MustCompile(`\bDENIED\b|(?i:\b403 forbidden\b)|\bresource "projects/[^"]+" \(or it may not exist\)`)
	// request is the request go-containerregistry names ahead of the answer, and the host it went to.
	request = regexp.MustCompile(`\b(?:GET|HEAD|POST|PUT) https?://([^/\s?]+)`)
)

// RefusalStatus reads a scanner's account of a failed pull of an image on host for the registry
// declining to serve it. It returns the HTTP status the refusal amounts to, 401 when the registry
// asked for a credential and 403 when it declined the request it was given, or 0 when the message
// is not a refusal.
//
// Read a line at a time. A line naming a request to another host is about something else, such as
// the vulnerability database a scanner downloads before it pulls the image, and is passed over. A
// line naming no request is taken at its word, because a message shortened to fit a terminal loses
// its start first.
func RefusalStatus(message, host string) int {
	names := hostNames(host)
	for _, line := range strings.Split(message, "\n") {
		if m := request.FindStringSubmatch(line); m != nil && !slices.Contains(names, m[1]) {
			continue
		}
		switch {
		case unauthorized.MatchString(line):
			return http.StatusUnauthorized
		case forbidden.MatchString(line):
			return http.StatusForbidden
		}
	}
	return 0
}

// hostNames are the hosts a refusal for an image on host can come from: the registry, the domains
// above it, where a registry's token service often lives (registry.gitlab.com hands out tokens from
// gitlab.com), and Docker Hub's several names for itself.
func hostNames(host string) []string {
	if host == dockerHub {
		return []string{dockerHub, "index.docker.io", "auth.docker.io", "docker.io"}
	}
	names := []string{host}
	for rest := host; strings.Count(rest, ".") > 1; {
		_, rest, _ = strings.Cut(rest, ".")
		names = append(names, rest)
	}
	return names
}

// shortDigest is how many hex characters of a digest an image keeps on screen: enough to tell two
// builds apart, as a short commit does.
const shortDigest = 12

// ShortDigest is an image reference as a terminal row names it, its digest cut to twelve hex
// characters and marked as cut. A reference with no digest, or a short one, is returned as it is.
func ShortDigest(ref string) string {
	name, digest, ok := strings.Cut(ref, "@")
	if !ok {
		return ref
	}
	algo, hex, ok := strings.Cut(digest, ":")
	if !ok || len(hex) <= shortDigest {
		return ref
	}
	return name + "@" + algo + ":" + hex[:shortDigest] + "…"
}

// LoginHost is a registry as a reader names it to `docker login`. Docker Hub's API host is not what
// anybody types.
func LoginHost(host string) string {
	if host == dockerHub || host == "index.docker.io" {
		return "docker.io"
	}
	return host
}

// HasCredential reports whether this machine holds a credential for a registry, where Trivy, Grype
// and Cosign read one. host may be the name a reader types or the API host.
func HasCredential(ctx context.Context, host string) (bool, error) {
	if host == "docker.io" || host == "index.docker.io" {
		host = dockerHub
	}
	c, err := DockerCredential(ctx, host)
	if err != nil {
		return false, err
	}
	return !c.empty(), nil
}
