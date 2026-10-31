package registry

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

// Each line below is what the tool printed, unedited, pulling an image that does not exist with no
// credential configured: Trivy 0.74.0 (`trivy image --quiet --format json <ref>`), Grype 0.121.0
// (`grype registry:<ref> -o sarif`) and Cosign 3.1.3 (`cosign verify --output json
// --certificate-identity-regexp '.*' --certificate-oidc-issuer-regexp '.*' <ref>`), the commands
// the scanners run, on 2026-10-30. A refusal reads the same whether the image is missing or
// private, which is the registry's choice: it does not say which to somebody who has not signed in.
//
// The registry's own answer is go-containerregistry's wording of the response, `GET <url>: <code>:
// <message>`, so each tool adds only its own lead.
var refusals = []struct {
	registry, host, line string
	status               int
}{
	{"Docker Hub", "registry-1.docker.io",
		"\t* remote error: GET https://index.docker.io/v2/acme-example/not-a-real-image/manifests/1.0: UNAUTHORIZED: authentication required; [map[Action:pull Class: Name:acme-example/not-a-real-image Type:repository]]",
		http.StatusUnauthorized},
	{"Docker Hub", "registry-1.docker.io",
		"  - oci-registry: failed to get image descriptor from registry: GET https://index.docker.io/v2/acme-example/not-a-real-image/manifests/1.0: UNAUTHORIZED: authentication required; [map[Action:pull Class: Name:acme-example/not-a-real-image Type:repository]]",
		http.StatusUnauthorized},
	{"Docker Hub", "registry-1.docker.io",
		"Error: GET https://index.docker.io/v2/acme-example/not-a-real-image/manifests/1.0: UNAUTHORIZED: authentication required; [map[Action:pull Class: Name:acme-example/not-a-real-image Type:repository]]",
		http.StatusUnauthorized},

	{"GHCR", "ghcr.io",
		"\t* remote error: GET https://ghcr.io/token?scope=repository%3Aacme-example%2Fnot-a-real-image%3Apull&service=ghcr.io: DENIED: requested access to the resource is denied",
		http.StatusForbidden},
	{"GHCR", "ghcr.io",
		"  - oci-registry: failed to get image descriptor from registry: GET https://ghcr.io/token?scope=repository%3Aacme-example%2Fnot-a-real-image%3Apull&service=ghcr.io: DENIED: requested access to the resource is denied",
		http.StatusForbidden},
	{"GHCR", "ghcr.io",
		"Error: GET https://ghcr.io/token?scope=repository%3Aacme-example%2Fnot-a-real-image%3Apull&service=ghcr.io: DENIED: requested access to the resource is denied",
		http.StatusForbidden},

	// ECR answers in plain text, so go-containerregistry names the status itself.
	{"ECR", "123456789012.dkr.ecr.us-east-1.amazonaws.com",
		"\t* remote error: GET https://123456789012.dkr.ecr.us-east-1.amazonaws.com/v2/acme/api/manifests/1.0: unexpected status code 401 Unauthorized: Not Authorized",
		http.StatusUnauthorized},
	{"ECR", "123456789012.dkr.ecr.us-east-1.amazonaws.com",
		"  - oci-registry: failed to get image descriptor from registry: GET https://123456789012.dkr.ecr.us-east-1.amazonaws.com/v2/acme/api/manifests/1.0: unexpected status code 401 Unauthorized: Not Authorized",
		http.StatusUnauthorized},
	{"ECR", "123456789012.dkr.ecr.us-east-1.amazonaws.com",
		"Error: GET https://123456789012.dkr.ecr.us-east-1.amazonaws.com/v2/acme/api/manifests/1.0: unexpected status code 401 Unauthorized: Not Authorized",
		http.StatusUnauthorized},

	{"GCR", "gcr.io",
		`	* remote error: GET https://gcr.io/v2/token?scope=repository%3Aacme-example-not-a-project%2Fapi%3Apull&service=gcr.io: DENIED: Unauthenticated request. Unauthenticated requests do not have permission "artifactregistry.repositories.downloadArtifacts" on resource "projects/acme-example-not-a-project/locations/us/repositories/gcr.io" (or it may not exist)`,
		http.StatusForbidden},
	{"GCR", "gcr.io",
		`  - oci-registry: failed to get image descriptor from registry: GET https://gcr.io/v2/token?scope=repository%3Aacme-example-not-a-project%2Fapi%3Apull&service=gcr.io: DENIED: Unauthenticated request. Unauthenticated requests do not have permission "artifactregistry.repositories.downloadArtifacts" on resource "projects/acme-example-not-a-project/locations/us/repositories/gcr.io" (or it may not exist)`,
		http.StatusForbidden},
	{"GCR", "gcr.io",
		`Error: GET https://gcr.io/v2/token?scope=repository%3Aacme-example-not-a-project%2Fapi%3Apull&service=gcr.io: DENIED: Unauthenticated request. Unauthenticated requests do not have permission "artifactregistry.repositories.downloadArtifacts" on resource "projects/acme-example-not-a-project/locations/us/repositories/gcr.io" (or it may not exist)`,
		http.StatusForbidden},

	{"Artifact Registry", "us-docker.pkg.dev",
		`	* remote error: GET https://us-docker.pkg.dev/v2/token?scope=repository%3Aacme-example-not-a-project%2Fimages%2Fapi%3Apull&service=: DENIED: Unauthenticated request. Unauthenticated requests do not have permission "artifactregistry.repositories.downloadArtifacts" on resource "projects/acme-example-not-a-project/locations/us/repositories/images" (or it may not exist)`,
		http.StatusForbidden},
	{"Artifact Registry", "us-docker.pkg.dev",
		`  - oci-registry: failed to get image descriptor from registry: GET https://us-docker.pkg.dev/v2/token?scope=repository%3Aacme-example-not-a-project%2Fimages%2Fapi%3Apull&service=: DENIED: Unauthenticated request. Unauthenticated requests do not have permission "artifactregistry.repositories.downloadArtifacts" on resource "projects/acme-example-not-a-project/locations/us/repositories/images" (or it may not exist)`,
		http.StatusForbidden},
	{"Artifact Registry", "us-docker.pkg.dev",
		`Error: GET https://us-docker.pkg.dev/v2/token?scope=repository%3Aacme-example-not-a-project%2Fimages%2Fapi%3Apull&service=: DENIED: Unauthenticated request. Unauthenticated requests do not have permission "artifactregistry.repositories.downloadArtifacts" on resource "projects/acme-example-not-a-project/locations/us/repositories/images" (or it may not exist)`,
		http.StatusForbidden},

	{"Azure Container Registry", "contoso.azurecr.io",
		"\t* remote error: GET https://contoso.azurecr.io/oauth2/token?scope=repository%3Aacme%2Fapi%3Apull&service=contoso.azurecr.io: UNAUTHORIZED: authentication required, visit https://aka.ms/acr/authorization for more information. CorrelationId: 81470148-3d21-40ce-b341-135807330139",
		http.StatusUnauthorized},
	{"Azure Container Registry", "contoso.azurecr.io",
		"  - oci-registry: failed to get image descriptor from registry: GET https://contoso.azurecr.io/oauth2/token?scope=repository%3Aacme%2Fapi%3Apull&service=contoso.azurecr.io: UNAUTHORIZED: authentication required, visit https://aka.ms/acr/authorization for more information. CorrelationId: 704ec0b7-21b7-4815-ba4c-240e441e87b6",
		http.StatusUnauthorized},
	{"Azure Container Registry", "contoso.azurecr.io",
		"Error: GET https://contoso.azurecr.io/oauth2/token?scope=repository%3Aacme%2Fapi%3Apull&service=contoso.azurecr.io: UNAUTHORIZED: authentication required, visit https://aka.ms/acr/authorization for more information. CorrelationId: 3122a410-32f8-4c1a-9326-776dc7284957",
		http.StatusUnauthorized},
}

func TestEveryScannerSaysWhatEveryRegistryRefused(t *testing.T) {
	for _, c := range refusals {
		if got := RefusalStatus(c.line, c.host); got != c.status {
			t.Errorf("%s: RefusalStatus = %d, want %d, for:\n%s", c.registry, got, c.status, c.line)
		}
	}
}

// A refusal is read out of everything the tool printed. Trivy lists the four places it looked, and
// the local ones fail for reasons of their own, one of them a socket's "permission denied". This is
// Trivy's stderr from the Docker Hub pull above, less the timestamp leading its first line and the
// Podman line, which names a path on the machine that ran it.
const trivyStderr = `FATAL	Fatal error	run error: image scan error: scan error: unable to initialize a scan service: unable to initialize artifact: unable to initialize container image: unable to find the specified image "docker.io/acme-example/not-a-real-image:1.0" in ["docker" "containerd" "podman" "remote"]: 4 errors occurred:
	* docker error: unable to inspect the image (docker.io/acme-example/not-a-real-image:1.0): Error response from daemon: No such image: acme-example/not-a-real-image:1.0
	* containerd error: failed to list images from containerd client: connection error: desc = "transport: Error while dialing: dial unix /run/containerd/containerd.sock: connect: permission denied"
	* remote error: GET https://index.docker.io/v2/acme-example/not-a-real-image/manifests/1.0: UNAUTHORIZED: authentication required; [map[Action:pull Class: Name:acme-example/not-a-real-image Type:repository]]
`

func TestARefusalIsReadAmongTheToolsOtherFailures(t *testing.T) {
	if got := RefusalStatus(trivyStderr, dockerHub); got != http.StatusUnauthorized {
		t.Errorf("RefusalStatus = %d, want 401", got)
	}
	// The same lines without the registry's answer: a socket refusing is not a registry refusing.
	if got := RefusalStatus(trivyStderr[:len(trivyStderr)-len("UNAUTHORIZED: authentication required; [map[Action:pull Class: Name:acme-example/not-a-real-image Type:repository]]\n")], dockerHub); got != 0 {
		t.Errorf("a local socket's permission denied read as a refusal: %d", got)
	}
}

// What a scan keeps of a failure is shortened to a line, and the start goes first. These are the
// errors the scanners return for the pulls above, as Draugr shortens them.
func TestAShortenedRefusalIsStillARefusal(t *testing.T) {
	for _, c := range []struct {
		host, detail string
		status       int
	}{
		{"contoso.azurecr.io", "run trivy: exit status 1: … UNAUTHORIZED: authentication required, visit https://aka.ms/acr/authorization for more information. CorrelationId: 81470148-3d21-40ce-b341-135807330139",
			http.StatusUnauthorized},
		{"ghcr.io", "run trivy: exit status 1: … GET https://ghcr.io/token?scope=repository%3Aacme-example%2Fnot-a-real-image%3Apull&service=ghcr.io: DENIED: requested access to the resource is denied",
			http.StatusForbidden},
		// Shortened past its code; the resource Artifact Registry names at the end still says it.
		{"gcr.io", `run trivy: exit status 1: run error: image scan error: scan error: unable to in … resource "projects/acme-example-not-a-project/locations/us/repositories/gcr.io" (or it may not exist)`,
			http.StatusForbidden},
		{"us-docker.pkg.dev", `cosign: verifying us-docker.pkg.dev/acme-example-not-a-project/images/api:1.0: exit status 1: Error: GET https://us-docker.pkg.dev/v2/token?scope=r … resource "projects/acme-example-not-a-project/locations/us/repositories/images" (or it may not exist)`,
			http.StatusForbidden},
	} {
		if got := RefusalStatus(c.detail, c.host); got != c.status {
			t.Errorf("RefusalStatus(%q) = %d, want %d", c.detail, got, c.status)
		}
	}
}

// A refusal of a request to another host is about something else the scanner fetched, such as its
// vulnerability database, and not the image.
func TestARefusalFromAnotherHostIsNotTheImages(t *testing.T) {
	const db = "GET https://ghcr.io/v2/aquasecurity/trivy-db/manifests/2: UNAUTHORIZED: authentication required"
	if got := RefusalStatus(db, "contoso.azurecr.io"); got != 0 {
		t.Errorf("a refusal from ghcr.io read as contoso.azurecr.io refusing: %d", got)
	}
	if got := RefusalStatus(db, "ghcr.io"); got != http.StatusUnauthorized {
		t.Errorf("the same refusal for an image on ghcr.io = %d, want 401", got)
	}
	// registry.gitlab.com hands out its tokens from gitlab.com. Its answer to an anonymous pull of
	// an image that does not exist, asked on 2026-10-30, worded as go-containerregistry words it.
	const gitlab = "GET https://gitlab.com/jwt/auth?scope=repository%3Aacme-example%2Fnot-a-real-image%3Apull&service=container_registry: DENIED: access forbidden"
	if got := RefusalStatus(gitlab, "registry.gitlab.com"); got != http.StatusForbidden {
		t.Errorf("a refusal from registry.gitlab.com's token service = %d, want 403", got)
	}
}

func TestWhatIsNotARefusal(t *testing.T) {
	for _, msg := range []string{
		"GET https://ghcr.io/v2/acme/api/manifests/1: MANIFEST_UNKNOWN: manifest unknown",
		"GET https://index.docker.io/v2/library/nginx/manifests/1: TOOMANYREQUESTS: You have reached your pull rate limit.",
		`dial unix /var/run/docker.sock: connect: permission denied`,
		"",
	} {
		if got := RefusalStatus(msg, "ghcr.io"); got != 0 {
			t.Errorf("RefusalStatus(%q) = %d, want 0", msg, got)
		}
	}
}

func TestShortDigest(t *testing.T) {
	for ref, want := range map[string]string{
		"contoso.azurecr.io/istio/pilot:1.30.5@sha256:78052a996140d7f0a3f03d04fb3352714cbc40e0b69dcf70b59ee07511ff3dfb": "contoso.azurecr.io/istio/pilot:1.30.5@sha256:78052a996140…",
		"ghcr.io/acme/api:1":            "ghcr.io/acme/api:1",
		"ghcr.io/acme/api@sha256:abc":   "ghcr.io/acme/api@sha256:abc",
		"ghcr.io/acme/api@not-a-digest": "ghcr.io/acme/api@not-a-digest",
	} {
		if got := ShortDigest(ref); got != want {
			t.Errorf("ShortDigest(%q) = %q, want %q", ref, got, want)
		}
	}
}

func TestLoginHost(t *testing.T) {
	for host, want := range map[string]string{
		dockerHub:            "docker.io",
		"index.docker.io":    "docker.io",
		"contoso.azurecr.io": "contoso.azurecr.io",
	} {
		if got := LoginHost(host); got != want {
			t.Errorf("LoginHost(%q) = %q, want %q", host, got, want)
		}
	}
}

func TestHasCredential(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("DOCKER_CONFIG", dir)
	t.Setenv("REGISTRY_AUTH_FILE", "")
	t.Setenv("XDG_RUNTIME_DIR", "")
	// #nosec G101 -- a placeholder credential, base64 of "user:pass".
	cfg := `{"auths":{"https://index.docker.io/v1/":{"auth":"dXNlcjpwYXNz"},"ghcr.io":{"auth":"dXNlcjpwYXNz"}}}`
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	for host, want := range map[string]bool{
		"docker.io": true, dockerHub: true, "ghcr.io": true, "contoso.azurecr.io": false,
	} {
		got, err := HasCredential(context.Background(), host)
		if err != nil || got != want {
			t.Errorf("HasCredential(%q) = %v, %v; want %v", host, got, err, want)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := HasCredential(context.Background(), "ghcr.io"); err == nil {
		t.Error("an unreadable configuration answered rather than failing")
	}
}
