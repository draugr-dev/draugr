package report

import (
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/norn"
)

// failedImage is an image every scanner failed to pull, as the engine accounts for it.
func failedImage(ref, detail string, refused *engine.Refusal, components ...string) engine.TargetOutcome {
	return engine.TargetOutcome{Kind: "image", Target: ref, Status: engine.TargetFailed, Detail: detail,
		Refusal: refused, Components: components}
}

// refused is a registry's answer as the engine records it, with whether the machine held a
// credential: nil when the run did not ask.
func refused(host string, status int, credential *bool) *engine.Refusal {
	return &engine.Refusal{Registry: host, Status: status, Credential: credential}
}

var (
	held     = func() *bool { b := true; return &b }()
	noneHeld = func() *bool { b := false; return &b }()
)

// acrDetail is what a scan keeps of Trivy's message for an Azure Container Registry image pulled
// with no login.
const acrDetail = "run trivy: exit status 1: … UNAUTHORIZED: authentication required, visit " +
	"https://aka.ms/acr/authorization for more information. CorrelationId: 5bf38f62-783a-4cad-a09e-5262470783fa"

func TestARegistryRefusalReadsAsDoctorSaysIt(t *testing.T) {
	for _, c := range []struct {
		name    string
		refused *engine.Refusal
		said    string
		login   bool
	}{
		{"no credential, asked for one", refused("contoso.azurecr.io", http.StatusUnauthorized, noneHeld),
			"401 unauthorized, no credential", true},
		{"no credential, declined", refused("ghcr.io", http.StatusForbidden, noneHeld), "403 forbidden, no credential", true},
		// A credential the registry did not accept: logging in again replaces it.
		{"credential refused", refused("docker.io", http.StatusUnauthorized, held), "401 unauthorized", true},
		// A credential that is accepted and lacks access: a login changes nothing.
		{"credential lacks access", refused("ghcr.io", http.StatusForbidden, held), "403 forbidden", false},
		// The run could not say: the answer is the registry's alone.
		{"credential unknown", refused("ghcr.io", http.StatusForbidden, nil), "403 forbidden", false},
	} {
		r, ok := registryRefusal(failedImage("contoso.azurecr.io/istio/pilot:1.30.5", acrDetail, c.refused))
		if !ok || r.said != c.said || r.login != c.login || r.host != c.refused.Registry {
			t.Errorf("%s: got %+v, %v; want %q, login %v", c.name, r, ok, c.said, c.login)
		}
	}
	if _, ok := registryRefusal(failedImage("ghcr.io/acme/api:1", "MANIFEST_UNKNOWN: manifest unknown", nil)); ok {
		t.Error("a missing manifest read as a refusal")
	}
}

func TestADigestIsShortenedOnScreen(t *testing.T) {
	const ref = "contoso.azurecr.io/istio/pilot:1.30.5@sha256:78052a996140d7f0a3f03d04fb3352714cbc40e0b69dcf70b59ee07511ff3dfb"
	if got, want := shownTarget("image", ref), "contoso.azurecr.io/istio/pilot:1.30.5@sha256:78052a996140…"; got != want {
		t.Errorf("shownTarget = %q, want %q", got, want)
	}
	for _, unchanged := range []string{"ghcr.io/acme/api:1", "ghcr.io/acme/api@sha256:abc", "ghcr.io/acme/api@weird"} {
		if got := shownTarget("image", unchanged); got != unchanged {
			t.Errorf("shownTarget(%q) = %q, want it unchanged", unchanged, got)
		}
	}
	if got := shownTarget("repository", "https://x/y@"+strings.Repeat("a", 40)); strings.Contains(got, "…") {
		t.Errorf("a repository's revision was shortened: %q", got)
	}
}

func TestAnImageIsNamedUnderItsRegistryWithoutTheHost(t *testing.T) {
	for _, c := range []struct{ target, host, want string }{
		{"contoso.azurecr.io/istio/pilot:1.30.5", "contoso.azurecr.io", "istio/pilot:1.30.5"},
		{"docker.io/acme/api:1", "docker.io", "acme/api:1"},
		{"index.docker.io/acme/api:1", "docker.io", "acme/api:1"},
		{"acme/api:1", "docker.io", "acme/api:1"},
	} {
		if got := inRegistry(c.target, c.host); got != c.want {
			t.Errorf("inRegistry(%q, %q) = %q, want %q", c.target, c.host, got, c.want)
		}
	}
	if loginCommand("docker.io") != "docker login" || loginCommand("ghcr.io") != "docker login ghcr.io" {
		t.Error("the login command names Docker Hub, which `docker login` assumes, or omits another registry")
	}
}

// refusedRun is the case the errors block was redesigned for: three images on one registry that
// wants a login, one of them declared by two components, an image on a second registry that
// declines this machine's credential, a repository that was not found, and an image that was read.
func refusedRun() Data {
	const (
		pilot = "contoso.azurecr.io/istio/pilot:1.30.5-distroless@sha256:78052a996140d7f0a3f03d04fb3352714cbc40e0b69dcf70b59ee07511ff3dfb"
		cni   = "contoso.azurecr.io/istio/install-cni:1.30.5@sha256:3392f63cfaefbf60f8b7ac41ce11851e77403c823147b277d7d5242be4679fa9"
		proxy = "contoso.azurecr.io/istio/proxyv2:1.30.5@sha256:abdd36489d1fd87e17bd70860c8007f9a7348c4846feaf10871b9ced9a530857"
		api   = "ghcr.io/acme/api:2.4.1@sha256:0f4c9d1e7b3a2f6c8d9e0a1b2c3d4e5f60718293a4b5c6d7e8f9012345678901"
	)
	acr := refused("contoso.azurecr.io", http.StatusUnauthorized, noneHeld)
	ghcr := refused("ghcr.io", http.StatusForbidden, held)
	ghcrDetail := "run trivy: exit status 1: … GET https://ghcr.io/token?scope=repository%3Aacme%2Fapi%3Apull&service=ghcr.io: DENIED: requested access to the resource is denied"
	return Data{
		Run: engine.Result{Targets: []engine.TargetOutcome{
			failedImage(pilot, acrDetail, acr, "mesh"),
			failedImage(cni, acrDetail, acr, "mesh"),
			failedImage(proxy, acrDetail, acr, "ingress", "mesh"),
			failedImage(api, ghcrDetail, ghcr, "billing"),
			{Kind: "image", Target: "gcr.io/distroless/static-debian12:nonroot", Status: engine.TargetReached, Components: []string{"ingress"}},
			failedRepository("https://github.com/acme/api-archive", "billing"),
		}},
		Verdict: norn.Result{Verdict: norn.Fail},
	}
}

func TestRefusedImagesAreSaidOncePerRegistry(t *testing.T) {
	t.Setenv("COLUMNS", "")
	out := renderWith(t, consoleReporter{}, refusedRun())
	for _, want := range []string{
		"ERRORS  5 of 6 targets not reached",
		"  contoso.azurecr.io  401 unauthorized, no credential\n    Image ",
		"    istio/proxyv2:1.30.5@sha256:abdd36489d1f…           ingress, mesh\n",
		"  docker login contoso.azurecr.io  then scan again\n",
		"  ghcr.io  403 forbidden\n    Image ",
		"  repository https://github.com/acme/api-archive@main  billing     Repository not found\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
	if n := strings.Count(out, "401 unauthorized"); n != 1 {
		t.Errorf("the registry's answer is said %d times, want once:\n%s", n, out)
	}
	// A login does not change what a credential the registry accepted may read.
	if strings.Contains(out, "docker login ghcr.io") {
		t.Errorf("a login is offered for a registry that declined a credential it accepted:\n%s", out)
	}
	if strings.Contains(out, "CorrelationId") || strings.Contains(out, "5bf38f62") {
		t.Errorf("the registry's request id reached the block:\n%s", out)
	}
}

// The page gives each target the reason the console gives it, grouped the same way, and keeps the
// control's raw message for what no target accounts for.
func TestThePageSaysWhatTheConsoleSays(t *testing.T) {
	d := goldenErrorsData()
	d.Run.ScanErrors["images"] = append(d.Run.ScanErrors["images"], "trivy: database download failed")
	page := renderWith(t, htmlReporter{}, d)
	i := strings.Index(page, `<h3 id="errors"`)
	if i < 0 {
		t.Fatalf("no errors section:\n%s", page)
	}
	section := page[i : i+strings.Index(page[i:], `<summary id="findings-h">`)]
	for _, want := range []string{
		`<h3 id="errors" class="err">Errors</h3>`,
		"5 of 6 targets not reached.",
		"<strong>contoso.azurecr.io</strong> · 401 unauthorized, no credential",
		`<code title="contoso.azurecr.io/istio/proxyv2:1.30.5@sha256:abdd36489d1fd87e17bd70860c8007f9a7348c4846feaf10871b9ced9a530857">istio/proxyv2:1.30.5@sha256:abdd36489d1f…</code> · components ingress, mesh`,
		`<code class="cmd">docker login contoso.azurecr.io</code> then scan again`,
		"<strong>ghcr.io</strong> · 403 forbidden",
		`<strong>repository</strong> <code title="https://github.com/acme/api-archive@main">https://github.com/acme/api-archive@main</code> · component billing · Repository not found`,
		"<strong>images</strong> · trivy: database download failed",
	} {
		if !strings.Contains(section, want) {
			t.Errorf("missing %q:\n%s", want, section)
		}
	}
	for _, unwanted := range []string{"CorrelationId", "aka.ms", "docker login ghcr.io", "run trivy"} {
		if strings.Contains(section, unwanted) {
			t.Errorf("the section carries %q:\n%s", unwanted, section)
		}
	}
	// Nothing unreached and nothing failed: no section.
	if page := renderWith(t, htmlReporter{}, goldenCleanData()); strings.Contains(page, `id="errors"`) {
		t.Error("a clean run has an errors section")
	}
}

// A target the run was canceled before reaching has no reason of its own, and the column stays for
// the one that does.
func TestATargetWithNoReasonKeepsTheReasonColumn(t *testing.T) {
	t.Setenv("COLUMNS", "")
	unstarted := engine.TargetOutcome{Kind: "repository", Target: "https://github.com/acme/a@main",
		Status: engine.TargetFailed, Components: []string{"api"}}
	out := renderWith(t, consoleReporter{}, Data{Run: engine.Result{Targets: []engine.TargetOutcome{
		unstarted, failedRepository("https://github.com/acme/b", "web"),
	}}})
	for _, want := range []string{"Components  Why", "acme/b@main  web         Repository not found"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
}

// On a terminal too narrow for the table, each target takes a line and what follows it the next,
// rather than a table cut down to fit, which cuts the reason first.
func TestErrorsFitTheTerminal(t *testing.T) {
	for _, cols := range []int{80, 120} {
		t.Run(strconv.Itoa(cols), func(t *testing.T) {
			t.Setenv("COLUMNS", strconv.Itoa(cols))
			out := renderWith(t, consoleReporter{}, refusedRun())
			block := out[strings.Index(out, "ERRORS"):]
			block = block[:strings.Index(block, "\n\n")]
			for _, line := range strings.Split(block, "\n") {
				if n := len([]rune(line)); n > cols {
					t.Errorf("%d columns: a line is %d wide:\n%s", cols, n, line)
				}
			}
			if !strings.Contains(block, "Repository not found") {
				t.Errorf("%d columns: the reason was cut:\n%s", cols, block)
			}
		})
	}
}
