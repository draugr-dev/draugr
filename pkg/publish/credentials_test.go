package publish

import (
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/credential"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// Every kind that reads `tokenEnv` says which variable is its own, so a descriptor naming any other
// is refused unless the pipeline lists it. A kind added without an entry would have no own variable
// and refuse every name, including the obvious one.
func TestEveryPublisherReadingATokenNamesItsOwn(t *testing.T) {
	for _, kind := range Kinds() {
		_, own := ownTokenEnv[kind]
		if reads := slices.Contains(reads[kind], "tokenEnv"); reads != own {
			t.Errorf("%s: reads tokenEnv = %v, has an own variable = %v", kind, reads, own)
		}
	}
	for kind := range ownTokenEnv {
		if !slices.Contains(Kinds(), kind) {
			t.Errorf("ownTokenEnv names %s, which is not a publisher", kind)
		}
	}
}

// A descriptor change alone must not be able to point a publisher at another of the job's secrets.
// Walked over every kind that reads tokenEnv, so a new publisher cannot skip the check.
func TestEveryPublisherRefusesATokenEnvThePipelineDoesNotList(t *testing.T) {
	t.Setenv("AWS_SECRET_ACCESS_KEY", "aws-secret")
	for _, kind := range Kinds() {
		if !slices.Contains(reads[kind], "tokenEnv") {
			continue
		}
		t.Run(kind, func(t *testing.T) {
			t.Setenv(credential.TokenEnvsVar, "")
			_, err := For(saga.PublisherConfig{Kind: kind, TokenEnv: "AWS_SECRET_ACCESS_KEY"}) // #nosec G101 -- the name of an environment variable
			var refused *credential.RefusedVariableError
			if !errors.As(err, &refused) || refused.Name != "AWS_SECRET_ACCESS_KEY" ||
				!strings.Contains(err.Error(), kind+" publisher: ") || !strings.Contains(err.Error(), credential.TokenEnvsVar) {
				t.Errorf("err = %v, want AWS_SECRET_ACCESS_KEY refused, naming DRAUGR_TOKEN_ENVS", err)
			}
			if err != nil && strings.Contains(err.Error(), "aws-secret") {
				t.Errorf("the refusal printed the secret: %v", err)
			}
			if CheckCredential(saga.PublisherConfig{Kind: kind, TokenEnv: "AWS_SECRET_ACCESS_KEY"}) == nil { // #nosec G101 -- the name of an environment variable
				t.Error("CheckCredential accepted what For refuses")
			}

			// Listed, or the kind's own, and the refusal is gone, whatever else the environment lacks.
			t.Setenv(credential.TokenEnvsVar, "AWS_SECRET_ACCESS_KEY")
			_, err = For(saga.PublisherConfig{Kind: kind, TokenEnv: "AWS_SECRET_ACCESS_KEY"}) // #nosec G101 -- the name of an environment variable
			if errors.As(err, &refused) {
				t.Errorf("a listed variable was refused: %v", err)
			}
			t.Setenv(credential.TokenEnvsVar, "")
			_, err = For(saga.PublisherConfig{Kind: kind, TokenEnv: ownTokenEnv[kind]})
			if errors.As(err, &refused) {
				t.Errorf("the kind's own variable was refused: %v", err)
			}
		})
	}
}

func TestCheckCredentialIgnoresWhatHoldsNoToken(t *testing.T) {
	if err := CheckCredential(saga.PublisherConfig{Kind: "file", Dir: "out"}); err != nil {
		t.Errorf("file: %v", err)
	}
	t.Setenv(apiURLEnv, "https://draugr.example")
	t.Setenv(apiTokenEnv, "drgr_ci_test")
	if err := CheckCredential(saga.PublisherConfig{Kind: "draugr-api", URL: "https://attacker.example"}); !errors.Is(err, ErrOriginRefused) {
		t.Errorf("draugr-api with a refused url: %v", err)
	}
	if err := CheckCredential(saga.PublisherConfig{Kind: "draugr-api"}); err != nil {
		t.Errorf("draugr-api on the environment's server: %v", err)
	}
}

// Every publisher's client refuses a token in clear text before it is sent, whatever address a
// publisher built. A request carrying none, such as an upload to a presigned URL, is not its
// business.
func TestThePublishersClientRefusesATokenInClearText(t *testing.T) {
	client := newRetryingClient(nil)
	req, _ := http.NewRequest(http.MethodPost, "http://forge.invalid/api", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer secret")
	resp, err := client.Do(req)
	if err == nil {
		_ = resp.Body.Close()
	}
	if !errors.Is(err, credential.ErrInsecure) {
		t.Errorf("err = %v, want ErrInsecure", err)
	}
	if client.CheckRedirect == nil {
		t.Error("the client follows redirects with no check on where a token goes")
	}
}
