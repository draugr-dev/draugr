package awsaccess

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// fixed is an Identifier that answers with one caller, or one error.
type fixed struct {
	caller Caller
	err    error
}

func (f fixed) CallerIdentity(context.Context) (Caller, error) { return f.caller, f.err }

// Credentials in the declared account pass; credentials in another are refused naming both
// accounts and the identity, which is what somebody needs to see which profile they are in.
func TestConfirmRefusesAnotherAccount(t *testing.T) {
	ours := Caller{Account: "111111111111", ARN: "arn:aws:sts::111111111111:assumed-role/audit/scan"}
	if got, err := Confirm(context.Background(), fixed{caller: ours}, "111111111111"); err != nil || got != ours {
		t.Errorf("the declared account = %+v, %v", got, err)
	}
	theirs := Caller{Account: "222222222222", ARN: "arn:aws:iam::222222222222:user/dev"}
	_, err := Confirm(context.Background(), fixed{caller: theirs}, "111111111111")
	want := "the credentials are arn:aws:iam::222222222222:user/dev, in account 222222222222, " +
		"not the declared account 111111111111"
	if err == nil || err.Error() != want {
		t.Errorf("another account = %v, want %q", err, want)
	}
	expired := errors.New("ask AWS who the credentials are: ExpiredToken")
	if _, err := Confirm(context.Background(), fixed{err: expired}, "111111111111"); !errors.Is(err, expired) {
		t.Errorf("an error = %v, want it passed on", err)
	}
}

// isolate empties every place the default chain looks for credentials, so the test reads the
// environment it sets rather than the machine's.
func isolate(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	for _, k := range []string{
		"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_PROFILE",
		"AWS_DEFAULT_PROFILE", "AWS_REGION", "AWS_DEFAULT_REGION", "AWS_WEB_IDENTITY_TOKEN_FILE",
		"AWS_ROLE_ARN", "AWS_CONTAINER_CREDENTIALS_FULL_URI", "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
		"AWS_ENDPOINT_URL", "AWS_ENDPOINT_URL_STS",
	} {
		t.Setenv(k, "")
	}
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(dir, "config"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(dir, "credentials"))
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
}

func TestNewWithNoCredentials(t *testing.T) {
	isolate(t)
	if _, err := New(context.Background()); !errors.Is(err, ErrNoCredentials) {
		t.Errorf("err = %v, want ErrNoCredentials", err)
	}
}

// With credentials and no region, STS is asked anyway, and a failure says what was being asked.
func TestCallerIdentityNamesWhatFailed(t *testing.T) {
	isolate(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unavailable", http.StatusBadRequest)
	}))
	defer srv.Close()
	t.Setenv("AWS_ACCESS_KEY_ID", "AAAAAAAAAAAAAAAAAAAA")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	t.Setenv("AWS_ENDPOINT_URL_STS", srv.URL)
	t.Setenv("AWS_MAX_ATTEMPTS", "1")
	id, err := New(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := id.CallerIdentity(context.Background()); err == nil ||
		!strings.HasPrefix(err.Error(), "ask AWS who the credentials are: ") {
		t.Errorf("err = %v", err)
	}
}

func TestNewRefusesAnUnreadableConfiguration(t *testing.T) {
	isolate(t)
	t.Setenv("AWS_PROFILE", "missing")
	if _, err := New(context.Background()); err == nil || !strings.Contains(err.Error(), "read the AWS configuration") {
		t.Errorf("err = %v", err)
	}
}
