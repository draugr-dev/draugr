package gcpaccess

import (
	"context"
	"net/http"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// oauth2Client is an HTTP client that signs each request with the credentials' token.
func oauth2Client(ctx context.Context, creds *google.Credentials) *http.Client {
	return oauth2.NewClient(ctx, creds.TokenSource)
}
