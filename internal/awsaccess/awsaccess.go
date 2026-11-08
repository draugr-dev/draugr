// Package awsaccess asks AWS which identity the credentials in the environment are, and which
// actions that identity's policies allow.
//
// The first question is asked by two callers: `draugr doctor`, to say whether a declared account is
// the one the credentials reach, and the prowler scanner, before Prowler runs. Prowler's output
// names the account it read and not the identity that read it, and credentials for another account
// produce a complete, plausible report about the wrong account. The second is the scanner's, to
// learn before the scan which services' reads will be denied.
//
// The credentials are the ones Prowler and every AWS SDK read: the AWS_* environment variables,
// AWS_PROFILE and the shared config and credentials files, an SSO session, or the role of the
// machine the scan runs on. Asking with the same chain is what makes the answer about the scan
// rather than about this process.
package awsaccess

import (
	"context"
	"errors"
	"fmt"
)

// ErrNoCredentials is a machine with no AWS credentials to ask with.
var ErrNoCredentials = errors.New("no AWS credentials found: set AWS_PROFILE, sign in with " +
	"`aws sso login`, or run where an instance or task role is attached")

// Caller is the identity the credentials resolve to.
type Caller struct {
	// Account is the 12-digit ID of the account the identity belongs to.
	Account string
	// ARN names the identity: a user, a role session or the account's root.
	ARN string
}

// Identifier asks AWS who the credentials are.
type Identifier interface {
	CallerIdentity(ctx context.Context) (Caller, error)
}

// Confirm asks who the credentials are and refuses an identity outside account.
//
// STS answers for any valid credentials, so an error here is credentials that do not work at all,
// and an identity in another account is credentials that work and would scan the wrong account.
func Confirm(ctx context.Context, id Identifier, account string) (Caller, error) {
	caller, err := id.CallerIdentity(ctx)
	if err != nil {
		return Caller{}, err
	}
	if caller.Account != account {
		return caller, fmt.Errorf("the credentials are %s, in account %s, not the declared account %s",
			caller.ARN, caller.Account, account)
	}
	return caller, nil
}
