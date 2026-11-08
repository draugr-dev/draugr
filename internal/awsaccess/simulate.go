package awsaccess

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// ErrNotSimulated is a caller IAM's policy simulator cannot be asked about: the account's root, or
// a federated user, whose permissions no IAM principal holds.
var ErrNotSimulated = errors.New("the policy simulator answers for IAM users and roles only")

// Simulator asks IAM what an identity's policies allow.
type Simulator interface {
	// RoleARN is the ARN of the role named name, with its path, as iam:GetRole returns it.
	RoleARN(ctx context.Context, name string) (string, error)
	// Allowed simulates the policies of principal, a user's or a role's ARN, for each action, with
	// iam:SimulatePrincipalPolicy, and returns the actions they allow.
	Allowed(ctx context.Context, principal string, actions []string) ([]string, error)
}

// Principal is the IAM principal whose policies decide what caller may do: the user itself, or for
// a role session the role it assumed. A session's ARN names the role without its path, and the
// simulator needs the path, which only iam:GetRole returns.
func Principal(ctx context.Context, sim Simulator, caller Caller) (string, error) {
	parts := strings.SplitN(caller.ARN, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" {
		return "", fmt.Errorf("%q is not an ARN", caller.ARN)
	}
	service, resource := parts[2], parts[5]
	switch {
	case service == "iam" && strings.HasPrefix(resource, "user/"):
		return caller.ARN, nil
	case service == "sts" && strings.HasPrefix(resource, "assumed-role/"):
		role, _, _ := strings.Cut(strings.TrimPrefix(resource, "assumed-role/"), "/")
		arn, err := sim.RoleARN(ctx, role)
		if err != nil {
			return "", err
		}
		return arn, nil
	}
	return "", fmt.Errorf("%s: %w", caller.ARN, ErrNotSimulated)
}

// Denied asks the simulator which of actions caller's policies do not allow, in the order given.
// An error is a question IAM did not answer, most often because the caller may not ask it.
func Denied(ctx context.Context, sim Simulator, caller Caller, actions []string) ([]string, error) {
	principal, err := Principal(ctx, sim, caller)
	if err != nil {
		return nil, err
	}
	allowed, err := sim.Allowed(ctx, principal, actions)
	if err != nil {
		return nil, err
	}
	held := map[string]bool{}
	for _, a := range allowed {
		held[strings.ToLower(a)] = true
	}
	var denied []string
	for _, a := range actions {
		// IAM matches action names without regard to case, and echoes them as it pleases.
		if !held[strings.ToLower(a)] {
			denied = append(denied, a)
		}
	}
	return denied, nil
}
