package awsaccess

// The AWS SDK for Go v2 (Apache-2.0) is linked into Draugr for these calls. It reads the same
// credential chain Prowler does, so the identity checked is the one Prowler scans as.

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// defaultRegion is where STS and IAM are asked when nothing in the environment names a region.
// Every commercial-partition credential is answered there; a GovCloud or China profile names its
// own.
const defaultRegion = "us-east-1"

// loadConfig reads the default credential chain and refuses one that yields no credentials.
func loadConfig(ctx context.Context) (aws.Config, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return aws.Config{}, fmt.Errorf("read the AWS configuration: %w", err)
	}
	if cfg.Region == "" {
		cfg.Region = defaultRegion
	}
	if cfg.Credentials == nil {
		return aws.Config{}, ErrNoCredentials
	}
	if _, err := cfg.Credentials.Retrieve(ctx); err != nil {
		// The chain's own error lists every provider it tried, which helps whoever is debugging the
		// lookup and nobody reading a scan's errors.
		slog.DebugContext(ctx, "no AWS credentials", "error", err)
		return aws.Config{}, ErrNoCredentials
	}
	return cfg, nil
}

// STS asks AWS Security Token Service who the credentials are.
type STS struct {
	client *sts.Client
}

// New loads the default credential chain and returns an Identifier that asks with it.
func New(ctx context.Context) (*STS, error) {
	cfg, err := loadConfig(ctx)
	if err != nil {
		return nil, err
	}
	return &STS{client: sts.NewFromConfig(cfg)}, nil
}

// CallerIdentity asks STS GetCallerIdentity, which needs no permission: any valid credentials may
// ask who they are.
func (s *STS) CallerIdentity(ctx context.Context) (Caller, error) {
	out, err := s.client.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return Caller{}, fmt.Errorf("ask AWS who the credentials are: %w", err)
	}
	return Caller{Account: aws.ToString(out.Account), ARN: aws.ToString(out.Arn)}, nil
}

// IAM asks AWS Identity and Access Management what the credentials' policies allow. Both of its
// calls need a permission of their own, iam:GetRole and iam:SimulatePrincipalPolicy, which a
// read-only role commonly lacks.
type IAM struct {
	client *iam.Client
}

// NewIAM loads the default credential chain and returns a Simulator that asks with it.
func NewIAM(ctx context.Context) (*IAM, error) {
	cfg, err := loadConfig(ctx)
	if err != nil {
		return nil, err
	}
	return &IAM{client: iam.NewFromConfig(cfg)}, nil
}

// RoleARN asks iam:GetRole for the role's ARN, which carries its path.
func (c *IAM) RoleARN(ctx context.Context, name string) (string, error) {
	out, err := c.client.GetRole(ctx, &iam.GetRoleInput{RoleName: aws.String(name)})
	if err != nil {
		return "", fmt.Errorf("ask IAM for role %s: %w", name, err)
	}
	if out.Role == nil {
		return "", fmt.Errorf("ask IAM for role %s: no role in the answer", name)
	}
	return aws.ToString(out.Role.Arn), nil
}

// Allowed asks iam:SimulatePrincipalPolicy whether principal's policies allow each action on any
// resource. The simulation weighs the principal's identity policies, its permissions boundary and
// the organization's service control policies; a resource's own policy and a session policy are
// outside it.
func (c *IAM) Allowed(ctx context.Context, principal string, actions []string) ([]string, error) {
	pages := iam.NewSimulatePrincipalPolicyPaginator(c.client, &iam.SimulatePrincipalPolicyInput{
		PolicySourceArn: aws.String(principal),
		ActionNames:     actions,
	})
	var allowed []string
	for pages.HasMorePages() {
		page, err := pages.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("simulate the policies of %s: %w", principal, err)
		}
		for _, r := range page.EvaluationResults {
			if r.EvalDecision == types.PolicyEvaluationDecisionTypeAllowed {
				allowed = append(allowed, aws.ToString(r.EvalActionName))
			}
		}
	}
	return allowed, nil
}
