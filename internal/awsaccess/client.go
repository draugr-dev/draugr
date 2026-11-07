package awsaccess

// The AWS SDK for Go v2 (Apache-2.0) is linked into Draugr for this one call. It reads the same
// credential chain Prowler does, so the identity checked is the one Prowler scans as.

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// defaultRegion is where STS is asked when nothing in the environment names a region. Every
// commercial-partition credential is answered there; a GovCloud or China profile names its own.
const defaultRegion = "us-east-1"

// STS asks AWS Security Token Service who the credentials are.
type STS struct {
	client *sts.Client
}

// New loads the default credential chain and returns an Identifier that asks with it.
func New(ctx context.Context) (*STS, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("read the AWS configuration: %w", err)
	}
	if cfg.Region == "" {
		cfg.Region = defaultRegion
	}
	if cfg.Credentials == nil {
		return nil, ErrNoCredentials
	}
	if _, err := cfg.Credentials.Retrieve(ctx); err != nil {
		// The chain's own error lists every provider it tried, which helps whoever is debugging the
		// lookup and nobody reading a scan's errors.
		slog.DebugContext(ctx, "no AWS credentials", "error", err)
		return nil, ErrNoCredentials
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
