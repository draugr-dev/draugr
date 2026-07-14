package cli

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/draugr-dev/draugr/internal/builtins"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/surveyor"
)

type surveyOptions struct {
	output       string
	name         string
	version      string
	merge        bool
	k8sImages    bool
	k8sNamespace string
	githubOrg    string
}

func newSurveyCommand() *cobra.Command {
	opts := &surveyOptions{}
	cmd := &cobra.Command{
		Use:   "survey",
		Short: "Discover an application's surface and write it to a Saga",
		Long: "Run discovery surveyors (\"the Ravens\") and materialize the results into a\n" +
			"Saga descriptor. With --merge, discovered components are merged into an existing\n" +
			"Saga at --output.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runSurvey(cmd.Context(), *opts, builtins.SurveyorRegistry(), cmd.OutOrStdout())
		},
	}
	cmd.Flags().StringVarP(&opts.output, "output", "o", "", "write the Saga here (default stdout)")
	cmd.Flags().StringVar(&opts.name, "name", "", "release name for a newly created Saga")
	cmd.Flags().StringVar(&opts.version, "version", "0.0.0", "release version for a newly created Saga")
	cmd.Flags().BoolVar(&opts.merge, "merge", false, "merge into the existing Saga at --output")
	cmd.Flags().BoolVar(&opts.k8sImages, "k8s-images", false, "discover container images in a Kubernetes cluster")
	cmd.Flags().StringVar(&opts.k8sNamespace, "k8s-namespace", "", "namespace for --k8s-images (default all)")
	cmd.Flags().StringVar(&opts.githubOrg, "github-org", "", "discover repositories in this GitHub org")
	return cmd
}

// runSurvey assembles surveyor requests from the options, runs them, and writes (or
// merges) the discovered components into a Saga.
func runSurvey(ctx context.Context, opts surveyOptions, reg *surveyor.Registry, stdout io.Writer) error {
	requests := surveyRequests(opts)
	if len(requests) == 0 {
		return fmt.Errorf("no surveyors selected (use --k8s-images or --github-org)")
	}

	frag, err := reg.Run(ctx, requests)
	if err != nil {
		slog.Warn("survey completed with issues", "error", err)
		if len(frag.Components) == 0 {
			return err
		}
	}

	model, err := baseModel(opts)
	if err != nil {
		return err
	}
	surveyor.Apply(&model, frag)

	out, err := yaml.Marshal(&model)
	if err != nil {
		return err
	}
	if opts.output != "" {
		return os.WriteFile(opts.output, out, 0o600)
	}
	_, err = stdout.Write(out)
	return err
}

func surveyRequests(opts surveyOptions) []surveyor.Request {
	var requests []surveyor.Request
	if opts.k8sImages {
		requests = append(requests, surveyor.Request{
			Surveyor: "k8s-images",
			Scope:    surveyScope(opts.k8sNamespace),
		})
	}
	if opts.githubOrg != "" {
		requests = append(requests, surveyor.Request{
			Surveyor: "github-org-repos",
			Scope:    surveyScope(opts.githubOrg),
		})
	}
	return requests
}

// baseModel returns the model to merge into: the existing Saga when --merge is set and
// --output exists, otherwise a fresh model with the given release info.
func baseModel(opts surveyOptions) (saga.Model, error) {
	if opts.merge && opts.output != "" && fileExists(opts.output) {
		m, err := loadSaga(opts.output)
		if err != nil {
			return saga.Model{}, err
		}
		return *m, nil
	}
	return saga.Model{Release: saga.Release{Name: opts.name, Version: opts.version}}, nil
}

func surveyScope(ref string) plugin.SurveyScope {
	return plugin.SurveyScope{Ref: ref}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
