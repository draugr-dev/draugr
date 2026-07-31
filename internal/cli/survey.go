package cli

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sort"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/draugr-dev/draugr/internal/builtins"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/surveyor"
)

// surveyOptions are the settings shared by every surveyor: what to write, and what to write it
// into. Anything specific to one surveyor belongs on that surveyor's own command.
type surveyOptions struct {
	output  string
	name    string
	version string
	merge   bool
}

// newSurveyCommand builds `draugr survey` and its per-platform subcommands.
//
// Subcommands rather than a flag per surveyor, because the flags were quietly related to each
// other and nothing said so. `--k8s-namespace` meant something only alongside `--k8s-images`, and
// `draugr survey --github-org acme --k8s-namespace prod` was accepted in silence — the namespace
// applied to nothing and nobody was told. A flag that does nothing without saying so is the
// failure this codebase refuses everywhere else.
//
// The prefixes were already doing a subcommand's work by hand: every surveyor's options had to be
// namespaced (`--k8s-…`, `--github-…`) to keep them apart in one flat set, which grows with each
// surveyor and puts unrelated options beside each other in one `--help`.
//
// Running several surveyors at once was the reason for the flat design, and it survives: `--merge`
// folds a survey into the Saga already at `--output`, which is how a descriptor is added to
// anyway.
func newSurveyCommand() *cobra.Command {
	opts := &surveyOptions{}
	cmd := &cobra.Command{
		Use:   "survey",
		Short: "Discover an application's surface and write it to a Saga",
		Long: "Discover what an application is made of and write it into a Saga descriptor.\n\n" +
			"Each surveyor is its own subcommand, so a surveyor's options sit with the surveyor\n" +
			"they belong to. Run more than one with --merge, which folds each survey into the\n" +
			"Saga already at --output:\n\n" +
			"  draugr survey k8s images --namespace prod -o draugr.saga.yaml\n" +
			"  draugr survey github repos --org acme --merge -o draugr.saga.yaml",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := reportRetiredSurveyFlags(cmd); err != nil {
				return err
			}
			return cmd.Help()
		},
	}

	cmd.PersistentFlags().StringVarP(&opts.output, "output", "o", "", "write the Saga here (default stdout)")
	cmd.PersistentFlags().StringVar(&opts.name, "name", "", "release name for a newly created Saga")
	cmd.PersistentFlags().StringVar(&opts.version, "version", "0.0.0", "release version for a newly created Saga")
	cmd.PersistentFlags().BoolVar(&opts.merge, "merge", false, "merge into the existing Saga at --output")

	registerRetiredSurveyFlags(cmd)
	cmd.AddCommand(newSurveyK8sCommand(opts), newSurveyGitHubCommand(opts))
	return cmd
}

// newSurveyK8sCommand groups the surveyors that read a Kubernetes cluster.
func newSurveyK8sCommand(opts *surveyOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "k8s",
		Short: "Discover from a Kubernetes cluster",
		Long: "Surveyors that read a Kubernetes cluster through the ambient kubeconfig\n" +
			"(KUBECONFIG, ~/.kube/config, or in-cluster).",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}

	var namespace string
	images := &cobra.Command{
		Use:   "images",
		Short: "Discover the container images running in a cluster",
		Long: "Enumerate the unique container images running in a cluster, with the digest each is\n" +
			"actually running, and write them as components.\n\n" +
			"Scoped to one namespace, this also proposes each component's exposure from cluster\n" +
			"topology — review it, then set criticality with `draugr classify`.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runSurvey(cmd.Context(), *opts, []surveyor.Request{{
				Surveyor: "k8s-images",
				Scope:    plugin.SurveyScope{Ref: namespace},
			}}, builtins.SurveyorRegistry(), cmd.OutOrStdout())
		},
	}
	images.Flags().StringVar(&namespace, "namespace", "", "limit discovery to one namespace (default all)")

	cmd.AddCommand(images)
	return cmd
}

// newSurveyGitHubCommand groups the surveyors that read GitHub.
func newSurveyGitHubCommand(opts *surveyOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "github",
		Short: "Discover from GitHub",
		Long: "Surveyors that read GitHub. Authentication comes from GITHUB_TOKEN, or a token\n" +
			"named in scope config.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}

	var org string
	repos := &cobra.Command{
		Use:   "repos",
		Short: "Discover the repositories in a GitHub organization",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if org == "" {
				return fmt.Errorf("--org is required: it names the GitHub organization to discover repositories in")
			}
			return runSurvey(cmd.Context(), *opts, []surveyor.Request{{
				Surveyor: "github-org-repos",
				Scope:    plugin.SurveyScope{Ref: org},
			}}, builtins.SurveyorRegistry(), cmd.OutOrStdout())
		},
	}
	repos.Flags().StringVar(&org, "org", "", "the GitHub organization to discover repositories in")

	cmd.AddCommand(repos)
	return cmd
}

// retiredSurveyFlags are the per-surveyor flags the subcommands replaced, and what to run instead.
//
// Registered rather than removed, so the answer is the replacement instead of "unknown flag".
// Hidden, because they are not choices — a flag list should offer what exists.
var retiredSurveyFlags = map[string]string{
	"k8s-images":    "draugr survey k8s images",
	"k8s-namespace": "draugr survey k8s images --namespace <ns>",
	"github-org":    "draugr survey github repos --org <org>",
}

func registerRetiredSurveyFlags(cmd *cobra.Command) {
	// k8s-images was a bool, so it has to stay one: as a string flag `--k8s-images` would fail
	// with "flag needs an argument" instead of reaching the error that names its replacement.
	cmd.Flags().Bool("k8s-images", false, "retired")
	_ = cmd.Flags().MarkHidden("k8s-images")
	for name := range retiredSurveyFlags {
		if name == "k8s-images" {
			continue
		}
		cmd.Flags().String(name, "", "retired")
		_ = cmd.Flags().MarkHidden(name)
	}
}

// reportRetiredSurveyFlags turns a retired flag into an error naming its replacement.
//
// The point of the rework is that a flag doing nothing in silence is unacceptable, so leaving one
// behind to be ignored would undo it.
func reportRetiredSurveyFlags(cmd *cobra.Command) error {
	names := make([]string, 0, len(retiredSurveyFlags))
	for name := range retiredSurveyFlags {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if f := cmd.Flags().Lookup(name); f != nil && f.Changed {
			return fmt.Errorf(
				"--%s was replaced by a subcommand, so each surveyor's options live with the "+
					"surveyor it belongs to. Use: %s", name, retiredSurveyFlags[name])
		}
	}
	return nil
}

// runSurvey runs the requested surveyors and writes (or merges) what they discovered into a Saga.
func runSurvey(ctx context.Context, opts surveyOptions, requests []surveyor.Request, reg *surveyor.Registry, stdout io.Writer) error {
	// Run always returns the fragments it did gather alongside a joined error, so a survey that
	// lost one source is still worth writing out. Reading frag after err is the contract here,
	// not an oversight — which is what the rule below would otherwise flag.
	// nosemgrep: trailofbits.go.invalid-usage-of-modified-variable.invalid-usage-of-modified-variable
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

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
