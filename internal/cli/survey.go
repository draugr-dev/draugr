package cli

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/draugr-dev/draugr/internal/builtins"
	"github.com/draugr-dev/draugr/internal/surfaces"
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
	replace bool
}

// newSurveyCommand builds `draugr survey` and its per-platform subcommands.
//
// Subcommands rather than a flag per surveyor, because one flat set hides which flags are
// related to each other. `--k8s-namespace` means something only alongside `--k8s-images`, and
// nothing about a flat list says so: `draugr survey --github-org acme --k8s-namespace prod`
// reads as a valid command, and the namespace applies to nothing. A flag that does nothing
// without saying so is the failure this codebase refuses everywhere else, and a subcommand
// cannot accept one that does not belong to it.
//
// The prefixes were already doing a subcommand's work by hand: every surveyor's options had to be
// namespaced (`--k8s-…`, `--github-…`) to keep them apart in one flat set, which grows with each
// surveyor and puts unrelated options beside each other in one `--help`.
//
// Running several surveyors at once was the reason for the flat design, and it survives: a survey
// folds into the Saga already at `--output`, which is how a descriptor is added to anyway.
//
// Merging is the default because the alternative loses work silently. A descriptor is edited by
// hand — exposure, criticality, exclusions, controls somebody chose — and none of that is
// rediscoverable by a survey. Overwriting it needs to be something you ask for, not something you
// get by forgetting a flag, because the failure is a file you have to reconstruct from memory and
// the success looks identical at the moment it happens.
func newSurveyCommand() *cobra.Command {
	opts := &surveyOptions{}
	cmd := &cobra.Command{
		Use:   "survey",
		Short: "Discover an application's surface and write it to a Saga",
		Long: "Discover what an application is made of and write it into a Saga descriptor.\n\n" +
			"Each surveyor is its own subcommand, so a surveyor's options sit with the surveyor\n" +
			"they belong to. Run as many as you like against one descriptor — each survey folds\n" +
			"into the Saga already at --output:\n\n" +
			"  draugr survey k8s images --namespace prod -o draugr.saga.yaml\n" +
			"  draugr survey github repos --org acme -o draugr.saga.yaml\n\n" +
			"A descriptor carries decisions a survey cannot rediscover — exposure, criticality,\n" +
			"exclusions — so an existing file is added to rather than overwritten. Use --replace\n" +
			"when you do want to start again.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}

	cmd.PersistentFlags().StringVarP(&opts.output, "output", "o", "", "write the Saga here (default stdout)")
	cmd.PersistentFlags().StringVar(&opts.name, "name", "", "release name for a newly created Saga")
	cmd.PersistentFlags().StringVar(&opts.version, "version", "0.0.0", "release version for a newly created Saga")
	cmd.PersistentFlags().BoolVar(&opts.replace, "replace", false,
		"overwrite the Saga at --output instead of adding to it")

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

	// --context belongs to the group: it says which cluster, which both surveyors need. A
	// surveyor-specific option would mean setting it twice to survey one cluster two ways.
	var kubeContext string
	scopeFor := func(ref string) plugin.SurveyScope {
		scope := plugin.SurveyScope{Ref: ref}
		if kubeContext != "" {
			scope.Config = plugin.Config{"context": kubeContext}
		}
		return scope
	}

	var namespaces []string
	images := &cobra.Command{
		Use:   "images",
		Short: "Discover the container images running in a cluster",
		Long: "Enumerate the unique container images running in a cluster, with the digest each is\n" +
			"actually running, and write them as components.\n\n" +
			"Scoped to a namespace, this also proposes each component's exposure from cluster\n" +
			"topology — review it, then set criticality with `draugr classify`.\n\n" +
			"--namespace may be repeated, and each one becomes its own component with its own\n" +
			"proposed exposure. That is the difference between three namespaces and no namespace\n" +
			"at all: the whole cluster is one component, and one exposure for everything running\n" +
			"anywhere in it would not mean anything.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runSurvey(cmd.Context(), *opts, requestPerNamespace("k8s-images", namespaces, scopeFor),
				builtins.SurveyorRegistry(), cmd.OutOrStdout())
		},
	}
	images.Flags().StringSliceVar(&namespaces, "namespace", nil,
		"limit discovery to a namespace; repeat for several, one component each (default all)")

	var clusterNamespaces []string
	cluster := &cobra.Command{
		Use:   "cluster",
		Short: "Discover the cluster itself, as infrastructure to audit",
		Long: "Write the cluster as an `infrastructure` component, so the CIS benchmark controls\n" +
			"apply to it. Separate from `k8s images`: those are the application, this is what it\n" +
			"runs on, and they will differ in criticality.\n\n" +
			"With --namespace, the component owns that namespace rather than the whole cluster.\n" +
			"Repeat it for several, and each becomes its own component — they are audited\n" +
			"separately because they are usually owned separately.\n\n" +
			"exposure and criticality are left unset — they are judgements no cluster holds; run\n" +
			"`draugr classify` for those.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runSurvey(cmd.Context(), *opts, requestPerNamespace("k8s-cluster", clusterNamespaces, scopeFor),
				builtins.SurveyorRegistry(), cmd.OutOrStdout())
		},
	}
	cluster.Flags().StringSliceVar(&clusterNamespaces, "namespace", nil,
		"the component owns this namespace rather than the whole cluster; repeat for several")

	cmd.PersistentFlags().StringVar(&kubeContext, "context", "",
		"kubeconfig context to survey (default the current one)")
	cmd.AddCommand(images, cluster)
	return cmd
}

// requestPerNamespace turns the namespaces a caller named into one survey request each.
//
// A surveyor scoped to a namespace describes that namespace: it names the component after it and
// proposes an exposure from its topology. Passing several as one scope would collapse them back
// into a single component and lose both — so the loop is here, at the boundary between what the
// caller asked for and what a surveyor is asked to do, and the surveyor keeps answering one
// question at a time.
//
// No namespace means the whole cluster, which is one request with an empty ref and the behaviour
// that has always been the default.
func requestPerNamespace(name string, namespaces []string, scopeFor func(string) plugin.SurveyScope) []surveyor.Request {
	if len(namespaces) == 0 {
		return []surveyor.Request{{Surveyor: name, Scope: scopeFor("")}}
	}
	out := make([]surveyor.Request, 0, len(namespaces))
	for _, ns := range namespaces {
		out = append(out, surveyor.Request{Surveyor: name, Scope: scopeFor(ns)})
	}
	return out
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
	// Checked before the merge, because afterwards the wider scope has won and there is nothing
	// left to notice. Somebody who passed --namespace is entitled to know it did not reach the
	// descriptor, even though keeping the wider scope was the right call.
	merged := opts.mergesInto()
	narrowed := saga.NarrowsScope(&model, frag)
	// Same reason, for the same kind of message: a merge keeps the exposure already in the
	// descriptor, so afterwards a proposal that was discarded is indistinguishable from one that
	// landed. Only the ones that landed are worth asking anyone to confirm.
	settled := classifiedComponents(model)
	surveyor.Apply(&model, frag)
	for _, target := range narrowed {
		slog.Warn("--namespace not applied: this target already covers the whole cluster",
			"target", target, "fix", "edit namespaces: in the descriptor to narrow it")
	}
	if added := enableControlsForSurface(&model); len(added) > 0 {
		// To stderr, so a descriptor written to stdout stays a descriptor.
		slog.Info("enabled controls for the discovered surface", "controls", strings.Join(added, ", "))
	}
	// stderr for the same reason. Also after the merge, so it describes the file rather than the
	// survey — a proposal the merge declined to apply is not a proposal anyone has to act on.
	if note := proposedExposureNote(proposedExposures(frag, settled)); note != "" {
		_, _ = fmt.Fprintln(os.Stderr, note)
	}

	out, err := yaml.Marshal(&model)
	if err != nil {
		return err
	}
	if opts.output != "" {
		if err := os.WriteFile(opts.output, out, 0o600); err != nil {
			return err
		}
		// Say what was produced. A command whose whole purpose is to write a file has to name
		// the file, count what it found, and say where it went — otherwise the only evidence of
		// a successful survey is the absence of an error, and `-o .saga.yaml` is a name `ls`
		// does not show. Silence and failure look identical, and the reader picks the wrong one.
		//
		// stderr, so a descriptor written to stdout stays a descriptor.
		_, _ = fmt.Fprintln(os.Stderr, surveySummary(opts, frag, model, merged))
		return nil
	}
	_, err = stdout.Write(out)
	return err
}

// exposureProposal is a component whose exposure a surveyor read rather than a person decided.
type exposureProposal struct {
	component string
	exposure  saga.Exposure
}

// classifiedComponents names the components that already carry an exposure.
func classifiedComponents(model saga.Model) map[string]bool {
	settled := map[string]bool{}
	for _, c := range model.Components {
		if c.Exposure != "" {
			settled[c.Name] = true
		}
	}
	return settled
}

// proposedExposures returns the exposures this survey proposed and the descriptor took, in the
// order the surveyor reported them.
//
// A surveyor reads topology, which is evidence about reachability rather than a decision about
// it: an Ingress says a route exists, not who may take it, and a namespace with no external
// Service may still be reachable through a gateway the cluster cannot see. The value is still
// worth writing — it is right more often than nothing is, and an unclassified component is
// treated as high-risk, which skews a report in its own direction.
//
// What it must not do is arrive silently. Written into a file, a proposal is indistinguishable
// from a value somebody chose, while being the input that decides whether a finding is P1 or P3.
// So the survey says which ones it guessed, and `draugr classify` is where they get settled.
func proposedExposures(frag saga.Fragment, settled map[string]bool) []exposureProposal {
	var out []exposureProposal
	for _, c := range frag.Components {
		if c.Exposure == "" || settled[c.Name] {
			continue
		}
		out = append(out, exposureProposal{component: c.Name, exposure: c.Exposure})
	}
	return out
}

// proposedExposureNote renders the proposals as one block, or "" when there are none.
//
// Names every component and its value rather than counting them, because the reader's next action
// is per-component: they are confirming or correcting each one, and a count tells them only that
// there is something to open the file for.
func proposedExposureNote(proposals []exposureProposal) string {
	if len(proposals) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("exposure proposed from cluster topology, not confirmed — run `draugr classify` to set it:\n")
	width := 0
	for _, p := range proposals {
		width = max(width, len(p.component))
	}
	for _, p := range proposals {
		fmt.Fprintf(&b, "  %-*s  %s\n", width, p.component, p.exposure)
	}
	return strings.TrimRight(b.String(), "\n")
}

// surveySummary describes the artifact rather than the mechanics: what is now in the file, and
// whether this survey added to something that was already there.
func surveySummary(opts surveyOptions, frag saga.Fragment, model saga.Model, merged bool) string {
	verb := "wrote"
	if merged {
		verb = "merged into"
	}

	var repos, images, hosts, infra int
	for _, c := range model.Components {
		repos += len(c.Repositories)
		images += len(c.Images)
		hosts += len(c.Hosts)
		infra += len(c.Infrastructure)
	}
	parts := []string{plural(len(model.Components), "component")}
	for _, p := range []struct {
		n    int
		noun string
	}{{repos, "repository"}, {images, "image"}, {hosts, "host"}, {infra, "infrastructure target"}} {
		if p.n > 0 {
			parts = append(parts, plural(p.n, p.noun))
		}
	}

	line := fmt.Sprintf("%s %s — %s", verb, opts.output, strings.Join(parts, ", "))
	// On a merge the total says little on its own; the reader wants to know what this run added.
	if merged {
		line += fmt.Sprintf(" (this survey found %s)", plural(len(frag.Components), "component"))
	}
	if len(model.Components) == 0 {
		// A descriptor describing nothing is almost always a scope or credentials problem, and
		// it is the one case where the count alone reads as success.
		line += " — nothing was discovered, so this descriptor scans nothing"
	}
	return line
}

// plural renders a count with its noun, pluralised the way English mostly manages.
//
// The -y → -ies rule only applies after a consonant: "repository" becomes "repositories" and
// "day" becomes "days".
func plural(n int, noun string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, noun)
	}
	if stem, ok := strings.CutSuffix(noun, "y"); ok && stem != "" && !strings.ContainsRune("aeiou", rune(stem[len(stem)-1])) {
		return fmt.Sprintf("%d %sies", n, stem)
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

// mergesInto reports whether this run adds to an existing descriptor rather than writing a new
// one. Both the loader and the summary ask it, so the file that gets written and the sentence
// describing it cannot disagree.
func (o surveyOptions) mergesInto() bool {
	return !o.replace && o.output != "" && fileExists(o.output)
}

// baseModel returns the model to add to: the existing Saga at --output, unless --replace says to
// start again or there is nothing there yet.
func baseModel(opts surveyOptions) (saga.Model, error) {
	if opts.mergesInto() {
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

// enableControlsForSurface turns on the controls the discovered components can be checked with.
//
// Only controls the descriptor says nothing about are touched. A control someone set — including
// one they set to `enabled: false` — is left exactly as it is, because `--merge` runs against a
// descriptor people edit, and a survey that re-enabled something you had switched off would be a
// worse failure than the one this fixes.
//
// Returns the controls it added, so the command can say what it did rather than changing the
// descriptor silently.
func enableControlsForSurface(model *saga.Model) []string {
	wanted := map[string]bool{}
	for i := range model.Components {
		c := &model.Components[i]
		for surface, controls := range surfaces.Controls {
			if !surfaces.ComponentHas(c, surface) {
				continue
			}
			for _, name := range controls {
				wanted[name] = true
			}
		}
	}

	var added []string
	for name := range wanted {
		if _, configured := model.Config.Controllers[name]; configured {
			continue
		}
		if model.Config.Controllers == nil {
			model.Config.Controllers = map[string]saga.ControllerSettings{}
		}
		model.Config.Controllers[name] = saga.ControllerSettings{"enabled": true}
		added = append(added, name)
	}
	sort.Strings(added)
	return added
}
