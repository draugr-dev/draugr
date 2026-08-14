package cli

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/draugr-dev/draugr/internal/builtins"
	"github.com/draugr-dev/draugr/internal/surfaces"
	"github.com/draugr-dev/draugr/internal/surveyors"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/surveyor"
)

// surveyOptions are the settings shared by every surveyor: what to write, and what to write it
// into. Anything specific to one surveyor belongs on that surveyor's own command.
type surveyOptions struct {
	output   string
	name     string
	version  string
	replace  bool
	fragment bool
}

// check rejects flag combinations that would produce a file Draugr then refuses to read.
//
// A fragment is recognised by its name — `draugr validate` and a `fragments:` reference both
// decide from the suffix — so a fragment written as `x.saga.yaml` is read as a Saga and rejected
// for having no release. The survey knows that before it connects to anything, and saying so then
// costs a retype rather than a survey.
func (o surveyOptions) check(cmd *cobra.Command) error {
	if !o.fragment {
		return nil
	}
	if o.output != "" && !IsFragmentFile(filepath.Base(o.output)) {
		return fmt.Errorf("--fragment writes a fragment, which is recognised by its name: "+
			"%q has to end in .saga-fragment.yaml (or .yml), or Draugr will read it back as a Saga",
			o.output)
	}
	// release: is what a fragment does not have. Silently ignoring these would leave somebody
	// believing they had named the thing they are describing.
	for _, name := range []string{"name", "version"} {
		if cmd.Flags().Changed(name) {
			return fmt.Errorf("--%s sets the release, and a fragment has none — it is part of a "+
				"descriptor rather than a thing to release", name)
		}
	}
	return nil
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
			"Each surveyor is its own subcommand. Run several against one descriptor — each\n" +
			"folds into the Saga already at --output:\n\n" +
			"  draugr survey k8s images --namespace prod -o draugr.saga.yaml\n" +
			"  draugr survey github repos --org acme -o draugr.saga.yaml\n" +
			"  draugr survey gitlab projects --group acme -o draugr.saga.yaml\n" +
			"  draugr survey azure repos --org acme -o draugr.saga.yaml\n\n" +
			"An existing file is added to, never overwritten. Use --replace to start again.",
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
	cmd.PersistentFlags().BoolVar(&opts.fragment, "fragment", false,
		"write a Saga fragment — components only, for a descriptor to include")

	// Checked here rather than per subcommand: --fragment is shared, and so are the flags it
	// contradicts. A flag that quietly does nothing is the failure this file is arranged to avoid.
	cmd.PersistentPreRunE = func(c *cobra.Command, _ []string) error {
		return opts.check(c)
	}

	cmd.AddCommand(newSurveyK8sCommand(opts), newSurveyGitHubCommand(opts),
		newSurveyGitLabCommand(opts), newSurveyAzureCommand(opts))
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
	var noExposure bool
	images := &cobra.Command{
		Use:   "images",
		Short: "Discover the container images running in a cluster",
		Long: "Enumerate the unique container images running in a cluster, with the digest each is\n" +
			"actually running, and write them as components.\n\n" +
			"A namespace is the unit: each becomes its own component, carrying only the images it\n" +
			"runs and an exposure proposed from its own topology. Review the exposures, then set\n" +
			"criticality with `draugr classify`.\n\n" +
			"--namespace narrows which ones are described, and may be repeated. Without it every\n" +
			"namespace is described, which on a large cluster is a lot of components — name the\n" +
			"ones you own.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			scoped := scopeFor
			if noExposure {
				scoped = func(ref string) plugin.SurveyScope {
					sc := scopeFor(ref)
					if sc.Config == nil {
						sc.Config = plugin.Config{}
					}
					sc.Config[surveyors.ProposeExposureKey] = false
					return sc
				}
			}
			return runSurvey(cmd.Context(), *opts, requestPerNamespace("k8s-images", namespaces, scoped),
				builtins.SurveyorRegistry(), cmd.OutOrStdout())
		},
	}
	images.Flags().StringSliceVar(&namespaces, "namespace", nil,
		"describe only this namespace; repeat for several (default every namespace)")
	images.Flags().BoolVar(&noExposure, "no-exposure", false,
		"do not guess each component's exposure; leave it unset for draugr classify")

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
// No namespace means every namespace, which is one request with an empty ref: a surveyor that
// describes a namespace still does so for each of them, and the empty scope is what tells it to
// find them rather than be given them. Enumerating here instead would mean building a Kubernetes
// client in the CLI to ask a question the surveyor is already connected to answer.
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

// newSurveyGitLabCommand groups the surveyors that read GitLab.
func newSurveyGitLabCommand(opts *surveyOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "gitlab",
		Short: "Discover from GitLab",
		Long: "Surveyors that read GitLab. Authentication comes from GITLAB_TOKEN, or a token\n" +
			"named in scope config. A self-managed instance is named by GITLAB_URL (or the\n" +
			"CI_API_V4_URL a runner already sets).",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}

	var group string
	projects := &cobra.Command{
		Use:   "projects",
		Short: "Discover the projects in a GitLab group",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if group == "" {
				return fmt.Errorf("--group is required: it names the GitLab group to discover projects in")
			}
			return runSurvey(cmd.Context(), *opts, []surveyor.Request{{
				Surveyor: "gitlab-group-projects",
				Scope:    plugin.SurveyScope{Ref: group},
			}}, builtins.SurveyorRegistry(), cmd.OutOrStdout())
		},
	}
	projects.Flags().StringVar(&group, "group", "",
		"the GitLab group to discover projects in; subgroups are included")

	cmd.AddCommand(projects)
	return cmd
}

// newSurveyAzureCommand groups the surveyors that read Azure DevOps.
func newSurveyAzureCommand(opts *surveyOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "azure",
		Short: "Discover from Azure DevOps",
		Long: "Surveyors that read Azure DevOps. Authentication comes from AZURE_DEVOPS_EXT_PAT\n" +
			"(or AZURE_DEVOPS_TOKEN, or a token named in scope config) — a personal access token\n" +
			"with the Code (read) scope. An Azure DevOps Server instance is named by\n" +
			"AZURE_DEVOPS_URL, including its collection.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}

	var org, project string
	repos := &cobra.Command{
		Use:   "repos",
		Short: "Discover the Git repositories in an Azure DevOps organization or project",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if org == "" {
				return fmt.Errorf("--org is required: it names the Azure DevOps organization to discover repositories in")
			}
			return runSurvey(cmd.Context(), *opts, []surveyor.Request{{
				Surveyor: "azure-devops-repos",
				Scope:    plugin.SurveyScope{Ref: azureScopeRef(org, project)},
			}}, builtins.SurveyorRegistry(), cmd.OutOrStdout())
		},
	}
	repos.Flags().StringVar(&org, "org", "", "the Azure DevOps organization to discover repositories in")
	repos.Flags().StringVar(&project, "project", "",
		"limit discovery to one project; omit to survey every project in the organization")

	cmd.AddCommand(repos)
	return cmd
}

// azureScopeRef builds the surveyor's scope from the two names Azure DevOps uses.
//
// Two flags rather than one "org/project" string: they are two names, and a single flag makes a
// project whose name contains a slash indistinguishable from an organization plus a project. The
// surveyor takes one string because the API path does, so the join belongs here — once, where the
// two halves are still separate.
func azureScopeRef(org, project string) string {
	if project == "" {
		return org
	}
	return org + "/" + project
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

	if opts.fragment {
		return surveyIntoFragment(opts, frag, stdout)
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
	settled := classifiedComponents(model.Components)
	surveyor.Apply(&model, frag)
	reportNarrowed(narrowed)
	if added := enableControlsForSurface(&model); len(added) > 0 {
		// To stderr, so a descriptor written to stdout stays a descriptor.
		slog.Info("enabled controls for the discovered surface", "controls", strings.Join(added, ", "))
	}
	// stderr for the same reason. Also after the merge, so it describes the file rather than the
	// survey — a proposal the merge declined to apply is not a proposal anyone has to act on.
	if note := proposedExposureNote(proposedExposures(frag, settled)); note != "" {
		_, _ = fmt.Fprintln(os.Stderr, note)
	}

	out, err := marshalSaga(&model)
	if err != nil {
		return err
	}
	// The reasoning goes beside the value, because that is where it is read. The note above is a
	// terminal that scrolls; the descriptor is opened later, in an editor, by somebody who may not
	// have run the survey — and a proposed exposure and a decided one look identical in a file.
	//
	// Filtered by the same rule the note uses: a component whose exposure the descriptor already
	// carried keeps its own value, and commenting that would describe somebody's decision as a
	// guess.
	if out, err = saga.AnnotateExposures(out, proposedReasons(frag, settled)); err != nil {
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
		_, _ = fmt.Fprintln(os.Stderr, surveySummary(opts, frag, model.Components, merged))
		return nil
	}
	_, err = stdout.Write(out)
	return err
}

// surveyIntoFragment writes what a survey found as a Saga fragment rather than a whole descriptor.
//
// A fragment is components and nothing else. It carries no `release:` — it is not a thing to be
// released, it is part of one — and no `config.controllers`, because FragmentConfig deliberately
// cannot express them: the descriptor that includes a fragment decides what to run against it.
// That is the point of the option, for a team that owns a namespace and hands its surface to a
// descriptor somebody else maintains.
func surveyIntoFragment(opts surveyOptions, frag saga.Fragment, stdout io.Writer) error {
	base, err := baseFragment(opts)
	if err != nil {
		return err
	}
	merged := opts.mergesInto()
	narrowed := saga.NarrowsScopeIn(base.Components, frag)
	settled := classifiedComponents(base.Components)
	for _, c := range frag.Components {
		base.Components = saga.UpsertComponent(base.Components, c)
	}
	reportNarrowed(narrowed)
	// Said once, because its absence is the one difference from a Saga a reader would otherwise
	// have to work out from an empty file. A fragment enabling controls would be a fragment
	// deciding policy for the descriptor that includes it.
	slog.Info("no controls enabled: a fragment describes a surface, and the descriptor that includes it decides what to run")
	if note := proposedExposureNote(proposedExposures(frag, settled)); note != "" {
		_, _ = fmt.Fprintln(os.Stderr, note)
	}

	out, err := marshalSaga(&base)
	if err != nil {
		return err
	}
	if out, err = saga.AnnotateExposures(out, proposedReasons(frag, settled)); err != nil {
		return err
	}
	if opts.output != "" {
		if err := os.WriteFile(opts.output, out, 0o600); err != nil {
			return err
		}
		_, _ = fmt.Fprintln(os.Stderr, surveySummary(opts, frag, base.Components, merged))
		return nil
	}
	_, err = stdout.Write(out)
	return err
}

// baseFragment returns the fragment to add to: the one at --output, unless --replace says to start
// again or there is nothing there yet.
func baseFragment(opts surveyOptions) (saga.Fragment, error) {
	if !opts.mergesInto() {
		return saga.Fragment{}, nil
	}
	data, err := os.ReadFile(opts.output) // #nosec G304 -- operator-provided path, by design
	if err != nil {
		return saga.Fragment{}, err
	}
	return saga.LoadFragment(data, opts.output)
}

// reportNarrowed says which --namespace values the merge declined to apply.
func reportNarrowed(narrowed []string) {
	for _, target := range narrowed {
		slog.Warn("--namespace not applied: this target already covers the whole cluster",
			"target", target, "fix", "edit namespaces: in the descriptor to narrow it")
	}
}

// exposureProposal is a component whose exposure a surveyor read rather than a person decided.
type exposureProposal struct {
	component string
	exposure  saga.Exposure
}

// classifiedComponents names the components that already carry an exposure.
func classifiedComponents(components []saga.Component) map[string]bool {
	settled := map[string]bool{}
	for _, c := range components {
		if c.Exposure != "" {
			settled[c.Name] = true
		}
	}
	return settled
}

// marshalSaga writes a descriptor at the indent every other command that touches one uses.
//
// yaml.Marshal's default is four, which is not a choice anybody made here — and a file written
// with it is reindented end to end the first time `draugr classify` sets a field in it.
func marshalSaga(doc any) ([]byte, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(saga.Indent)
	if err := enc.Encode(doc); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
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

// proposedReasons is what each proposed exposure was read from, for the components the descriptor
// actually took a proposal for.
func proposedReasons(frag saga.Fragment, settled map[string]bool) map[string]string {
	if len(frag.ExposureReasons) == 0 {
		return nil
	}
	out := make(map[string]string, len(frag.ExposureReasons))
	for _, p := range proposedExposures(frag, settled) {
		if reason := frag.ExposureReasons[p.component]; reason != "" {
			out[p.component] = reason
		}
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
func surveySummary(opts surveyOptions, frag saga.Fragment, components []saga.Component, merged bool) string {
	verb := "wrote"
	if merged {
		verb = "merged into"
	}

	var repos, images, hosts, infra int
	for _, c := range components {
		repos += len(c.Repositories)
		images += len(c.Images)
		hosts += len(c.Hosts)
		infra += len(c.Infrastructure)
	}
	parts := []string{plural(len(components), "component")}
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
	if len(components) == 0 {
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
