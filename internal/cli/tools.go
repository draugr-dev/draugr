package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/draugr-dev/draugr/internal/builtins"
	"github.com/draugr-dev/draugr/internal/netpolicy"
	"github.com/draugr-dev/draugr/internal/tools"
	"github.com/draugr-dev/draugr/pkg/config"

	"github.com/draugr-dev/draugr/pkg/tui"
)

func newToolsCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tools",
		Short: "Manage the external scanner tools Draugr uses",
		Long: "Provision and inspect the external scanners (trivy, gitleaks, …) Draugr runs.\n\n" +
			"Installs are opt-in and checksum-verified. A scan never downloads anything.",
	}
	cmd.AddCommand(newToolsInstallCommand())
	cmd.AddCommand(newToolsListCommand())
	cmd.AddCommand(newToolsOutdatedCommand())
	return cmd
}

func newToolsOutdatedCommand() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "outdated",
		Short: "Compare each pinned tool against the version its upstream publishes",
		Long: "Asks each tool's upstream what it publishes now and reports it beside the version " +
			"this Draugr installs.\n\n" +
			"The only command here that reaches the network without being asked to install " +
			"something. Nothing is downloaded and nothing on disk changes.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if netpolicy.Offline() {
				return netpolicy.Refuse("draugr tools outdated",
					"the release listings each tool publishes")
			}
			return runToolsOutdated(cmd.Context(), cmd.OutOrStdout(), asJSON, nil)
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false,
		"write the comparison as JSON, for a pipeline proposing a bump")
	return cmd
}

// runToolsOutdated reports what each upstream publishes beside what Draugr pins.
//
// Exits non-zero only where something could not be asked. Being behind is a fact to act on rather
// than a failure: a pipeline reads the JSON and decides, and a person reading the table has not
// done anything wrong by being one release back.
// A nil client is the default one, which is what the command passes. It is a parameter so a test
// can supply a transport that cannot reach anything: making every upstream unreachable by setting
// proxy variables works only while nothing in the process has read them first, and whether
// anything has is a property of the dependency graph rather than of this code.
func runToolsOutdated(ctx context.Context, w io.Writer, asJSON bool, client *http.Client) error {
	drift := tools.Outdated(ctx, client)

	if asJSON {
		type row struct {
			Tool   string `json:"tool"`
			Pinned string `json:"pinned"`
			Latest string `json:"latest,omitempty"`
			Behind bool   `json:"behind"`
			Error  string `json:"error,omitempty"`
		}
		out := make([]row, 0, len(drift))
		var unreachable int
		for _, d := range drift {
			r := row{Tool: d.Tool, Pinned: d.Pinned, Latest: d.Latest, Behind: d.Behind()}
			if d.Err != nil {
				r.Error = d.Err.Error()
				unreachable++
			}
			out = append(out, r)
		}
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		if err := enc.Encode(out); err != nil {
			return err
		}
		// The document is written first and the failure reported after, so a pipeline gets both
		// the rows and the exit code. Without the second, the one consumer this format exists for
		// reads "could not reach npm" as "current", which is the confusion `Drift.Err` is shaped
		// to prevent and the table mode already avoids.
		if unreachable > 0 {
			return fmt.Errorf("%d tool(s) could not be compared", unreachable)
		}
		return nil
	}

	col := tui.For(w)
	table := tui.NewTable(col, "Tool", "Pinned", "Upstream", "")
	var behind, unknown int
	for _, d := range drift {
		switch {
		case d.Err != nil:
			unknown++
			table.Row(tui.Styled(tui.StyleStrong, d.Tool), tui.PlainCell(d.Pinned),
				tui.Styled(tui.StyleMuted, "?"),
				tui.Styled(tui.StyleMuted, "could not ask: "+d.Err.Error()))
		case d.Behind():
			behind++
			table.Row(tui.Styled(tui.StyleStrong, d.Tool), tui.PlainCell(d.Pinned),
				tui.Styled(tui.StyleAccent, d.Latest),
				tui.Styled(tui.StyleMuted, "draugr tools install "+d.Tool))
		default:
			table.Row(tui.Styled(tui.StyleStrong, d.Tool), tui.PlainCell(d.Pinned),
				tui.Styled(tui.StyleMuted, d.Latest), tui.Styled(tui.StyleMuted, "current"))
		}
	}
	table.Render(w)

	// A pin is not a version somebody forgot to update. It is the build Draugr verified, so the
	// line says what being behind means rather than implying the reader is late.
	// Counted over what answered, not over everything. "0 of 11 behind" beside two rows that
	// could not be reached reads as a clean bill of health for tools nobody asked about.
	line := fmt.Sprintf("%d of %d behind the version their upstream publishes.",
		behind, len(drift)-unknown)
	if unknown > 0 {
		line += fmt.Sprintf(" %s could not be asked.", plural(unknown, "tool"))
	}
	_, _ = fmt.Fprintf(w, "\n%s\n", col.Paint(tui.StyleMuted, line))
	if unknown > 0 {
		return fmt.Errorf("%d tool(s) could not be compared", unknown)
	}
	return nil
}

type toolsInstallOptions struct {
	yes     bool
	dryRun  bool
	force   bool
	all     bool
	saga    string
	version string
	// wanted is the version to install per tool, resolved from draugr.config.yaml and then
	// --version. Absent means the version Draugr ships.
	wanted map[string]string
}

// want is the version to install for a tool, or "" for the one Draugr ships.
func (o toolsInstallOptions) want(name string) string { return o.wanted[name] }

func newToolsInstallCommand() *cobra.Command {
	opts := &toolsInstallOptions{}
	cmd := &cobra.Command{
		Use:   "install [tool...]",
		Short: "Download pinned, checksum-verified tools into ~/.draugr/bin",
		Long: "Download pinned scanner/utility binaries, verify each against a SHA-256 recorded in\n" +
			"Draugr, and install them into ~/.draugr/bin (which Draugr adds to PATH automatically).\n" +
			"With --saga, installs only the tools that descriptor's scan will run; with --all or no\n" +
			"arguments, every tool Draugr can provision. Prints the plan first; when run\n" +
			"interactively it asks for confirmation. Never downloads without being asked.",
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			dir, err := tools.BinDir()
			if err != nil {
				return err
			}
			names, all, err := installNames(cmd.OutOrStdout(), args, *opts)
			if err != nil {
				return err
			}
			if opts.wanted, err = wantedVersions(args, opts.version); err != nil {
				return err
			}
			install := func(name string) (tools.Installed, error) {
				return tools.InstallVersion(cmd.Context(), name, opts.want(name), dir, nil, opts.force)
			}
			// Names them, because someone preparing an air-gapped machine wants the list of what
			// they will have to bring across.
			if netpolicy.Offline() {
				wanted := names
				if all {
					wanted = tools.Installable()
				}
				if len(wanted) == 0 {
					return nil
				}
				return netpolicy.Refuse("draugr tools install",
					"the pinned release archive for: "+strings.Join(wanted, ", "))
			}
			return runToolsInstall(cmd.OutOrStdout(), cmd.InOrStdin(), names, all, *opts, install)
		},
	}
	cmd.Flags().BoolVarP(&opts.yes, "yes", "y", false, "skip the confirmation prompt")
	cmd.Flags().BoolVar(&opts.dryRun, "dry-run", false, "print the install plan and exit")
	cmd.Flags().StringVar(&opts.version, "version", "",
		"install this version instead of the one Draugr ships (one tool at a time)")
	cmd.Flags().BoolVar(&opts.force, "force", false,
		"reinstall even when the pinned version is already present (repairs a modified binary)")
	cmd.Flags().StringVar(&opts.saga, "saga", "",
		"install only the tools this descriptor's scan will run")
	cmd.Flags().BoolVar(&opts.all, "all", false,
		"install every tool Draugr can provision (what no arguments already does)")
	return cmd
}

// installNames decides what to install: the tools named, everything, or what a descriptor needs.
//
// Installing the whole catalog is a poor default on a security tool, every binary put on PATH is
// one more thing to trust, patch and explain. But it is the existing behavior and changing it
// silently would provision less than a pipeline expects. So --saga is opt-in, and the case for it
// is made where it is relevant rather than in the docs.
//
// The second result says the selection is the whole catalog, and it is not the same as an empty
// list. A descriptor whose controls all run on scanners built into Draugr needs nothing installed,
// and inferring "everything" from the empty result would answer `--saga` by downloading the
// catalog it was passed to avoid, one line under a message saying there was nothing to install.
func installNames(w io.Writer, args []string, opts toolsInstallOptions) ([]string, bool, error) {
	// --all is what no arguments already does, so it changes nothing about the outcome. It exists so
	// that the expensive case can be asked for deliberately, and so a reader of a pipeline can tell
	// a considered choice from a command that was never narrowed.
	if opts.all {
		switch {
		case opts.saga != "":
			return nil, false, fmt.Errorf(
				"--all and --saga ask for different things: one installs every tool Draugr provisions, "+
					"the other installs what %s needs. Pick one", opts.saga)
		case len(args) > 0:
			return nil, false, fmt.Errorf(
				"--all and an explicit tool list ask for different things: one installs every tool "+
					"Draugr provisions, the other installs %s. Pick one", strings.Join(quoteAll(args), ", "))
		}
		return nil, true, nil
	}
	if opts.saga == "" {
		if len(args) == 0 {
			noteDescriptorInWorkingDir(w)
			return nil, true, nil
		}
		return args, false, nil
	}
	if len(args) > 0 {
		return nil, false, fmt.Errorf(
			"--saga and an explicit tool list ask for different things: one installs what %s needs, "+
				"the other installs %s. Pick one", opts.saga, strings.Join(quoteAll(args), ", "))
	}

	model, err := loadSaga(opts.saga)
	if err != nil {
		return nil, false, err
	}
	required := requiredTools(builtins.Registry(), model)

	var names, unprovisionable []string
	installable := tools.Installable()
	for _, t := range required {
		if slices.Contains(installable, t.Binary) {
			names = appendUnique(names, t.Binary)
			continue
		}
		unprovisionable = appendUnique(unprovisionable, t.Binary)
	}
	sort.Strings(names)

	// The gap is the interesting part. Installing three of five and reporting success leaves
	// someone one failed scan away from discovering the other two.
	if len(unprovisionable) > 0 {
		sort.Strings(unprovisionable)
		_, _ = fmt.Fprintf(w, "%s needs %s, which Draugr cannot provision. Install %s separately (`draugr doctor %s` says where from).\n\n",
			opts.saga, strings.Join(quoteAll(unprovisionable), ", "),
			pluralThem(len(unprovisionable)), opts.saga)
	}
	if len(names) == 0 {
		_, _ = fmt.Fprintf(w, "Nothing to install: %s needs no tool Draugr provisions.\n", opts.saga)
	}
	return names, false, nil
}

func pluralThem(n int) string {
	if n == 1 {
		return "it"
	}
	return "them"
}

// noteDescriptorInWorkingDir points out --saga when a descriptor is sitting right there.
//
// Deliberately a note rather than a default. Inferring the descriptor from the working directory
// would mean a CI job running `tools install -y` in a repo that happens to contain one suddenly
// provisions a smaller set, and it may then be handed a different Saga to scan. Installing less
// than before, silently, is how a mystery failure appears in somebody else's pipeline.
func noteDescriptorInWorkingDir(w io.Writer) {
	// Every name a scan would find, not just the one `draugr init` writes. A project whose
	// descriptor is called anything else got no note at all, which is the project least likely to
	// know the flag exists.
	//
	// Exactly one, because the note quotes a path and a saving. With several descriptors beside
	// each other there is no way to tell which one this host is being prepared for, and naming the
	// first alphabetically would put a specific number against a guess.
	found, err := descriptorsIn(".")
	if err != nil || len(found) != 1 {
		return
	}
	descriptor := found[0]
	model, err := loadSaga(descriptor)
	if err != nil {
		return // not our problem here; scan and doctor will say so properly
	}
	// Count only what --saga would actually install. Counting tools Draugr cannot provision
	// would promise a number the flag does not deliver.
	installable := tools.Installable()
	needed := 0
	for _, t := range requiredTools(builtins.Registry(), model) {
		if slices.Contains(installable, t.Binary) {
			needed++
		}
	}
	// Defensive: no saving means nothing worth saying. Not reachable through any descriptor today,
	// because cosign and gosec are never *required* by a control, cosign verifies downloads and gosec
	// is opt-in, so a Saga cannot demand the whole catalog.
	if needed >= len(installable) {
		return
	}
	_, _ = fmt.Fprintf(w, "Note: `--saga %s` would install %d of these %d tools, the ones that descriptor's scan runs.\n\n",
		descriptor, needed, len(installable))
}

func newToolsListCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List the scanner tools Draugr knows about and their install status",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runToolsList(cmd.Context(), cmd.OutOrStdout())
		},
	}
}

// runToolsInstall provisions the named tools (all installable ones when names is empty) via
// install, which is injectable for tests. Returns an error if any install fails, after
// attempting them all.
// provenanceLabel summarizes how a provisioned tool was verified: the SHA-256 pin always
// applies; cosign adds signed provenance when the upstream publishes it.
func provenanceLabel(res tools.Installed) string {
	switch {
	case res.SignatureVerified:
		return "sha256 + cosign verified"
	case res.ProvenanceNote != "":
		return "sha256 verified; " + res.ProvenanceNote
	default:
		return "sha256 verified"
	}
}

// checkInstallable reports any names Draugr cannot provision, suggesting the closest match.
func checkInstallable(names []string) error {
	known := tools.Installable()
	set := make(map[string]bool, len(known))
	for _, k := range known {
		set[k] = true
	}
	for _, t := range tools.All() {
		set[t.Binary] = true
	}
	var unknown []string
	for _, n := range names {
		if !set[n] {
			unknown = append(unknown, n)
		}
	}
	if len(unknown) == 0 {
		return nil
	}
	msg := fmt.Sprintf("cannot install %s", strings.Join(quoteAll(unknown), ", "))
	if len(unknown) == 1 {
		if near := closestName(unknown[0], known); near != "" {
			msg += fmt.Sprintf(", did you mean %q?", near)
		}
	}
	return fmt.Errorf("%s\ninstallable: %s", msg, strings.Join(known, ", "))
}

func quoteAll(names []string) []string {
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = fmt.Sprintf("%q", n)
	}
	return out
}

// closestName returns the known tool within a small edit distance of want, or "" if none is
// close enough to be worth suggesting.
func closestName(want string, known []string) string {
	best, bestDist := "", 3 // suggest only for near-misses
	for _, k := range known {
		if d := editDistance(want, k); d < bestDist {
			best, bestDist = k, d
		}
	}
	return best
}

// editDistance is Levenshtein, enough for "did you mean" on short tool names.
func editDistance(a, b string) int {
	prev := make([]int, len(b)+1)
	cur := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(min(cur[j-1]+1, prev[j]+1), prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}
	return prev[len(b)]
}

func runToolsInstall(w io.Writer, in io.Reader, names []string, all bool, opts toolsInstallOptions, install func(name string) (tools.Installed, error)) error {
	if all {
		names = tools.Installable()
	}
	// A selection can legitimately be empty: a descriptor whose controls all run on scanners built
	// into Draugr asks for nothing. installNames has already said so, and a plan with no rows under
	// it would read as a second, contradictory answer.
	if len(names) == 0 {
		return nil
	}
	// An unknown name is a typo, not a choice. Reject it up front rather than rendering a row of
	// dashes and asking whether to proceed. And fail the whole command, since half-installing after a
	// misspelling is the surprising outcome.
	if err := checkInstallable(names); err != nil {
		return err
	}

	// Show the plan before doing anything, with what is already satisfied marked as such.
	planned := names
	have := present(context.Background(), planned, opts)
	writeInstallPlan(w, names, all, have, opts)

	if opts.dryRun {
		_, _ = fmt.Fprintln(w, "\n(dry run, nothing installed)")
		return nil
	}
	// Confirm only when interactive (a TTY); non-interactive runs (CI, pipes) proceed so
	// existing automation isn't broken. -y always skips the prompt.
	// Nothing to decide when nothing will be downloaded. A confirmation that gates no action
	// teaches people to answer it without reading, on the one command where reading matters.
	if len(have) == len(planned) {
		_, _ = fmt.Fprintln(w, "\nEverything is already current.")
		return nil
	}
	if !opts.yes && isTTY(in) {
		_, _ = fmt.Fprint(w, "\nProceed? [y/N] ")
		if !confirmed(in) {
			_, _ = fmt.Fprintln(w, "Aborted.")
			return nil
		}
	}
	_, _ = fmt.Fprintln(w)

	col := tui.For(w)
	var failed, unchanged int
	var skipped []string
	for _, name := range names {
		res, err := install(name)
		if err != nil {
			// With no arguments the request was "everything this host can have", so a tool whose
			// runtime is not here is not something this command was asked for and failed to do.
			// Refusing the batch over it fails nine installs to report a tenth, and the tenth is
			// usually a scanner the descriptor never names.
			//
			// Named, it stays a failure. Asking for a tool and being told it worked is the
			// guarantee worth keeping, and it is the one `--saga` and every pipeline rely on.
			if all && errors.Is(err, tools.ErrRuntimeMissing) {
				_, _ = fmt.Fprintf(w, "%s %s: %v\n", col.Paint(tui.StyleMuted, "–"), name, err)
				skipped = append(skipped, name)
				continue
			}
			_, _ = fmt.Fprintf(w, "%s %s: %v\n", col.Paint(tui.StyleFail, "✗"), name, err)
			failed++
			continue
		}
		// Counted, not printed. The plan above already named every tool that was current, with
		// its version and where it lives; repeating the list afterwards reads as a second check
		// that found something different, and on a full install it buries the one line that
		// describes what actually happened under seven that describe what did not.
		//
		// A tool that turns out not to be current after all is not AlreadyPresent. It is installed here
		// and gets its own line, so the case worth seeing is still loud.
		if res.AlreadyPresent {
			unchanged++
			continue
		}
		_, _ = fmt.Fprintf(w, "%s %s %s → %s %s\n", col.Paint(tui.StylePass, "✓"), res.Name, res.Version,
			res.Path, col.Paint(tui.StyleMuted, "("+provenanceLabel(res)+")"))
	}

	if unchanged > 0 {
		_, _ = fmt.Fprintln(w, col.Paint(tui.StyleMuted, fmt.Sprintf("%s unchanged.", plural(unchanged, "tool"))))
	}

	// Named, so the command that installs them is one somebody can copy. A count alone leaves a
	// reader to work out which of ten rows was the skipped one.
	if len(skipped) > 0 {
		_, _ = fmt.Fprintln(w, col.Paint(tui.StyleMuted, fmt.Sprintf(
			"%s skipped, this host has no runtime to build %s with. Install one and run "+
				"`draugr tools install %s`.",
			plural(len(skipped), "tool"), pronounFor(len(skipped)), strings.Join(skipped, " "))))
	}

	if failed > 0 {
		return fmt.Errorf("%d tool(s) failed to install", failed)
	}
	return nil
}

// pronounFor keeps the skipped line reading as a sentence at either count.
func pronounFor(n int) string {
	if n == 1 {
		return "it"
	}
	return "them"
}

// downloads counts what Draugr will actually fetch.
//
// Distinct from the number of tools outstanding: semgrep is planned, needed and absent, and Draugr
// downloads none of it. The confirmation gate means *this* number, because a prompt is about what
// the command is going to do to the machine.

// writeInstallPlan prints what `tools install` will do, before doing it.
// present reports which of names are already installed at the pinned version.
//
// Resolved before the plan is rendered rather than discovered inside the install loop. The plan is
// the moment someone decides whether to let a security tool write to their machine, and it was
// describing work it would not do, six rows for one download. detectTool resolves one tool. A var
// so a test can decide what is installed without arranging binaries on PATH.
var detectTool = func(ctx context.Context, t tools.Tool) tools.Status {
	return tools.Detect(ctx, t, nil, nil)
}

func present(ctx context.Context, names []string, opts toolsInstallOptions) map[string]string {
	found := map[string]string{}
	if opts.force {
		return found // --force reinstalls regardless, so nothing counts as satisfied
	}
	catalog := tools.Catalog()
	for _, name := range names {
		t, ok := catalog[name]
		if !ok {
			continue
		}
		st := detectTool(ctx, t)
		if !st.Found {
			continue
		}
		// A current binary whose data is missing is not current. kube-bench at the pinned version with
		// no cfg/ tree cannot run, and reporting it as satisfied is how an install that would have fixed
		// it gets skipped. Which is this same mistake one layer up.
		if st.DataChecked && !st.DataFound {
			continue
		}
		// A different version is still work to do, so only the requested one counts. Which is the pin
		// from the config when there is one, and otherwise the version Draugr ships.
		if want := opts.want(name); want != "" {
			if st.Version != strings.TrimPrefix(want, "v") {
				continue
			}
		} else if spec, ok := tools.Spec(name); ok && st.Version != spec.Version {
			continue
		}
		// The language-package paths have no release spec, so their pinned version comes from
		// their own map. Named individually this became a list of special cases that a fourth
		// install path would silently not join.
		if pinned := tools.ManagedVersion(name); pinned != "" && st.Version != pinned {
			continue
		}
		found[name] = st.Version
	}
	return found
}

func writeInstallPlan(w io.Writer, names []string, _ bool, have map[string]string, opts toolsInstallOptions) {
	dir, _ := tools.BinDir()
	catalog := tools.Catalog()
	category := func(name string) string {
		if t, ok := catalog[name]; ok && t.Category != "" {
			return t.Category
		}
		return "-"
	}
	_, _ = fmt.Fprintln(w, tui.For(w).Paint(tui.StyleMuted, "PLAN"))
	col := tui.For(w)
	table := tui.NewTable(col, "Tool", "Version", "Category", "Verify", "Destination").Indent("  ")

	// A satisfied tool keeps its row. Dropping it would read as forgetting it, and "nothing to do" is
	// information. But it says so, and it is not counted as work.
	satisfied := func(name string) bool { _, ok := have[name]; return ok }
	todo := 0

	for _, name := range names {
		// A tool obtained as a Python package has no release asset to describe, so its row is
		// built from what it does have: the pinned version, and the environment it lands in.
		if pySpec, isPython := tools.PythonTool(name); isPython {
			if satisfied(name) {
				table.Row(tui.Styled(tui.StyleMuted, name), tui.PlainCell(tools.PythonVersion(name)),
					tui.PlainCell(category(name)), tui.PlainCell("-"),
					tui.Styled(tui.StyleMuted, "already at "+have[name]))
				continue
			}
			todo++
			table.Row(tui.Styled(tui.StyleAccent, name), tui.PlainCell(tools.PythonVersion(name)),
				tui.PlainCell(category(name)), tui.PlainCell("sha256 (+deps)"),
				tui.Styled(tui.StyleMuted, filepath.Join(dir, pySpec.Package)))
			continue
		}
		// Same for an npm package: no release asset, so the row is the pinned version and the
		// tree it lands in. Without this the plan says "(not installable)" and then installs it,
		// which is a preflight contradicting the thing it is a preflight for.
		if nodeSpec, isNode := tools.NodeTool(name); isNode {
			if satisfied(name) {
				table.Row(tui.Styled(tui.StyleMuted, name), tui.PlainCell(tools.NodeVersion(name)),
					tui.PlainCell(category(name)), tui.PlainCell("-"),
					tui.Styled(tui.StyleMuted, "already at "+have[name]))
				continue
			}
			todo++
			table.Row(tui.Styled(tui.StyleAccent, name), tui.PlainCell(tools.NodeVersion(name)),
				tui.PlainCell(category(name)), tui.PlainCell("sha512 (+deps)"),
				tui.Styled(tui.StyleMuted, filepath.Join(dir, nodeSpec.Command)))
			continue
		}
		// And a tool built from its module: no release asset either, so the row is the pinned
		// version and the binary it produces. Without this the plan says "(not installable)" and
		// then installs it, which is a preflight contradicting the thing it is a preflight for.
		if _, isGo := tools.GoTool(name); isGo {
			if satisfied(name) {
				table.Row(tui.Styled(tui.StyleMuted, name), tui.PlainCell(tools.GoVersion(name)),
					tui.PlainCell(category(name)), tui.PlainCell("-"),
					tui.Styled(tui.StyleMuted, "already at "+have[name]))
				continue
			}
			todo++
			table.Row(tui.Styled(tui.StyleAccent, name), tui.PlainCell(tools.GoVersion(name)),
				tui.PlainCell(category(name)), tui.PlainCell("checksum db (+deps)"),
				tui.Styled(tui.StyleMuted, filepath.Join(dir, name)))
			continue
		}
		spec, err := tools.SpecFor(name, opts.want(name))
		ok := err == nil
		if !ok {
			table.Row(tui.Styled(tui.StyleAccent, name), tui.PlainCell("-"),
				tui.PlainCell(category(name)), tui.PlainCell("-"),
				tui.Styled(tui.StyleMuted, "(not installable)"))
			continue
		}
		if satisfied(name) {
			table.Row(tui.Styled(tui.StyleMuted, name), tui.PlainCell(spec.Version),
				tui.PlainCell(category(name)), tui.PlainCell("-"),
				tui.Styled(tui.StyleMuted, "already at "+have[name]))
			continue
		}
		todo++
		verify := planVerify(spec)
		table.Row(tui.Styled(tui.StyleAccent, name), tui.PlainCell(spec.Version),
			tui.PlainCell(category(name)), tui.PlainCell(verify),
			tui.Styled(tui.StyleMuted, filepath.Join(dir, spec.Binary)))
	}
	table.Render(w)

	// Always, not only when something is already present. A fresh host is where the count matters
	// most, and it was the one case that got none: eleven rows and nothing saying eleven.
	//
	// Nothing here says the selection was the whole catalog. Where that is worth knowing a
	// descriptor is present, and noteDescriptorInWorkingDir has already said it with a number and
	// the flag that narrows it. Where no descriptor is present, `--saga` is not advice anybody can
	// take.
	line := fmt.Sprintf("%s to install", plural(todo, "tool"))
	if n := len(have); n > 0 {
		line += fmt.Sprintf(", %d already current", n)
	}
	_, _ = fmt.Fprintf(w, "\n%s.\n", line)
}

// isTTY reports whether r is an interactive terminal, used to decide whether to prompt
// (interactive) or proceed automatically (CI/pipes). A var so tests can force it.
var isTTY = func(r io.Reader) bool { return tui.IsTerminal(r) }

func runToolsList(ctx context.Context, w io.Writer) error {
	// Map each tool binary to the controls it backs (a binary like trivy serves several).
	controlsFor := map[string][]string{}
	for _, s := range builtins.Registry().Scanners() {
		info := s.Info()
		for _, c := range info.Controls {
			controlsFor[info.Binary] = appendUnique(controlsFor[info.Binary], c)
		}
	}

	col := tui.For(w)
	table := tui.NewTable(col, "Tool", "Category", "Controls", "Pinned", "Source", "Status")
	for _, t := range tools.All() {
		category := t.Category
		if category == "" {
			category = "-"
		}
		controls := "-"
		if cs := controlsFor[t.Binary]; len(cs) > 0 {
			sort.Strings(cs)
			controls = strings.Join(cs, ",")
		}
		// The runtime is named where there is one, because `draugr tools install` on its own is
		// advice that does not work on a host without it, and nothing else in this table says a
		// prerequisite exists. Three of these tools publish no release binary at all and are built
		// here from source, which is not a fact a reader can infer from anything else on the row.
		pinned, source := "-", "system PATH"
		if spec, ok := tools.Spec(t.Binary); ok {
			pinned, source = spec.Version, "draugr tools install"
		} else if _, ok := tools.PythonTool(t.Binary); ok {
			pinned, source = tools.PythonVersion(t.Binary), "draugr tools install · needs Python"
		} else if _, ok := tools.NodeTool(t.Binary); ok {
			pinned, source = tools.NodeVersion(t.Binary), "draugr tools install · needs Node"
		} else if _, ok := tools.GoTool(t.Binary); ok {
			pinned, source = tools.GoVersion(t.Binary), "draugr tools install · needs Go"
		}

		status, statusStyle := "✗ not found", tui.StyleFail
		// Through detectTool, like the install plan above it. Called directly, this row read the
		// machine the test happened to run on, so the one command whose whole output is a table of
		// what is on this machine was the one nothing could pin.
		if st := detectTool(ctx, t); st.Found {
			version := st.Version
			if version == "" {
				version = "?"
			}
			status, statusStyle = fmt.Sprintf("✓ %s (%s)", version, st.Path), tui.StylePass
			// Present is not the same answer as present at the version this build pins, and a
			// tick said both. `tools install` already knew the difference and would have replaced
			// it, so the two commands disagreed about one machine.
			if pinned != "-" && version != "?" && version != pinned {
				status = fmt.Sprintf("~ %s (%s)", version, st.Path)
				statusStyle = tui.StyleAccent
			}
		}
		table.Row(
			tui.Styled(tui.StyleAccent, t.Binary),
			tui.PlainCell(category),
			tui.PlainCell(controls),
			tui.PlainCell(pinned),
			tui.Styled(tui.StyleMuted, source),
			tui.Styled(statusStyle, status),
		)
	}
	table.Render(w)
	return nil
}

// appendUnique appends s to xs if not already present.
func appendUnique(xs []string, s string) []string {
	for _, x := range xs {
		if x == s {
			return xs
		}
	}
	return append(xs, s)
}

// planVerify says how strongly the install will be able to verify this download, before it runs.
//
// The plan is where someone decides whether to let Draugr write a security tool to their machine,
// so the strength of the check belongs there rather than in the result afterwards. A recorded
// SHA-256 exists only for the version Draugr ships; any other version is checked against what the
// upstream publishes, which for some tools is nothing.
func planVerify(spec tools.InstallSpec) string {
	if a, ok := spec.Assets[tools.PlatformKey()]; ok && a.SHA256 != "" {
		if spec.Cosign != nil {
			return "sha256 + cosign"
		}
		return "sha256"
	}
	switch {
	case spec.Cosign != nil:
		return "upstream cosign"
	case spec.ChecksumsURLTemplate != "":
		return "upstream sha256"
	default:
		return "unverified"
	}
}

// wantedVersions resolves the version to install per tool: the pins in draugr.config.yaml, then
// --version on top for the single tool it was given with.
//
// --version applies to one tool because it takes one value. Applying it to several would install
// a version number that means something different to each of them.
func wantedVersions(args []string, flag string) (map[string]string, error) {
	wanted := map[string]string{}
	wd, err := os.Getwd()
	if err == nil {
		res, err := config.Load(rootConfigPath, wd)
		if err != nil {
			return nil, err
		}
		for name, t := range res.File.Tools {
			if t.Version != "" {
				wanted[name] = t.Version
			}
		}
	}
	if flag == "" {
		return wanted, nil
	}
	if len(args) != 1 {
		return nil, fmt.Errorf("--version applies to a single tool: name one, e.g. " +
			"`draugr tools install trivy --version 0.69.3`, or pin several in draugr.config.yaml")
	}
	wanted[args[0]] = flag
	return wanted, nil
}
