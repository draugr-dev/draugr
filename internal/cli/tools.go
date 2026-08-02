package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/draugr-dev/draugr/internal/builtins"
	"github.com/draugr-dev/draugr/internal/netpolicy"
	"github.com/draugr-dev/draugr/internal/tools"

	"github.com/draugr-dev/draugr/pkg/tui"
)

func newToolsCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tools",
		Short: "Manage the external scanner tools Draugr uses",
		Long: "Provision and inspect the external scanners (trivy, gitleaks, …) Draugr runs.\n" +
			"Installs are opt-in and checksum-verified — nothing is ever downloaded during a scan.",
	}
	cmd.AddCommand(newToolsInstallCommand())
	cmd.AddCommand(newToolsListCommand())
	return cmd
}

type toolsInstallOptions struct {
	yes    bool
	dryRun bool
	force  bool
	saga   string
}

func newToolsInstallCommand() *cobra.Command {
	opts := &toolsInstallOptions{}
	cmd := &cobra.Command{
		Use:   "install [tool...]",
		Short: "Download pinned, checksum-verified tools into ~/.draugr/bin",
		Long: "Download pinned scanner/utility binaries, verify each against a SHA-256 recorded in\n" +
			"Draugr, and install them into ~/.draugr/bin (which Draugr adds to PATH automatically).\n" +
			"With no arguments, installs every tool Draugr can provision; with --saga, only the\n" +
			"tools that descriptor's scan will actually run. Prints the plan first; when run\n" +
			"interactively it asks for confirmation. Never downloads without being asked.",
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			dir, err := tools.BinDir()
			if err != nil {
				return err
			}
			install := func(name string) (tools.Installed, error) {
				return tools.Install(cmd.Context(), name, dir, nil, opts.force)
			}
			names, err := installNames(cmd.OutOrStdout(), args, *opts)
			if err != nil {
				return err
			}
			// Names them, because someone preparing an air-gapped machine wants the list of what
			// they will have to bring across. An empty selection means everything installable.
			if netpolicy.Offline() {
				wanted := names
				if len(wanted) == 0 {
					wanted = tools.Installable()
				}
				return netpolicy.Refuse("draugr tools install",
					"the pinned release archive for: "+strings.Join(wanted, ", "))
			}
			return runToolsInstall(cmd.OutOrStdout(), cmd.InOrStdin(), names, *opts, install)
		},
	}
	cmd.Flags().BoolVarP(&opts.yes, "yes", "y", false, "skip the confirmation prompt")
	cmd.Flags().BoolVar(&opts.dryRun, "dry-run", false, "print the install plan and exit")
	cmd.Flags().BoolVar(&opts.force, "force", false,
		"reinstall even when the pinned version is already present (repairs a modified binary)")
	cmd.Flags().StringVar(&opts.saga, "saga", "",
		"install only the tools this descriptor's scan will run")
	return cmd
}

// installNames decides what to install: the tools named, everything, or what a descriptor needs.
//
// Installing the whole catalogue is a poor default on a security tool — every binary put on PATH
// is one more thing to trust, patch and explain — but it is the existing behaviour and changing
// it silently would provision less than a pipeline expects. So --saga is opt-in, and the case for
// it is made where it is relevant rather than in the docs.
func installNames(w io.Writer, args []string, opts toolsInstallOptions) ([]string, error) {
	if opts.saga == "" {
		if len(args) == 0 {
			noteDescriptorInWorkingDir(w)
		}
		return args, nil
	}
	if len(args) > 0 {
		return nil, fmt.Errorf(
			"--saga and an explicit tool list ask for different things: one installs what %s needs, "+
				"the other installs %s. Pick one", opts.saga, strings.Join(quoteAll(args), ", "))
	}

	model, err := loadSaga(opts.saga)
	if err != nil {
		return nil, err
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
		_, _ = fmt.Fprintf(w, "%s needs %s, which Draugr cannot provision — install %s separately (`draugr doctor %s` says where from).\n\n",
			opts.saga, strings.Join(quoteAll(unprovisionable), ", "),
			pluralThem(len(unprovisionable)), opts.saga)
	}
	if len(names) == 0 {
		_, _ = fmt.Fprintf(w, "Nothing to install: %s needs no tool Draugr provisions.\n", opts.saga)
	}
	return names, nil
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
// provisions a smaller set — and it may then be handed a different Saga to scan. Installing less
// than before, silently, is how a mystery failure appears in somebody else's pipeline.
func noteDescriptorInWorkingDir(w io.Writer) {
	const descriptor = "draugr.saga.yaml"
	if _, err := os.Stat(descriptor); err != nil {
		return
	}
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
	// Defensive: no saving means nothing worth saying. Not reachable through any descriptor
	// today, because cosign and gosec are never *required* by a control — cosign verifies
	// downloads and gosec is opt-in — so a Saga cannot demand the whole catalogue.
	if needed >= len(installable) {
		return
	}
	_, _ = fmt.Fprintf(w, "Note: `--saga %s` would install %d of these %d tools — the ones that descriptor's scan runs.\n\n",
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
	// Accept every tool Draugr knows, not just the binary-installable ones: semgrep is a Python
	// package, so `tools install semgrep` legitimately prints a pipx command instead of
	// downloading anything. Rejecting it here would break that.
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
			msg += fmt.Sprintf(" — did you mean %q?", near)
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

func runToolsInstall(w io.Writer, in io.Reader, names []string, opts toolsInstallOptions, install func(name string) (tools.Installed, error)) error {
	all := len(names) == 0
	if all {
		names = tools.Installable()
	}
	// An unknown name is a typo, not a choice. Reject it up front rather than rendering a row of
	// dashes and asking whether to proceed — and fail the whole command, since half-installing
	// after a misspelling is the surprising outcome.
	if err := checkInstallable(names); err != nil {
		return err
	}

	// Show the plan before doing anything, with what is already satisfied marked as such.
	//
	// planned, not names: semgrep is not in Installable() — it is a Python package, not a
	// download — so a bulk install adds it to the plan without it ever being in the list. Asking
	// only about names would leave the one tool most likely to be present unchecked.
	planned := names
	if all && !slices.Contains(planned, "semgrep") {
		planned = append(append([]string{}, planned...), "semgrep")
	}
	have := present(context.Background(), planned, opts.force)
	writeInstallPlan(w, names, all, have)

	if opts.dryRun {
		_, _ = fmt.Fprintln(w, "\n(dry run — nothing installed)")
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
	var failed int
	for _, name := range names {
		if name == "semgrep" {
			// Only when it is actually absent. An instruction to install something you already
			// have reads as a failure, and the natural response is to run the command again.
			if _, ok := have["semgrep"]; !ok {
				printSemgrepHint(w)
			}
			continue
		}
		res, err := install(name)
		if err != nil {
			_, _ = fmt.Fprintf(w, "%s %s: %v\n", col.Paint(tui.StyleFail, "✗"), name, err)
			failed++
			continue
		}
		if res.AlreadyPresent {
			_, _ = fmt.Fprintf(w, "%s %s %s already installed → %s\n",
				col.Paint(tui.StyleMuted, "•"), res.Name, res.Version,
				col.Paint(tui.StyleMuted, res.Path))
			continue
		}
		_, _ = fmt.Fprintf(w, "%s %s %s → %s %s\n", col.Paint(tui.StylePass, "✓"), res.Name, res.Version,
			res.Path, col.Paint(tui.StyleMuted, "("+provenanceLabel(res)+")"))
	}

	// Semgrep isn't a downloadable binary; when installing everything, surface how to get it —
	// unless it is already here, in which case there is nothing to surface.
	if _, ok := have["semgrep"]; all && !ok {
		printSemgrepHint(w)
	}

	if failed > 0 {
		return fmt.Errorf("%d tool(s) failed to install", failed)
	}
	return nil
}

func printSemgrepHint(w io.Writer) {
	_, _ = fmt.Fprintf(w, "ℹ semgrep is a Python package, not a standalone binary — run:\n    %s\n",
		tools.SemgrepPipxCommand())
}

// writeInstallPlan prints what `tools install` will do, before doing it.
// present reports which of names are already installed at the pinned version.
//
// Resolved before the plan is rendered rather than discovered inside the install loop. The plan
// is the moment someone decides whether to let a security tool write to their machine, and it
// was describing work it would not do — six rows for one download.
// detectTool resolves one tool. A var so a test can decide what is installed without arranging
// binaries on PATH.
var detectTool = func(ctx context.Context, t tools.Tool) tools.Status {
	return tools.Detect(ctx, t, nil, nil)
}

func present(ctx context.Context, names []string, force bool) map[string]string {
	found := map[string]string{}
	if force {
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
		// A current binary whose data is missing is not current. kube-bench at the pinned
		// version with no cfg/ tree cannot run, and reporting it as satisfied is how an install
		// that would have fixed it gets skipped — which is this same mistake one layer up.
		if st.DataChecked && !st.DataFound {
			continue
		}
		// A different version is still work to do, so only the pinned one counts.
		if spec, ok := tools.Spec(name); ok && st.Version != spec.Version {
			continue
		}
		if name == "semgrep" && st.Version != tools.SemgrepVersion() {
			continue
		}
		found[name] = st.Version
	}
	return found
}

func writeInstallPlan(w io.Writer, names []string, all bool, have map[string]string) {
	dir, _ := tools.BinDir()
	catalog := tools.Catalog()
	category := func(name string) string {
		if t, ok := catalog[name]; ok && t.Category != "" {
			return t.Category
		}
		return "-"
	}
	_, _ = fmt.Fprintln(w, "Install plan:")
	col := tui.For(w)
	table := tui.NewTable(col, "Tool", "Version", "Category", "Verify", "Destination").Indent("  ")

	// A satisfied tool keeps its row. Dropping it would read as forgetting it, and "nothing to
	// do" is information — but it says so, and it is not counted as work.
	satisfied := func(name string) bool { _, ok := have[name]; return ok }
	todo := 0

	showSemgrep := all
	for _, name := range names {
		if name == "semgrep" {
			showSemgrep = true
			continue
		}
		spec, ok := tools.Spec(name)
		if !ok {
			table.Row(tui.Styled(tui.StyleAccent, name), tui.PlainCell("-"),
				tui.PlainCell(category(name)), tui.PlainCell("-"),
				tui.Styled(tui.StyleMuted, "(not installable)"))
			continue
		}
		if satisfied(name) {
			table.Row(tui.Styled(tui.StyleMuted, name), tui.PlainCell(spec.Version),
				tui.PlainCell(category(name)), tui.PlainCell("—"),
				tui.Styled(tui.StyleMuted, "already at "+have[name]))
			continue
		}
		todo++
		verify := "sha256"
		if spec.Cosign != nil {
			verify = "sha256 + cosign"
		}
		table.Row(tui.Styled(tui.StyleAccent, name), tui.PlainCell(spec.Version),
			tui.PlainCell(category(name)), tui.PlainCell(verify),
			tui.Styled(tui.StyleMuted, filepath.Join(dir, spec.Binary)))
	}
	if showSemgrep {
		if satisfied("semgrep") {
			table.Row(tui.Styled(tui.StyleMuted, "semgrep"), tui.PlainCell(tools.SemgrepVersion()),
				tui.PlainCell(category("semgrep")), tui.PlainCell("—"),
				tui.Styled(tui.StyleMuted, "already at "+have["semgrep"]))
		} else {
			todo++
			table.Row(tui.Styled(tui.StyleAccent, "semgrep"), tui.PlainCell(tools.SemgrepVersion()),
				tui.PlainCell(category("semgrep")), tui.PlainCell("pypi hash"),
				tui.Styled(tui.StyleMuted, "pipx (command printed)"))
		}
	}
	table.Render(w)

	if n := len(have); n > 0 {
		_, _ = fmt.Fprintf(w, "\n%s to install, %d already current.\n", plural(todo, "tool"), n)
	}
}

// isTTY reports whether r is an interactive terminal — used to decide whether to prompt
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
		pinned, source := "-", "system PATH"
		if spec, ok := tools.Spec(t.Binary); ok {
			pinned, source = spec.Version, "draugr tools install"
		} else if t.Binary == "semgrep" {
			pinned, source = tools.SemgrepVersion(), "pipx"
		}

		status, statusStyle := "✗ not found", tui.StyleFail
		if st := tools.Detect(ctx, t, nil, nil); st.Found {
			version := st.Version
			if version == "" {
				version = "?"
			}
			status, statusStyle = fmt.Sprintf("✓ %s (%s)", version, st.Path), tui.StylePass
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
