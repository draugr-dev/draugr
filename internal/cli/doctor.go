package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/draugr-dev/draugr/internal/builtins"
	"github.com/draugr-dev/draugr/internal/controllers"
	"github.com/draugr-dev/draugr/internal/netpolicy"
	"github.com/draugr-dev/draugr/internal/sbom"
	"github.com/draugr-dev/draugr/internal/selfupdate"
	"github.com/draugr-dev/draugr/internal/surfaces"
	"github.com/draugr-dev/draugr/internal/tools"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"

	"github.com/draugr-dev/draugr/pkg/tui"
)

type doctorOptions struct {
	json    bool
	offline bool
	// failOnUncovered turns the uncovered-surface note into a failure. Off by default: a
	// deliberately narrow descriptor is a legitimate thing to have, and a preflight that fails on
	// a choice somebody made is one people learn to ignore.
	failOnUncovered bool
	// strict does the same for a tool that is not the version Draugr tests.
	strict bool
}

// doctorRun is what runDoctor needs from the command's flags.
//
// A struct rather than two more parameters: they are both booleans, and adjacent unlabeled
// booleans at a call site are a thing nobody can read and everybody eventually transposes.
type doctorRun struct {
	json            bool
	failOnUncovered bool
	// strict turns "not the version we tested" from a note into a failure, for a pipeline that
	// would rather stop than scan with a build nothing has exercised. Off by default: a different
	// version is very likely fine, and a check that fails on very-likely-fine is one people stop
	// running.
	strict bool
}

func newDoctorCommand() *cobra.Command {
	opts := &doctorOptions{}
	cmd := &cobra.Command{
		Use:   "doctor [saga.yaml]",
		Short: "Check that the external scanners a scan needs are installed",
		Long: "Report which external scanner tools are present, missing, or out of date, with an\n" +
			"install hint for each.\n\n" +
			"Given a Saga, also validates the descriptor and checks only the tools its enabled\n" +
			"controls need; without one, checks them all. Exits non-zero when the descriptor is\n" +
			"invalid or a required tool is missing.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			sagaPath := ""
			if len(args) == 1 {
				sagaPath = args[0]
			}
			detect := func(ctx context.Context, t tools.Tool) tools.Status {
				return tools.Detect(ctx, t, nil, nil)
			}
			// Best-effort update check (current vs latest), unless opted out. It never blocks or
			// fails the command: a short timeout, errors ignored.
			var latest func(context.Context) (string, error)
			if !opts.offline && !netpolicy.SkipUpdateCheck() {
				latest = func(ctx context.Context) (string, error) {
					ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
					defer cancel()
					return selfupdate.LatestVersion(ctx, nil)
				}
			}
			run := doctorRun{json: opts.json, failOnUncovered: opts.failOnUncovered, strict: opts.strict}
			return runDoctor(cmd.Context(), cmd.OutOrStdout(), builtins.Registry(), sagaPath, run, detect, latest)
		},
	}
	cmd.Flags().BoolVar(&opts.json, "json", false, "output results as JSON")
	cmd.Flags().BoolVar(&opts.strict, "strict", false,
		"also fail when a tool is not the version Draugr tests, not only when one is missing")
	cmd.Flags().BoolVar(&opts.failOnUncovered, "fail-on-uncovered", false,
		"fail if the descriptor declares a surface no enabled control looks at (reported either way)")
	// Kept as a command-local flag as well as the root one: it is documented, it is in people's
	// CI, and "do not check for a release" is a narrower request than "this machine has no
	// network" that someone may still want to make on its own.
	cmd.Flags().BoolVar(&opts.offline, "offline", false,
		"skip the check for a newer draugr release (also DRAUGR_NO_UPDATE_CHECK=1; implied by the root --offline)")
	return cmd
}

// runDoctor validates the descriptor (when given) and reports tool availability. detect is
// injectable for testing. It returns an error, mapped to a non-zero exit. When the descriptor
// is invalid or any required tool is missing.
func runDoctor(
	ctx context.Context,
	w io.Writer,
	reg *engine.Registry,
	sagaPath string,
	run doctorRun,
	detect func(context.Context, tools.Tool) tools.Status,
	latest func(context.Context) (string, error),
) error {
	dv := draugrVersionReport(ctx, latest)
	if !run.json {
		writeDraugrLine(w, dv)
	}

	// Descriptor check: loading validates (parse + env-resolve + schema).
	var required []tools.Tool
	var model *saga.Model
	// inventoryOnly marks the no-descriptor run: it reports what is present without deciding
	// that anything is missing, because nothing has asked for anything yet.
	inventoryOnly := false
	if sagaPath != "" {
		loaded, err := saga.LoadFile(sagaPath)
		if err != nil {
			if run.json {
				_ = writeDoctorJSON(w, dv, &descriptorReport{Path: sagaPath, Valid: false, Error: err.Error()}, nil, nil)
			} else {
				col := tui.For(w)
				// The reason is carried by the error, which the CLI prints. Written here too it
				// appeared twice, verbatim, on adjacent lines.
				_, _ = fmt.Fprintf(w, "Descriptor  %s (%s)\n", col.Paint(tui.StyleFail, "✗ invalid"),
					sagaPath)
			}
			return fmt.Errorf("invalid descriptor: %w", err)
		}
		model = loaded
		required = requiredTools(reg, model)
	} else {
		// No descriptor, so nothing has been selected and nothing is required. The catalog is an
		// inventory here. "what could Draugr use, and what have you got", and treating every entry as
		// required told a clean machine it was missing seven tools it may never need. kube-bench is
		// the clearest case: the default infrastructure scanner is native and needs no binary at all,
		// so demanding it is asking for a tool to run a scanner nobody chose.
		required = tools.All()
		inventoryOnly = true
	}

	// Computed before the tool table so both output paths and the verdict below read one answer.
	// A tool that is present is only half of "will this scan tell me what I think it will": the
	// other half is whether anything is looking at what the descriptor declares.
	var uncovered []string
	if model != nil {
		uncovered = surfaces.Uncovered(model)
	}

	statuses := make([]tools.Status, 0, len(required))
	missing := 0
	for _, t := range required {
		st := detect(ctx, t)
		statuses = append(statuses, st)
		if !st.Found && !t.Optional {
			missing++ // optional tools (e.g. cosign) are reported but don't fail the check
		}
		// A tool present but missing its data cannot run either, and this is the whole reason
		// doctor exists: to answer "is a scan going to fail for something absent" before the
		// scan, rather than leaving the tool to complain about a symptom afterwards.
		if st.Found && st.DataChecked && !st.DataFound && !t.Optional {
			missing++
		}
	}

	if run.json {
		var desc *descriptorReport
		if sagaPath != "" {
			desc = &descriptorReport{Path: sagaPath, Valid: true}
		}
		if err := writeDoctorJSON(w, dv, desc, statuses, uncovered); err != nil {
			return err
		}
	} else {
		if sagaPath != "" {
			col := tui.For(w)
			_, _ = fmt.Fprintf(w, "Descriptor  %s %s\n\n",
				col.Paint(tui.StylePass, "✓ valid"), col.Paint(tui.StyleMuted, "("+sagaPath+")"))
		}
		writeDoctorTable(w, statuses)
		writeNetworkCalls(w, reg)
		if model != nil {
			printUncoveredSurfaceNote(w, model)
		}
	}

	if missing > 0 && inventoryOnly {
		// Reported, not failed. Which of these matter depends on a descriptor, and there is not one.
		// `draugr doctor <saga>` is the question with an answer.
		if !run.json {
			_, _ = fmt.Fprintf(w, "\n%s\n", tui.For(w).Paint(tui.StyleMuted,
				fmt.Sprintf("%d of these are not installed. Which you need depends on your "+
					"descriptor. Run `draugr doctor <saga>` to check just those, or "+
					"`draugr tools install` to fetch them all.", missing)))
		}
		return nil
	}
	// Asked for, so it decides the exit code. After the missing check, because a tool that is not
	// there is the larger problem and its message is the one to lead with.
	if run.strict {
		if n := untestedCount(statuses); n > 0 {
			return fmt.Errorf("%s not the version Draugr tests; run `draugr tools install --force`, "+
				"or drop --strict to accept them", isAre(n, plural(n, "tool")))
		}
	}
	if missing > 0 {
		// The advice is the error rather than a line above it. Printed as both, the count and the
		// remedy appeared on one line and the count again on the next, which is the same fact
		// twice in the place a reader is already deciding what to do. JSON callers get the
		// structure and the exit code, and no prose either way.
		advice := missingToolsAdvice(statuses)
		if run.json {
			return errors.New(advice)
		}
		return fmt.Errorf("%s", advice)
	}
	// After the missing-tool checks, because a tool that is absent stops the scan outright while
	// an uncovered surface only narrows it, and the more serious answer should be the one given.
	if len(uncovered) > 0 && run.failOnUncovered {
		if !run.json {
			_, _ = fmt.Fprintf(w, "\n%s\n", tui.For(w).Paint(tui.StyleFail,
				fmt.Sprintf("%d declared surface(s) no enabled control looks at, and "+
					"--fail-on-uncovered was set.", len(uncovered))))
		}
		return fmt.Errorf("%d declared surface(s) not covered by an enabled control", len(uncovered))
	}
	if !run.json {
		// "All required tools present" over an empty table is ambiguous: it reads the same
		// whether nothing was needed or nothing was checked. The two are worth telling apart,
		// because the second is a bug and looks exactly like the first.
		msg := "All required tools present."
		if len(required) == 0 {
			// Deliberately not "…because everything runs natively": this is also the answer when
			// no control is enabled at all, and claiming otherwise would describe a scan that
			// was never planned.
			msg = "No external tools required."
		}
		_, _ = fmt.Fprintln(w, "\n"+tui.For(w).Paint(tui.StylePass, msg))
	}
	return nil
}

// requiredTools returns the external tools needed by the controls enabled anywhere in the
// model: for each registered scanner serving an enabled control, its binary, plus git when
// the scanner works on a checked-out repository.
func requiredTools(reg *engine.Registry, model *saga.Model) []tools.Tool {
	enabled := func(control string) bool {
		if model.Config.ControllerEnabled(control) {
			return true
		}
		for i := range model.Components {
			if model.Components[i].ControllerEnabled(control, model.Config) {
				return true
			}
		}
		return false
	}

	catalog := tools.Catalog()
	seen := map[string]bool{}
	var out []tools.Tool
	// A binary the catalog does not describe is still checked. Skipping it silently is how
	// `doctor` came to report "all required tools present" for a control whose scanner was not
	// installed at all, the one command whose job is answering "will a scan work?" answering yes
	// because it had never heard of the tool.
	add := func(binary string) {
		if binary == "" || seen[binary] {
			return
		}
		seen[binary] = true
		if t, ok := catalog[binary]; ok {
			// Everything reaching this function was selected by the descriptor: a scanner serving
			// an enabled control, something that scanner also requires, or a block the Saga turned
			// on. `Optional` in the catalog is about the inventory view, where nothing has been
			// chosen and the question is "what could Draugr use". Carried through to here it means
			// doctor reports a clean environment for a scan that cannot run, which is the one
			// answer this command must never give.
			t.Optional = false
			out = append(out, t)
			return
		}
		out = append(out, tools.Tool{
			Binary:      binary,
			Category:    tools.CategoryScanner,
			InstallHint: externalInstallHint(binary),
		})
	}

	// A control served by several scanners only requires the ones it will actually run. Asking
	// for the rest sends someone to install a tool the scan would never have used, and reports a
	// control as unable to run when it can.
	selected := map[string]map[string]bool{}
	for _, c := range reg.Controllers() {
		ci := c.Info()
		if len(ci.DefaultScanners) == 0 {
			continue
		}
		selected[ci.Name] = controllers.SelectedScanners(*model, ci.Name, ci.DefaultScanners)
	}

	// An analyzer named in config.reachability is required and is not selectable from a scanner
	// block, resolveScanners refuses it there deliberately, so the selection above filters it out
	// with every scanner the control will not run. The descriptor field exists for this: it names
	// the analyzer "so `draugr doctor` can tell you what to install before a scan finds out for
	// you", and until now the scan found out.
	analyzer := map[string]bool{}
	if r := model.Config.Reachability; r != nil {
		for _, name := range r.Analyzers {
			analyzer[name] = true
		}
	}

	for _, s := range reg.Scanners() {
		info := s.Info()
		serves := false
		for _, c := range info.Controls {
			if !enabled(c) {
				continue
			}
			// Named as an analyzer, so the control runs it whatever its scanner block says. Still
			// inside the enabled check: config.reachability is project-wide, and an analyzer whose
			// control is switched off is a tool this scan will never reach for.
			if analyzer[info.Name] {
				serves = true
				break
			}
			if set, selectable := selected[c]; selectable && !set[info.Name] {
				continue // a scanner this control will not run for this model
			}
			serves = true
			break
		}
		if !serves {
			continue
		}
		add(info.Binary)
		for _, extra := range info.AlsoRequires {
			add(extra)
		}
		for _, tk := range info.TargetKinds {
			if tk == plugin.TargetRepository {
				add("git")
			}
		}
	}

	// SBOM generation is not a control, so no scanner declares it. It is required by the Saga's
	// config.sbom block instead.
	if s := model.Config.SBOM; s != nil && s.Enabled {
		add(sbom.Binary)
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Binary < out[j].Binary })
	return out
}

func writeDoctorTable(w io.Writer, statuses []tools.Status) {
	col := tui.For(w)
	// Named like every other block here. It was the one section with no heading, which made the
	// two that had one read as asides to it rather than as its equals.
	_, _ = fmt.Fprintf(w, "%s\n", doctorHeading(col, "Tools"))
	t := tui.NewTable(col, "Tool", "Status", "Version", "Notes")
	for _, st := range statuses {
		status, version, notes := "✓ found", st.Version, st.Path
		style := tui.StylePass
		switch {
		case !st.Found && st.Tool.Optional:
			// Optional tools aren't a problem, so they mustn't read as one.
			status, notes, style = "– optional", "optional: "+installAdvice(st.Tool), tui.StyleMuted
		case !st.Found:
			status, notes, style = "✗ missing", "install: "+installAdvice(st.Tool), tui.StyleFail
		case st.Err != nil:
			version, notes = "?", fmt.Sprintf("%s (version check failed)", st.Path)
		case st.DataChecked && !st.DataFound:
			// Found, runnable, and useless. Reported as a failure rather than a note, because it
			// fails a scan exactly as surely as the binary being absent.
			status, notes, style = "✗ no data", st.Tool.DataHint, tui.StyleFail
		case st.DataChecked && st.DataDetail != "":
			notes = st.Path + " · " + st.DataDetail
		}
		// Found and runnable, and not the build Draugr's own suite ran against. In the row
		// because this is where somebody looks up one tool, and counted below because a machine
		// that has not reinstalled in a while has most of them and a mark on every row is not a
		// mark. Never a failure: refusing to work would be Draugr mistaking "I have not tested
		// this" for "this is wrong".
		if pin := untestedVersion(st); pin != "" {
			notes = fmt.Sprintf("%s · tested against %s", notes, pin)
		}
		if version == "" {
			version = "-"
		}
		t.Row(
			tui.PlainCell(st.Tool.Binary),
			tui.Styled(style, status),
			tui.PlainCell(version),
			tui.Styled(tui.StyleMuted, notes),
		)
	}
	t.Render(w)

	// One line rather than eleven marks. An older scanner finds fewer things, and a scan that
	// quietly finds fewer things is the failure a security tool must not have, so this says the
	// count and the command that closes it rather than leaving a reader to compare two columns
	// fourteen times.
	if n := untestedCount(statuses); n > 0 {
		_, _ = fmt.Fprintf(w, "%s\n", col.Paint(tui.StyleAccent, fmt.Sprintf(
			"%s not the version Draugr tests. Older scanners find fewer things; "+
				"`draugr tools install --force` installs the tested build.", isAre(n, plural(n, "tool")))))
	}
}

// isAre agrees the verb with the count, which plural does not do for the caller.
func isAre(n int, subject string) string {
	if n == 1 {
		return subject + " is"
	}
	return subject + " are"
}

// untestedCount is how many found tools are running something other than the pinned version.
func untestedCount(statuses []tools.Status) int {
	n := 0
	for _, st := range statuses {
		if untestedVersion(st) != "" {
			n++
		}
	}
	return n
}

// untestedVersion returns the version Draugr pins when a found tool is not running it, and ""
// when it matches, when there is no pin, or when the version could not be read.
//
// String equality after dropping a leading v. Not an ordering: "older than tested" and "newer than
// tested" are both untested, and a comparison that ranked them would have to decide what a version
// scheme means for eight tools that do not share one.
func untestedVersion(st tools.Status) string {
	if !st.Found || st.Err != nil || st.Version == "" {
		return ""
	}
	pin := strings.TrimPrefix(tools.PinnedVersion(st.Tool.Binary), "v")
	if pin == "" || pin == strings.TrimPrefix(st.Version, "v") {
		return ""
	}
	return pin
}

type descriptorReport struct {
	Path  string `json:"path"`
	Valid bool   `json:"valid"`
	Error string `json:"error,omitempty"`
}

// draugrReport is the running-vs-latest version summary shown by doctor.
type draugrReport struct {
	Version         string `json:"version"`
	Latest          string `json:"latest,omitempty"`
	UpdateAvailable bool   `json:"updateAvailable,omitempty"`
}

// draugrVersionReport reports the running version and, when latest is non-nil and reachable,
// the latest available. Best-effort: a failed/blocked check just omits Latest.
func draugrVersionReport(ctx context.Context, latest func(context.Context) (string, error)) draugrReport {
	r := draugrReport{Version: selfupdate.CurrentVersion()}
	if latest == nil {
		return r
	}
	if v, err := latest(ctx); err == nil && v != "" {
		r.Latest = v
		r.UpdateAvailable = v != r.Version
	}
	return r
}

// writeDraugrLine prints the human-readable Draugr version line.
func writeDraugrLine(w io.Writer, r draugrReport) {
	switch {
	case r.Latest == "":
		_, _ = fmt.Fprintf(w, "Draugr      %s\n\n", displayVersion(r.Version))
	case r.UpdateAvailable:
		col := tui.For(w)
		_, _ = fmt.Fprintf(w, "Draugr      %s  %s\n\n", displayVersion(r.Version),
			col.Paint(tui.StyleAccent, fmt.Sprintf("(latest: %s. Run 'draugr self-update')",
				displayVersion(r.Latest))))
	default:
		_, _ = fmt.Fprintf(w, "Draugr      %s  %s\n\n", displayVersion(r.Version),
			tui.For(w).Paint(tui.StyleMuted, "(up to date)"))
	}
}

// displayVersion prefixes a semver with "v"; leaves a dev build as-is.
func displayVersion(v string) string {
	if v == "" || v == "dev" {
		return "dev"
	}
	return "v" + v
}

type toolReport struct {
	Binary  string `json:"binary"`
	Found   bool   `json:"found"`
	Version string `json:"version,omitempty"`
	Path    string `json:"path,omitempty"`
	Hint    string `json:"hint,omitempty"`
	// TestedVersion is the version Draugr pins, present only when this tool is not running it.
	// Absent means the two agree, or that there is no pin to compare against, and a consumer can
	// treat its presence as the whole answer rather than comparing two strings itself.
	TestedVersion string `json:"testedVersion,omitempty"`
}

func writeDoctorJSON(
	w io.Writer, dv draugrReport, desc *descriptorReport, statuses []tools.Status, uncovered []string,
) error {
	report := struct {
		Draugr     draugrReport      `json:"draugr"`
		Descriptor *descriptorReport `json:"descriptor,omitempty"`
		Tools      []toolReport      `json:"tools"`
		Missing    int               `json:"missing"`
		// UncoveredSurfaces are what the descriptor declares that no enabled control looks at.
		// Present here because the answer a person gets and the answer a pipeline gets diverging
		// is worse than either being absent.
		UncoveredSurfaces []string `json:"uncoveredSurfaces,omitempty"`
	}{
		Draugr: dv, Descriptor: desc, Tools: make([]toolReport, 0, len(statuses)),
		UncoveredSurfaces: uncovered,
	}

	for _, st := range statuses {
		tr := toolReport{
			Binary: st.Tool.Binary, Found: st.Found, Version: st.Version, Path: st.Path,
			TestedVersion: untestedVersion(st),
		}
		if !st.Found {
			tr.Hint = st.Tool.InstallHint
			report.Missing++
		}
		report.Tools = append(report.Tools, tr)
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

// networkCall is one place Draugr can reach out from, and what for.
type networkCall struct {
	When string
	What string
}

// networkCalls is every outbound call Draugr makes, so someone preparing an air-gapped runner
// has the list rather than discovering it one failure at a time.
//
// Written out rather than derived: the point is to be complete, and a list assembled from
// whatever happens to be registered would silently shrink when something moves. It changes when
// a network call is added, which is exactly when someone should be made to think about it.
var networkCalls = []networkCall{
	{"draugr tools install", "each tool's pinned release archive, verified against a recorded SHA-256"},
	{"draugr feeds update", "the CISA KEV catalog and the FIRST EPSS scores"},
	{"draugr self-update", "the latest draugr release"},
	{"draugr doctor", "the latest draugr release, to compare against yours (skipped by --offline)"},
	{"a scan, before it starts", "the reference data each scanner reads, host by host under HOSTS"},
	{"a scan, per target", "the registry, for an image; the endpoint itself, for a host or DAST target"},
	// The only entry where the traffic does not go to something of yours. Listed separately
	// because an air-gapped runner is not the only reason to care: this one discloses your
	// hostnames to a third party, and someone reading this list to decide what Draugr may reach
	// should see that without having to know the control exists.
	{"a scan, with the threats control", "abuse.ch, which learns each host's name"},
}

// doctorHeading names a section the way a scan report names one.
//
// The same shape rather than a second one. A reader meets `CONTROLS` and `SIGNALS` in a report and
// `Network` here, and two casings for one idea is a thing to learn twice; whichever is right, one
// of them is the product's.
func doctorHeading(col tui.Painter, name string) string {
	return col.Paint(tui.StyleMuted, strings.ToUpper(name))
}

// writeNetworkCalls lists what Draugr fetches and when.
//
// Shown always rather than only under --offline. Someone deciding whether Draugr can run in
// their environment is asking this before they have a reason to pass the flag, and a list that
// appears only once you already know to ask for it answers the wrong question.
func writeNetworkCalls(w io.Writer, reg *engine.Registry) {
	col := tui.For(w)
	_, _ = fmt.Fprintf(w, "\n%s  %s\n", doctorHeading(col, "Network"),
		col.Paint(tui.StyleMuted, networkHeading()))
	// Width from the longest entry rather than a constant: a hardcoded 26 silently stops
	// aligning the moment an entry outgrows it, and the misalignment is the only warning.
	width := 0
	for _, c := range networkCalls {
		if len(c.When) > width {
			width = len(c.When)
		}
	}
	for _, c := range networkCalls {
		_, _ = fmt.Fprintf(w, "  %-*s %s\n", width, c.When, col.Paint(tui.StyleMuted, c.What))
	}
	writeScannerHosts(w, reg)
}

// scannerHost is one host a scanner contacts for its reference data, and what for.
type scannerHost struct {
	Host string
	What string
	When string
}

// writeScannerHosts lists the hosts a scan contacts, from the registry rather than from a list
// kept by hand.
//
// This is the section somebody copies into an egress rule, which is the common case: a runner that
// blocks outbound by default is ordinary, and a disconnected one is not. A host is what such a rule
// takes, so a host is what this prints.
//
// Derived, because the hand-kept version of this was wrong. It named two of the seven sources, and
// nothing about it could have said so. What keeps a derived list from silently shrinking is the
// test holding every scanner to declaring what it reads, which a list written here could never do.
func writeScannerHosts(w io.Writer, reg *engine.Registry) {
	if reg == nil {
		return
	}
	seen := map[string]bool{}
	var rows []scannerHost
	for _, sc := range reg.Scanners() {
		info := sc.Info()
		for _, d := range info.Data {
			when := "before the scan"
			if d.PerScan {
				when = "every scan"
			}
			for _, host := range d.Hosts {
				// Four Trivy-backed scanners read one database. One row, because a reader is
				// writing a firewall rule rather than auditing the registry.
				key := host + "\x00" + d.Name
				if seen[key] {
					continue
				}
				seen[key] = true
				rows = append(rows, scannerHost{Host: host, What: d.Name, When: when})
			}
		}
	}
	if len(rows) == 0 {
		return
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Host != rows[j].Host {
			return rows[i].Host < rows[j].Host
		}
		return rows[i].What < rows[j].What
	})

	col := tui.For(w)
	_, _ = fmt.Fprintf(w, "\n%s  %s\n", doctorHeading(col, "Hosts"),
		col.Paint(tui.StyleMuted, "(a scan contacts these; for an egress allowlist)"))
	width := 0
	for _, r := range rows {
		if len(r.Host) > width {
			width = len(r.Host)
		}
	}
	for _, r := range rows {
		_, _ = fmt.Fprintf(w, "  %-*s %s\n", width, r.Host,
			col.Paint(tui.StyleMuted, r.What+" · "+r.When))
	}
}

// networkHeading says whether the calls below are live or suppressed.
func networkHeading() string {
	if netpolicy.Offline() {
		return "(offline: none of these will happen)"
	}
	return "(what Draugr fetches, and when · --offline stops all of it)"
}

// missingToolsAdvice counts what is missing and suggests `tools install` only when it could
// actually help.
//
// Some scanners are execed but never distributed, retire.js publishes to npm, the Mend CLI is
// proprietary. And telling somebody to run a command that will not find their tool is worse
// advice than none: they run it, it succeeds, and the thing is still missing.
func missingToolsAdvice(statuses []tools.Status) string {
	installable := tools.Installable()
	var missing, fetchable int
	for _, st := range statuses {
		if st.Tool.Optional || (st.Found && (!st.DataChecked || st.DataFound)) {
			continue
		}
		missing++
		if slices.Contains(installable, st.Tool.Binary) {
			fetchable++
		}
	}
	// The remedy first, because it is what somebody does next, and only then where the rest come
	// from. A column has a name; "above" is a position, and a reflow is the first thing that moves
	// it.
	if fetchable == missing {
		return fmt.Sprintf("%s missing. Run `draugr tools install`.", plural(missing, "required tool"))
	}
	if fetchable > 0 {
		return fmt.Sprintf("%s missing. Run `draugr tools install` for %d of them; the Notes "+
			"column says where the rest come from.", plural(missing, "required tool"), fetchable)
	}
	return fmt.Sprintf("%s missing. The Notes column says where each one comes from.",
		plural(missing, "required tool"))
}

// installAdvice says how to get one missing tool, preferring the command Draugr can run.
//
// The row beside a tool's name is where somebody reads what to do about it, and a bare upstream
// URL was printed there even for tools `draugr tools install` fetches. Following it gets whatever
// version the internet offers, where the command gets the pinned release with its SHA-256 checked,
// which is the difference `tools install` exists to make. The summary line under the table already
// named the command, so one screen gave two answers and the wrong one sat closer to the question.
//
// Only a bare URL is replaced. Several hints carry a prerequisite the command does not remove:
// kube-bench needs its cfg/ directory beside the binary or every run dies, retire.js needs a Node
// runtime, govulncheck needs a Go toolchain. A hint with prose in it is doing work, and swapping
// it for the command would drop the half a reader is about to need.
func installAdvice(t tools.Tool) string {
	if isBareURL(t.InstallHint) && slices.Contains(tools.Installable(), t.Binary) {
		return "draugr tools install " + t.Binary
	}
	return t.InstallHint
}

// isBareURL reports whether a hint is a link and nothing else, which is a hint carrying no
// prerequisite and therefore one the install command can replace outright.
func isBareURL(hint string) bool {
	return strings.HasPrefix(hint, "http") && !strings.ContainsAny(hint, " ,")
}

// externalInstallHint says where a tool Draugr does not distribute comes from.
//
// `draugr tools install` fetches pinned releases Draugr has verified, which it can only do for
// tools it vouched for. For the rest, proprietary ones especially. Naming the source is the
// whole of the help available, and it is much more use than telling somebody to run a command
// that will not find it.
func externalInstallHint(binary string) string {
	if from, ok := externalTools[binary]; ok {
		return from
	}
	return "required by a registered scanner; not in Draugr's tool catalog"
}

// externalTools names where to get a tool Draugr execs but never downloads.
var externalTools = map[string]string{
	"mend": "proprietary; install the Mend CLI from Mend's documentation (Draugr does not " +
		"distribute it). See internal/scanners/mend-sca.md",
}
