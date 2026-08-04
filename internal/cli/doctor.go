package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/spf13/cobra"

	"github.com/draugr-dev/draugr/internal/builtins"
	"github.com/draugr-dev/draugr/internal/controllers"
	"github.com/draugr-dev/draugr/internal/netpolicy"
	"github.com/draugr-dev/draugr/internal/sbom"
	"github.com/draugr-dev/draugr/internal/selfupdate"
	"github.com/draugr-dev/draugr/internal/tools"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"

	"github.com/draugr-dev/draugr/pkg/tui"
)

type doctorOptions struct {
	json    bool
	offline bool
}

func newDoctorCommand() *cobra.Command {
	opts := &doctorOptions{}
	cmd := &cobra.Command{
		Use:   "doctor [saga.yaml]",
		Short: "Check that the external scanners a scan needs are installed",
		Long: "Report which external scanner tools are present, missing, or of what version,\n" +
			"with an install hint for each — a preflight so a missing tool is caught up front\n" +
			"instead of failing mid-scan. Given a Saga, it also validates the descriptor and\n" +
			"checks only the tools its enabled controls need; without one, it checks them all.\n" +
			"Exits non-zero when the descriptor is invalid or a required tool is missing.",
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
			return runDoctor(cmd.Context(), cmd.OutOrStdout(), builtins.Registry(), sagaPath, opts.json, detect, latest)
		},
	}
	cmd.Flags().BoolVar(&opts.json, "json", false, "output results as JSON")
	// Kept as a command-local flag as well as the root one: it is documented, it is in people's
	// CI, and "do not check for a release" is a narrower request than "this machine has no
	// network" that someone may still want to make on its own.
	cmd.Flags().BoolVar(&opts.offline, "offline", false,
		"skip the check for a newer draugr release (also DRAUGR_NO_UPDATE_CHECK=1; implied by the root --offline)")
	return cmd
}

// runDoctor validates the descriptor (when given) and reports tool availability. detect is
// injectable for testing. It returns an error — mapped to a non-zero exit — when the
// descriptor is invalid or any required tool is missing.
func runDoctor(
	ctx context.Context,
	w io.Writer,
	reg *engine.Registry,
	sagaPath string,
	asJSON bool,
	detect func(context.Context, tools.Tool) tools.Status,
	latest func(context.Context) (string, error),
) error {
	dv := draugrVersionReport(ctx, latest)
	if !asJSON {
		writeDraugrLine(w, dv)
	}

	// Descriptor check: loading validates (parse + env-resolve + schema).
	var required []tools.Tool
	// inventoryOnly marks the no-descriptor run: it reports what is present without deciding
	// that anything is missing, because nothing has asked for anything yet.
	inventoryOnly := false
	if sagaPath != "" {
		model, err := saga.LoadFile(sagaPath)
		if err != nil {
			if asJSON {
				_ = writeDoctorJSON(w, dv, &descriptorReport{Path: sagaPath, Valid: false, Error: err.Error()}, nil)
			} else {
				col := tui.For(w)
				_, _ = fmt.Fprintf(w, "Descriptor  %s — %s\n", col.Paint(tui.StyleFail, "✗ invalid"), err)
			}
			return fmt.Errorf("invalid descriptor: %w", err)
		}
		required = requiredTools(reg, model)
	} else {
		// No descriptor, so nothing has been selected and nothing is required. The catalogue is
		// an inventory here — "what could Draugr use, and what have you got" — and treating
		// every entry as required told a clean machine it was missing seven tools it may never
		// need. kube-bench is the clearest case: the default infrastructure scanner is native
		// and needs no binary at all, so demanding it is asking for a tool to run a scanner
		// nobody chose.
		required = tools.All()
		inventoryOnly = true
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

	if asJSON {
		var desc *descriptorReport
		if sagaPath != "" {
			desc = &descriptorReport{Path: sagaPath, Valid: true}
		}
		if err := writeDoctorJSON(w, dv, desc, statuses); err != nil {
			return err
		}
	} else {
		if sagaPath != "" {
			col := tui.For(w)
			_, _ = fmt.Fprintf(w, "Descriptor  %s %s\n\n",
				col.Paint(tui.StylePass, "✓ valid"), col.Paint(tui.StyleMuted, "("+sagaPath+")"))
		}
		writeDoctorTable(w, statuses)
		writeNetworkCalls(w)
	}

	if missing > 0 && inventoryOnly {
		// Reported, not failed. Which of these matter depends on a descriptor, and there is not
		// one — `draugr doctor <saga>` is the question with an answer.
		if !asJSON {
			_, _ = fmt.Fprintf(w, "\n%s\n", tui.For(w).Paint(tui.StyleMuted,
				fmt.Sprintf("%d of these are not installed. Which you need depends on your "+
					"descriptor — run `draugr doctor <saga>` to check just those, or "+
					"`draugr tools install` to fetch them all.", missing)))
		}
		return nil
	}
	if missing > 0 {
		if !asJSON {
			_, _ = fmt.Fprintf(w, "\n%s\n", tui.For(w).Paint(tui.StyleFail,
				fmt.Sprintf("%d required tool(s) missing. Install them (see notes above), "+
					"or run `draugr tools install`.", missing)))
		}
		return fmt.Errorf("%d required tool(s) not found", missing)
	}
	if !asJSON {
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
	// installed at all — the one command whose job is answering "will a scan work?" answering
	// yes because it had never heard of the tool.
	add := func(binary string) {
		if binary == "" || seen[binary] {
			return
		}
		seen[binary] = true
		if t, ok := catalog[binary]; ok {
			out = append(out, t)
			return
		}
		out = append(out, tools.Tool{
			Binary:      binary,
			Category:    tools.CategoryScanner,
			InstallHint: "required by a registered scanner; not in Draugr's tool catalog",
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

	for _, s := range reg.Scanners() {
		info := s.Info()
		serves := false
		for _, c := range info.Controls {
			if !enabled(c) {
				continue
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

	// SBOM generation is not a control, so no scanner declares it — it is required by the
	// Saga's config.sbom block instead.
	if s := model.Config.SBOM; s != nil && s.Enabled {
		add(sbom.Binary)
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Binary < out[j].Binary })
	return out
}

func writeDoctorTable(w io.Writer, statuses []tools.Status) {
	col := tui.For(w)
	t := tui.NewTable(col, "Tool", "Status", "Version", "Notes")
	for _, st := range statuses {
		status, version, notes := "✓ found", st.Version, st.Path
		style := tui.StylePass
		switch {
		case !st.Found && st.Tool.Optional:
			// Optional tools aren't a problem, so they mustn't read as one.
			status, notes, style = "– optional", "optional: "+st.Tool.InstallHint, tui.StyleMuted
		case !st.Found:
			status, notes, style = "✗ missing", "install: "+st.Tool.InstallHint, tui.StyleFail
		case st.Err != nil:
			version, notes = "?", fmt.Sprintf("%s (version check failed)", st.Path)
		case st.DataChecked && !st.DataFound:
			// Found, runnable, and useless. Reported as a failure rather than a note, because it
			// fails a scan exactly as surely as the binary being absent.
			status, notes, style = "✗ no data", st.Tool.DataHint, tui.StyleFail
		case st.DataChecked && st.DataDetail != "":
			notes = st.Path + " · " + st.DataDetail
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
			col.Paint(tui.StyleAccent, fmt.Sprintf("(latest: %s — run 'draugr self-update')",
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
}

func writeDoctorJSON(w io.Writer, dv draugrReport, desc *descriptorReport, statuses []tools.Status) error {
	report := struct {
		Draugr     draugrReport      `json:"draugr"`
		Descriptor *descriptorReport `json:"descriptor,omitempty"`
		Tools      []toolReport      `json:"tools"`
		Missing    int               `json:"missing"`
	}{Draugr: dv, Descriptor: desc, Tools: make([]toolReport, 0, len(statuses))}

	for _, st := range statuses {
		tr := toolReport{Binary: st.Tool.Binary, Found: st.Found, Version: st.Version, Path: st.Path}
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
	{"a scan, before it starts", "Trivy's vulnerability database and Nuclei's template set"},
	{"a scan, per target", "the registry, for an image; the endpoint itself, for a host or DAST target"},
	// The only entry where the traffic does not go to something of yours. Listed separately
	// because an air-gapped runner is not the only reason to care: this one discloses your
	// hostnames to a third party, and someone reading this list to decide what Draugr may reach
	// should see that without having to know the control exists.
	{"a scan, with the threats control", "abuse.ch, which learns each host's name"},
}

// writeNetworkCalls lists what Draugr fetches and when.
//
// Shown always rather than only under --offline. Someone deciding whether Draugr can run in
// their environment is asking this before they have a reason to pass the flag, and a list that
// appears only once you already know to ask for it answers the wrong question.
func writeNetworkCalls(w io.Writer) {
	col := tui.For(w)
	_, _ = fmt.Fprintf(w, "\nNetwork  %s\n", col.Paint(tui.StyleMuted, networkHeading()))
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
}

// networkHeading says whether the calls below are live or suppressed.
func networkHeading() string {
	if netpolicy.Offline() {
		return "(offline: none of these will happen)"
	}
	return "(what Draugr fetches, and when — suppress with --offline)"
}
