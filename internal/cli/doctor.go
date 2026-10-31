package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/spf13/cobra"

	"github.com/draugr-dev/draugr/internal/builtins"
	"github.com/draugr-dev/draugr/internal/login"
	"github.com/draugr-dev/draugr/internal/needs"
	"github.com/draugr-dev/draugr/internal/netpolicy"
	"github.com/draugr-dev/draugr/internal/preflight"
	"github.com/draugr-dev/draugr/internal/registry"
	"github.com/draugr-dev/draugr/internal/sagafetch"
	"github.com/draugr-dev/draugr/internal/selfupdate"
	"github.com/draugr-dev/draugr/internal/surfaces"
	"github.com/draugr-dev/draugr/internal/tools"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"

	"github.com/draugr-dev/draugr/internal/english"
	"github.com/draugr-dev/draugr/pkg/report"
	"github.com/draugr-dev/draugr/pkg/skald"
	"github.com/draugr-dev/draugr/pkg/tui"
)

type doctorOptions struct {
	json bool
	// failOnUncovered turns the uncovered-surface note into a failure. Off by default: a
	// deliberately narrow descriptor is a legitimate thing to have, and a preflight that fails on
	// a choice somebody made is one people learn to ignore.
	failOnUncovered bool
	// strict does the same for a tool that is not the version Draugr tests.
	strict bool
	// requirePolicy is --policy: the organization's policy has to be checked.
	requirePolicy bool
	// The scope a scan takes, so a preflight checks the targets that scan would read.
	components, controls, labels, exposure, criticality []string
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
	// reach checks each target the descriptor's scan would read. Set by the command; a test that
	// sets it supplies probes, so nothing leaves the machine.
	reach bool
	// offline skips the reachability checks that need the network, and reports each as not
	// checked.
	offline bool
	// requirePolicy makes an organization policy that could not be checked a failure.
	requirePolicy bool
	scope         engine.Scope
	probes        preflight.Probes
	// data reads the state of the scanners' data. Set by the command; nil reads none, so a test
	// asks no tool on the machine running it.
	data func(context.Context, *engine.Registry, *saga.Model) []engine.ScannerData
	// pins are the tools.<name>.version settings in effect, which a found tool is held to in place
	// of the version Draugr tests. Set by the command; nil holds every tool to Draugr's own.
	pins map[string]toolPin
}

func newDoctorCommand() *cobra.Command {
	opts := &doctorOptions{}
	cmd := &cobra.Command{
		Use:   "doctor [saga.yaml]",
		Short: "Check that a scan's tools are installed and its targets reachable",
		Long: "Report which external scanner tools are present, missing, or out of date, with an\n" +
			"install hint for each.\n\n" +
			"Given a Saga, also validates the descriptor, checks only the tools its enabled\n" +
			"controls need, and checks each target: repositories resolve, paths exist, images\n" +
			"are readable and hosts connect; without one, checks every tool. Exits non-zero\n" +
			"when the descriptor is invalid, a required tool is missing or a target check fails.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			sagaPath := ""
			if len(args) == 1 {
				sagaPath = args[0]
			}
			detect := func(ctx context.Context, t tools.Tool) tools.Status {
				return tools.Detect(ctx, t, nil, nil)
			}
			// The root --offline, read through the policy it sets, so doctor and every fetch it
			// reaches answer the same question the same way.
			offline := netpolicy.Offline()
			// Best-effort update check (current vs latest), unless opted out. It never blocks or
			// fails the command: a short timeout, errors ignored.
			var latest func(context.Context) (string, error)
			if !netpolicy.SkipUpdateCheck() {
				latest = func(ctx context.Context) (string, error) {
					ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
					defer cancel()
					return selfupdate.LatestVersion(ctx, nil)
				}
			}
			// The pins `tools install` reads, so a tool is held to the build that command would put
			// in its place.
			pins, err := configuredToolPins()
			if err != nil {
				return err
			}
			run := doctorRun{
				json: opts.json, failOnUncovered: opts.failOnUncovered, strict: opts.strict,
				reach: true, offline: offline, requirePolicy: opts.requirePolicy,
				data: doctorData, pins: pins,
				scope: engine.Scope{
					Components: opts.components, Controls: opts.controls, Labels: opts.labels,
					Exposure: exposures(opts.exposure), Criticality: criticalities(opts.criticality),
				},
			}
			return runDoctor(cmd.Context(), cmd.OutOrStdout(), builtins.Registry(), sagaPath, run, detect, latest)
		},
	}
	cmd.Flags().BoolVar(&opts.json, "json", false, "output results as JSON")
	cmd.Flags().BoolVar(&opts.strict, "strict", false,
		"also fail when a tool is not the version it is pinned to (tools.<name>.version), or the version "+
			"Draugr tests where it has no pin, not only when one is missing")
	cmd.Flags().BoolVar(&opts.failOnUncovered, "fail-on-uncovered", false,
		"fail if the descriptor declares a surface no enabled control looks at (reported either way)")
	// No --offline of its own. The root flag is the one that sets the network policy, and a local
	// flag of the same name shadows it: doctor would skip its own checks while every fetch it reached
	// still read the policy as online. DRAUGR_NO_UPDATE_CHECK=1 is the narrower request, skipping
	// only the release check.
	cmd.Flags().BoolVar(&opts.requirePolicy, "policy", false,
		"ask the draugr-api server the descriptor publishes to for the organization's policy, sending the token; "+
			"without it doctor sends no token, and with it not being able to check is an error")
	cmd.Flags().StringSliceVar(&opts.components, "components", nil,
		"check only the targets of these components")
	cmd.Flags().StringSliceVar(&opts.labels, "labels", nil,
		"check only the targets of components carrying these `key=value` labels; repeat for more, "+
			"one key twice means either value")
	cmd.Flags().StringSliceVar(&opts.exposure, "exposure", nil,
		"check only the targets of components declaring one of these exposures: "+
			strings.Join(namesOf(saga.Exposures), ", "))
	cmd.Flags().StringSliceVar(&opts.criticality, "criticality", nil,
		"check only the targets of components declaring one of these criticalities: "+
			strings.Join(namesOf(saga.Criticalities), ", "))
	cmd.Flags().StringSliceVar(&opts.controls, "controls", nil,
		"check only the targets these controls would read")
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
		loaded, err := doctorLoad(ctx, sagaPath, run.reach, run.offline)
		// The control names validate and scan check. A misspelled control passes the schema, so
		// without this doctor would call the descriptor valid and the scan would then refuse it.
		if err == nil {
			err = checkDescriptorControls(reg, sagaPath, loaded)
		}
		if err != nil {
			if run.json {
				_ = writeDoctorJSON(w, dv, &descriptorReport{Path: sagaPath, Valid: false, Error: err.Error()}, nil, nil, 0, nil, nil, nil, nil)
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
		// The configuration's controller defaults merged under the descriptor before anything reads
		// it, as `draugr scan` merges them, because a default that selects a scanner makes that
		// scanner's tool required. Everything below, the tools, the targets and the policy, then
		// describes the scan that would run.
		if _, _, err := applyConfigDefaults(ctx, model); err != nil {
			return err
		}
		required = needs.Tools(reg, model)
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

	var checks []preflight.Check
	if model != nil && run.reach {
		var err error
		if checks, err = checkTargets(ctx, reg, model, run); err != nil {
			return err
		}
	}

	// The organization's policy, from the server the descriptor publishes to. Judged on the
	// descriptor as the scan would send it, with the machine's configured defaults merged under it.
	//
	// Asked only under --policy. Doctor is what somebody runs on a descriptor they have not
	// reviewed yet, and asking means sending the token to the server it names.
	var orgPolicy *skald.PolicyCheck
	var askedAs []login.Login
	if model != nil {
		held := ""
		switch {
		case run.offline:
			held = policyOffline
		case !run.requirePolicy:
			held = policyNotAsked
		}
		var err error
		orgPolicy, askedAs, err = checkOrgPolicyAs(ctx, model, (&saga.Resolved{Model: model}).Effective(), held)
		if err != nil {
			return err
		}
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

	var data []engine.ScannerData
	if run.data != nil {
		data = run.data(ctx, reg, model)
	}

	if run.json {
		var desc *descriptorReport
		if sagaPath != "" {
			desc = &descriptorReport{Path: sagaPath, Valid: true}
		}
		if err := writeDoctorJSON(w, dv, desc, statuses, run.pins, missing, uncovered, checks, orgPolicy, data); err != nil {
			return err
		}
	} else {
		if sagaPath != "" {
			col := tui.For(w)
			_, _ = fmt.Fprintf(w, "Descriptor  %s %s\n",
				col.Paint(tui.StylePass, "✓ valid"), col.Paint(tui.StyleMuted, "("+sagaPath+")"))
			// The TOOLS heading has no blank line of its own above it; every later section does.
			if len(statuses) > 0 {
				_, _ = fmt.Fprintln(w)
			}
		}
		// No heading over an empty table. "No external tools required." closes the report and says
		// it, and a bare header row above it reads as a list that failed to print.
		if len(statuses) > 0 {
			writeDoctorTable(w, statuses, run.pins)
		}
		writeDoctorData(w, data)
		if len(checks) > 0 {
			writeTargetChecks(w, checks)
		}
		if orgPolicy != nil {
			_, _ = fmt.Fprintln(w)
			// Whose sign-in the server judged the descriptor for, since a login is a person's and the
			// same descriptor can be judged differently for another organization.
			col := tui.For(w)
			var under []string
			for _, l := range askedAs {
				under = append(under, doctorLoginLine(col, l))
			}
			report.WritePolicyTableWith(w, col, orgPolicy, model.ProjectName(), under)
		}
		writeNetworkCalls(w, reg, model)
		if model != nil {
			printUncoveredSurfaceNote(w, model)
			printUntrackedNote(w, model)
		}
	}

	// Asked for, so it decides the exit code, with a descriptor or without one.
	strictErr := func() error {
		if !run.strict {
			return nil
		}
		if tested, pinned := offTargetCounts(statuses, run.pins); tested+pinned > 0 {
			return fmt.Errorf("%s; run `draugr tools install --force`, or drop --strict to accept %s",
				offTargetPhrase(tested, pinned), english.Choose(tested+pinned, "it", "them"))
		}
		return nil
	}
	if missing > 0 && inventoryOnly {
		// Reported, not failed. Which of these matter depends on a descriptor, and there is not one.
		// `draugr doctor <saga>` is the question with an answer.
		if !run.json {
			_, _ = fmt.Fprintf(w, "\n%s\n", tui.For(w).Paint(tui.StyleMuted,
				fmt.Sprintf("%d of these are not installed. Which you need depends on your "+
					"descriptor. Run `draugr doctor <saga>` to check just those, or "+
					"`draugr tools install` to fetch the ones it can; the Notes column says where the rest "+
					"come from.", missing)))
		}
		// --strict asks about the tools that are present, and a missing one does not answer that.
		return strictErr()
	}
	// With a descriptor, a missing tool is the larger problem, so its message leads and --strict
	// answers when nothing is missing. Either way the command exits non-zero.
	if missing == 0 {
		if err := strictErr(); err != nil {
			return err
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
	// After the missing-tool checks and before the surface note: a target this machine cannot
	// reach fails the scan the way a missing tool does, where an uncovered surface only narrows it.
	if n := preflight.FailedCount(checks); n > 0 {
		return fmt.Errorf("%s failed", english.Count(n, "target check"))
	}
	// A scan of this descriptor would be refused or would fail its gate, which is the answer doctor
	// exists to give before the scan. --policy adds that not knowing is also a failure.
	if run.requirePolicy {
		if err := requirePolicy(orgPolicy); err != nil {
			return err
		}
	}
	if orgPolicy != nil {
		switch orgPolicy.Outcome {
		case skald.PolicyRefuse:
			return fmt.Errorf("the organization's policy would refuse a scan of this descriptor: %s", refusedRules(orgPolicy))
		case skald.PolicyFail:
			return fmt.Errorf("the organization's policy would fail a scan of this descriptor: %s", failingRules(orgPolicy))
		}
	}
	// After the missing-tool checks, because a tool that is absent stops the scan outright while
	// an uncovered surface only narrows it, and the more serious answer should be the one given.
	//
	// The descriptor's gate.failOnCaveats is read as well, so the preflight and the scan cannot
	// disagree: a descriptor whose scan would fail on not-checked fails here, before any scanner
	// runs, without anybody remembering the flag.
	if len(uncovered) > 0 && (run.failOnUncovered || failsOnNotChecked(model)) {
		why := "--fail-on-uncovered was set"
		if !run.failOnUncovered {
			why = "config.gate.failOnCaveats lists not-checked"
		}
		if !run.json {
			_, _ = fmt.Fprintf(w, "\n%s\n", tui.For(w).Paint(tui.StyleFail,
				fmt.Sprintf("%s no enabled control looks at, and %s.", english.Count(len(uncovered), "declared surface"), why)))
		}
		return fmt.Errorf("%s not covered by an enabled control", english.Count(len(uncovered), "declared surface"))
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

// doctorLoad loads the descriptor. When targets are to be checked, remote fragments are fetched
// as `validate` fetches them, because a fragment that cannot be fetched is the first target a scan
// fails on.
func doctorLoad(ctx context.Context, path string, reach, offline bool) (*saga.Model, error) {
	// Offline, a remote fragment is not fetched, and the loader that fetches nothing is the one used.
	if !reach || offline {
		return saga.LoadFile(path)
	}
	fetcher := sagafetch.New(ctx)
	defer fetcher.Close()
	res, err := saga.ResolveFile(path, fetcher)
	if err != nil {
		return nil, err
	}
	return res.Model, nil
}

// checkTargets plans the scan the flags describe and checks each target it would read.
//
// Planned by the engine rather than read off the descriptor, so the targets are the ones the scan
// would read: a repository no enabled control scans is not checked, and one two components share is
// checked once. Every effect is allowed, because the question is what the scan could touch, and the
// approval it asks for is the scan's own business.
func checkTargets(ctx context.Context, reg *engine.Registry, model *saga.Model, run doctorRun) ([]preflight.Check, error) {
	if err := run.scope.Validate(*model, controlNames(reg)); err != nil {
		return nil, err
	}
	rootLocalRepositories(ctx, model)
	eng := engine.New(reg,
		engine.WithScope(run.scope.Resolve(*model)),
		engine.WithAllowedEffects([]string{
			string(plugin.EffectNetwork), string(plugin.EffectDisclosure),
			string(plugin.EffectMutate), string(plugin.EffectPrivilege),
		}))
	jobs, err := eng.Plan(*model)
	if err != nil {
		return nil, fmt.Errorf("the scan cannot be planned:\n  %s", strings.ReplaceAll(err.Error(), "\n", "\n  "))
	}
	targets := make([]plugin.Target, 0, len(jobs))
	for _, j := range jobs {
		targets = append(targets, j.Job.Target)
	}
	return preflight.Run(ctx, targets, preflight.Options{Offline: run.offline, Probes: run.probes}), nil
}

// writeTargetChecks lists each target check and its result: a table when it fits the terminal, and
// otherwise each target on a line of its own with its result under it, as the scan's errors block
// does. A table cut to fit would cut the result, the one column a reader came for. An image's
// digest is shortened either way.
func writeTargetChecks(w io.Writer, checks []preflight.Check) {
	col := tui.For(w)
	_, _ = fmt.Fprintf(w, "\n%s\n", doctorHeading(col, "Targets"))
	targets := make([]string, len(checks))
	results := make([]tui.Cell, len(checks))
	widths := []int{len("Kind"), len("Target"), len("Result")}
	for i, c := range checks {
		targets[i] = c.Target
		if c.Kind == "image" {
			targets[i] = registry.ShortDigest(c.Target)
		}
		switch c.Status {
		case preflight.Passed:
			results[i] = tui.Styled(tui.StylePass, "✓ "+c.Detail)
		case preflight.Failed:
			results[i] = tui.Styled(tui.StyleFail, "✗ "+c.Detail)
		default:
			results[i] = tui.Styled(tui.StyleMuted, "not checked: "+c.Detail)
		}
		widths[0] = max(widths[0], utf8.RuneCountInString(c.Kind))
		widths[1] = max(widths[1], utf8.RuneCountInString(targets[i]))
		widths[2] = max(widths[2], utf8.RuneCountInString(results[i].Text))
	}
	if cols := tui.Columns(w); cols > 0 && widths[0]+widths[1]+widths[2]+4 > cols {
		for i, c := range checks {
			_, _ = fmt.Fprintf(w, "%s %s\n", c.Kind, targets[i])
			_, _ = fmt.Fprintf(w, "  %s\n", col.Paint(results[i].Style, results[i].Text))
		}
		return
	}
	t := tui.NewTable(col, "Kind", "Target", "Result")
	for i, c := range checks {
		t.Row(tui.PlainCell(c.Kind), tui.PlainCell(targets[i]), results[i])
	}
	t.Render(w)
}

func writeDoctorTable(w io.Writer, statuses []tools.Status, pins map[string]toolPin) {
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
		// Found and runnable, and not the build an install would fetch. In the row because this is
		// where somebody looks up one tool, and counted below because a machine that has not
		// reinstalled in a while has most of them and a mark on every row is not a mark. Never a
		// failure: refusing to work would be Draugr mistaking "I have not tested this" for "this is
		// wrong".
		//
		// A configured pin's file is named on its row whether or not the tool matches it, because
		// it is why the row is held to a version other than the one Draugr tests. The version is
		// named only when the tool is not at it.
		target := versionTargetFor(st.Tool.Binary, pins)
		switch {
		case target.pin != nil && offTarget(st, target):
			notes = fmt.Sprintf("%s · pinned to %s in %s", notes, target.version, herePath(target.pin.Path))
		case target.pin != nil:
			notes = fmt.Sprintf("%s · pinned in %s", notes, herePath(target.pin.Path))
		case offTarget(st, target):
			notes = fmt.Sprintf("%s · tested against %s", notes, target.version)
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
	if tested, pinned := offTargetCounts(statuses, pins); tested+pinned > 0 {
		_, _ = fmt.Fprintf(w, "%s\n", col.Paint(tui.StyleAccent, fmt.Sprintf(
			"%s. `draugr tools install --force` %s.", offTargetPhrase(tested, pinned), forceInstalls(tested, pinned))))
	}
}

// versionTarget is the version doctor holds a found tool to: the one `draugr tools install`
// fetches for it.
type versionTarget struct {
	// version is without a leading v, and "" when there is nothing to compare against.
	version string
	// pin is the configured pin the version comes from, or nil for the version Draugr tests.
	pin *toolPin
}

// versionTargetFor resolves the version an install of binary fetches: its pin in
// draugr.config.yaml, resolved as `tools install` resolves it, or else the version Draugr tests.
func versionTargetFor(binary string, pins map[string]toolPin) versionTarget {
	if p, ok := pins[binary]; ok {
		v, ok := tools.PlannedVersion(binary, p.Version)
		if !ok {
			v = p.Version
		}
		return versionTarget{version: strings.TrimPrefix(strings.TrimSpace(v), "v"), pin: &p}
	}
	return versionTarget{version: strings.TrimPrefix(tools.PinnedVersion(binary), "v")}
}

// offTarget reports whether a found tool runs another version than its target. False when it
// matches, when there is no target, or when the version could not be read.
//
// String equality after dropping a leading v. Not an ordering: "older than tested" and "newer than
// tested" are both untested, and a comparison that ranked them would have to decide what a version
// scheme means for eight tools that do not share one.
func offTarget(st tools.Status, target versionTarget) bool {
	if !st.Found || st.Err != nil || st.Version == "" || target.version == "" {
		return false
	}
	return target.version != strings.TrimPrefix(st.Version, "v")
}

// offTargetCounts counts the found tools off their target: tested is those held to the version
// Draugr tests, pinned those held to a configured pin.
func offTargetCounts(statuses []tools.Status, pins map[string]toolPin) (tested, pinned int) {
	for _, st := range statuses {
		target := versionTargetFor(st.Tool.Binary, pins)
		switch {
		case !offTarget(st, target):
		case target.pin != nil:
			pinned++
		default:
			tested++
		}
	}
	return tested, pinned
}

// offTargetPhrase counts the found tools off their target. "Installed" keeps the count apart from
// the count of tools that are not installed, which an inventory prints beside it.
func offTargetPhrase(tested, pinned int) string {
	var parts []string
	if tested > 0 {
		parts = append(parts, english.Count(tested, "installed tool")+" "+
			english.Choose(tested, "is", "are")+" not the version Draugr tests")
	}
	if pinned > 0 {
		subject := english.Count(pinned, "installed tool")
		if tested > 0 {
			subject = strconv.Itoa(pinned)
		}
		parts = append(parts, subject+" "+english.Choose(pinned, "is", "are")+" not at "+
			english.Choose(pinned, "its pinned version", "their pinned versions"))
	}
	return strings.Join(parts, " and ")
}

// forceInstalls names what `draugr tools install --force` installs for the tools off their target.
func forceInstalls(tested, pinned int) string {
	switch {
	case tested > 0 && pinned > 0:
		return "installs the pinned build where there is a pin and the tested build otherwise"
	case pinned > 0:
		return "installs the pinned build"
	default:
		return "installs the tested build"
	}
}

// doctorData is the state of the data each scanner in use reads, or every registered scanner's
// with no descriptor, as the tools report it from what is on disk. Nothing is downloaded.
func doctorData(ctx context.Context, reg *engine.Registry, model *saga.Model) []engine.ScannerData {
	if reg == nil {
		return nil
	}
	scanners := reg.Scanners()
	if model != nil {
		scanners = scanners[:0:0]
		for _, info := range needs.Scanners(reg, model) {
			if sc, ok := reg.Scanner(info.Name); ok {
				scanners = append(scanners, sc)
			}
		}
	}
	return engine.DataStates(ctx, scanners)
}

// writeDoctorData lists each data source in the words the scan's evidence block uses, so the two
// answers read alike. Nothing when no scanner reports one.
func writeDoctorData(w io.Writer, data []engine.ScannerData) {
	var lines []string
	for _, d := range data {
		if l := report.DataSourceState(d); l != "" {
			lines = append(lines, l)
		}
	}
	if len(lines) == 0 {
		return
	}
	col := tui.For(w)
	_, _ = fmt.Fprintf(w, "\n%s\n", doctorHeading(col, "Data"))
	for _, l := range lines {
		_, _ = fmt.Fprintf(w, "  %s\n", l)
	}
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
	// TestedVersion is the version Draugr pins, present only when this tool is not running it and
	// draugr.config.yaml pins none. Absent means the two agree, or that there is no pin to compare
	// against, and a consumer can treat its presence as the whole answer rather than comparing two
	// strings itself.
	TestedVersion string `json:"testedVersion,omitempty"`
	// PinnedVersion is the version tools.<name>.version pins, present only when this tool is not
	// running it, on the same terms as TestedVersion. PinnedIn is the file that pins it.
	PinnedVersion string `json:"pinnedVersion,omitempty"`
	PinnedIn      string `json:"pinnedIn,omitempty"`
}

// writeDoctorJSON writes the report. missing is the count the exit code is decided on, passed in
// rather than recounted so the document and the exit code cannot disagree about one machine: a
// tool with no data is missing, and an optional tool that is absent is not.
func writeDoctorJSON(
	w io.Writer, dv draugrReport, desc *descriptorReport, statuses []tools.Status, pins map[string]toolPin,
	missing int, uncovered []string, checks []preflight.Check, policy *skald.PolicyCheck, data []engine.ScannerData,
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
		// Targets are the reachability checks, one per distinct target the scan would read.
		Targets []preflight.Check `json:"targets,omitempty"`
		// Policy is the organization's policy check, absent where the descriptor publishes to no
		// draugr-api server.
		Policy *skald.PolicyCheck `json:"policy,omitempty"`
		// Data is the state of each data source the scanners read, in report.json's scannerData
		// form.
		Data []skald.ScannerData `json:"data,omitempty"`
	}{
		Draugr: dv, Descriptor: desc, Tools: make([]toolReport, 0, len(statuses)), Missing: missing,
		UncoveredSurfaces: uncovered, Targets: checks, Policy: policy, Data: skald.ScannerDataFrom(data),
	}

	for _, st := range statuses {
		tr := toolReport{Binary: st.Tool.Binary, Found: st.Found, Version: st.Version, Path: st.Path}
		if target := versionTargetFor(st.Tool.Binary, pins); offTarget(st, target) {
			if target.pin != nil {
				tr.PinnedVersion, tr.PinnedIn = target.version, target.pin.Path
			} else {
				tr.TestedVersion = target.version
			}
		}
		switch {
		case !st.Found:
			tr.Hint = st.Tool.InstallHint
		case st.DataChecked && !st.DataFound:
			// Present and unable to run, so the hint is how to get its data.
			tr.Hint = st.Tool.DataHint
		}
		report.Tools = append(report.Tools, tr)
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

// disclosedTo is the host each disclosing scanner tells about a target, and what it tells.
//
// Written out because an effect's detail is a sentence rather than a host, and a host is what an
// egress rule takes. TestEveryDisclosingScannerNamesItsHost holds every scanner declaring the
// disclosure effect to an entry here, so a new one cannot be missing from the list. An empty entry
// is a scanner whose disclosure goes only to the target's own registry, which the scan contacts
// anyway.
var disclosedTo = map[string]struct{ Host, What string }{
	"urlhaus":       {"urlhaus-api.abuse.ch", "learns each host's name"},
	"virustotal":    {"www.virustotal.com", "learns each host's domain"},
	"mend-sca":      {"$MEND_URL", "learns the dependency inventory"},
	"mend-licenses": {"$MEND_URL", "learns the dependency inventory"},
	"cosign":        {"rekor.sigstore.dev", "learns an image digest, for a signature with no inclusion proof"},
	"notation":      {},
}

// scanContact is one host a scan contacts besides its own targets, and why.
type scanContact struct {
	Control, Scanner, Host, What string
}

// scanContacts lists, per control, the hosts a scan contacts besides its targets: the reference
// data each scanner fetches, and the third party a disclosing scanner tells. For a descriptor, the
// scanners its scan would run; with none, every registered scanner.
//
// Derived from the registry, because the hand-kept version of this was wrong: it named two of the
// seven data sources, and nothing about it could have said so. The test holding every scanner to
// declaring what it reads is what keeps a derived list from silently shrinking.
func scanContacts(reg *engine.Registry, model *saga.Model) []scanContact {
	var scanners []plugin.ScannerInfo
	if model == nil {
		for _, s := range reg.Scanners() {
			scanners = append(scanners, s.Info())
		}
	} else {
		scanners = needs.Scanners(reg, model)
	}
	var rows []scanContact
	for _, info := range scanners {
		for _, control := range info.Controls {
			for _, d := range info.Data {
				when := "before the scan"
				if d.PerScan {
					when = "every scan"
				}
				for _, host := range d.Hosts {
					rows = append(rows, scanContact{control, info.Name, host, d.Name + " · " + when})
				}
			}
			if to := disclosedTo[info.Name]; to.Host != "" {
				rows = append(rows, scanContact{control, info.Name, to.Host, to.What})
			}
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if a.Control != b.Control {
			return a.Control < b.Control
		}
		if a.Host != b.Host {
			return a.Host < b.Host
		}
		if a.What != b.What {
			return a.What < b.What
		}
		return a.Scanner < b.Scanner
	})
	return rows
}

// withoutScanner drops the scanner from each row and the duplicates that leaves: four
// Trivy-backed scanners read one database, and a reader writing a firewall rule wants one row.
func withoutScanner(rows []scanContact) []scanContact {
	var out []scanContact
	for _, r := range rows {
		r.Scanner = ""
		if n := len(out); n > 0 && out[n-1] == r {
			continue
		}
		out = append(out, r)
	}
	return out
}

// doctorHeading names a section the way a scan report names one.
//
// The same shape rather than a second one. A reader meets `CONTROLS` and `SIGNALS` in a report and
// `Network` here, and two casings for one idea is a thing to learn twice; whichever is right, one
// of them is the product's.
func doctorHeading(col tui.Painter, name string) string {
	return col.Paint(tui.StyleMuted, strings.ToUpper(name))
}

// writeNetworkCalls lists, per control, what a scan contacts besides its targets.
//
// Shown always rather than only under --offline. Someone deciding whether Draugr can run in
// their environment is asking this before they have a reason to pass the flag, and a list that
// appears only once you already know to ask for it answers the wrong question.
//
// Only the scan. The commands that fetch something say so in their names, tools install, feeds
// update, self-update, and a scan contacting the targets it was given needs no line either.
func writeNetworkCalls(w io.Writer, reg *engine.Registry, model *saga.Model) {
	if reg == nil {
		return
	}
	rows := scanContacts(reg, model)
	col := tui.For(w)
	_, _ = fmt.Fprintf(w, "\n%s  %s\n", doctorHeading(col, "Network"),
		col.Paint(tui.StyleMuted, networkHeading()))
	if len(rows) == 0 {
		// Said rather than left as an empty heading, which reads as a list that failed to print.
		_, _ = fmt.Fprintf(w, "  draugr scan  %s\n", col.Paint(tui.StyleMuted, "(contacts only its targets)"))
		return
	}
	_, _ = fmt.Fprintf(w, "  draugr scan\n")
	writeContactList(w, col, withoutScanner(rows))
}

// writeContactList prints rows under their control, the control named once.
func writeContactList(w io.Writer, col tui.Painter, rows []scanContact) {
	cw, hw := 0, 0
	for _, r := range rows {
		cw, hw = max(cw, len(r.Control)), max(hw, len(r.Host))
	}
	prev := ""
	for _, r := range rows {
		control := r.Control
		if control == prev {
			control = ""
		}
		prev = r.Control
		_, _ = fmt.Fprintf(w, "    %-*s  %-*s  %s\n", cw, control, hw, r.Host, col.Paint(tui.StyleMuted, r.What))
	}
}

// networkHeading says whether the calls below are live or suppressed.
func networkHeading() string {
	if netpolicy.Offline() {
		return "(offline: none of these will happen)"
	}
	return "(besides its targets · --offline stops all of it)"
}

// missingToolsAdvice counts what is missing and suggests `tools install` only when it could
// actually help.
//
// Some scanners are execed and never fetched, retire.js publishes to npm, the Mend CLI is
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
		return fmt.Sprintf("%s missing. Run `draugr tools install`.", english.Count(missing, "required tool"))
	}
	if fetchable > 0 {
		return fmt.Sprintf("%s missing. Run `draugr tools install` for %d of them; the Notes "+
			"column says where the rest come from.", english.Count(missing, "required tool"), fetchable)
	}
	return fmt.Sprintf("%s missing. The Notes column says where each one comes from.",
		english.Count(missing, "required tool"))
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

// failsOnNotChecked reports whether the descriptor's gate fails a scan on a declared surface no
// enabled control looks at.
func failsOnNotChecked(model *saga.Model) bool {
	return model != nil && model.Config.Gate != nil &&
		slices.Contains(model.Config.Gate.FailOnCaveats, saga.CaveatNotChecked)
}
