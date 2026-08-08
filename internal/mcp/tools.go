package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/draugr-dev/draugr/internal/builtins"
	"github.com/draugr-dev/draugr/internal/git"
	"github.com/draugr-dev/draugr/internal/scanpolicy"
	"github.com/draugr-dev/draugr/internal/surfaces"
	"github.com/draugr-dev/draugr/internal/tools"
	"github.com/draugr-dev/draugr/internal/version"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/norn"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/prioritization"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// EmptyInput is the argument type for tools that take none. The SDK derives a schema from the
// input type, and an empty struct is how you say "no arguments" rather than "any arguments".
type EmptyInput struct{}

// --- list_controls ---

// Control is one control an agent could enable.
type Control struct {
	Name            string   `json:"name" jsonschema:"the control's name, as used under config.controllers in a Saga"`
	Scope           string   `json:"scope" jsonschema:"whether the control runs per component or once for the project"`
	Purpose         string   `json:"purpose" jsonschema:"what the control checks for"`
	DefaultScanners []string `json:"defaultScanners" jsonschema:"scanners that run when the control is enabled"`
	OptInScanners   []string `json:"optInScanners,omitempty" jsonschema:"additional scanners, each enabled explicitly under controllers.<control>.<scanner>.enabled"`
	// ScannerOptions is what each of this control's scanners accepts in its Saga block, keyed by
	// scanner name. An entry present but empty means that scanner accepts no options; anything
	// else written under its block is rejected before the scan runs.
	ScannerOptions map[string][]plugin.Option `json:"scannerOptions,omitempty" jsonschema:"options each scanner accepts in its Saga block, keyed by scanner name; an empty list means it accepts none"`
}

// ControlsOutput is the list_controls result.
type ControlsOutput struct {
	Controls []Control `json:"controls"`
	// Hint is where the agent should put what it learned. Returning capability without saying
	// how to use it just moves the guesswork somewhere else.
	Hint string `json:"hint"`
}

// ListControls reports the controls this build registers.
func ListControls(reg *engine.Registry) ControlsOutput {
	serving := map[string][]string{}
	for _, s := range reg.Scanners() {
		info := s.Info()
		for _, c := range info.Controls {
			serving[c] = append(serving[c], info.Name)
		}
	}
	options := map[string][]plugin.Option{}
	for _, s := range reg.Scanners() {
		info := s.Info()
		// Always an entry, even when the list is empty. A scanner missing from this map and a
		// scanner accepting nothing look identical to a caller otherwise, and they lead to
		// opposite next steps: write the option, or stop trying.
		opts := plugin.Options(info.ConfigSchema)
		if opts == nil {
			opts = []plugin.Option{}
		}
		options[info.Name] = opts
	}
	out := ControlsOutput{
		Hint: "Enable a control under config.controllers.<name> in the Saga, or per component. " +
			"An opt-in scanner additionally needs controllers.<control>.<scanner>.enabled: true. " +
			"A scanner accepts only the options listed in scannerOptions — anything else is " +
			"rejected when the descriptor is validated, so do not invent keys.",
	}
	for _, ctrl := range reg.Controllers() {
		info := ctrl.Info()
		isDefault := map[string]bool{}
		for _, d := range info.DefaultScanners {
			isDefault[d] = true
		}
		var optIn []string
		for _, s := range serving[info.Name] {
			if !isDefault[s] {
				optIn = append(optIn, s)
			}
		}
		sort.Strings(optIn)
		out.Controls = append(out.Controls, Control{
			Name:            info.Name,
			Scope:           string(info.Scope),
			Purpose:         info.Summary,
			DefaultScanners: info.DefaultScanners,
			OptInScanners:   optIn,
			ScannerOptions:  scannerOptionsFor(options, info.DefaultScanners, optIn),
		})
	}
	sort.Slice(out.Controls, func(i, j int) bool { return out.Controls[i].Name < out.Controls[j].Name })
	return out
}

// scannerOptionsFor narrows the registry-wide option map to the scanners one control can use, so
// a caller reading a control's entry sees the keys it may write and no others.
func scannerOptionsFor(all map[string][]plugin.Option, sets ...[]string) map[string][]plugin.Option {
	out := map[string][]plugin.Option{}
	for _, names := range sets {
		for _, n := range names {
			if opts, ok := all[n]; ok {
				out[n] = opts
			}
		}
	}
	return out
}

// --- get_saga_schema ---

// SchemaOutput carries the descriptor's JSON Schema.
//
// Schema is a decoded object rather than raw bytes so a client receives the schema itself: MCP
// validates a tool's output against the schema derived from this type, and a []byte field
// derives as an array, which the schema document then fails to be.
type SchemaOutput struct {
	Schema  map[string]any `json:"schema" jsonschema:"the JSON Schema for a Saga descriptor"`
	Version string         `json:"draugrVersion" jsonschema:"the Draugr build this schema came from"`
	Hint    string         `json:"hint"`
}

// GetSchema returns the schema embedded in this binary — the one that will actually be
// enforced, as opposed to whatever is published on the web for some other version.
func GetSchema() (SchemaOutput, error) {
	var doc map[string]any
	if err := json.Unmarshal(saga.SchemaJSON, &doc); err != nil {
		return SchemaOutput{}, fmt.Errorf("decode embedded schema: %w", err)
	}
	return SchemaOutput{
		Schema:  doc,
		Version: version.Version,
		Hint: "Unknown keys are rejected, so field names must match exactly. " +
			"Validate any descriptor you write with validate_saga before relying on it.",
	}, nil
}

// --- validate_saga ---

// ValidateInput accepts a descriptor either by path or inline.
type ValidateInput struct {
	Path    string `json:"path,omitempty" jsonschema:"path to a Saga descriptor on disk"`
	Content string `json:"content,omitempty" jsonschema:"the descriptor's YAML content, for validating an edit before writing it"`
}

// ValidateOutput reports whether the descriptor is usable.
type ValidateOutput struct {
	Valid bool `json:"valid"`
	// Error is why it isn't, in the same words the CLI would use.
	Error string `json:"error,omitempty"`
	// Components and Controls describe what the descriptor actually asks for, which is how an
	// agent checks that a descriptor says what it intended rather than merely parsing.
	Components []string `json:"components,omitempty"`
	Controls   []string `json:"controls,omitempty"`
}

// ValidateSagaTool validates a descriptor from a path or inline content.
func ValidateSagaTool(_ context.Context, _ *mcp.CallToolRequest, in ValidateInput) (*mcp.CallToolResult, ValidateOutput, error) {
	switch {
	case in.Path == "" && in.Content == "":
		return nil, ValidateOutput{}, fmt.Errorf("give either path or content")
	case in.Path != "" && in.Content != "":
		return nil, ValidateOutput{}, fmt.Errorf("give path or content, not both")
	}

	var model *saga.Model
	var err error
	if in.Path != "" {
		model, err = saga.LoadFile(in.Path)
	} else {
		model, err = saga.Load([]byte(in.Content))
	}
	if err != nil {
		// A validation failure is the answer, not a tool failure — returning it as an error
		// would make the agent think the call went wrong rather than the descriptor.
		return nil, ValidateOutput{Valid: false, Error: err.Error()}, nil
	}

	out := ValidateOutput{Valid: true}
	enabled := map[string]bool{}
	for i := range model.Components {
		out.Components = append(out.Components, model.Components[i].Name)
	}
	for name := range model.Config.Controllers {
		enabled[name] = true
	}
	for i := range model.Components {
		for name := range model.Components[i].Controllers {
			enabled[name] = true
		}
	}
	for name := range enabled {
		out.Controls = append(out.Controls, name)
	}
	sort.Strings(out.Controls)
	return nil, out, nil
}

// --- summarize_report ---

// SummarizeInput points at a report already on disk.
type SummarizeInput struct {
	Path string `json:"path" jsonschema:"path to a results.sarif or report.json produced by draugr scan"`
	// MinPriority narrows the list the way --min-priority does on the CLI.
	MinPriority string `json:"minPriority,omitempty" jsonschema:"only return findings at this priority or above: p1, p2, p3 or p4"`
	// Limit caps how many findings come back. Context is the scarce resource here.
	Limit int `json:"limit,omitempty" jsonschema:"maximum findings to return; defaults to 20"`
}

// Finding is one prioritized result, flattened to what a reader needs to act.
type Finding struct {
	Priority string  `json:"priority,omitempty" jsonschema:"P1 (act now) through P4 (lowest)"`
	Severity string  `json:"severity" jsonschema:"critical, high, medium or low"`
	Score    float64 `json:"score,omitempty" jsonschema:"CVSS-style numeric severity, when the scanner gave one"`
	RuleID   string  `json:"ruleId"`
	Scanner  string  `json:"scanner,omitempty"`
	Location string  `json:"location,omitempty" jsonschema:"file:line, image reference, or endpoint"`
	Message  string  `json:"message"`
	HelpURI  string  `json:"helpUri,omitempty" jsonschema:"where the rule is documented; fetch this rather than guessing what the rule means"`
}

// SummarizeOutput is the ranked answer to "what should I fix?".
type SummarizeOutput struct {
	Total    int       `json:"total" jsonschema:"findings in the report before any filtering"`
	Returned int       `json:"returned"`
	Counts   Counts    `json:"counts"`
	Findings []Finding `json:"findings"`
	Note     string    `json:"note,omitempty"`
}

// Counts tallies the whole report, not just what was returned — a narrowed list shouldn't make
// the rest of the backlog look like it vanished.
type Counts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

// defaultLimit caps a summary. An agent pays for every finding it reads, and the point of
// prioritization is that the first few are the ones that matter.
const defaultLimit = 20

// SummarizeReportTool reads a report from disk and returns it ranked.
func SummarizeReportTool(_ context.Context, _ *mcp.CallToolRequest, in SummarizeInput) (*mcp.CallToolResult, SummarizeOutput, error) {
	if in.Path == "" {
		return nil, SummarizeOutput{}, fmt.Errorf("path is required")
	}
	data, err := os.ReadFile(in.Path) //nolint:gosec // an operator-chosen path, same as the CLI takes
	if err != nil {
		return nil, SummarizeOutput{}, fmt.Errorf("read report: %w", err)
	}
	rep, err := sarif.FromSARIF(data)
	if err != nil {
		return nil, SummarizeOutput{}, fmt.Errorf(
			"parse %s as SARIF: %w (summarize_report reads results.sarif; a report.json summary has no findings to rank)",
			in.Path, err)
	}
	return nil, summarize(rep, in.MinPriority, in.Limit), nil
}

// summarize ranks, filters and truncates a report.
func summarize(rep sarif.Report, minPriority string, limit int) SummarizeOutput {
	if limit <= 0 {
		limit = defaultLimit
	}
	out := SummarizeOutput{Total: len(rep.Results)}

	findings := make([]Finding, 0, len(rep.Results))
	for _, res := range rep.Results {
		sev := res.Severity("")
		switch sev {
		case sarif.SeverityCritical:
			out.Counts.Critical++
		case sarif.SeverityHigh:
			out.Counts.High++
		case sarif.SeverityMedium:
			out.Counts.Medium++
		default:
			out.Counts.Low++
		}
		if !atOrAbove(res.Priority, minPriority) {
			continue
		}
		loc := res.Location.URI
		if loc != "" && res.Location.StartLine > 0 {
			loc = fmt.Sprintf("%s:%d", loc, res.Location.StartLine)
		}
		findings = append(findings, Finding{
			Priority: res.Priority,
			Severity: string(sev),
			Score:    res.Score,
			RuleID:   res.RuleID,
			Scanner:  res.Tool,
			Location: loc,
			Message:  res.Message,
			HelpURI:  rep.HelpURI(res.RuleID),
		})
	}
	sortFindings(findings)

	out.Returned = len(findings)
	if len(findings) > limit {
		out.Note = fmt.Sprintf(
			"showing the %d highest-priority of %d matching findings; raise limit to see more",
			limit, len(findings))
		findings = findings[:limit]
		out.Returned = limit
	}
	out.Findings = findings
	return out
}

// atOrAbove reports whether a finding's priority clears the requested floor. An unprioritized
// finding is always kept: silently dropping findings because the Saga lacks classification
// would answer a different question than the one asked.
func atOrAbove(got, want string) bool {
	if want == "" || got == "" {
		return true
	}
	return prioritization.Priority(strings.ToUpper(got)).Rank() >=
		prioritization.Priority(strings.ToUpper(want)).Rank()
}

// sortFindings puts the most urgent first: priority, then severity, then score.
func sortFindings(fs []Finding) {
	rank := map[string]int{"P1": 4, "P2": 3, "P3": 2, "P4": 1}
	sev := map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1}
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if ra, rb := rank[strings.ToUpper(a.Priority)], rank[strings.ToUpper(b.Priority)]; ra != rb {
			return ra > rb
		}
		if sa, sb := sev[a.Severity], sev[b.Severity]; sa != sb {
			return sa > sb
		}
		return a.Score > b.Score
	})
}

// --- scan (opt-in) ---

// ScanInput selects what to scan.
type ScanInput struct {
	Path        string `json:"path" jsonschema:"path to the Saga descriptor to scan"`
	MinPriority string `json:"minPriority,omitempty" jsonschema:"only return findings at this priority or above: p1, p2, p3 or p4"`
	Limit       int    `json:"limit,omitempty" jsonschema:"maximum findings to return; defaults to 20"`
}

// ScanOutput is the verdict plus the ranked findings behind it, and the boundary of what it
// describes.
//
// Scope is not decoration. A verdict arriving on its own reads as the answer to whatever question
// prompted the scan, and the question is usually broader than the one Draugr answers: an assistant
// asked whether a repository is safe to ship, handed a PASS, has every reason to stop. Naming the
// controls that ran and the surfaces nothing looked at makes the floor visible as a floor.
type ScanOutput struct {
	Verdict string `json:"verdict" jsonschema:"pass or fail, by the same policy the CI gate applies"`
	// Controls that actually ran, so the caller can see the scope rather than infer it.
	Controls []string `json:"controls" jsonschema:"the controls this scan ran; nothing outside them was examined"`
	// Uncovered names surfaces the descriptor declares that no enabled control looked at.
	Uncovered []string `json:"uncovered,omitempty" jsonschema:"surfaces this descriptor declares that no enabled control examined"`
	// Unexamined is the same sentence for everything no control covers at all.
	Unexamined string `json:"unexamined" jsonschema:"what a Draugr scan does not examine, whatever the verdict"`
	// Delivered names where the descriptor's publishers put the report, so a caller can point
	// the user at a file, or read it back later instead of scanning again.
	Delivered []string `json:"delivered,omitempty" jsonschema:"where this run's reports were delivered, from the descriptor's config.publishers"`
	SummarizeOutput
}

// unexaminedNote is what a passing verdict does not mean. It is constant because the classes it
// names are constant: they are properties of what scanners do, not of any particular descriptor.
const unexaminedNote = "This verdict covers the controls above and nothing else. It does not " +
	"examine trust boundaries, whether a build context carries secrets into an image, how " +
	"credentials are passed to subprocesses, protocol assumptions, or authorization logic. If " +
	"the question was whether this is safe to ship rather than whether it passes the gate, read " +
	"the code as well."

// scanTool builds the scan handler over reg. It's a closure rather than a bare function because
// the registry is the one thing a scan can't derive from its arguments.
func scanTool(reg *engine.Registry, mode ScanMode) mcp.ToolHandlerFor[ScanInput, ScanOutput] {
	return func(ctx context.Context, req *mcp.CallToolRequest, in ScanInput) (*mcp.CallToolResult, ScanOutput, error) {
		if in.Path == "" {
			return nil, ScanOutput{}, fmt.Errorf("path is required")
		}
		// Loaded before the prompt, because the prompt describes what the descriptor asks for.
		// A question that names only a path asks the reader to approve something it has not
		// described, and the reader is usually not the person who wrote the file.
		model, err := saga.LoadFile(in.Path)
		if err != nil {
			return nil, ScanOutput{}, fmt.Errorf("load %s: %w", in.Path, err)
		}
		if mode == ScanAsk {
			if err := confirmScan(ctx, req, in.Path, describeScan(reg, model, in.Path)); err != nil {
				return nil, ScanOutput{}, err
			}
		}
		// Shared for this run, as the CLI does — an assistant asking for a scan should not pay
		// for five clones of one repository either.
		pool := git.NewPool()
		defer pool.Close()
		ctx = git.WithPool(ctx, pool)
		run, runErr := engine.New(reg, engine.WithPrioritization(scanpolicy.DefaultPrioritizer(nil))).Run(ctx, *model)
		if runErr != nil {
			// Say so rather than swallowing it: a partial scan that reads as complete is worse
			// than an error, because the agent will report "no findings" with confidence.
			return nil, ScanOutput{}, fmt.Errorf("scan: %w", runErr)
		}
		reports := make(map[string]sarif.Report, len(run.Controls))
		for name, cr := range run.Controls {
			reports[name] = cr.Report
		}
		verdict := norn.Policy{FailOn: sarif.LevelError}.Evaluate(reports)

		controls := make([]string, 0, len(run.Controls))
		for name := range run.Controls {
			controls = append(controls, name)
		}
		sort.Strings(controls)

		// The descriptor's reports and publishers, exactly as `draugr scan` runs them.
		//
		// An assistant scanning on someone's behalf is the case where the artifact matters most,
		// because a conversation is the least durable place a result can land: the session closes
		// and the finding is gone. A descriptor declaring `publishers: [{kind: file, dir: …}]` is
		// asking for the opposite. Honouring the controls, the exclusions and the gate from a
		// descriptor while dropping two of its blocks is also the silent no-op this project
		// refuses everywhere else.
		delivered, publishErr := deliver(ctx, model, run, verdict, in.MinPriority)

		out := ScanOutput{
			Verdict:         string(verdict.Verdict),
			Controls:        controls,
			Uncovered:       surfaces.Uncovered(model),
			Unexamined:      unexaminedNote,
			Delivered:       delivered,
			SummarizeOutput: summarize(sarif.Merge(collect(reports)...), in.MinPriority, in.Limit),
		}
		// A delivery failure is returned rather than folded into the verdict: the findings are
		// real either way, and a caller told "fail" without being told the upload never happened
		// will report a scan that was filed when it was not.
		if publishErr != nil {
			return nil, out, fmt.Errorf("scan completed but publishing failed: %w", publishErr)
		}
		return nil, out, nil
	}
}

func collect(m map[string]sarif.Report) []sarif.Report {
	names := make([]string, 0, len(m))
	for k := range m {
		names = append(names, k)
	}
	sort.Strings(names) // deterministic merge order
	out := make([]sarif.Report, 0, len(m))
	for _, n := range names {
		out = append(out, m[n])
	}
	return out
}

// confirmScan asks the user, through the client, before doing something expensive on their
// machine. It fails closed: if the client can't ask, or the user says no, no scan happens.
//
// The failure message names the way out, because "elicitation is unsupported" is meaningless to
// someone who chose --scan=ask from a docs page and has no idea their client doesn't implement
// it.
func confirmScan(ctx context.Context, req *mcp.CallToolRequest, path, message string) error {
	if req == nil || req.Session == nil {
		return fmt.Errorf("scan needs approval but there is no session to ask through; " +
			"start the server with --scan=always to run scans without asking")
	}
	if init := req.Session.InitializeParams(); init == nil || init.Capabilities == nil ||
		init.Capabilities.Elicitation == nil {
		return fmt.Errorf("scan needs your approval, but this client can't prompt for it "+
			"(no elicitation support). Run `draugr scan %s` yourself, or restart the server "+
			"with --scan=always to allow scans without asking", path)
	}
	// A form with nothing in it: there is nothing to fill in, so accept and decline are the
	// whole answer. The protocol has no dedicated confirmation mode, and an empty object schema
	// is how that intent is expressed within one that does exist.
	//
	// The schema is not optional even when it asks for nothing. RequestedSchema has no
	// omitempty, so leaving it unset put `"requestedSchema": null` on the wire, and a client
	// holding to the spec rejects the request — which made --scan=ask fail before it could ask,
	// with the error pointing at a handshake rather than at anything a reader could act on.
	res, err := req.Session.Elicit(ctx, &mcp.ElicitParams{
		Mode:    "form",
		Message: message,
		RequestedSchema: map[string]any{
			"type":       "object",
			"properties": map[string]any{},
		},
	})
	if err != nil {
		return fmt.Errorf("could not ask for approval to scan: %w", err)
	}
	if res.Action != "accept" {
		return fmt.Errorf("scan declined")
	}
	return nil
}

// --- check_tools ---

// CheckToolsInput optionally narrows the check to what one descriptor actually needs.
type CheckToolsInput struct {
	Path string `json:"path,omitempty" jsonschema:"path to a Saga descriptor; without it, every tool Draugr knows about is checked"`
}

// ToolStatus is one external tool Draugr would execute.
type ToolStatus struct {
	Name      string `json:"name"`
	Installed bool   `json:"installed"`
	Version   string `json:"version,omitempty"`
	Path      string `json:"path,omitempty"`
	Category  string `json:"category,omitempty" jsonschema:"scanner (backs a control) or utility (supporting, e.g. git)"`
	Optional  bool   `json:"optional,omitempty" jsonschema:"absence of an optional tool is not a problem"`
	// Install is the command a person would run. Draugr will not run it for you.
	Install string `json:"install,omitempty"`
}

// CheckToolsOutput is the answer to "can Draugr actually scan here?".
type CheckToolsOutput struct {
	Ready   bool         `json:"ready" jsonschema:"true when nothing required is missing"`
	Tools   []ToolStatus `json:"tools"`
	Missing []string     `json:"missing,omitempty" jsonschema:"required tools that are absent"`
	// Remedy is the single command that installs everything missing.
	Remedy string `json:"remedy,omitempty"`
	Note   string `json:"note"`
}

// CheckToolsTool reports which external scanners are present.
//
// This exists because of what Draugr does when one is missing: the control can't run, and a
// scan that can't run is not a pass. An assistant that hits that needs to say what's wrong and
// what fixes it — which is a question about the machine, and answering it is free.
//
// It deliberately stops there. Draugr will not install anything on a user's behalf over MCP:
// that's a write to their machine, and their client already has a permission model for running
// commands which is stronger than anything this server could offer. Report the command; let the
// person approve it where they already approve such things.
func CheckToolsTool(ctx context.Context, _ *mcp.CallToolRequest, in CheckToolsInput) (*mcp.CallToolResult, CheckToolsOutput, error) {
	required := tools.All()
	if in.Path != "" {
		model, err := saga.LoadFile(in.Path)
		if err != nil {
			return nil, CheckToolsOutput{}, fmt.Errorf("load %s: %w", in.Path, err)
		}
		required = requiredFor(model)
	}

	out := CheckToolsOutput{Ready: true}
	for _, t := range required {
		st := tools.Detect(ctx, t, nil, nil)
		s := ToolStatus{
			Name: t.Binary, Installed: st.Found, Version: st.Version,
			Path: st.Path, Category: t.Category, Optional: t.Optional,
		}
		if !st.Found {
			s.Install = t.InstallHint
			if !t.Optional {
				out.Ready = false
				out.Missing = append(out.Missing, t.Binary)
			}
		}
		out.Tools = append(out.Tools, s)
	}
	sort.Strings(out.Missing)

	switch {
	case len(out.Missing) > 0:
		out.Remedy = "draugr tools install " + strings.Join(out.Missing, " ")
		out.Note = "Controls backed by a missing scanner cannot run, and a scan that cannot run " +
			"reports a failure rather than a pass. Draugr will not install these for you — run " +
			"the remedy command, or ask the user to."
	default:
		out.Note = "Everything required is present."
	}
	return nil, out, nil
}

// requiredFor returns the tools the controls enabled anywhere in the model would execute. It
// mirrors `draugr doctor`: no point reporting kube-bench missing when nothing asks for it.
func requiredFor(model *saga.Model) []tools.Tool {
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
	need := map[string]bool{}
	for _, s := range builtins.Registry().Scanners() {
		info := s.Info()
		for _, c := range info.Controls {
			if enabled(c) && info.Binary != "" {
				need[info.Binary] = true
			}
		}
	}
	var out []tools.Tool
	for _, t := range tools.All() {
		// git is needed by any repository-scoped control, and utilities are cheap to report.
		if need[t.Binary] || t.Category == tools.CategoryUtility {
			out = append(out, t)
		}
	}
	return out
}
