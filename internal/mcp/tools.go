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
	"github.com/draugr-dev/draugr/pkg/diff"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/norn"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/prioritization"
	"github.com/draugr-dev/draugr/pkg/report"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
	"github.com/draugr-dev/draugr/pkg/surveyor"
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
	HelpURI  string  `json:"helpUri,omitempty" jsonschema:"where the rule is documented, for background beyond the remediation below"`

	// What follows is what turns a report into work. Without it an assistant can say a finding
	// is critical and cannot say what to do about it — so it either guesses a fix or sends the
	// reader to a search engine for text this report already contains.

	// Remediation is the fix in the scanner's own words, not a summary of it.
	Remediation string `json:"remediation,omitempty" jsonschema:"how to fix this, as the scanner published it; prefer this over inferring a fix from the message"`
	// Action classifies what kind of fix it is, so an assistant can tell work it can do from
	// work that belongs to whoever publishes the image or operates the cluster.
	Action string `json:"action,omitempty" jsonschema:"upgrade (a fixed version exists here), upstream (the fix is in an image or OS somebody else publishes), external (not this project's to change), or none (no fix published anywhere)"`
	// Package names what to upgrade and to what.
	Package      string `json:"package,omitempty" jsonschema:"the package this finding is in"`
	Version      string `json:"version,omitempty" jsonschema:"the version installed"`
	FixedVersion string `json:"fixedVersion,omitempty" jsonschema:"the first release that resolves it; absent means no fix is published, which is a different answer from unknown"`
	Ecosystem    string `json:"ecosystem,omitempty" jsonschema:"the package manager the name belongs to: pip, npm, gem. A name alone is ambiguous across ecosystems"`
	PURL         string `json:"purl,omitempty" jsonschema:"package URL, portable across ecosystems"`
	// Component ties a finding to the part of the system it was found in, which is what its
	// priority was computed from.
	Component string `json:"component,omitempty" jsonschema:"the component in the descriptor this finding belongs to"`
	// Image and OSEndOfLife answer "why can I not just upgrade this".
	Image       string `json:"image,omitempty" jsonschema:"the image this finding is in, when it came from one"`
	OSEndOfLife bool   `json:"osEndOfLife,omitempty" jsonschema:"the operating system release is past end of service life, so no fix will be published for it"`
}

// SummarizeOutput is the ranked answer to "what should I fix?".
type SummarizeOutput struct {
	Total int `json:"total" jsonschema:"findings the report judged, before any priority filter; excludes suppressed"`
	// Suppressed is reported rather than hidden: an assistant that cannot see a decision was
	// made cannot tell an accepted risk from one nobody has looked at.
	Suppressed int       `json:"suppressed,omitempty" jsonschema:"findings the descriptor excluded with a stated reason; reported, not ranked, and not part of total"`
	Returned   int       `json:"returned"`
	Counts     Counts    `json:"counts"`
	Findings   []Finding `json:"findings"`
	Note       string    `json:"note,omitempty"`
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
	out := SummarizeOutput{}

	findings := make([]Finding, 0, len(rep.Results))
	for _, res := range rep.Results {
		// A suppressed finding is a decision somebody recorded, not work to hand back. Counting
		// it puts an accepted risk into the answer to "what should I fix", where an assistant
		// will propose fixing something the owner signed off — and the reason they gave, which
		// is the whole content of the decision, does not travel with the number.
		if res.Suppressed() {
			out.Suppressed++
			continue
		}
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
		findings = append(findings, findingFrom(rep, res))
	}
	sortFindings(findings)

	out.Total = out.Counts.Critical + out.Counts.High + out.Counts.Medium + out.Counts.Low
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

// gatePriority reads the descriptor's priority gate, which has no flag to override it here.
func gatePriority(g *saga.GateConfig) string {
	if g == nil {
		return ""
	}
	return g.FailOnPriority
}

// findingFrom converts a result into the shape this server returns.
//
// One conversion for every tool here, so a finding an assistant reads from a diff carries the
// same fields as one it reads from a summary. Two of these would drift, and the drift would look
// like a finding losing its remediation for a reason nobody could see.
func findingFrom(rep sarif.Report, res sarif.Result) Finding {
	loc := res.Location.URI
	if loc != "" && res.Location.StartLine > 0 {
		loc = fmt.Sprintf("%s:%d", loc, res.Location.StartLine)
	}
	f := Finding{
		Priority:    res.Priority,
		Severity:    string(res.Severity("")),
		Score:       res.Score,
		RuleID:      res.RuleID,
		Scanner:     res.Tool,
		Location:    loc,
		Message:     res.Message,
		HelpURI:     rep.HelpURI(res.RuleID),
		Remediation: remediationText(rep, res),
		Action:      string(res.Remediation()),
		Component:   res.Component,
		Image:       res.Image,
		OSEndOfLife: res.OSEndOfLife,
	}
	if p := res.Package; p != nil {
		f.Package, f.Version = p.Name, p.Version
		f.FixedVersion, f.Ecosystem, f.PURL = p.FixedVersion, p.Ecosystem, p.PURL
	}
	return f
}

// remediationText returns what the scanner published about how to fix a rule.
//
// From the report rather than a lookup: scanners record their remediation in the rule, Draugr
// carries it through, and it is already on disk beside the finding. An assistant sent to a help
// URI for the same text pays a network round trip for it, and for a benchmark that URI is a
// registration form in front of a PDF — so the answer is reachable only to a reader who is not an
// assistant.
//
// Empty when it would only repeat the message, which is the common case for a scanner that gives
// no separate remediation. Repeating the finding as its own fix reads like advice and is not.
func remediationText(rep sarif.Report, res sarif.Result) string {
	rule, ok := rep.Rules[res.RuleID]
	if !ok {
		return ""
	}
	fix := strings.TrimSpace(rule.FullDescription)
	if fix == "" || fix == strings.TrimSpace(rule.ShortDescription) || fix == strings.TrimSpace(res.Message) {
		return ""
	}
	return fix
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
			ask, err := consent(req, in.Path, describeScan(reg, model, in.Path))
			if err != nil {
				return nil, ScanOutput{}, err
			}
			if ask != nil {
				// The question, not an answer: the call ends here and the client asks it, then
				// calls again carrying the reply. Returning a result rather than blocking on one
				// is what the protocol requires from 2026-07-28 — and the SDK asks on behalf of
				// clients too old to do it themselves, so this one path serves both.
				return ask, ScanOutput{}, nil
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
		// The descriptor's gate, not a fixed default. A Saga that gates licenses at critical or
		// fails on P1 says so for a reason, and an agent reporting a verdict under a policy the
		// project did not choose disagrees with the project's own CI about its own descriptor.
		verdict := norn.Policy{
			FailOn:         sarif.SeverityHigh,
			PerControl:     scanpolicy.GateThresholds(model.Config.Gate),
			FailOnPriority: gatePriority(model.Config.Gate),
		}.Evaluate(reports)

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
		// asking for the opposite. Honoring the controls, the exclusions and the gate from a
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

// consentRequestID names the one question this tool asks.
//
// The client echoes it back with the answer, so it has to be stable across the two calls and
// distinct from anything else the server might ask in future.
const consentRequestID = "draugr.scan.approve"

// consent decides whether this call may scan.
//
// Returns a result to send back while the question is unanswered, and nil once it has been
// answered with a yes. Every other outcome is an error, and every one of them means no scan: a
// declined prompt, a canceled one, a client that cannot ask, an answer that does not parse. The
// failure of consent is never a scan.
//
// Asking by returning a request rather than blocking on one is what the protocol requires from
// version 2026-07-28, which forbids a server sending `elicitation/create` while it is serving a
// request. The SDK performs the round trip for clients too old to do it themselves and re-invokes
// this handler with the answer, so both generations take this one path.
func consent(req *mcp.CallToolRequest, path, message string) (*mcp.CallToolResult, error) {
	if req == nil || req.Params == nil {
		return nil, fmt.Errorf("scan needs approval but there is nothing to ask through; " +
			"start the server with --scan=always to run scans without asking")
	}
	// Refused here rather than left to the round trip. A client that never declared elicitation
	// cannot answer this question however it is asked, and the SDK's own failure for that case —
	// "client does not support elicitation" — is meaningless to somebody who chose --scan=ask from
	// a docs page and has no idea their client does not implement it. The way out is worth naming
	// while there is still a message to name it in.
	if req.Session != nil {
		if init := req.Session.InitializeParams(); init == nil || init.Capabilities == nil ||
			init.Capabilities.Elicitation == nil {
			return nil, fmt.Errorf("scan needs your approval, but this client can't prompt for it "+
				"(no elicitation support). Run `draugr scan %s` yourself, or restart the server "+
				"with --scan=always to allow scans without asking", path)
		}
	}

	answer, answered := req.Params.InputResponses[consentRequestID]
	if !answered {
		// The description travels with the question. A prompt naming only a path asks somebody to
		// approve something it has not described, and the reader is rarely whoever wrote the file.
		//
		// The schema is not optional even when it asks for nothing: RequestedSchema has no
		// omitempty, so leaving it unset puts `"requestedSchema": null` on the wire, and a client
		// holding to the spec rejects the request — which fails --scan=ask before it can ask.
		return &mcp.CallToolResult{
			InputRequests: mcp.InputRequestMap{
				consentRequestID: &mcp.ElicitParams{
					Mode:    "form",
					Message: message,
					RequestedSchema: map[string]any{
						"type":       "object",
						"properties": map[string]any{},
					},
				},
			},
		}, nil
	}

	elicited, ok := answer.(*mcp.ElicitResult)
	if !ok {
		// An answer of the wrong shape is not a yes. Reading it as one would turn a protocol
		// mismatch into an unapproved scan, the single outcome this must never produce.
		return nil, fmt.Errorf("scan approval came back in a form Draugr does not understand "+
			"(%T); run `draugr scan %s` yourself, or start the server with --scan=always",
			answer, path)
	}
	if elicited.Action != "accept" {
		return nil, fmt.Errorf("scan declined")
	}
	return nil, nil
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

// ExplainInput asks what a rule means and how to fix it.
type ExplainInput struct {
	RuleID string `json:"ruleId" jsonschema:"the rule to explain, in full or by the part that is unambiguous: 4.3.1 finds kube-bench/cis/4.3.1"`
	Path   string `json:"path" jsonschema:"path to a results.sarif produced by draugr scan"`
}

// ExplainOutput is what the scan already recorded about a rule.
type ExplainOutput struct {
	RuleID      string   `json:"ruleId"`
	Description string   `json:"description,omitempty" jsonschema:"what the check is, in full rather than the truncated line a report shows"`
	Remediation string   `json:"remediation,omitempty" jsonschema:"how to fix it, as the scanner published it"`
	HelpURI     string   `json:"helpUri,omitempty"`
	FoundIn     []string `json:"foundIn,omitempty" jsonschema:"where this rule fired, capped"`
	Note        string   `json:"note,omitempty"`
}

// ExplainRuleTool answers what a finding means and what to change.
//
// A rule id and a truncated line is enough to rank a finding and not enough to decide anything.
// The answer is already in the report: scanners publish remediation text and Draugr records it.
// Without this an assistant is left to fetch a help URI — a network round trip for text on disk,
// and for a benchmark a registration form in front of a PDF, which is not an answer at all.
func ExplainRuleTool(_ context.Context, _ *mcp.CallToolRequest, in ExplainInput) (*mcp.CallToolResult, ExplainOutput, error) {
	if in.RuleID == "" || in.Path == "" {
		return nil, ExplainOutput{}, fmt.Errorf("ruleId and path are both required")
	}
	data, err := os.ReadFile(in.Path) //nolint:gosec // an operator-chosen path, same as the CLI takes
	if err != nil {
		return nil, ExplainOutput{}, fmt.Errorf("read report: %w", err)
	}
	rep, err := sarif.FromSARIF(data)
	if err != nil {
		return nil, ExplainOutput{}, fmt.Errorf("parse %s as SARIF: %w", in.Path, err)
	}

	id, rule, err := matchRule(rep, in.RuleID)
	if err != nil {
		return nil, ExplainOutput{}, err
	}
	out := ExplainOutput{
		RuleID:      id,
		Description: strings.TrimSpace(rule.ShortDescription),
		Remediation: strings.TrimSpace(rule.FullDescription),
		HelpURI:     rule.HelpURI,
		FoundIn:     locationsOf(rep, id),
	}
	if out.Remediation == out.Description {
		// Repeating the check as its own fix reads like advice and is not.
		out.Remediation = ""
	}
	if out.Remediation == "" {
		out.Note = "this scanner published no remediation for the rule; helpUri is where it documents it"
	}
	return nil, out, nil
}

// matchRule finds the rule a query names: exactly first, then by suffix.
//
// A reader — or an assistant relaying one — retypes the part that identifies the check rather
// than the namespace in front of it. An ambiguous abbreviation lists what it could have meant
// instead of choosing: picking one would explain a rule nobody asked about, and the caller would
// have no way to tell.
func matchRule(rep sarif.Report, query string) (string, sarif.Rule, error) {
	if rule, ok := rep.Rules[query]; ok {
		return query, rule, nil
	}
	var matched []string
	for id := range rep.Rules {
		if strings.HasSuffix(id, "/"+query) || strings.EqualFold(id, query) {
			matched = append(matched, id)
		}
	}
	sort.Strings(matched)
	switch len(matched) {
	case 0:
		return "", sarif.Rule{}, fmt.Errorf("no rule %q in this report — only rules this scan "+
			"reported are here, and the id is the one in a finding's ruleId", query)
	case 1:
		return matched[0], rep.Rules[matched[0]], nil
	default:
		return "", sarif.Rule{}, fmt.Errorf("%q matches %s — name one of them",
			query, strings.Join(matched, ", "))
	}
}

// locationsOf lists where a rule fired, deduplicated and capped.
func locationsOf(rep sarif.Report, id string) []string {
	const most = 5
	seen := map[string]bool{}
	var out []string
	total := 0
	for _, res := range rep.Results {
		if res.RuleID != id || res.Location.URI == "" || seen[res.Location.URI] {
			continue
		}
		seen[res.Location.URI] = true
		total++
		if len(out) < most {
			out = append(out, res.Location.URI)
		}
	}
	if total > most {
		out = append(out, fmt.Sprintf("and %d more", total-most))
	}
	return out
}

// FixListInput asks what to do about a report.
type FixListInput struct {
	Path  string `json:"path" jsonschema:"path to a results.sarif produced by draugr scan"`
	Limit int    `json:"limit,omitempty" jsonschema:"maximum actions to return; defaults to 20"`
}

// FixListOutput is the work a report implies, rather than the findings in it.
type FixListOutput struct {
	Actions []report.Action `json:"actions" jsonschema:"things to do, most urgent first; each says how many findings it clears"`
	Clears  int             `json:"clears" jsonschema:"findings these actions resolve between them"`
	Note    string          `json:"note,omitempty"`
}

// FixListTool answers "what should I do" with actions rather than findings.
//
// One remediation usually clears many findings: eight vulnerabilities in one library are one
// upgrade, and every package inside an image somebody else publishes is one newer image. An
// assistant handed the findings has to work that out for itself, and will do it differently each
// time — so this uses the same grouping the terminal prints, and the two cannot disagree.
func FixListTool(_ context.Context, _ *mcp.CallToolRequest, in FixListInput) (*mcp.CallToolResult, FixListOutput, error) {
	if in.Path == "" {
		return nil, FixListOutput{}, fmt.Errorf("path is required")
	}
	data, err := os.ReadFile(in.Path) //nolint:gosec // an operator-chosen path, same as the CLI takes
	if err != nil {
		return nil, FixListOutput{}, fmt.Errorf("read report: %w", err)
	}
	rep, err := sarif.FromSARIF(data)
	if err != nil {
		return nil, FixListOutput{}, fmt.Errorf("parse %s as SARIF: %w", in.Path, err)
	}

	limit := in.Limit
	if limit <= 0 {
		limit = defaultLimit
	}
	// A merged report has already lost which control each finding came from, so the grouping
	// falls back to the rule id — see ActionsFor.
	actions := report.ActionsFor(map[string]sarif.Report{"": rep})
	out := FixListOutput{}
	for _, a := range actions {
		out.Clears += a.Clears
	}
	if len(actions) > limit {
		out.Note = fmt.Sprintf(
			"showing the %d most urgent of %d actions; raise limit to see more", limit, len(actions))
		actions = actions[:limit]
	}
	out.Actions = actions
	return nil, out, nil
}

// DiffInput compares two reports.
type DiffInput struct {
	BasePath string `json:"basePath" jsonschema:"path to the results.sarif from the base revision"`
	HeadPath string `json:"headPath" jsonschema:"path to the results.sarif from the revision being proposed"`
	// FailOnNew mirrors the flag CI uses, so an assistant can ask the question the pipeline
	// will ask rather than a different one.
	FailOnNew string `json:"failOnNew,omitempty" jsonschema:"report whether a new finding at or above this severity would fail a gate: critical, high, medium or low"`
	Limit     int    `json:"limit,omitempty" jsonschema:"maximum new findings to return; defaults to 20"`
}

// DiffOutput says what a change introduced and what it resolved.
type DiffOutput struct {
	NewCount   int `json:"newCount" jsonschema:"findings present in head and absent from base"`
	FixedCount int `json:"fixedCount" jsonschema:"findings present in base and absent from head"`
	// New is what the change introduced, most urgent first, carrying the same remediation and
	// package detail a summary does.
	New []Finding `json:"new,omitempty"`
	// Fixed is named rather than only counted, because it is the half of a change worth saying
	// out loud and an assistant summarizing a diff has nothing else to praise.
	Fixed []Finding `json:"fixed,omitempty"`
	// WouldFail answers the question CI will ask, when failOnNew is given.
	WouldFail   bool   `json:"wouldFail,omitempty" jsonschema:"true when a new finding meets failOnNew; only meaningful when failOnNew was given"`
	GateApplied string `json:"gateApplied,omitempty" jsonschema:"the threshold wouldFail was computed against"`
	Note        string `json:"note,omitempty"`
}

// DiffReportsTool compares two scans and reports what the change introduced.
//
// The question in a coding session is almost never "what is wrong with this repository" — it is
// "did what I just wrote make it worse". A project with two hundred inherited findings answers the
// first question the same way before and after a change, which tells an assistant nothing about
// the change. This is the same comparison `draugr diff` makes, so the answer an assistant gives
// and the answer the pull request gate gives cannot differ.
func DiffReportsTool(_ context.Context, _ *mcp.CallToolRequest, in DiffInput) (*mcp.CallToolResult, DiffOutput, error) {
	if in.BasePath == "" || in.HeadPath == "" {
		return nil, DiffOutput{}, fmt.Errorf("basePath and headPath are both required")
	}
	base, err := readSARIF(in.BasePath)
	if err != nil {
		return nil, DiffOutput{}, err
	}
	head, err := readSARIF(in.HeadPath)
	if err != nil {
		return nil, DiffOutput{}, err
	}

	limit := in.Limit
	if limit <= 0 {
		limit = defaultLimit
	}
	res := diff.Compare(base, head)
	rules := sarif.Report{Rules: res.Rules}

	out := DiffOutput{NewCount: len(res.New), FixedCount: len(res.Fixed)}
	out.New = findingsFrom(rules, res.New, limit)
	out.Fixed = findingsFrom(rules, res.Fixed, limit)

	if in.FailOnNew != "" {
		band, err := sarif.ParseSeverity(in.FailOnNew)
		if err != nil {
			return nil, DiffOutput{}, fmt.Errorf("failOnNew: %w", err)
		}
		out.GateApplied = string(band)
		out.WouldFail = len(res.GateNew(band, "")) > 0
	}
	if len(res.New) > limit {
		out.Note = fmt.Sprintf("showing the %d most urgent of %d new findings; raise limit to see more",
			limit, len(res.New))
	}
	return nil, out, nil
}

// readSARIF loads a report, saying which path failed rather than only that one did.
func readSARIF(path string) (sarif.Report, error) {
	// #nosec G304 -- the report to read is an argument of the tool call, and a caller that can
	// reach this server can already read its own files. Refusing a path they named would make
	// every read-a-report tool useless for the case it exists for.
	data, err := os.ReadFile(path)
	if err != nil {
		return sarif.Report{}, fmt.Errorf("read %s: %w", path, err)
	}
	rep, err := sarif.FromSARIF(data)
	if err != nil {
		return sarif.Report{}, fmt.Errorf("parse %s as SARIF: %w", path, err)
	}
	return rep, nil
}

// findingsFrom converts results into the shape this server returns everywhere, capped.
func findingsFrom(rules sarif.Report, results []sarif.Result, limit int) []Finding {
	out := make([]Finding, 0, min(len(results), limit))
	for _, res := range results {
		if res.Suppressed() {
			continue
		}
		if len(out) == limit {
			break
		}
		out = append(out, findingFrom(rules, res))
	}
	return out
}

// SurveyRequest is one surveyor and what to point it at.
type SurveyRequest struct {
	Surveyor string `json:"surveyor" jsonschema:"which surveyor to run; list_surveyors names them"`
	Ref      string `json:"ref,omitempty" jsonschema:"what to survey: a Kubernetes namespace, a GitHub organization, a GitLab group, an Azure DevOps project"`
}

// SurveyInput asks one or more surveyors what is out there.
type SurveyInput struct {
	// Surveys is a list because an application is rarely one surface. The repositories in an
	// organization and the images running in a namespace are the same application described
	// twice, and merging them into one descriptor is the point — running them separately gives
	// two descriptors that each look complete.
	Surveys []SurveyRequest `json:"surveys" jsonschema:"the surveyors to run; results merge into one descriptor"`
	Name    string          `json:"name,omitempty" jsonschema:"release name for the descriptor"`
	Version string          `json:"version,omitempty" jsonschema:"release version for the descriptor; defaults to 0.0.0"`
}

// SurveyOutput is a descriptor to look at, not a file that appeared on disk.
type SurveyOutput struct {
	// Saga is the descriptor as YAML, for the caller to show, edit and write itself.
	Saga string `json:"saga" jsonschema:"the descriptor this survey produced, as YAML"`
	// Components names what was found, so a caller can say what it discovered without parsing.
	Components []string `json:"components,omitempty"`
	// Controls are the ones the discovered surface turned on.
	Controls []string `json:"controls,omitempty"`
	Note     string   `json:"note,omitempty"`
	// Warning carries what the survey could not reach. A survey that half worked and reads as
	// complete is the failure worth naming: the descriptor looks finished and is not.
	Warning string `json:"warning,omitempty"`
}

// SurveyTool discovers a surface and returns a descriptor for it.
//
// It returns the descriptor rather than writing one. A tool that writes a file is a tool that has
// to ask first, and merging into an existing descriptor carries decisions — which exposure wins,
// what a narrower scope means — that belong with the person who owns the file. Handing back YAML
// lets an assistant show it, validate it with validate_saga, and let a human decide where it goes.
//
// Writing a descriptor by hand from get_saga_schema is the alternative, and it is guesswork about
// a live system: which namespaces exist, which images are actually running, at which digest.
func SurveyTool(reg *surveyor.Registry) mcp.ToolHandlerFor[SurveyInput, SurveyOutput] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in SurveyInput) (*mcp.CallToolResult, SurveyOutput, error) {
		if len(in.Surveys) == 0 {
			return nil, SurveyOutput{}, fmt.Errorf("surveys is required — list_surveyors names them")
		}
		requests := make([]surveyor.Request, 0, len(in.Surveys))
		for _, s := range in.Surveys {
			if s.Surveyor == "" {
				return nil, SurveyOutput{}, fmt.Errorf("each survey needs a surveyor — list_surveyors names them")
			}
			requests = append(requests, surveyor.Request{
				Surveyor: s.Surveyor,
				Scope:    plugin.SurveyScope{Ref: s.Ref},
			})
		}
		out := SurveyOutput{}
		frag, err := reg.Run(ctx, requests)
		if err != nil {
			// Run returns what it did gather alongside the error, so a survey that lost one
			// source is still worth handing back — with the loss named, because a descriptor
			// that is missing half a cluster looks exactly like one for a smaller cluster.
			if len(frag.Components) == 0 {
				return nil, SurveyOutput{}, fmt.Errorf("survey: %w", err)
			}
			out.Warning = "the survey did not complete; this descriptor may be missing part of " +
				"the surface: " + err.Error()
		}

		name := in.Name
		if name == "" && len(in.Surveys) == 1 {
			name = in.Surveys[0].Ref
		}
		if name == "" {
			name = "unnamed"
		}
		version := in.Version
		if version == "" {
			version = "0.0.0"
		}
		model := saga.Model{Release: saga.Release{Name: name, Version: version}}
		surveyor.Apply(&model, frag)
		// Without this the descriptor declares images and enables nothing to look at them — a
		// scan that examines nothing and passes, which is the verdict this project is otherwise
		// careful never to produce.
		out.Controls = surfaces.EnableControls(&model)

		data, err := saga.Marshal(&model)
		if err != nil {
			return nil, SurveyOutput{}, fmt.Errorf("render descriptor: %w", err)
		}
		out.Saga = string(data)
		for _, c := range model.Components {
			out.Components = append(out.Components, c.Name)
		}
		out.Note = "not written to disk — validate it with validate_saga, then write it where the " +
			"project keeps its descriptor"
		return nil, out, nil
	}
}

// ListSurveyorsOutput names what can be discovered.
type ListSurveyorsOutput struct {
	Surveyors []SurveyorInfo `json:"surveyors"`
	Hint      string         `json:"hint"`
}

// SurveyorInfo is one surveyor and what it finds.
type SurveyorInfo struct {
	Name     string   `json:"name"`
	Provides []string `json:"provides" jsonschema:"what it discovers: repositories, images, hosts"`
}

// ListSurveyorsTool names the surveyors this build has.
//
// From the registry rather than a list written here, so a surveyor added to Draugr is reachable
// without anyone remembering to mention it in two places.
func ListSurveyorsTool(reg *surveyor.Registry) mcp.ToolHandlerFor[struct{}, ListSurveyorsOutput] {
	return func(_ context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, ListSurveyorsOutput, error) {
		out := ListSurveyorsOutput{
			Hint: "run one with survey, then validate_saga the descriptor it returns. Each reads " +
				"a live system with whatever credentials this machine already has: a kubeconfig, " +
				"GITHUB_TOKEN, GITLAB_TOKEN, AZURE_DEVOPS_EXT_PAT.",
		}
		for _, name := range reg.Names() {
			s, ok := reg.Get(name)
			if !ok {
				continue
			}
			info := SurveyorInfo{Name: name}
			for _, k := range s.Info().Provides {
				info.Provides = append(info.Provides, string(k))
			}
			out.Surveyors = append(out.Surveyors, info)
		}
		return nil, out, nil
	}
}
