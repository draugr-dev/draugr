// Package mcp exposes Draugr to AI coding agents over the Model Context Protocol.
//
// The reason this exists is narrower than "agents are popular". An agent asked to check a change
// for security problems will do it one way or another: if Draugr isn't callable it improvises —
// shells out to whatever scanner it can find, picks its own scope, and reads raw tool output in
// its own context window. That improvised answer has no recorded scope, no organizational risk
// context, and no relationship to what CI will decide. Being callable is what makes the agent's
// answer and the pipeline's answer the same answer.
//
// Two design rules follow from that:
//
//   - **Read-only by default.** Scanning clones repositories, executes external tools and
//     reaches the network. An agent triggering that unprompted is a bad surprise, so `scan` is
//     registered only when the operator opts in. Everything else is safe to call freely.
//   - **Return decisions, not data.** A tool that hands back raw scanner output has moved the
//     problem into the agent's context window rather than solving it. These tools return
//     prioritized, deduplicated, normalized results — the same thing a person sees.
package mcp

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/draugr-dev/draugr/internal/version"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/surveyor"
)

// ScanMode says whether, and on what terms, a client may start a scan.
type ScanMode string

// The scan modes. A scan clones repositories, executes external tools and reaches the network,
// so the question isn't only "may it" but "who agrees to it, and when".
const (
	// ScanOff doesn't register the tool at all. The default: an assistant can't set off work
	// like that because it was curious, and the read-only tools are where the value starts.
	ScanOff ScanMode = "off"
	// ScanAsk registers it and asks the user to approve each call, through the client. This is
	// the mode to want — permission granted for the scan in front of you rather than for every
	// scan this session — but it needs a client that implements elicitation, and many don't.
	ScanAsk ScanMode = "ask"
	// ScanAlways registers it and runs without asking. Right for a sandbox or CI, where there's
	// nobody to ask.
	ScanAlways ScanMode = "always"
)

// ParseScanMode validates a mode name.
func ParseScanMode(s string) (ScanMode, error) {
	switch ScanMode(s) {
	case "", ScanOff:
		return ScanOff, nil
	case ScanAsk:
		return ScanAsk, nil
	case ScanAlways:
		return ScanAlways, nil
	}
	return "", fmt.Errorf("unknown scan mode %q (want off, ask, or always)", s)
}

// Options configures the server's exposed surface.
type Options struct {
	// Scan says whether a client may start scans. The zero value is ScanOff.
	Scan ScanMode
	// Registry supplies the controllers and scanners. Required.
	Registry *engine.Registry
	// Root is the directory searched for Saga descriptors to expose as resources. Empty means
	// the working directory.
	Root string
	// Surveyors supplies the discovery plugins. Empty disables survey and list_surveyors, so a
	// caller embedding this server chooses whether it may reach a cluster or a forge at all.
	Surveyors *surveyor.Registry
}

// serverName is how Draugr identifies itself to a client.
const serverName = "draugr"

// iconURL is the mark a client shows beside the server. Served from draugr.dev rather than
// embedded as a data URI: the icon is cosmetic, and inlining base64 into every initialize
// response to save one cacheable request is the wrong trade. The domain matters — clients are
// told to check an icon comes from the same origin as the server, and draugr.dev is what the
// dev.draugr namespace authenticates against.
const iconURL = "https://draugr.dev/brand/draugr-mark.png"

// NewServer builds the MCP server. Tools are registered here rather than discovered so the
// exposed surface is a deliberate, reviewable list.
func NewServer(opts Options) (*mcp.Server, error) {
	if opts.Registry == nil {
		return nil, fmt.Errorf("mcp: registry is required")
	}
	// Normalize before anything reads it. The zero value has to mean off, or a caller that
	// builds Options without naming a mode silently gets scanning — the one default that must
	// never happen by accident.
	mode, err := ParseScanMode(string(opts.Scan))
	if err != nil {
		return nil, err
	}
	opts.Scan = mode
	s := mcp.NewServer(&mcp.Implementation{
		Name:    serverName,
		Version: version.Version,
		Icons: []mcp.Icon{{
			Source:   iconURL,
			MIMEType: "image/png",
			Sizes:    []string{"512x512"},
		}},
	}, &mcp.ServerOptions{
		Instructions: instructions(opts.Scan),
	})

	root := opts.Root
	if root == "" {
		wd, err := os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("mcp: resolve working directory: %w", err)
		}
		root = wd
	}
	// Descriptor discovery is best-effort. A server that refuses to start because one directory
	// was unreadable is worse than one that advertises fewer resources.
	if err := addSagaResources(s, root); err != nil {
		slog.Warn("mcp: could not scan for Saga descriptors", "root", root, "error", err)
	}

	reg := opts.Registry

	mcp.AddTool(s, &mcp.Tool{
		Name: "list_controls",
		Description: "List the security controls Draugr can run: what each one checks, which " +
			"scanner backs it, and whether it applies per component or to the whole project. " +
			"Call this before writing or editing a Saga descriptor, so the controls you enable " +
			"are ones that exist.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, _ EmptyInput) (*mcp.CallToolResult, ControlsOutput, error) {
		return nil, ListControls(reg), nil
	})

	mcp.AddTool(s, &mcp.Tool{
		Name: "get_saga_schema",
		Description: "Return the JSON Schema for the Saga descriptor (*.saga.yaml) that this " +
			"build of Draugr enforces. Use it to write or correct a descriptor rather than " +
			"guessing at field names — the schema is the authority, and it rejects unknown keys.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, _ EmptyInput) (*mcp.CallToolResult, SchemaOutput, error) {
		out, err := GetSchema()
		return nil, out, err
	})

	mcp.AddTool(s, &mcp.Tool{
		Name: "validate_saga",
		Description: "Check a Saga descriptor against the schema and report what's wrong. " +
			"Give either a path on disk or the YAML content directly. Validating is free and " +
			"has no side effects, so prefer it over assuming an edit was correct.",
	}, ValidateSagaTool)

	mcp.AddTool(s, &mcp.Tool{
		Name: "check_tools",
		Description: "Report which external scanners Draugr can find on this machine, and what " +
			"to run if any are missing. Call this when a scan fails or before suggesting one: a " +
			"control whose scanner is absent cannot run, and Draugr reports that as a failure " +
			"rather than a pass. This only looks — it will not install anything.",
	}, CheckToolsTool)

	mcp.AddTool(s, &mcp.Tool{
		Name: "explain_rule",
		Description: "Explain what a finding means and how to fix it, from the scan's own " +
			"report. Returns the check in full and the remediation the scanner published. " +
			"Prefer this over fetching a rule's help URI: the answer is already on disk, and " +
			"for a benchmark that URI is often a registration form in front of a PDF.",
	}, ExplainRuleTool)
	mcp.AddTool(s, &mcp.Tool{
		Name: "fix_list",
		Description: "Turn a report into the things to do about it, most urgent first, each " +
			"saying how many findings it clears. Ask this rather than summarize_report when " +
			"the question is what to change: one upgrade usually clears many findings, and an " +
			"image somebody else publishes is one action however many packages are wrong " +
			"inside it.",
	}, FixListTool)
	if opts.Surveyors != nil {
		mcp.AddTool(s, &mcp.Tool{
			Name: "list_surveyors",
			Description: "Name the surveyors this build has and what each discovers. Call it " +
				"before survey, so the surveyor you ask for is one that exists.",
		}, ListSurveyorsTool(opts.Surveyors))
		mcp.AddTool(s, &mcp.Tool{
			Name: "survey",
			Description: "Discover what an application is made of — the images running in a " +
				"Kubernetes namespace, the repositories in an organization — and return a Saga " +
				"descriptor for it. Prefer this over writing a descriptor from the schema: " +
				"which namespaces exist and which images are actually running, at which digest, " +
				"is not something to guess at. It reads a live system with credentials this " +
				"machine already has, and returns YAML rather than writing a file.",
		}, SurveyTool(opts.Surveyors))
	}

	mcp.AddTool(s, &mcp.Tool{
		Name: "diff_reports",
		Description: "Compare two scans and report what a change introduced and what it " +
			"resolved. Ask this rather than summarize_report when the question is whether a " +
			"change made things worse: a project with inherited findings answers 'what is " +
			"wrong' the same way before and after, which says nothing about the change. Give " +
			"failOnNew to learn whether a pull request gate would fail.",
	}, DiffReportsTool)
	mcp.AddTool(s, &mcp.Tool{
		Name: "summarize_report",
		Description: "Read an existing Draugr report (results.sarif or report.json) and return " +
			"its findings ranked by priority, deduplicated, with the rule documentation link " +
			"for each. This is the cheap way to answer 'what should I fix first?' — it reads a " +
			"scan that already happened rather than starting a new one. It covers the controls " +
			"that scan ran and nothing else, so treat it as a floor to build on rather than a " +
			"complete account of a codebase's security.",
	}, SummarizeReportTool)

	if opts.Scan != ScanOff {
		// The description states what the scan does not cover, because a tool description is the
		// only place a caller learns the scope before deciding the question is settled.
		//
		// A verdict is a complete-looking result, and a complete-looking result is read as the
		// answer to whatever prompted it. The prompt is usually "is this safe to ship"; the scan
		// answers "do the declared controls, over the declared components, produce findings above
		// the gate". Those overlap without being the same, and the gap is exactly the classes no
		// scanner computes — trust boundaries, credential handling, build-context hygiene. An
		// assistant that stops at the verdict skips them, having done nothing wrong.
		//
		// So the description names the boundary. Nothing here weakens the claim: reproducibility,
		// ranking and a gate are things a one-off read cannot give. It says which question was
		// answered, so the caller can go on to the others.
		desc := "Run a scan for a Saga descriptor and return the verdict with findings " +
			"ranked by priority. This is expensive and has side effects: it clones " +
			"repositories, executes external scanners and reaches the network. Prefer " +
			"summarize_report when a recent report already exists.\n\n" +
			"Scope: this runs the controls the descriptor declares over the components it " +
			"declares, and nothing else. It is a reproducible floor, not a substitute for " +
			"reading the code. It does not reason about trust boundaries, whether a build " +
			"context carries secrets into an image, how credentials are passed to subprocesses, " +
			"protocol assumptions, or anything a control was not enabled for. If the question " +
			"was whether a repository is safe to ship rather than whether it passes this gate, " +
			"keep looking after this returns — the findings here are the part that can be " +
			"checked the same way every time, not the whole answer."
		if opts.Scan == ScanAsk {
			desc += " Each call asks the user to approve it first."
		}
		mcp.AddTool(s, &mcp.Tool{Name: "scan", Description: desc}, scanTool(reg, opts.Scan))
	}
	return s, nil
}

// instructions tells a client what this server is for. Clients surface it to the model, so it's
// worth saying what Draugr adds over the model running scanners itself.
func instructions(mode ScanMode) string {
	s := "Draugr answers security questions about a codebase from its Saga descriptor — a " +
		"committed, reviewed declaration of what the application is and which controls apply.\n\n" +
		"Prefer these tools over running scanners yourself. Draugr's findings are deduplicated " +
		"across tools, normalized to one schema, and ranked by priority (P1–P4) using the " +
		"component's declared exposure and criticality — organizational context that isn't " +
		"inferable from source code. Scanner output read directly has none of that, and costs " +
		"far more context to read.\n\n" +
		"This server only reads. If check_tools reports something missing, give the user the " +
		"command it returns — do not try to make the server install it, and don't quietly work " +
		"around a missing scanner by running one yourself: the point is that the descriptor " +
		"decides what gets checked.\n\n" +
		"The Saga is the scope. If a descriptor exists, trust it over your own guess at what " +
		"should be scanned; if one doesn't, get_saga_schema and list_controls are what you need " +
		"to write one."
	switch mode {
	case ScanOff:
		s += "\n\nScanning is not enabled on this server, so these tools only read. To run a " +
			"scan, the user must restart Draugr with `draugr mcp --scan=ask`, or run " +
			"`draugr scan` themselves."
	case ScanAsk:
		s += "\n\nThe scan tool asks the user to approve each call, because a scan clones " +
			"repositories and runs external tools. Expect a pause, and don't call it " +
			"speculatively."
	case ScanAlways:
	}
	return s
}
