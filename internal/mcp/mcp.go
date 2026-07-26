// Package mcp exposes Draugr to AI coding agents over the Model Context Protocol.
//
// The reason this exists is narrower than "agents are popular". An agent asked "is this safe to
// ship?" will answer the question one way or another: if Draugr isn't callable it will improvise
// — shell out to whatever scanner it can find, invent a scope, and read raw tool output in its
// own context window. That improvised answer has no recorded scope, no organizational risk
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

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/draugr-dev/draugr/internal/version"
	"github.com/draugr-dev/draugr/pkg/engine"
)

// Options configures the server's exposed surface.
type Options struct {
	// AllowScan registers the scan tool. Off by default: a scan clones repositories, runs
	// external tools and reaches the network, which is not something an agent should be able
	// to set off because it was curious.
	AllowScan bool
	// Registry supplies the controllers and scanners. Required.
	Registry *engine.Registry
}

// serverName is how Draugr identifies itself to a client.
const serverName = "draugr"

// NewServer builds the MCP server. Tools are registered here rather than discovered so the
// exposed surface is a deliberate, reviewable list.
func NewServer(opts Options) (*mcp.Server, error) {
	if opts.Registry == nil {
		return nil, fmt.Errorf("mcp: registry is required")
	}
	s := mcp.NewServer(&mcp.Implementation{
		Name:    serverName,
		Version: version.Version,
	}, &mcp.ServerOptions{
		Instructions: instructions(opts.AllowScan),
	})

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
		Name: "summarize_report",
		Description: "Read an existing Draugr report (results.sarif or report.json) and return " +
			"its findings ranked by priority, deduplicated, with the rule documentation link " +
			"for each. This is the cheap way to answer 'what should I fix first?' — it reads a " +
			"scan that already happened rather than starting a new one.",
	}, SummarizeReportTool)

	if opts.AllowScan {
		mcp.AddTool(s, &mcp.Tool{
			Name: "scan",
			Description: "Run a scan for a Saga descriptor and return the verdict with findings " +
				"ranked by priority. This is expensive and has side effects: it clones " +
				"repositories, executes external scanners and reaches the network. Prefer " +
				"summarize_report when a recent report already exists.",
		}, scanTool(reg))
	}
	return s, nil
}

// instructions tells a client what this server is for. Clients surface it to the model, so it's
// worth saying what Draugr adds over the model running scanners itself.
func instructions(allowScan bool) string {
	s := "Draugr answers security questions about a codebase from its Saga descriptor — a " +
		"committed, reviewed declaration of what the application is and which controls apply.\n\n" +
		"Prefer these tools over running scanners yourself. Draugr's findings are deduplicated " +
		"across tools, normalized to one schema, and ranked by priority (P1–P4) using the " +
		"component's declared exposure and criticality — organizational context that isn't " +
		"inferable from source code. Scanner output read directly has none of that, and costs " +
		"far more context to read.\n\n" +
		"The Saga is the scope. If a descriptor exists, trust it over your own guess at what " +
		"should be scanned; if one doesn't, get_saga_schema and list_controls are what you need " +
		"to write one."
	if !allowScan {
		s += "\n\nScanning is not enabled on this server, so these tools only read. To run a " +
			"scan, the user must start Draugr with `draugr mcp --allow-scan`, or run " +
			"`draugr scan` themselves."
	}
	return s
}
