package mcp

import (
	"context"
	"strings"
	"time"

	"github.com/draugr-dev/draugr/internal/version"

	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/norn"
	"github.com/draugr-dev/draugr/pkg/publish"
	"github.com/draugr-dev/draugr/pkg/report"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// deliver runs the descriptor's reports and publishers, and names where each one put the result.
//
// The names are what makes this useful to a caller rather than merely correct. An assistant that
// knows a SARIF file exists can point the user at it, or read it back with summarize_report
// instead of paying for another scan — which is the whole reason the cheap tool exists.
//
// A publisher whose destination is decided by the environment (a code-scanning upload, a
// pull-request comment) is named by kind alone. Guessing at a URL from environment variables that
// may not be set would state something Draugr has not checked.
func deliver(
	ctx context.Context,
	model *saga.Model,
	run engine.Result,
	verdict norn.Result,
	minPriority string,
) ([]string, error) {
	if len(model.Config.Publishers) == 0 {
		return nil, nil
	}
	data := report.Data{
		// The same two the CLI sets. Left off, a report delivered through an assistant names no
		// project and publishes a VEX document with no product — the descriptor said both.
		Project:      model.ProjectName(),
		Publishes:    model.Publishes,
		Release:      model.Release,
		Run:          run,
		Verdict:      verdict,
		MinPriority:  minPriority,
		Repositories: report.RepositoriesFrom(run),
		VEX:          model.Config.VEX,
		// Stamped for the same reason the CLI stamps it: a report offered as evidence has to say
		// when it ran and what produced it.
		Generated: time.Now(),
		Version:   reportVersion(),
	}
	if err := publish.Run(ctx, model.Config.Reports, model.Config.Publishers, data); err != nil {
		return nil, err
	}
	return deliveryLines(model), nil
}

// reportVersion stamps the build into a published report, matching what `draugr scan` writes so
// a report delivered through MCP and one delivered from the CLI cannot be told apart by it.
func reportVersion() string {
	if version.Version == "" || version.Version == "dev" {
		return "(development build)"
	}
	return "v" + strings.TrimPrefix(version.Version, "v")
}
