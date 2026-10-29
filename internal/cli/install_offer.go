package cli

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/draugr-dev/draugr/internal/english"
	"github.com/draugr-dev/draugr/internal/needs"
	"github.com/draugr-dev/draugr/internal/netpolicy"
	"github.com/draugr-dev/draugr/internal/tools"
	"github.com/draugr-dev/draugr/pkg/config"
	"github.com/draugr-dev/draugr/pkg/engine"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/tui"
)

// installOffer asks, before a scan, whether to install the scanners it is missing.
//
// Only of somebody at a terminal: stdin, stdout and stderr all interactive. A pipeline, an
// assistant driving the CLI and a redirected report get the scan as it was, which ends by naming
// the command that installs what was missing. Asking is the whole of the consent, so nothing is
// downloaded on any answer but yes.
type installOffer struct {
	in  io.Reader
	out io.Writer
	// terminal reports whether a person is there to answer.
	terminal func() bool
	lookPath func(string) (string, error)
	install  func(ctx context.Context, name, version string) (tools.Installed, error)
	// remember writes output.offerInstall: false where the next scan reads it, and returns the path
	// and the command that undoes it.
	remember func() (path, undo string, err error)
}

// defaultInstallOffer is the offer as a scan makes it.
func defaultInstallOffer() installOffer {
	return installOffer{
		in:  os.Stdin,
		out: os.Stderr,
		terminal: func() bool {
			return isTTY(os.Stdin) && tui.IsTerminal(os.Stdout) && tui.IsTerminal(os.Stderr)
		},
		lookPath: exec.LookPath,
		install: func(ctx context.Context, name, version string) (tools.Installed, error) {
			dir, err := tools.BinDir()
			if err != nil {
				return tools.Installed{}, err
			}
			return tools.InstallVersion(ctx, name, version, dir, nil, false)
		},
		remember: rememberNoInstallOffer,
	}
}

// missingScanner is a scanner this scan would run that is not on PATH, with the controls it blocks.
type missingScanner struct {
	tool     string
	controls []string
}

// missingForScan lists the tools `draugr tools install` fetches that this scan needs and cannot
// find, in name order, each with the controls it would leave unrun.
func missingForScan(reg *engine.Registry, model *saga.Model, scope engine.Scope, lookPath func(string) (string, error)) []missingScanner {
	inScope := func(control string) bool {
		if len(scope.Controls) == 0 {
			return true
		}
		for _, c := range scope.Controls {
			if c == control {
				return true
			}
		}
		return false
	}
	byTool := map[string][]string{}
	for _, u := range needs.Uses(reg, model) {
		var controls []string
		for _, c := range u.Controls {
			if inScope(c) {
				controls = append(controls, c)
			}
		}
		if len(controls) == 0 {
			continue
		}
		for _, tool := range append([]string{u.Info.Binary}, u.Info.AlsoRequires...) {
			if tool == "" || !tools.Provisionable(tool) {
				continue
			}
			if _, err := lookPath(tool); err == nil {
				continue
			}
			for _, c := range controls {
				byTool[tool] = appendUnique(byTool[tool], c)
			}
		}
	}
	out := make([]missingScanner, 0, len(byTool))
	for tool, controls := range byTool {
		sort.Strings(controls)
		out = append(out, missingScanner{tool: tool, controls: controls})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].tool < out[j].tool })
	return out
}

// run makes the offer and acts on the answer. It never fails the scan: an install that goes wrong
// is reported, and the scan then says which controls it could not run.
func (o installOffer) run(ctx context.Context, reg *engine.Registry, model *saga.Model, scope engine.Scope, cfg config.File) {
	if !cfg.Output.Offers() || netpolicy.Offline() || !o.terminal() {
		return
	}
	missing := missingForScan(reg, model, scope, o.lookPath)
	if len(missing) == 0 {
		return
	}
	var names, controls []string
	for _, m := range missing {
		names = append(names, m.tool)
		for _, c := range m.controls {
			controls = appendUnique(controls, c)
		}
	}
	sort.Strings(controls)

	col := tui.For(o.out)
	cmd := "draugr tools install " + strings.Join(names, " ")
	_, _ = fmt.Fprintf(o.out, "%s %s not installed, so %s would not run.\n",
		english.And(names), english.Choose(len(names), "is", "are"), english.And(controls))
	_, _ = fmt.Fprintf(o.out, "Install %s now with %s? [Y/n/never] ",
		english.Choose(len(names), "it", "them"), col.Paint(tui.StyleAccent, cmd))

	reply, answered := answer(o.in)
	if !answered {
		// Input closed before a line was entered, Ctrl-D or an empty pipe: no answer, so no.
		reply = "n"
	}
	switch reply {
	case "", "y", "yes":
		_, _ = fmt.Fprintln(o.out)
		for _, name := range names {
			res, err := o.install(ctx, name, cfg.Tools[name].Version)
			if err != nil {
				_, _ = fmt.Fprintf(o.out, "%s %s: %v\n", col.Paint(tui.StyleFail, "✗"), name, err)
				continue
			}
			_, _ = fmt.Fprintf(o.out, "%s %s %s → %s %s\n", col.Paint(tui.StylePass, "✓"), res.Name,
				res.Version, res.Path, col.Paint(tui.StyleMuted, "("+provenanceLabel(res)+")"))
		}
	case "never":
		path, undo, err := o.remember()
		if err != nil {
			_, _ = fmt.Fprintf(o.out, "%s could not write output.offerInstall: false: %v. The scan continues.\n",
				col.Paint(tui.StyleFail, "✗"), err)
			break
		}
		_, _ = fmt.Fprintf(o.out, "Wrote output.offerInstall: false to %s. %s asks again.\n",
			shortHome(path), col.Paint(tui.StyleAccent, undo))
	}
	_, _ = fmt.Fprintln(o.out)
}

// answer reads one line and returns it trimmed and lowercased, and whether a line was entered at
// all. Enter alone is an answer, the default; input that ends first is not.
func answer(in io.Reader) (string, bool) {
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && strings.TrimSpace(line) == "" {
		return "", false
	}
	return strings.ToLower(strings.TrimSpace(line)), true
}

// rememberNoInstallOffer writes output.offerInstall: false to the file a scan reads it from: the
// one --config or DRAUGR_CONFIG names, or else ~/.draugr/config.yaml. Never the project's
// draugr.config.yaml, which is committed: one person declining is not a decision for the team.
func rememberNoInstallOffer() (path, undo string, err error) {
	if explicit := config.Explicit(rootConfigPath); explicit != "" {
		// Named on the command, because DRAUGR_CONFIG may not be set where the reader types it and
		// a bare unset would edit the project's file instead.
		path, undo = explicit, "`draugr config unset --config "+explicit+" output.offerInstall`"
	} else {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", "", err
		}
		path, undo = filepath.Join(home, ".draugr", "config.yaml"), "`draugr config unset --global output.offerInstall`"
	}
	err = editConfigAt(path, func(doc []byte) ([]byte, error) {
		return config.Set(doc, "output.offerInstall", "false")
	})
	return path, undo, err
}
