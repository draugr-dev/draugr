# Plugin evals

Prompts a user would type, answered by a model with the plugin loaded and this checkout's
`draugr mcp` behind it. Each case is graded on the tools the model called and on what it told the
user.

Run the cases a change affects when it could change what a tool returns or how a model uses it: a
change to `internal/mcp/`, `internal/cli/mcp.go`, this plugin, or the report output those tools
read. A reworded tool description can change what the model does while every Go test still passes.

Each case directory holds:

- `prompt.md`, the user's message, with the turn limit and the tools allowed.
- `scaffold.sh`, which builds the workspace from `fixture.sh`: the `monorepo-paths` integration
  scenario, two services declared as two components, scanned with `secrets` and `sast` only.
- `graders/`, one file per check: `tool_used` for a tool the model has to call, `regex` for text
  the trace or the workspace must or must not contain, and `llm` for a judgment a pattern cannot
  make.

## Running it

It needs `claude` (Claude Code), `gitleaks` and `semgrep` on `PATH`.

The cases run locally, each as a Claude Code session under the login `claude` is signed in with.
Sign `claude` in to a claude.ai plan and leave `ANTHROPIC_API_KEY` unset. Run it from a plain shell
rather than from inside a Claude Code session, or unset `CLAUDECODE` and the `CLAUDE_CODE_*`
variables first.

Run one case at a time, named by its directory under `evals/`, with one run:

```bash
make build
cd contrib/claude-plugin
KUBECONFIG=/nonexistent/kubeconfig \
PATH="$(git rev-parse --show-toplevel)/bin:$HOME/.draugr/bin:$PATH" claude plugin eval . \
  --case <name> --runs 1 \
  --trust-plugin --scaffold --mocks off \
  --allow-tools "mcp__plugin_draugr_draugr__*" Write \
  --ablation none --model claude-sonnet-5-5 --judge-model claude-haiku-5-5 \
  --threshold 0.8 --max-cost-usd 3 --no-publish
```

`KUBECONFIG` names a file that does not exist, so survey-no-cluster finds no cluster whatever this
machine is configured for. Results go to `evals/results/`, which is ignored.

An `llm` grader is read by a smaller model than the one being graded. State what a PASS contains as
conditions it can check one by one; a criterion written as a double negative is the one that judge
misreads. The judge reads the final reply unless the grader sets `focus: trace`, which a case needs
when the model may make the fix with `Write` and report it in one line.
