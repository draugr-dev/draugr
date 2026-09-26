# Plugin evals

Prompts a user would type, answered by a model with the plugin loaded and this checkout's
`draugr mcp` behind it. Each case is graded on the tools the model called and on what it told the
user. The `Evals` workflow runs the suite on a pull request that changes `internal/mcp/`,
`internal/cli/mcp.go` or this plugin.

Each case directory holds:

- `prompt.md`, the user's message, with the turn limit and the tools allowed.
- `scaffold.sh`, which builds the workspace from `fixture.sh`: the `monorepo-paths` integration
  scenario, two services declared as two components, scanned with `secrets` and `sast` only.
- `graders/`, one file per check: `tool_used` for a tool the model has to call, `regex` for text
  the trace or the workspace must or must not contain, and `llm` for a judgment a pattern cannot
  make.

## Running it

It needs `claude` (Claude Code), `gitleaks` and `semgrep` on `PATH`, and an Anthropic API key.
Every run is billed to that key.

```bash
make build
cd contrib/claude-plugin
export ANTHROPIC_API_KEY=...
PATH="$PWD/../../bin:$HOME/.draugr/bin:$PATH" claude plugin eval . \
  --trust-plugin --scaffold --mocks off \
  --allow-tools "mcp__plugin_draugr_draugr__*" Write \
  --ablation none --model claude-sonnet-5 --judge-model claude-haiku-4-5 \
  --threshold 0.8 --runs 1 --max-cost-usd 2 --no-publish
```

`--case <name>` runs one case. One run per case costs about US$0.65 for the suite; `--runs 3`, the
default, about US$3.20. Results go to `evals/results/`, which is ignored.

An `llm` grader is read by a smaller model than the one being graded. State what a PASS contains as
conditions it can check one by one; a criterion written as a double negative is the one that judge
misreads.
