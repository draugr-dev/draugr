#!/bin/sh
# SessionStart hook for the Draugr plugin.
#
# The plugin registers draugr mcp as an MCP server and does not carry the binary. Without
# draugr on PATH the server fails to start, and the only trace is a failed entry in /mcp that
# nobody is prompted to open. This hook names the missing binary and the page that installs it,
# once per fresh context, and prints nothing when draugr is present.
#
# It names the page rather than an install command: a command that downloads a script and runs it
# is shown to plugin users as an install-time risk, and the page carries that command beside the
# signature check and every other method.
#
# The output is a JSON object. systemMessage is shown to the user, and additionalContext
# tells Claude why the Draugr tools are absent so it does not look for them or improvise a scan.
# Both strings are fixed, so no value needs escaping, and printf is a shell builtin, so the
# hook runs with nothing on PATH but the shell.

if command -v draugr >/dev/null 2>&1; then
	exit 0
fi

printf '%s\n' '{
  "systemMessage": "The Draugr MCP server cannot start because the draugr binary is not on PATH.\nInstall it from https://draugr.dev/docs/latest/getting-started/install/, then restart Claude Code.",
  "hookSpecificOutput": {
    "hookEventName": "SessionStart",
    "additionalContext": "The Draugr plugin is enabled, and the draugr binary is not on PATH, so the Draugr MCP server and its tools are unavailable in this session. When the user asks for Draugr or a security scan, tell them to install Draugr from https://draugr.dev/docs/latest/getting-started/install/ and to restart Claude Code afterward."
  }
}'
