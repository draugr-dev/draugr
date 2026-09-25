#!/usr/bin/env bash
# Set the Claude Code plugin's version to a release's.
#
# Claude Code gives a user a new copy of an installed plugin only when the `version` in its
# plugin.json changes, and it reads that file from the repository tree the marketplace points
# at. So the version is committed, unlike the MCP Registry entry and the .mcpb manifest, which
# are rendered from templates when the release publishes and never land in the tree. The release
# pull request is the one commit that carries a new version into main, and `Release prepare`
# runs this beside `changelog.sh promote` so the tag it produces holds both.
#
# Only plugin.json carries the version. Claude Code prefers it over the marketplace entry's
# without a warning, so a second copy there would be a value nobody reads until it disagrees.
#
# Usage: set-plugin-version.sh <version> [plugin.json]     # version without the leading v
set -euo pipefail

VERSION="${1:?usage: set-plugin-version.sh <version> [plugin.json]}"
VERSION="${VERSION#v}"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "set-plugin-version: '$VERSION' is not X.Y.Z" >&2; exit 1; }
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FILE="${2:-$ROOT/contrib/claude-plugin/.claude-plugin/plugin.json}"

python3 - "$FILE" "$VERSION" <<'PY'
import json, sys
path, version = sys.argv[1:3]
with open(path) as f:
    doc = json.load(f)
if "version" not in doc:
    raise SystemExit(f"set-plugin-version: {path} has no version field to set")
doc["version"] = version
with open(path, "w") as f:
    f.write(json.dumps(doc, indent=2) + "\n")
print(f"set-plugin-version: {path} -> {version}")
PY
