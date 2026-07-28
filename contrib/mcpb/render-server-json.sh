#!/usr/bin/env bash
# Render server.json for a released version, ready for `mcp-publisher publish`.
#
# server.json.tmpl is the committed source: everything a human decides — the namespace, the
# description, the icon — lives there. Three fields are derived from the release and are
# placeholders in the template, because a committed copy of them is a copy that goes stale the
# moment the next version ships, and a stale hash is a download the client correctly refuses.
#
# The hash is read from the release's own .mcpb.sha256 rather than recomputed locally, so this
# cannot certify a bundle that differs from the one people download.
#
# Usage: render-server-json.sh <version> [output]      # version without the leading v
set -euo pipefail

VERSION="${1:?usage: render-server-json.sh <version> [output]}"
VERSION="${VERSION#v}"
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="${2:-$HERE/server.json}"
REPO="draugr-dev/draugr"

tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
gh release download "v$VERSION" --repo "$REPO" --pattern "draugr-$VERSION.mcpb.sha256" -D "$tmp"
sha=$(cut -d' ' -f1 "$tmp/draugr-$VERSION.mcpb.sha256")
[ ${#sha} -eq 64 ] || { echo "expected a 64-character sha256, got: $sha" >&2; exit 1; }

python3 - "$HERE/server.json.tmpl" "$OUT" "$VERSION" "$sha" <<'PY'
import json, sys
tmpl, out, version, sha = sys.argv[1:5]
text = open(tmpl).read().replace("__VERSION__", version).replace("__SHA256__", sha)
doc = json.loads(text)  # fail here rather than handing the registry a broken document
if "__" in json.dumps(doc):
    raise SystemExit("unsubstituted placeholder left in server.json")
open(out, "w").write(json.dumps(doc, indent=2) + "\n")
print(f"  {out}")
print(f"  {doc['packages'][0]['identifier']}")
print(f"  sha256 {sha}")
PY
