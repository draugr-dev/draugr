#!/usr/bin/env bash
# Point contrib/mcpb/server.json at a release's bundle.
#
# The registry entry names a specific bundle URL and its SHA-256, so it has to be refreshed for
# each release we publish. Doing that by hand means eventually publishing a manifest whose hash
# belongs to a different build — the client would then refuse the download, which is the right
# behaviour and a miserable thing to debug.
#
# The hash is read from the release's own .mcpb.sha256, not recomputed locally, so this can't
# certify a bundle that differs from the published one.
#
# Usage: update-server-json.sh <version>      # without the leading v
set -euo pipefail

VERSION="${1:?usage: update-server-json.sh <version>}"
VERSION="${VERSION#v}"
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="draugr-dev/draugr"
FILE="$HERE/server.json"

tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
gh release download "v$VERSION" --repo "$REPO" --pattern "draugr-$VERSION.mcpb.sha256" -D "$tmp"
sha=$(cut -d' ' -f1 "$tmp/draugr-$VERSION.mcpb.sha256")
[ ${#sha} -eq 64 ] || { echo "expected a 64-character sha256, got: $sha" >&2; exit 1; }

python3 - "$FILE" "$VERSION" "$sha" "$REPO" <<'PY'
import json, sys
path, version, sha, repo = sys.argv[1:5]
doc = json.load(open(path))
doc["version"] = version
pkg = doc["packages"][0]
pkg["version"] = version
pkg["fileSha256"] = sha
pkg["identifier"] = (
    f"https://github.com/{repo}/releases/download/v{version}/draugr-{version}.mcpb"
)
open(path, "w").write(json.dumps(doc, indent=2) + "\n")
print(f"  {path} → {version}")
print(f"  {pkg['identifier']}")
print(f"  sha256 {sha}")
PY
