#!/usr/bin/env bash
# Build the MCP Bundle (.mcpb) for a published release.
#
# An .mcpb is a zip holding a manifest and the server itself, so a client can install a local
# MCP server in one step. It's also the only packaging the MCP Registry accepts for something
# distributed as a native binary — npm, PyPI, Cargo and NuGet don't apply, and an OCI image
# would be worse than useless here: `check_tools` would report the *container's* scanners rather
# than the user's, and file paths wouldn't match the host.
#
# One bundle covers every platform, because it has to. The registry's package schema has no
# os/arch fields, so it cannot route a client to the right build — the bundle must contain them
# all and choose at launch via the manifest's platform_overrides. That keys on OS but not
# architecture, hence the macOS universal binary: it's the only way a single manifest entry
# serves both Apple silicon and Intel.
#
# Usage: build.sh <version> [output-dir]      # version without the leading v
set -euo pipefail

VERSION="${1:?usage: build.sh <version> [output-dir]}"
VERSION="${VERSION#v}"
OUT="${2:-$PWD}"
REPO="draugr-dev/draugr"
HERE="$(cd "$(dirname "$0")" && pwd)"

for c in gh zip python3; do command -v "$c" >/dev/null || { echo "$c is required" >&2; exit 1; }; done

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bundle/server"

echo "▶ fetching draugr $VERSION release archives"
for a in linux_amd64 darwin_amd64 darwin_arm64 windows_amd64; do
  gh release download "v$VERSION" --repo "$REPO" --pattern "draugr_${VERSION}_${a}.*" -D "$work" >/dev/null
done

tar -xzf "$work/draugr_${VERSION}_linux_amd64.tar.gz"  -C "$work" draugr
mv "$work/draugr" "$work/bundle/server/draugr-linux-amd64"
unzip -qo "$work/draugr_${VERSION}_windows_amd64.zip" draugr.exe -d "$work"
mv "$work/draugr.exe" "$work/bundle/server/draugr.exe"

echo "▶ building the macOS universal binary"
tar -xzf "$work/draugr_${VERSION}_darwin_amd64.tar.gz" -C "$work" draugr && mv "$work/draugr" "$work/amd64"
tar -xzf "$work/draugr_${VERSION}_darwin_arm64.tar.gz" -C "$work" draugr && mv "$work/draugr" "$work/arm64"
python3 "$HERE/lipo.py" "$work/amd64" "$work/arm64" "$work/bundle/server/draugr-darwin"
chmod +x "$work/bundle/server/"*

# Ask the binary what it serves rather than maintaining a list beside it. A hand-written
# manifest drifts the moment a tool is added — this bundle's own prototype shipped a manifest
# advertising five tools against a binary that served four. It doubles as a smoke test: a
# binary that can't start can't answer, and the build stops here.
echo "▶ reading the tool list from the binary"
tools=$(
  {
    printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"mcpb-build","version":"1"}}}'
    printf '%s\n' '{"jsonrpc":"2.0","method":"notifications/initialized"}'
    printf '%s\n' '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
    sleep 2
  } | "$work/bundle/server/draugr-linux-amd64" mcp 2>/dev/null | python3 -c '
import json, sys
for line in sys.stdin:
    msg = json.loads(line)
    if msg.get("id") == 2:
        tools = [{"name": t["name"], "description": t["description"].split(".")[0] + "."}
                 for t in msg["result"]["tools"]]
        print(json.dumps(sorted(tools, key=lambda t: t["name"]), indent=4))
        break
else:
    raise SystemExit("the server did not answer tools/list")
'
)
[ -n "$tools" ] || { echo "could not read the tool list from the binary" >&2; exit 1; }
echo "  $(python3 -c "import json,sys; print(', '.join(t['name'] for t in json.loads(sys.argv[1])))" "$tools")"

# Copied in rather than referenced by URL: a bundle a client installed months ago should still
# have its icon, and an .mcpb is meant to be self-contained.
cp "$HERE/icon.png" "$work/bundle/icon.png"

echo "▶ writing the manifest"
python3 - "$HERE/manifest.json.tmpl" "$VERSION" "$tools" > "$work/bundle/manifest.json" <<'PYEOF'
import json, sys
tmpl, version, tools = sys.argv[1], sys.argv[2], sys.argv[3]
text = open(tmpl).read().replace("__VERSION__", version).replace("__TOOLS__", tools)
json.dumps(json.loads(text))          # fail here rather than shipping a broken manifest
print(text, end="")
PYEOF

bundle="$OUT/draugr-$VERSION.mcpb"
(cd "$work/bundle" && zip -qr "$bundle" .)

# The registry records a SHA-256 per package, and a client verifies the download against it.
sha=$(sha256sum "$bundle" | cut -d' ' -f1)
printf '%s  %s\n' "$sha" "$(basename "$bundle")" > "$bundle.sha256"

printf '\n  %s\n  %s bytes\n  sha256 %s\n\n' "$bundle" "$(stat -c%s "$bundle")" "$sha"
