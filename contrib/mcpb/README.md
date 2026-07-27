# MCP Bundle

`draugr-<version>.mcpb` — a zip holding a manifest and the Draugr binary, so an MCP client can
install a local server in one step. Attached to every release by `.github/workflows/release.yml`.

## Why this format

The [MCP Registry](https://registry.modelcontextprotocol.io) only accepts packages from npm,
PyPI, NuGet, Cargo, OCI or MCPB. Draugr is a Go binary, so of those only MCPB fits — and it's a
better fit than it first appears, because an OCI image would be actively wrong here:
`check_tools` would report the *container's* scanners rather than the user's, and file paths in
`validate_saga` and `summarize_report` wouldn't match the host.

## Why one bundle for every platform

The registry's package schema has no `os` or `arch` field, so it cannot route a client to the
right build. One bundle must therefore contain them all and choose at launch, via the manifest's
`platform_overrides` — which key on OS but *not* architecture.

Hence `lipo.py`: a macOS universal binary is the only way a single manifest entry serves both
Apple silicon and Intel. Apple's `lipo` is macOS-only and the release runs on Linux, so the fat
header is written directly; the format is simple and well specified.

Linux ships amd64 only. Linux arm64 desktops running an MCP client are rare enough that ~50 MB
of bundle for every user isn't the right trade — that audience is well served by
`curl https://draugr.dev/install.sh | sh`.

## The tool list is read from the binary

`build.sh` starts the bundled server, asks it `tools/list`, and writes the answer into the
manifest. A hand-maintained list drifts the first time a tool is added — the prototype for this
shipped a manifest advertising five tools against a binary that served four. It also acts as a
smoke test: a binary that can't start can't answer, and the build stops.

## Building by hand

```bash
./contrib/mcpb/build.sh 0.38.0 /tmp     # version without the leading v
```

It downloads that release's published archives rather than rebuilding, so the binaries inside
are bit-for-bit the ones already covered by `checksums.txt` and its cosign signature.
