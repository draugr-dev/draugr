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

## Listing in the MCP Registry

`server.json` is the registry entry. It names one specific bundle URL and its SHA-256, so it
must be refreshed for each release we publish:

```bash
./contrib/mcpb/update-server-json.sh 0.39.0
```

The hash is read from the release's own `.mcpb.sha256` rather than recomputed, so the entry
can't certify a bundle that differs from the published one. Getting this wrong means a client
refuses the download — correct behaviour, and miserable to debug.

### Namespace

`dev.draugr/draugr` — the reverse-DNS form of `draugr.dev`, which is what domain-based
authentication requires. We own the domain, so the identity is tied to it rather than to a
GitHub account.

### Publishing, first time

There is no key to find: **you generate one**, publish the public half in DNS, and sign with the
private half.

**1. Generate an Ed25519 keypair.** Keep `key.pem` — losing it means you can't publish updates
without changing the DNS record.

```bash
openssl genpkey -algorithm Ed25519 -out key.pem
```

> On macOS the system `openssl` is LibreSSL and has no Ed25519 in `genpkey`. Use
> `brew install openssl@3` and call it explicitly, or use the ECDSA P-384 variant in the
> [registry's authentication guide](https://github.com/modelcontextprotocol/registry/blob/main/docs/modelcontextprotocol-io/authentication.mdx).

**2. Derive the TXT record.**

```bash
PUBLIC_KEY="$(openssl pkey -in key.pem -pubout -outform DER | tail -c 32 | base64)"
echo "draugr.dev. IN TXT \"v=MCPv1; k=ed25519; p=${PUBLIC_KEY}\""
```

**3. Add it in DNS — at the apex.** Our DNS is at Squarespace. Add a `TXT` record on
`draugr.dev` itself (host `@`), value `v=MCPv1; k=ed25519; p=…`.

> **This is the step that goes wrong.** The record must be on the **apex**, not under a
> selector like `_mcp-registry.draugr.dev`. MCP DNS auth follows SPF-style placement, not
> DKIM-style. Put it under a selector and the registry never sees it, failing with a generic
> signature error that says nothing about placement.
>
> If you ever rotate the key, **delete the old TXT record**. A stale one is tried first and
> fails verification.

Wait for propagation, then confirm the registry will see what you see:

```bash
dig +short TXT draugr.dev | grep MCPv1
```

**4. Log in and publish.**

```bash
PRIVATE_KEY="$(openssl pkey -in key.pem -noout -text | grep -A3 "priv:" | tail -n +2 | tr -d ' :\n')"
mcp-publisher login dns --domain draugr.dev --private-key "$PRIVATE_KEY"
mcp-publisher publish                          # from this directory
```

`--private-key` wants the hex-encoded key, not the path to `key.pem`.

The publisher CLI lives in
[modelcontextprotocol/registry](https://github.com/modelcontextprotocol/registry) under
`cmd/publisher`. Check its current flags before running — the tool and the registry are both
young and move.

### Publishing again later

Steps 1–3 are one-off. Subsequent publishes are step 4 alone, after
`update-server-json.sh <version>`.

### Not every release needs republishing

The registry entry points at a fixed version. Refresh it when the MCP surface changes — a new
tool, a changed transport, a fix in the server — not for releases that don't affect it. Each
republish asks every client to re-download 60 MB.
