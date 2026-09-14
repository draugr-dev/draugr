#!/usr/bin/env python3
"""Move a pinned scanner to a new version, and record what that version actually hashes to.

    scripts/update-tool-pins.py --check                 what is behind, and by how much
    scripts/update-tool-pins.py trivy grype             move these to their latest release
    scripts/update-tool-pins.py --all                   move everything that is behind

Every URL in `internal/tools/install.go` sits beside a `URLTemplate` carrying `{version}`, which is
what makes this safe to automate: the new URL is derived from the template the tool already
declares rather than guessed from the old URL's shape, so a release that renames its assets fails
loudly here instead of pinning a 404.

**The hash comes from the bytes, never from a release page.** Where an upstream publishes a
checksums file this reads it and then downloads the asset and compares, because a checksums file is
a claim and the bytes are the fact. Where one does not, the download is the only source. Either way
nothing is written until every platform for a tool has been fetched and hashed.
"""

import argparse
import hashlib
import json
import pathlib
import re
import sys
import urllib.error
import urllib.request

INSTALL_GO = pathlib.Path(__file__).resolve().parent.parent / "internal/tools/install.go"

# The upstream each tool is released from, for asking what the newest version is.
REPOS = {
    "trivy": "aquasecurity/trivy",
    "cosign": "sigstore/cosign",
    "kube-bench": "aquasecurity/kube-bench",
    "gosec": "securego/gosec",
    "gitleaks": "gitleaks/gitleaks",
    "syft": "anchore/syft",
    "grype": "anchore/grype",
    "nuclei": "projectdiscovery/nuclei",
}


def fetch(url: str, timeout: int = 180) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "draugr-pin-updater"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def latest(repo: str) -> str:
    payload = json.loads(fetch(f"https://api.github.com/repos/{repo}/releases/latest", 30))
    return payload["tag_name"].lstrip("v")


def blocks(source: str) -> dict[str, tuple[int, int]]:
    """Where each tool's spec starts and ends, so an edit cannot reach into its neighbor."""
    starts = [(m.group(1), m.start()) for m in
              re.finditer(r'\t"([a-z-]+)": \{\n\t\tBinary:\s+"', source)]
    out = {}
    for i, (name, start) in enumerate(starts):
        end = starts[i + 1][1] if i + 1 < len(starts) else len(source)
        out[name] = (start, end)
    return out


def pinned(source: str, start: int, end: int) -> str:
    return re.search(r'Version: "([^"]+)"', source[start:end]).group(1)


def assets(source: str, start: int, end: int) -> list[str]:
    """Every URLTemplate in this tool's spec, which is one per platform plus its signing material."""
    return re.findall(r'URLTemplate:\s+"([^"]+)"', source[start:end])


def sha256_of(url: str) -> str:
    digest = hashlib.sha256()
    digest.update(fetch(url))
    return digest.hexdigest()


def published_sums(source: str, start: int, end: int, version: str) -> dict[str, str]:
    """The upstream's own checksums file, keyed by asset filename. Empty where none is published."""
    m = re.search(r'ChecksumsURLTemplate:\s+"([^"]+)"', source[start:end])
    if not m:
        return {}
    try:
        text = fetch(m.group(1).replace("{version}", version)).decode()
    except urllib.error.URLError as err:
        sys.exit(f"  checksums file for {version} is not there: {err}")
    out = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 2:
            out[parts[1].lstrip("*")] = parts[0]
    return out


def bump(source: str, tool: str, version: str) -> str:
    start, end = blocks(source)[tool]
    was = pinned(source, start, end)
    if was == version:
        print(f"{tool}: already {version}")
        return source
    print(f"{tool}: {was} → {version}")

    body = source[start:end]
    claimed = published_sums(source, start, end, version)

    # Hash every platform before rewriting anything, so a release missing one asset leaves the
    # manifest on the version that is known to be whole.
    fresh: dict[str, str] = {}
    for template in assets(source, start, end):
        url = template.replace("{version}", version)
        try:
            actual = sha256_of(url)
        except urllib.error.URLError as err:
            sys.exit(f"  {url}\n  is not there: {err}\n  the asset names may have changed at "
                     f"{version}; the manifest is untouched")
        name = url.rsplit("/", 1)[-1]
        if name in claimed and claimed[name] != actual:
            sys.exit(f"  {name}: the checksums file says {claimed[name]} and the bytes hash to "
                     f"{actual}; the manifest is untouched")
        fresh[url] = actual
        print(f"    {name} {actual[:16]}…")

    body = body.replace(f'Version: "{was}"', f'Version: "{version}"', 1)
    # URLs are rebuilt from the template rather than string-replaced on the old version, which
    # would also rewrite a version that happens to appear inside a path.
    for template in assets(source, start, end):
        old_url = template.replace("{version}", was)
        new_url = template.replace("{version}", version)
        body = body.replace(f'"{old_url}"', f'"{new_url}"')

    # A hash belongs to the template above it, and only where one follows before the next template
    # starts. Pairing them by position in a flat list is what a signing block breaks: a checksums
    # file and its bundle declare URLs and carry no SHA256 of their own, so every platform after
    # them takes the hash of the entry two places back, and the manifest pins a value the bytes
    # never had.
    pieces = list(re.finditer(r'URLTemplate:\s+"([^"]+)"', body))
    for n, piece in enumerate(pieces):
        stop = pieces[n + 1].start() if n + 1 < len(pieces) else len(body)
        digest = re.search(r'SHA256:(\s+)"([a-f0-9]{64})"', body[piece.end():stop])
        if not digest:
            continue
        want = fresh[piece.group(1).replace("{version}", version)]
        at = piece.end() + digest.start()
        body = body[:at] + f'SHA256:{digest.group(1)}"{want}"' + body[piece.end() + digest.end():]
        pieces = list(re.finditer(r'URLTemplate:\s+"([^"]+)"', body))
    return source[:start] + body + source[end:]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("tools", nargs="*", help="tools to move; default is none")
    parser.add_argument("--check", action="store_true", help="report what is behind and stop")
    parser.add_argument("--all", action="store_true", help="move everything that is behind")
    args = parser.parse_args()

    source = INSTALL_GO.read_text()
    where = blocks(source)

    if args.check or args.all:
        behind = []
        for tool in sorted(where):
            if tool not in REPOS:
                continue
            start, end = where[tool]
            now, new = pinned(source, start, end), latest(REPOS[tool])
            mark = "  " if now == new else "->"
            print(f"{mark} {tool:12} {now:10} {new}")
            if now != new:
                behind.append(tool)
        if args.check:
            return
        args.tools = behind

    for tool in args.tools:
        if tool not in where:
            sys.exit(f"{tool} is not in the manifest")
        source = bump(source, tool, latest(REPOS[tool]))

    INSTALL_GO.write_text(source)
    print("\ninstall.go written; run `go test ./internal/tools/` and install them for real")


if __name__ == "__main__":
    main()
