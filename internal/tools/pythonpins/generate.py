#!/usr/bin/env python3
"""Generate a hash-pinned requirements file for a Python-packaged scanner.

    python3 internal/tools/pythonpins/generate.py semgrep 1.173.0

Writes internal/tools/pythonpins/<tool>.txt: every package in the resolved tree, with the SHA-256
of every macOS and Linux wheel PyPI publishes for the pinned version, in the form
`pip install --require-hashes` demands.

Generated rather than hand-maintained. A bump is a regenerated file and a diff somebody reads, not
hundreds of lines edited by hand, and a hand-edited hash is one nobody can check.

WHICH PYTHONS IT COVERS. The tree is resolved once for each Python minor from OLDEST to NEWEST, the
range installPython in internal/tools/python.go builds a virtual environment with. A package that
publishes one wheel per Python has a different file on each, so a set resolved on one Python holds
no hash for the wheel another needs, and the install there falls back to an unpinned resolve. The
wheel chosen for each minor is recorded above its requirement, which is what the Go tests read to
hold the file to that claim.

pip resolves for another minor from this interpreter (`--python-version`), but it judges a
dependency's environment markers by the interpreter running it. So after each resolve the markers
are evaluated again for the target minor, and a package that minor requires and the resolve left
out stops the generator rather than leaving a set that installs without it.

WHAT IT DOES NOT COVER. The tree is resolved for this machine's platform. Other platforms get the
hashes of their wheels too, so one whose tree is the same installs pinned; one whose tree differs
fails the installer's `pip check` and falls back, and the fallback says so at install time.
"""

import json
import platform
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

# The Python minors the set is resolved for: installPython's range, minPythonMinor to
# newestPythonMinor in internal/tools/python.go. TestThePinsCoverEveryPythonTheInstallerUses holds
# the two together.
OLDEST, NEWEST = 10, 14

# Wheel platform tags a Draugr install can use. Windows is not one: the installer builds a POSIX
# virtual environment.
PLATFORMS = ("manylinux", "musllinux", "linux_", "macosx_")

# Run with the virtual environment's interpreter, which has pip and so pip's copy of `packaging`:
# the host's python3 may have neither. Reads {"minor", "report"} on stdin and prints each
# requirement the target minor's markers ask for that the resolved set cannot meet.
MARKER_CHECK = r"""
import json, sys
from pip._vendor.packaging.requirements import Requirement
from pip._vendor.packaging.utils import canonicalize_name

job = json.load(sys.stdin)
minor = job["minor"]
resolved = {canonicalize_name(p["metadata"]["name"]): p for p in job["report"]["install"]}
env = {"python_version": "3.%d" % minor, "python_full_version": "3.%d.0" % minor}
problems = []
for pkg in resolved.values():
    extras = set(pkg.get("requested_extras") or [])
    for spec in pkg["metadata"].get("requires_dist") or []:
        req = Requirement(spec)
        if req.marker is not None:
            wanted = [dict(env, extra=e) for e in extras] or [dict(env, extra="")]
            if not any(req.marker.evaluate(w) for w in wanted):
                continue
        got = resolved.get(canonicalize_name(req.name))
        if got is None:
            problems.append("%s needs %s, which the resolve left out" % (pkg["metadata"]["name"], spec))
        elif not req.specifier.contains(got["metadata"]["version"], prereleases=True):
            problems.append("%s needs %s and the resolve chose %s" % (
                pkg["metadata"]["name"], spec, got["metadata"]["version"]))
print(json.dumps(problems))
"""


def resolve(pip: Path, tool: str, version: str, minor: int, tmp: Path) -> dict:
    """Resolve the tool's tree for one Python minor, wheels only, and return pip's report."""
    report = tmp / f"report-3.{minor}.json"
    # --only-binary because --python-version requires it, and because a wheel is what a hash can
    # be checked against before anything runs; an sdist would build on the user's machine.
    # --ignore-installed so the pip and setuptools already in the venv are not left out.
    subprocess.run(
        [str(pip), "install", "--dry-run", "--quiet", "--ignore-installed",
         "--only-binary=:all:", "--python-version", f"3.{minor}",
         "--report", str(report), f"{tool}=={version}"],
        check=True,
    )
    return json.loads(report.read_text())


def missing_for_minor(python: Path, minor: int, report: dict) -> list:
    job = json.dumps({"minor": minor, "report": report})
    out = subprocess.run([str(python), "-c", MARKER_CHECK], input=job, capture_output=True,
                         text=True, check=True)
    return json.loads(out.stdout)


def published_wheels(name: str, version: str) -> dict:
    """Every wheel PyPI publishes for one release, filename to SHA-256."""
    url = f"https://pypi.org/pypi/{name}/{version}/json"
    request = urllib.request.Request(url, headers={"User-Agent": "draugr-pythonpins"})
    with urllib.request.urlopen(request, timeout=60) as resp:  # noqa: S310 -- a fixed https host
        files = json.load(resp)["urls"]
    return {f["filename"]: f["digests"]["sha256"] for f in files
            if f["packagetype"] == "bdist_wheel"}


def usable(filename: str) -> bool:
    platforms = filename[:-len(".whl")].split("-")[-1].split(".")
    return any(p == "any" or p.startswith(PLATFORMS) for p in platforms)


def marker(minors: list) -> str:
    if minors == list(range(OLDEST, NEWEST + 1)):
        return ""
    return " ; " + " or ".join(f'python_version == "3.{m}"' for m in minors)


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    tool, version = sys.argv[1], sys.argv[2]
    out = Path(__file__).parent / f"{tool}.txt"
    minors = list(range(OLDEST, NEWEST + 1))

    # (name, version) -> {minor: (filename, sha256)}: the wheel pip chose for each minor.
    chosen: dict = {}
    names: dict = {}
    problems = []
    with tempfile.TemporaryDirectory() as tmp:
        venv = Path(tmp) / "venv"
        subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True)
        pip, python = venv / "bin" / "pip", venv / "bin" / "python"
        subprocess.run([str(pip), "install", "--quiet", "--upgrade", "pip"], check=True)

        for minor in minors:
            report = resolve(pip, tool, version, minor, Path(tmp))
            problems += [f"Python 3.{minor}: {p}" for p in missing_for_minor(python, minor, report)]
            for pkg in report["install"]:
                name, ver = pkg["metadata"]["name"], pkg["metadata"]["version"]
                info = pkg.get("download_info", {})
                filename = info.get("url", "").rsplit("/", 1)[-1]
                digest = info.get("archive_info", {}).get("hashes", {}).get("sha256")
                if not digest:
                    # A package with no publisher hash cannot be pinned, and a requirements file
                    # that quietly omits one pins less than it appears to.
                    problems.append(f"Python 3.{minor}: no sha256 from PyPI for {name} {ver}")
                    continue
                key = (name.lower(), ver)
                names[key] = name
                chosen.setdefault(key, {})[minor] = (filename, digest)

    if problems:
        print("\n".join(problems), file=sys.stderr)
        return 1

    blocks = []
    for key in sorted(chosen):
        name, ver = names[key], key[1]
        wheels = {f: d for f, d in published_wheels(name, ver).items() if usable(f)}
        by_minor = chosen[key]
        for minor, (filename, digest) in sorted(by_minor.items()):
            if wheels.get(filename) != digest:
                print(f"Python 3.{minor}: {filename} is not among the wheels PyPI lists for "
                      f"{name} {ver}, or its hash differs", file=sys.stderr)
                return 1
        # One comment line per distinct wheel, naming the minors it was chosen for.
        notes: dict = {}
        for minor, (filename, digest) in sorted(by_minor.items()):
            notes.setdefault((filename, digest), []).append(minor)
        lines = [f"# {' '.join(f'3.{m}' for m in ms)}: {f} sha256:{d}"
                 for (f, d), ms in notes.items()]
        hashes = " \\\n".join(f"    --hash=sha256:{d}" for d in sorted(set(wheels.values())))
        lines.append(f"{name}=={ver}{marker(sorted(by_minor))} \\\n{hashes}")
        blocks.append("\n".join(lines))

    claim = " ".join(f"3.{m}" for m in minors)
    header = (
        f"# Generated by internal/tools/pythonpins/generate.py, do not edit.\n"
        f"#\n"
        f"# {tool} {version}, resolved for each Python minor below on {sys.platform} "
        f"{platform.machine()}.\n"
        f"# Each package carries the hash of every macOS and Linux wheel PyPI publishes for its\n"
        f"# version. The line above it names the wheel chosen for each Python.\n"
        f"#\n"
        f"# Regenerate:  python3 internal/tools/pythonpins/generate.py {tool} <version>\n"
        f"#\n"
        f"# pinned-for: {claim}\n"
    )
    out.write_text(header + "\n" + "\n\n".join(blocks) + "\n")
    print(f"{out}: {len(blocks)} packages pinned for Python {claim}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
