#!/usr/bin/env bash
# Fail if a released section of the CHANGELOG has changed.
#
# Released notes are a record. Once v0.44.0 is tagged, what its section said is what shipped, and
# editing it rewrites history that users, release notes and the published site already quote.
#
# The failure this exists for is not malice, it is aim: an entry meant for `[Unreleased]` landing
# one section lower. That produces a perfectly valid CHANGELOG describing a fix in a release that
# does not contain it, and nothing else notices — not the build, not the tests, not review.
#
# Each released section is compared against the same section at its own tag, so the check needs
# no baseline branch and works identically on a laptop and in CI.

set -euo pipefail

FILE="${1:-CHANGELOG.md}"
fail=0

# notes <version> — a version's section, read from a stream on stdin.
notes() {
  awk -v v="$1" '
    $0 ~ "^## \\[" v "\\]"  { f = 1; next }
    f && /^## \[/           { exit }
    # The link-reference block at the foot of the file belongs to no version and gains a line
    # every release. Without this the oldest section swallows it and always looks changed.
    f && /^\[[^]]+\]: http/  { exit }
    f                       { print }
  '
}

# working <version> — the section as it stands now, including uncommitted edits. Reading the
# working tree rather than HEAD is the point: the mistake should surface before it is committed,
# not after it is pushed.
working() { notes "$1" <"$FILE"; }

# released <version> <tag> — the section as it was when that version was tagged.
released() { git show "${2}:${FILE}" 2>/dev/null | notes "$1"; }

# Every released version in the working copy, newest first. [Unreleased] is deliberately skipped:
# it is the part that is supposed to change.
versions=$(grep -oE '^## \[[0-9]+\.[0-9]+\.[0-9]+\]' "$FILE" | tr -d '#[] ' || true)

for v in $versions; do
  tag="v${v}"
  if ! git rev-parse -q --verify "refs/tags/${tag}" >/dev/null; then
    # A version section with no tag yet — mid-release, between the CHANGELOG merge and the tag.
    continue
  fi
  # No section under that version at its own tag — the promote-on-release convention is newer
  # than the oldest releases, where the notes were still under [Unreleased] when it was cut.
  # Nothing to compare against, so nothing to claim.
  if [ -z "$(released "$v" "$tag")" ]; then
    continue
  fi
  if ! diff -q <(working "$v") <(released "$v" "$tag") >/dev/null 2>&1; then
    echo "changelog-guard: the notes for ${v} differ from what was released at ${tag}." >&2
    echo >&2
    diff <(released "$v" "$tag") <(working "$v") | sed 's/^/    /' >&2
    echo >&2
    echo "  Released notes are a record of what shipped. If this entry belongs to work that" >&2
    echo "  has not been released, move it under ## [Unreleased]." >&2
    fail=1
  fi
done

[ "$fail" -eq 0 ] || exit 1
echo "changelog-guard: released sections unchanged ✓"
