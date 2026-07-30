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

# Every file that holds released notes. One today; if the changelog is ever split for size, the
# archive goes here too. Named up front because the alternative is worse than an extra line: this
# script iterates the versions it finds, so archiving a section would quietly stop checking it,
# and the guard would narrow exactly as the history it protects grew.
FILES=("CHANGELOG.md")
[ -f CHANGELOG-ARCHIVE.md ] && FILES+=("CHANGELOG-ARCHIVE.md")
[ "$#" -gt 0 ] && FILES=("$@")

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

# working <version> <file> — the section as it stands now, including uncommitted edits. Reading
# the working tree rather than HEAD is the point: the mistake should surface before it is
# committed, not after it is pushed.
working() { notes "$1" <"$2"; }

# releasedIn <version> <tag> — which changelog file held that version at that tag. A version
# archived today was not archived then, so the file it lives in now may not be the file it
# shipped in.
releasedIn() {
  local f
  for f in "${FILES[@]}"; do
    # Match the heading rather than the body. A section legitimately starts with a blank line,
    # and testing the body through a command substitution strips it — which reports "no such
    # section" for every version and leaves the guard checking nothing while reporting success.
    if git show "${2}:${f}" 2>/dev/null | grep -qE "^## \\[${1//./\\.}\\]"; then
      printf '%s' "$f"
      return
    fi
  done
}

# released <version> <tag> <file> — the section as it was when that version was tagged.
#
# Streamed rather than captured: $(...) strips trailing newlines, and comparing a stripped
# version against an unstripped one reports a difference that is not there.
released() { git show "${2}:${3}" 2>/dev/null | notes "$1"; }

checked=0
for file in "${FILES[@]}"; do
  [ -f "$file" ] || continue

  # Every released version in this file, newest first. [Unreleased] is deliberately skipped: it
  # is the part that is supposed to change.
  versions=$(grep -oE '^## \[[0-9]+\.[0-9]+\.[0-9]+\]' "$file" | tr -d '#[] ' || true)

  for v in $versions; do
    tag="v${v}"
    if ! git rev-parse -q --verify "refs/tags/${tag}" >/dev/null; then
      # A version section with no tag yet — mid-release, between the CHANGELOG merge and the tag.
      continue
    fi
    # No section under that version at its own tag — the promote-on-release convention is newer
    # than the oldest releases, where the notes were still under [Unreleased] when it was cut.
    # Nothing to compare against, so nothing to claim.
    relfile=$(releasedIn "$v" "$tag")
    if [ -z "$relfile" ]; then
      continue
    fi
    checked=$((checked + 1))
    if ! diff -q <(working "$v" "$file") <(released "$v" "$tag" "$relfile") >/dev/null 2>&1; then
      echo "changelog-guard: ${file} — the notes for ${v} differ from what was released at ${tag}." >&2
      echo >&2
      diff <(released "$v" "$tag" "$relfile") <(working "$v" "$file") | sed 's/^/    /' >&2
      echo >&2
      echo "  Released notes are a record of what shipped. If this entry belongs to work that" >&2
      echo "  has not been released, move it under ## [Unreleased]." >&2
      fail=1
    fi
  done
done

[ "$fail" -eq 0 ] || exit 1
echo "changelog-guard: ${checked} released section(s) unchanged ✓"
