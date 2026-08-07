#!/usr/bin/env bash
# Work on CHANGELOG.md without hand-editing the bits that are easy to get subtly wrong.
#
# The failures this exists for are all quiet ones — a valid-looking file that says the wrong
# thing, which no build, test or reviewer catches:
#
#   - two `### Fixed` blocks under one release, so the notes a tag publishes contain half the
#     entries and nobody can tell which half;
#   - an entry added under the wrong heading, or under a released section instead of Unreleased;
#   - a release promoted with the compare links left pointing at the previous tag;
#   - a release promoted with nothing in it, because the entry that was meant to be there never
#     landed.
#
#   ./scripts/changelog.sh check              structure + released sections unchanged
#   ./scripts/changelog.sh show [version]     print what a tag would publish (default: Unreleased)
#   ./scripts/changelog.sh add fixed          read an entry from stdin into [Unreleased]
#   ./scripts/changelog.sh promote 0.59.0     [Unreleased] -> a dated section, links updated
#
# `check` runs in `make gate` and in CI. `show` is worth running before you tag: it prints exactly
# what the release workflow will extract, which is the last chance to notice something missing.
set -euo pipefail

FILE="${CHANGELOG_FILE:-CHANGELOG.md}"

# The headings Keep a Changelog defines, in the order they should appear. Anything else is a typo
# — "### Fix" reads fine and lands nowhere the release notes look.
SECTIONS=(Added Changed Deprecated Removed Fixed Security)

die() { echo "changelog: $*" >&2; exit 1; }

usage() {
	sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
	exit "${1:-0}"
}

# section_of prints the body of one version's section, exactly as the release workflow extracts
# it. Version "Unreleased" is spelled as it appears in the file.
section_of() {
	awk -v v="$1" '
		$0 ~ "^## \\[" v "\\]" { f = 1; next }
		f && /^## \[/           { exit }
		f                       { print }
	' "$FILE"
}

cmd_show() {
	local version="${1:-Unreleased}"
	local body
	body=$(section_of "$version")
	[ -n "$body" ] || die "no section for [$version] in $FILE"
	printf '%s\n' "$body"
}

# cmd_next prints the version [Unreleased] implies, counting from the last released one.
#
# The rule is the one the notes already state, read rather than remembered: anything under Added
# or Changed is new capability or altered behaviour, so a minor. A section holding only Fixed or
# Security is a patch. Deprecated and Removed are minor for the same reason both headings exist —
# a user who has to change something.
#
# Major is deliberately never derived. Deciding that an interface is now unsupportable is a
# judgement about people, and a script that could reach it from a heading would eventually reach
# it by accident.
cmd_next() {
	local body
	body=$(section_of Unreleased)
	case "$(printf '%s' "$body" | tr -d '[:space:]')" in
	"" | "_Nothingyet._")
		die "[Unreleased] is empty — there is no next version to derive."
		;;
	esac

	local previous major minor patch
	previous=$(grep -oE '^## \[[0-9]+\.[0-9]+\.[0-9]+\]' "$FILE" | head -1 | tr -d '#[] ')
	[ -n "$previous" ] || die "no released section in $FILE to count from"
	IFS=. read -r major minor patch <<<"$previous"

	if printf '%s\n' "$body" | grep -qE '^### (Added|Changed|Deprecated|Removed)$'; then
		echo "$major.$((minor + 1)).0"
	else
		echo "$major.$minor.$((patch + 1))"
	fi
}

cmd_check() {
	[ -f "$FILE" ] || die "$FILE not found"
	local problems=0

	grep -q '^## \[Unreleased\]' "$FILE" || {
		echo "  no [Unreleased] section — new entries have nowhere to go" >&2
		problems=1
	}

	# Heading checks apply to [Unreleased] only. Released sections are a record — changelog-guard
	# already holds them to what their tag said, and the early history predates Keep a Changelog,
	# so failing on it would mean a check that can never pass and therefore never gets read.
	#
	# Unreleased is where a new mistake lands, and it is the only place a fix is still free.
	local version="" heading seen
	while IFS= read -r line; do
		case "$line" in
		"## ["*) version="${line#\#\# [}"; version="${version%%]*}"; seen=" " ;;
		"### "*)
			[ "$version" = "Unreleased" ] || continue
			heading="${line#\#\#\# }"
			case " ${SECTIONS[*]} " in
			*" $heading "*) ;;
			*)
				echo "  [$version]: '### $heading' is not a Keep a Changelog heading (want: ${SECTIONS[*]})" >&2
				problems=1
				;;
			esac
			case "$seen" in
			*" $heading "*)
				echo "  [$version]: '### $heading' appears more than once — the published notes will be split" >&2
				problems=1
				;;
			esac
			seen="$seen$heading "
			;;
		esac
	done <"$FILE"

	# Every released version needs a link reference, or the notes render a bare [0.58.0].
	local v
	while read -r v; do
		grep -q "^\[$v\]:" "$FILE" || {
			echo "  [$v]: no link reference at the foot of the file" >&2
			problems=1
		}
	done < <(grep -oE '^## \[[0-9]+\.[0-9]+\.[0-9]+\]' "$FILE" | tr -d '#[] ')

	grep -q '^\[Unreleased\]:' "$FILE" || {
		echo "  [Unreleased]: no link reference at the foot of the file" >&2
		problems=1
	}

	[ "$problems" -eq 0 ] || die "$FILE has structural problems (above)"

	# Released notes are a record; the existing guard compares each against its own tag.
	./scripts/changelog-guard.sh "$FILE"
	echo "changelog: structure ok"
}

cmd_add() {
	local heading="${1:-}"
	[ -n "$heading" ] || die "which section? one of: ${SECTIONS[*],,}"
	# Accept any case; write the canonical one.
	local want="" s
	for s in "${SECTIONS[@]}"; do
		[ "${s,,}" = "${heading,,}" ] && want="$s"
	done
	[ -n "$want" ] || die "'$heading' is not a Keep a Changelog section (want: ${SECTIONS[*],,})"

	local entry
	entry=$(cat)
	[ -n "${entry//[[:space:]]/}" ] || die "nothing on stdin to add"

	CL_FILE="$FILE" CL_SECTION="$want" CL_ENTRY="$entry" python3 - <<'PY'
import os, re, sys

path, want, entry = os.environ["CL_FILE"], os.environ["CL_SECTION"], os.environ["CL_ENTRY"].rstrip("\n")
order = ["Added", "Changed", "Deprecated", "Removed", "Fixed", "Security"]
text = open(path).read()

start = text.index("## [Unreleased]")
end = text.index("\n## [", start + 5)
head, body, tail = text[:start], text[start:end], text[end:]

body = body.replace("\n_Nothing yet._\n", "\n", 1)

# Find the section, or work out where it belongs so the headings stay in Keep a Changelog order.
marker = f"\n### {want}\n"
if marker in body:
    at = body.index(marker) + len(marker)
    body = body[:at] + "\n" + entry + "\n" + body[at:]
else:
    later = [f"\n### {s}\n" for s in order[order.index(want) + 1:] if f"\n### {s}\n" in body]
    block = f"\n### {want}\n\n{entry}\n"
    if later:
        at = body.index(later[0])
        body = body[:at] + block + body[at:]
    else:
        body = body.rstrip("\n") + "\n" + block

body = re.sub(r"\n{3,}", "\n\n", body).rstrip("\n") + "\n"
open(path, "w").write(head + body + tail)
PY
	echo "changelog: added to [Unreleased] → $want"
}

cmd_promote() {
	local version="${1:-}"
	local date="${2:-$(date -u +%Y-%m-%d)}"
	[ -n "$version" ] || die "which version? e.g. promote 0.59.0"
	[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "'$version' is not X.Y.Z"
	grep -q "^## \[$version\]" "$FILE" && die "[$version] already exists in $FILE"

	local body
	body=$(section_of Unreleased)
	case "$(printf '%s' "$body" | tr -d '[:space:]')" in
	""|"_Nothingyet._")
		# Refusing is the point. A release promoted with nothing in it is how an entry that
		# never landed becomes a release nobody can describe.
		die "[Unreleased] is empty — nothing to release. Add the entry first, or check that the one you wrote actually landed."
		;;
	esac

	local previous
	previous=$(grep -oE '^## \[[0-9]+\.[0-9]+\.[0-9]+\]' "$FILE" | head -1 | tr -d '#[] ')

	CL_FILE="$FILE" CL_VERSION="$version" CL_DATE="$date" CL_PREV="$previous" python3 - <<'PY'
import os

path = os.environ["CL_FILE"]
version, date, prev = os.environ["CL_VERSION"], os.environ["CL_DATE"], os.environ["CL_PREV"]
text = open(path).read()

start = text.index("## [Unreleased]")
end = text.index("\n## [", start + 5)
body = text[start:end]
moved = body[len("## [Unreleased]\n"):].strip("\n")

text = (text[:start]
        + f"## [Unreleased]\n\n_Nothing yet._\n\n## [{version}] - {date}\n\n{moved}\n"
        + text[end:])

# The compare link must follow the new tag, or [Unreleased] keeps describing the last release's
# range and quietly shows changes that already shipped.
old = f"[Unreleased]: https://github.com/draugr-dev/draugr/compare/v{prev}...HEAD"
new = (f"[Unreleased]: https://github.com/draugr-dev/draugr/compare/v{version}...HEAD\n"
       f"[{version}]: https://github.com/draugr-dev/draugr/releases/tag/v{version}")
if old not in text:
    raise SystemExit(f"changelog: could not find the [Unreleased] compare link for v{prev}; "
                     "update the link references by hand")
open(path, "w").write(text.replace(old, new, 1))
PY
	echo "changelog: promoted [Unreleased] → [$version] - $date"
	echo
	echo "What v$version will publish:"
	echo "---"
	section_of "$version"
	echo "---"
	echo "Read that before tagging. It is the last point at which a missing entry is cheap to fix."
}

case "${1:-}" in
check) shift; cmd_check "$@" ;;
show) shift; cmd_show "$@" ;;
add) shift; cmd_add "$@" ;;
next) shift; cmd_next "$@" ;;
promote) shift; cmd_promote "$@" ;;
-h | --help | help | "") usage 0 ;;
*) die "unknown command '$1' (try: check, show, add, next, promote)" ;;
esac
