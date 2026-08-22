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

# Where an unreleased entry actually lives: one file per change, assembled at release.
#
# Entries used to be appended straight into [Unreleased], which meant every open pull request
# edited the same few lines of the same file. Two of them is a conflict, and the conflict is worse
# than it looks: resolving it by hand is how a section ends up in the wrong order, or how somebody
# drops the other change while fixing their own. A file per change cannot collide with anything.
FRAGMENTS="${CHANGELOG_FRAGMENTS:-changelog.d}"

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
#
# For Unreleased this is what the file says on its own; unreleased_body is what a reader should
# see, which is that plus everything waiting in a fragment.
section_of() {
	awk -v v="$1" '
		$0 ~ "^## \\[" v "\\]" { f = 1; next }
		f && /^## \[/           { exit }
		f                       { print }
	' "$FILE"
}

# fragment_files lists the fragments for one section, in a deterministic order.
#
# Sorted by name, so two people adding an entry the same afternoon get the same notes whichever
# order their pull requests merged in. A contributor who cares where theirs lands names the file
# accordingly; nobody has cared yet.
fragment_files() {
	local section="${1,,}"
	[ -d "$FRAGMENTS" ] || return 0
	find "$FRAGMENTS" -maxdepth 1 -type f -name "*.$section.md" -print 2>/dev/null | sort
}

# all_fragments lists every waiting fragment, whatever its section.
all_fragments() {
	local section
	for section in "${SECTIONS[@]}"; do
		fragment_files "$section"
	done
}

# fragments_body prints every waiting fragment as Keep a Changelog sections, in the canonical
# order. Empty when nothing is waiting.
fragments_body() {
	local section f first
	for section in "${SECTIONS[@]}"; do
		first=1
		while IFS= read -r f; do
			[ -n "$f" ] || continue
			if [ "$first" = 1 ]; then
				printf '### %s\n\n' "$section"
				first=0
			fi
			# Trailing blank lines trimmed here rather than in each fragment, so a file that ends
			# with a newline and one that does not produce the same notes.
			sed -e :a -e '/^\n*$/{$d;N;};/\n$/ba' "$f"
			printf '\n'
		done < <(fragment_files "$section")
	done
}

# unreleased_body is everything that would ship in the next release: what the file already holds
# under [Unreleased], plus every fragment.
#
# Both, because the two coexist during a transition and because a release that dropped one of them
# would publish notes missing an entry somebody wrote — which is the failure this whole file is
# built to prevent.
unreleased_body() {
	local inline fragments
	inline=$(section_of Unreleased)
	case "$(printf '%s' "$inline" | tr -d '[:space:]')" in
	"" | "_Nothingyet._") inline="" ;;
	esac
	fragments=$(fragments_body)

	if [ -n "$inline" ] && [ -n "$fragments" ]; then
		printf '%s\n\n%s\n' "$inline" "$fragments"
	elif [ -n "$inline" ]; then
		printf '%s\n' "$inline"
	elif [ -n "$fragments" ]; then
		printf '%s\n' "$fragments"
	fi
}

cmd_show() {
	local version="${1:-Unreleased}"
	local body
	if [ "$version" = "Unreleased" ]; then
		body=$(unreleased_body)
	else
		body=$(section_of "$version")
	fi
	[ -n "$body" ] || die "no section for [$version] in $FILE"
	printf '%s\n' "$body"
}

# cmd_next prints the version [Unreleased] implies, counting from the last released one.
#
# The rule is the one the notes already state, read rather than remembered: anything under Added
# or Changed is new capability or altered behavior, so a minor. A section holding only Fixed or
# Security is a patch. Deprecated and Removed are minor for the same reason both headings exist —
# a user who has to change something.
#
# Major is deliberately never derived. Deciding that an interface is now unsupportable is a
# judgement about people, and a script that could reach it from a heading would eventually reach
# it by accident.
cmd_next() {
	local body
	body=$(unreleased_body)
	case "$(printf '%s' "$body" | tr -d '[:space:]')" in
	"" | "_Nothingyet._")
		die "[Unreleased] is empty — there is no next version to derive."
		;;
	esac

	# Refuse rather than guess. A heading nobody recognizes is invisible to the rule below, so
	# `### Improvements` holding a new capability derives a patch — the version is wrong, the tag
	# is wrong, and nothing about either says so. `check` catches the heading, but this must not
	# depend on somebody having run it first.
	local heading
	while IFS= read -r heading; do
		heading="${heading#\#\#\# }"
		case " ${SECTIONS[*]} " in
		*" $heading "*) ;;
		*) die "[Unreleased] has '### $heading', which is not a Keep a Changelog heading (want: ${SECTIONS[*]}). Run './scripts/changelog.sh check'." ;;
		esac
	done < <(printf '%s\n' "$body" | grep '^### ' || true)

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

	# Headings in Keep a Changelog order. Promotion preserves whatever order it finds, so a Fixed
	# section written above Added publishes notes that lead with the fixes — which reads as a
	# release about repairs when it is a release about capability. `add` places entries correctly;
	# this catches the file being edited by hand, which is the only way to get it wrong.
	local last=-1 index i
	version=""
	while IFS= read -r line; do
		case "$line" in
		"## ["*) version="${line#\#\# [}"; version="${version%%]*}"; last=-1 ;;
		"### "*)
			[ "$version" = "Unreleased" ] || continue
			heading="${line#\#\#\# }"
			index=-1
			for i in "${!SECTIONS[@]}"; do
				[ "${SECTIONS[$i]}" = "$heading" ] && index=$i
			done
			if [ "$index" -ge 0 ] && [ "$index" -lt "$last" ]; then
				echo "  [$version]: '### $heading' is out of order (want: ${SECTIONS[*]}). Use './scripts/changelog.sh add' rather than editing by hand." >&2
				problems=1
			fi
			[ "$index" -ge 0 ] && last=$index
			;;
		esac
	done <"$FILE"

	# Fragment names, because one that does not match is invisible: it sits in the directory
	# looking like a queued entry and ships in no release at all.
	local frag base section known
	if [ -d "$FRAGMENTS" ]; then
		while IFS= read -r frag; do
			[ -n "$frag" ] || continue
			base=$(basename "$frag")
			case "$base" in
			README.md | .gitkeep) continue ;;
			esac
			section="${base%.md}"
			section="${section##*.}"
			known=0
			for i in "${SECTIONS[@]}"; do
				[ "${i,,}" = "$section" ] && known=1
			done
			if [ "$base" = "$section" ] || [ "$known" -eq 0 ]; then
				echo "  $frag: name must end .<section>.md, one of: ${SECTIONS[*],,}" >&2
				problems=1
			fi
		done < <(find "$FRAGMENTS" -maxdepth 1 -type f -name '*.md' | sort)
	fi

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

# cmd_add writes one entry as its own file, for the release to assemble.
#
# A file rather than a line in CHANGELOG.md, because every open pull request would otherwise edit
# the same few lines: two of them conflict, and resolving that by hand is how a section ends up out
# of order or how somebody drops the other change while fixing their own. Nothing here can collide
# with anything.
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

	# A name from the entry's own first bold phrase, so a directory listing reads as a list of
	# changes rather than a list of hashes. An explicit second argument wins, for when the derived
	# one is unhelpful.
	local slug="${2:-}"
	if [ -z "$slug" ]; then
		slug=$(printf '%s' "$entry" | grep -oPm1 '\*\*\K[^*]+' | head -1 |
			tr '[:upper:]' '[:lower:]' | tr -cs 'a-z0-9' '-' | sed 's/^-*//; s/-*$//' | cut -c1-48)
	fi
	[ -n "$slug" ] || slug=$(printf '%s' "$entry" | sha256sum | cut -c1-12)

	mkdir -p "$FRAGMENTS"
	local path="$FRAGMENTS/$slug.${want,,}.md"
	# Refused rather than overwritten. Two entries deriving the same name is a coincidence worth
	# looking at, and silently replacing one of them loses a change nobody will notice is missing.
	[ -e "$path" ] && die "$path already exists — pass a name as the third argument"

	printf '%s\n' "$entry" >"$path"
	echo "changelog: wrote $path (assembled into [Unreleased] at release)"
}

cmd_promote() {
	local version="${1:-}"
	local date="${2:-$(date -u +%Y-%m-%d)}"
	[ -n "$version" ] || die "which version? e.g. promote 0.59.0"
	[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "'$version' is not X.Y.Z"
	grep -q "^## \[$version\]" "$FILE" && die "[$version] already exists in $FILE"

	local body
	body=$(unreleased_body)
	case "$(printf '%s' "$body" | tr -d '[:space:]')" in
	""|"_Nothingyet._")
		# Refusing is the point. A release promoted with nothing in it is how an entry that
		# never landed becomes a release nobody can describe.
		die "[Unreleased] is empty — nothing to release. Add the entry first, or check that the one you wrote actually landed."
		;;
	esac

	local previous
	previous=$(grep -oE '^## \[[0-9]+\.[0-9]+\.[0-9]+\]' "$FILE" | head -1 | tr -d '#[] ')

	CL_FILE="$FILE" CL_VERSION="$version" CL_DATE="$date" CL_PREV="$previous" CL_BODY="$body" python3 - <<'PY'
import os

path = os.environ["CL_FILE"]
version, date, prev = os.environ["CL_VERSION"], os.environ["CL_DATE"], os.environ["CL_PREV"]
text = open(path).read()

start = text.index("## [Unreleased]")
end = text.index("\n## [", start + 5)
# Everything waiting, assembled by the caller: what the file holds under [Unreleased] plus every
# fragment. Reading the file alone here would publish an empty release and silently drop every
# entry that was written as a fragment.
moved = os.environ["CL_BODY"].strip("\n")

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

	# The fragments have been folded in, so they are no longer waiting. Cleared here rather
	# than left to the caller: a fragment that survives its own release is an entry that
	# ships twice, in two releases, with nothing to say which was meant.
	local f
	while IFS= read -r f; do
		[ -n "$f" ] && rm -f "$f"
	done < <(all_fragments)

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
