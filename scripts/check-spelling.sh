#!/usr/bin/env bash
# Fail if a file outside Go uses a non-American spelling.
#
# `misspell` runs inside golangci-lint with `locale: US`, which covers the Go tree. It does not
# read Markdown, YAML or shell — and that is where most of the prose is: the docs, the colocated
# plugin pages, the README, the workflow comments, the site's source material. Half of it is
# quoted onto a public site, so a spelling that drifts here drifts in front of readers.
#
# One vocabulary, checked the same way in both halves of the tree, rather than one half enforced
# and the other left to whoever wrote it.
#
# Needs the `misspell` binary, at the version CI pins so a local pass means a CI pass:
#   go install github.com/client9/misspell/cmd/misspell@v0.3.4
set -uo pipefail

cd "$(dirname "$0")/.."

bin="${MISSPELL:-misspell}"
if ! command -v "$bin" >/dev/null 2>&1; then
  if [ -x "$(go env GOPATH)/bin/misspell" ]; then
    bin="$(go env GOPATH)/bin/misspell"
  else
    echo "check-spelling: misspell not found — go install github.com/client9/misspell/cmd/misspell@v0.3.4" >&2
    exit 1
  fi
fi

# Go files are included even though golangci-lint already runs misspell over them: the two
# implementations disagree on individual words, and the file types they cover do not overlap
# anyway (nothing else reads .json, .py or .tape).
#
# Neither of them, though, matches a word that is not standing alone — `organisation's` and
# `TestPainterColours` are invisible to both, because a possessive or a compound identifier is
# not the token they look up. That is what the stem pass at the foot of this script is for.
#
# Vendored third-party files are excluded. Their spelling is theirs, and "correcting" a schema we
# validate against would mean validating against a document nobody publishes.
#
# Released CHANGELOG sections are excluded, and not for convenience: scripts/changelog-guard.sh
# fails the build if one changes, because what a tagged release said is what shipped. Checking
# them here would demand an edit the other guard forbids — two checks that cannot both pass. The
# `[Unreleased]` section is checked below, which is the part still being written.
#
# `--others` includes files that are not tracked yet, because a new file is exactly the one a
# spelling check is worth running on. Checking only what is committed means a file's first run of
# `make gate` never looks at it, and the first thing that does is CI, after the push.
# `--exclude-standard` keeps .gitignore honored, so build output and local scratch stay out.
mapfile -t files < <(
  git ls-files --cached --others --exclude-standard \
    '*.md' '*.yml' '*.yaml' '*.sh' '*.txt' '*.go' '*.json' '*.py' '*.tape' |
    grep -v '^CHANGELOG\.md$' |
    grep -v '^pkg/report/testdata/gitlab/' |
    # This script states every spelling it rejects, so it cannot be held to its own rule without
    # forbidding itself. The exclusion is the file that defines the rule, and nothing else.
    grep -v '^scripts/check-spelling\.sh$'
)

# A listed file that is not on disk stops the readers below partway through — awk treats it as
# fatal and abandons every file after it, which prints nothing and exits 0. That is a check that
# reports a pass for the half of the tree it never opened, so it is refused outright rather than
# worked around. It happens after a rename whose deletion is staged and whose addition is not.
missing=()
for f in "${files[@]}"; do
  [ -f "$f" ] || missing+=("$f")
done
if [ "${#missing[@]}" -gt 0 ]; then
  printf 'check-spelling: listed but not on disk: %s\n' "${missing[@]}" >&2
  echo "  Refusing to check a subset — stage the rename (git add -A) and run again." >&2
  exit 1
fi

# `analyses` is ignored because it is not reliably wrong: it is the correct American plural of
# "analysis", and it is a path in VirusTotal's API that a guard asserts Draugr never calls. A
# check that renames somebody else's endpoint turns a real assertion into one that matches
# nothing. The British verb form has to be caught by a reader instead.
ignore="analyses"

fail=0
if [ "${#files[@]}" -gt 0 ]; then
  out=$("$bin" -locale US -i "$ignore" "${files[@]}" 2>/dev/null)
  if [ -n "$out" ]; then
    echo "$out"
    fail=1
  fi
fi

# The CHANGELOG's unreleased section only. Extracted to a temporary file rather than piped,
# because misspell reports a path and a line, and a reader given "/dev/stdin:4" has to go and
# find what that was. The heading offset is added back so the number points at CHANGELOG.md.
unreleased_start=$(grep -n '^## \[Unreleased\]' CHANGELOG.md | head -1 | cut -d: -f1)
if [ -n "$unreleased_start" ]; then
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT
  awk 'f && /^## \[/ { exit } /^## \[Unreleased\]/ { f = 1 } f' CHANGELOG.md >"$tmp/unreleased.md"
  out=$("$bin" -locale US -i "$ignore" "$tmp/unreleased.md" 2>/dev/null)
  if [ -n "$out" ]; then
    # Rewrite the path and shift the line number back onto the real file. Matched rather than
    # split into fields: the message itself contains colons, and rebuilding it from fields would
    # reformat the part of the line a reader is actually meant to read.
    echo "$out" | sed -E "s|^[^:]*:([0-9]+):|CHANGELOG.md:\1:|" \
      | awk -F: -v off="$((unreleased_start - 1))" \
        '{ printf "%s:%d:%s\n", $1, $2 + off, substr($0, length($1) + length($2) + 3) }'
    fail=1
  fi
fi

# Stems, for the words the dictionary pass cannot see: a possessive (`organisation's`) and a
# compound identifier (`TestPainterColours`, `miscolours`) are not tokens misspell looks up, so
# both variants of it walk straight past them. A test name is read as often as a comment.
#
# Case-sensitive, and each stem listed in both forms. That is what keeps `ModelLoadsFile` out of
# the `modell` rule: it contains `ModelL`, which is neither `modell` nor `Modell`. Matching
# case-insensitively here reports a dozen identifiers that were never misspelled, and a check
# with false positives gets an exception added until it stops meaning anything.
stems='colour|Colour|behaviour|Behaviour|licence|Licence|catalogue|Catalogue'
stems+='|organis|Organis|recognis|Recognis|honour|Honour|artefact|Artefact'
stems+='|neighbour|Neighbour|serialis|Serialis|materialis|Materialis|authoris|Authoris'
stems+='|normalis|Normalis|labell|Labell|cancelled|Cancelled|favour|Favour|defence|Defence'
stems+='|modell|Modell|signall|Signall|travell|Travell|summaris|Summaris|penalis|Penalis'
stems+='|categoris|Categoris|synchronis|Synchronis|sanitis|Sanitis|initialis|Initialis'
stems+='|optimis|Optimis|prioritis|Prioritis|utilis|Utilis'
# `analyse` only where it is the verb. `analyses` is the American plural of "analysis" and a
# VirusTotal endpoint path, and `analysis` is simply correct.
stems+='|analyse[^s]|Analyse[^s]'

if [ "${#files[@]}" -gt 0 ]; then
  # URLs and Markdown link targets are blanked before matching, and only for matching — the line
  # is still printed whole. A published path is somebody else's identifier: `/learn/software-
  # licences/` is a page that exists under that name, and respelling it produces a 404 that no
  # test here would notice. Link *text* is prose and stays in scope.
  #
  # `licen[cs]e` is skipped for the same class of reason: it is a regex in the source that
  # deliberately accepts both spellings.
  out=$(awk -v pat="$stems" '
    {
      line = $0
      gsub(/https?:\/\/[^ )"`,>]+/, "", line)
      gsub(/\]\([^)]*\)/, "]", line)
      if (line ~ pat && line !~ /licen\[cs\]e/) printf "%s:%d:%s\n", FILENAME, FNR, $0
    }' "${files[@]}")
  if [ -n "$out" ]; then
    echo "$out"
    fail=1
  fi
fi

if [ "$fail" -ne 0 ]; then
  echo "check-spelling: use American spelling (misspell -locale US -w <file> fixes most; a" >&2
  echo "  possessive or a compound identifier has to be renamed by hand)" >&2
  exit 1
fi

echo "check-spelling: American spelling throughout ✓"
