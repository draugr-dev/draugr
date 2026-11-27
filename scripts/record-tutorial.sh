#!/usr/bin/env bash
# Record docs/getting-started/tutorial.tape: the tutorial's commands typed and run for real on the
# release it pins, from a fresh home, into <out>/tutorial.mp4 and tutorial.ascii.
#
#   scripts/record-tutorial.sh <out>
#
# Needs vhs, ttyd and ffmpeg on PATH. The fresh home's PATH is the system's own directories plus Go
# and Node, which govulncheck and retire.js need. The home is /tmp/draugr-tutorial, made anew each
# time, because its path is printed on screen wherever a tool or a feed is installed, and a short
# one keeps those tables on one line each.
set -euo pipefail

OUT=${1:?usage: record-tutorial.sh <out folder>}
TAPE=$(cd "$(dirname "$0")/.." && pwd)/docs/getting-started/tutorial.tape
for t in vhs ttyd ffmpeg go node npm; do
  command -v "$t" >/dev/null || { echo "record-tutorial: $t is not on PATH" >&2; exit 1; }
done

mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
HOME_DIR=/tmp/draugr-tutorial
# Go writes its module cache read-only, so the last render's home is made writable before removal.
[ ! -d "$HOME_DIR" ] || chmod -R u+w "$HOME_DIR"
rm -rf "$HOME_DIR" "$OUT/sys"
mkdir -p "$HOME_DIR" "$OUT/sys"
for t in go node npm; do ln -s "$(readlink -f "$(command -v "$t")")" "$OUT/sys/$t"; done

# The scans' times are on screen, so start below a third of the CPUs' load.
until awk -v n="$(nproc)" '{exit !($1 < n/3)}' /proc/loadavg; do sleep 15; done

cd "$OUT"
TUTORIAL_HOME=$HOME_DIR TUTORIAL_PATH=$OUT/sys:/usr/bin:/bin vhs "$TAPE"
ls -l "$OUT/tutorial.mp4" "$OUT/tutorial.ascii"
