#!/usr/bin/env bash
# Record docs/getting-started/tutorial.tape: the tutorial's commands typed and run for real on the
# release it pins, from a fresh home, into <out>/tutorial.mp4 and tutorial.ascii. <out>/timing.log
# holds when each command started, in seconds on the clock from when the tape shows the screen. The
# video falls behind the clock while a scan keeps the machine busy, so check a time against a frame.
#
#   scripts/record-tutorial.sh <out>
#
# Needs vhs, ttyd and ffmpeg on PATH. The fresh home's PATH is the system's own directories plus Go
# and Node, which govulncheck and retire.js need. The home is ~/dev, or DRAUGR_TUTORIAL_HOME, made
# anew each time. Its path is printed on screen wherever a tool or a feed is installed, so it reads
# as a person's home folder, and a short one keeps those tables on one line each. The runner writes
# a marker file into the home it makes and removes a home only when the marker is there, so a
# folder of somebody's own at that path is never deleted.
set -euo pipefail

OUT=${1:?usage: record-tutorial.sh <out folder>}
TAPE=$(cd "$(dirname "$0")/.." && pwd)/docs/getting-started/tutorial.tape
for t in vhs ttyd ffmpeg go node npm; do
  command -v "$t" >/dev/null || { echo "record-tutorial: $t is not on PATH" >&2; exit 1; }
done

mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
HOME_DIR=${DRAUGR_TUTORIAL_HOME:-$HOME/dev}
MARKER=.draugr-tutorial-home
if [ -e "$HOME_DIR" ] && [ ! -e "$HOME_DIR/$MARKER" ] && [ -n "$(ls -A "$HOME_DIR" 2>/dev/null || echo x)" ]; then
  echo "record-tutorial: $HOME_DIR exists and this script did not make it; move it or set DRAUGR_TUTORIAL_HOME" >&2
  exit 1
fi
# Go writes its module cache read-only, so the last render's home is made writable before removal.
[ ! -d "$HOME_DIR" ] || chmod -R u+w "$HOME_DIR"
rm -rf "$HOME_DIR" "$OUT/sys" "$OUT/timing.raw"
mkdir -p "$HOME_DIR" "$OUT/sys"
: >"$HOME_DIR/$MARKER"
for t in go node npm; do ln -s "$(readlink -f "$(command -v "$t")")" "$OUT/sys/$t"; done

# The scans' times are on screen, so start below a third of the CPUs' load.
until awk -v n="$(nproc)" '{exit !($1 < n/3)}' /proc/loadavg; do sleep 15; done

cd "$OUT"
TUTORIAL_HOME=$HOME_DIR TUTORIAL_PATH=$OUT/sys:/usr/bin:/bin TUTORIAL_TIMING=$OUT/timing.raw vhs "$TAPE"
# The video starts when the tape shows the screen, just after the hidden clear.
awk '!t && / clear$/ { t = $1; next } t { printf "%7.1f  %s\n", $1 - t, substr($0, index($0, " ") + 1) }' \
  "$OUT/timing.raw" >"$OUT/timing.log"
ls -l "$OUT/tutorial.mp4" "$OUT/tutorial.ascii" "$OUT/timing.log"
