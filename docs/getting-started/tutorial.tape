# The terminal half of docs/getting-started/tutorial.md, stages 1 to 4, typed and run for real.
#
# Render it with scripts/record-tutorial.sh, which makes a fresh home and runs this tape from the
# folder the video goes to. Every command typed here is one the tutorial shows, in its order, at
# the version and demo commit it pins; change both together. scripts/check-tutorial-tape.py, in
# make gate, fails when they differ.

Output tutorial.mp4
Output tutorial.ascii

Require git
Require curl
Require script

Set Shell bash
Set FontSize 18
Set Width 1600
Set Height 900
Set Padding 24
Set TypingSpeed 45ms
Set WindowBar Colorful

# Off camera: a shell whose every byte of output is logged as the terminal received it, so a cut can
# scroll back to the top of a command's output from the same run, the fresh home the runner made, a
# plain prompt to wait on, an install fetch the site counts apart from a reader's (the typed command
# is the tutorial's own), and a log of when each command starts, which the narration is timed
# against. script(1) runs the shell on a terminal of its own at this window's size, so what a command
# prints is what it prints here without the log.
Hide
Type `exec script -qf -c 'bash --noprofile --norc' "$TUTORIAL_SESSION"`
Enter
Sleep 500ms
Type `trap 'printf "%s %s\n" "$EPOCHREALTIME" "$BASH_COMMAND" >>"$TUTORIAL_TIMING"' DEBUG`
Enter
Type `export HOME="$TUTORIAL_HOME" PATH="$TUTORIAL_HOME/.local/bin:$TUTORIAL_PATH" DRAUGR_NO_UPDATE_CHECK=1 PS1='$ '`
Enter
Type `curl() { local a=() x; for x in "$@"; do [ "$x" = https://draugr.dev/install.sh ] && x="$x?internal"; a+=("$x"); done; command curl "${a[@]}"; }`
Enter
Type `cd "$HOME" && clear`
Enter
Wait /^\$$/
Show

# 1. Scan with nothing declared
Type "# 1. Scan with nothing declared"
Enter
Sleep 1.5s
Type "curl -fsSL https://draugr.dev/install.sh | DRAUGR_VERSION=v0.193.0 sh"
Enter
Wait@120s /^\$$/
Sleep 1.5s
Type "draugr version"
Enter
Wait /^\$$/
Sleep 2s
Type "git clone https://github.com/draugr-dev/draugr-demo"
Enter
Wait@120s /^\$$/
Type "cd draugr-demo"
Enter
Wait /^\$$/
Type "git checkout bb729745becb4825ba9d3123c98ebb2ada5ce038"
Enter
Wait /^\$$/
Sleep 1s
Type "mv draugr.saga.yaml draugr.saga.yaml.aside"
Enter
Wait /^\$$/
Type "git status --short"
Enter
Wait /^\$$/
Sleep 2s
Type "draugr tools install --yes"
Enter
Wait@600s /^\$$/
Sleep 2s
Type "draugr scan ."
Enter
Wait@600s /^\$$/
Sleep 6s

# 2. Declare what each part is
Type "clear"
Enter
Type "# 2. Declare what each part is"
Enter
Sleep 1.5s
Type "mv draugr.saga.yaml.aside draugr.saga.yaml"
Enter
Wait /^\$$/
Type "draugr tools install --yes"
Enter
Wait@600s /^\$$/
Sleep 1.5s
Type "draugr feeds update"
Enter
Wait@300s /^\$$/
Sleep 2s
Type "sed -i.bak -e '/^ *exposure:/d' -e '/^ *criticality:/d' draugr.saga.yaml .draugr/components/platform.saga-fragment.yaml"
Enter
Wait /^\$$/
Type "git status --short"
Enter
Wait /^\$$/
Sleep 2s
Type "draugr scan --no-publish --report sarif -o before"
Enter
Wait@600s /^\$$/
Sleep 6s
Type "mv draugr.saga.yaml.bak draugr.saga.yaml"
Enter
Wait /^\$$/
Type "mv .draugr/components/platform.saga-fragment.yaml.bak .draugr/components/platform.saga-fragment.yaml"
Enter
Wait /^\$$/
Type "git status --short"
Enter
Wait /^\$$/
Sleep 2s
Type "draugr scan --no-publish --report sarif -o after --top 1"
Enter
Wait@600s /^\$$/
Sleep 6s
Type "clear"
Enter
Type "draugr diff before/results.sarif after/results.sarif"
Enter
Wait /^\$$/
Sleep 8s

# 3. Read a finding
Type "clear"
Enter
Type "# 3. Read a finding"
Enter
Sleep 1.5s
Type "draugr scan --no-publish --report html -o out"
Enter
Wait@600s /^\$$/
Sleep 4s

# 4. Gate pull requests
Type "clear"
Enter
Type "# 4. Gate pull requests"
Enter
Sleep 1.5s
Type "draugr diff before/results.sarif after/results.sarif --format markdown"
Enter
Wait /^\$$/
Sleep 6s
Type "clear"
Enter
Type "draugr diff before/results.sarif after/results.sarif --fail-on-new P1 --view compact --top 1"
Enter
Wait /^\$$/
Sleep 4s
Type "echo $?"
Enter
Wait /^\$$/
Sleep 4s

# Not on the page: the day the scanners' data came from, since a later day prints different counts.
Type "draugr doctor | grep 'trivy vulnerability database'"
Enter
Wait@120s /^\$$/
Sleep 5s
