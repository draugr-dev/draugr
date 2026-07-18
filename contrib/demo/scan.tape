# vhs tape for the README demo GIF of zero-config `draugr scan .`.
# Render:  vhs contrib/demo/scan.tape   → contrib/demo/scan.gif
#
# Prerequisites (so the GIF shows real, prioritized findings quickly):
#   - `draugr` on PATH (a release build)
#   - the scanners installed:  draugr tools install -y   (Trivy, Gitleaks) + Semgrep via pipx
#   - run from a findings-rich repo — the draugr-demo sandbox is ideal:
#       git clone https://github.com/draugr-dev/draugr-demo && cd draugr-demo
#
# See charmbracelet/vhs for install. A CI job (charmbracelet/vhs-action) can regenerate this
# on demand and commit contrib/demo/scan.gif.

Output contrib/demo/scan.gif

Set Shell bash
Set FontSize 18
Set Width 1200
Set Height 700
Set Theme "Dracula"
Set Padding 20

Type "draugr scan ."
Sleep 800ms
Enter
Sleep 8s
