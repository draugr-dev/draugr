package scanners

import (
	"strings"
	"testing"
)

// guardedSuExec is the entrypoint of a Go service on Alpine: started as root it fixes the data
// directory's owner and hands over to PUID and PGID, and started as anyone else it runs the command.
const guardedSuExec = `#!/bin/sh
set -e

PUID=${PUID:-1000}
PGID=${PGID:-1000}

if [ "$(id -u)" = "0" ]; then
  # Make the data directory the user's.
  mkdir -p /data
  chown -R "$PUID:$PGID" /data
  exec su-exec "$PUID:$PGID" "$@"
fi
exec "$@"
`

// Each command that starts a program as another user counts, with the user it names and the line it
// is on.
func TestEveryDropCommandCounts(t *testing.T) {
	for name, tc := range map[string]struct {
		script, command, user string
		line                  int
	}{
		"su-exec":           {"#!/bin/sh\nchown -R app /data\nexec su-exec app \"$@\"\n", "su-exec", "app", 3},
		"gosu":              {"#!/bin/bash\nset -euo pipefail\nexec gosu postgres:postgres postgres \"$@\"\n", "gosu", "postgres:postgres", 3},
		"setpriv":           {"#!/bin/sh\nexec setpriv --reuid=1000 --regid=1000 --init-groups -- /app/server\n", "setpriv", "1000", 2},
		"setpriv spaced":    {"#!/bin/sh\nexec setpriv --reuid app --regid app --clear-groups /app/server\n", "setpriv", "app", 2},
		"runuser":           {"#!/bin/sh\nexec runuser -u node -- node server.js\n", "runuser", "node", 2},
		"runuser long":      {"#!/bin/sh\nexec /sbin/runuser --user=node -g node node server.js\n", "runuser", "node", 2},
		"s6-setuidgid":      {"#!/bin/sh\nexec s6-setuidgid app /app/run\n", "s6-setuidgid", "app", 2},
		"chpst":             {"#!/bin/sh\nexec chpst -u app:app -U app /app/run\n", "chpst", "app:app", 2},
		"chpst numeric":     {"#!/bin/sh\nexec chpst -u :1000:1000 /app/run\n", "chpst", "1000:1000", 2},
		"env shebang":       {"#!/usr/bin/env bash\nexec su-exec app \"$@\"\n", "su-exec", "app", 2},
		"setup before":      {"#!/bin/sh\nif ! getent passwd app >/dev/null; then\n  adduser -D app\nfi\nfind /data ! -user app -exec chown app {} +\ngosu app /app/migrate\nexec gosu app /app/server\n", "gosu", "app", 7},
		"guard":             {guardedSuExec, "su-exec", "$PUID:$PGID", 11},
		"guard -eq":         {"#!/bin/sh\nif [ $(id -u) -eq 0 ]; then\n  exec su-exec app \"$@\"\nfi\nexec \"$@\"\n", "su-exec", "app", 3},
		"guard reversed":    {"#!/bin/sh\nif [ 0 = \"`id -u`\" ]; then exec gosu app \"$@\"; fi\nexec \"$@\"\n", "gosu", "app", 2},
		"guard brackets":    {"#!/bin/bash\nif [[ \"$(id -u)\" == 0 ]]; then\n  exec gosu app \"$@\"\nfi\nexec \"$@\"\n", "gosu", "app", 3},
		"guard test":        {"#!/bin/sh\nif test \"$(id -u)\" -eq 0; then\n  exec gosu app \"$@\"\nelse\n  exec \"$@\"\nfi\n", "gosu", "app", 3},
		"guard one line":    {"#!/bin/sh\n[ \"$(id -u)\" = 0 ] && exec su-exec app \"$@\"\nexec \"$@\"\n", "su-exec", "app", 2},
		"not root first":    {"#!/bin/sh\nif [ \"$(id -u)\" != \"0\" ]; then\n  exec \"$@\"\nfi\nchown app /data\nexec su-exec app \"$@\"\n", "su-exec", "app", 6},
		"not root one line": {"#!/bin/sh\n[ \"$(id -u)\" -ne 0 ] && exec \"$@\"\nexec su-exec app \"$@\"\n", "su-exec", "app", 3},
		"negated guard":     {"#!/bin/sh\nif ! [ \"$(id -u)\" = 0 ]; then exec \"$@\"; fi\nexec su-exec app \"$@\"\n", "su-exec", "app", 3},
		"exit on a path":    {"#!/bin/sh\nif [ -z \"$PUID\" ]; then\n  echo \"set PUID\" >&2\n  exit 1\nfi\nexec su-exec \"$PUID\" \"$@\"\n", "su-exec", "$PUID", 6},
		"case":              {"#!/bin/sh\ncase \"$1\" in\n  -*) set -- server \"$@\" ;;\n  *) ;;\nesac\nexec su-exec app \"$@\"\n", "su-exec", "app", 6},
		"case, every arm":   {"#!/bin/sh\ncase \"$1\" in\n  (a|b) exec su-exec app sh ;;\n  (*) exec su-exec app \"$@\"\nesac\n", "su-exec", "app", 3},
		"heredoc":           {"#!/bin/sh\ncat > /etc/app.conf <<EOF\nexec nginx\nEOF\nexec su-exec app \"$@\"\n", "su-exec", "app", 5},
		"redirect only":     {"#!/bin/sh\nexec 2>&1\nexec su-exec app \"$@\"\n", "su-exec", "app", 3},
		"both branches":     {"#!/bin/sh\nif [ -n \"$DEBUG\" ]; then\n  exec su-exec app sh -x /app/run\nelse\n  exec su-exec app /app/run\nfi\n", "su-exec", "app", 3},
	} {
		t.Run(name, func(t *testing.T) {
			got, ok := scriptDrop(tc.script)
			if !ok {
				t.Fatalf("no drop read from\n%s", tc.script)
			}
			if got.command != tc.command || got.user != tc.user || got.line != tc.line {
				t.Errorf("drop %+v, want %s to %s on line %d", got, tc.command, tc.user, tc.line)
			}
		})
	}
}

// A script that leaves any path a start as root takes without a drop, or does something beside the
// drop this reading cannot vouch for, is no evidence.
func TestAScriptThatMayRunAsRootIsNoEvidence(t *testing.T) {
	for name, script := range map[string]string{
		"behind another condition": "#!/bin/sh\nif [ \"$1\" = server ]; then\n  exec su-exec app \"$@\"\nfi\nexec \"$@\"\n",
		"guard and a condition":    "#!/bin/sh\nif [ \"$1\" = postgres ] && [ \"$(id -u)\" = 0 ]; then\n  exec gosu postgres \"$@\"\nfi\nexec \"$@\"\n",
		"one arm of a case":        "#!/bin/sh\ncase \"$1\" in\n  server) exec su-exec app \"$@\" ;;\nesac\nexec \"$@\"\n",
		"one line, unrelated":      "#!/bin/sh\n[ -n \"$PUID\" ] && exec su-exec \"$PUID\" \"$@\"\nexec \"$@\"\n",
		"to root":                  "#!/bin/sh\nexec su-exec root \"$@\"\n",
		"to uid 0":                 "#!/bin/sh\nexec gosu 0:0 \"$@\"\n",
		"to 0 by default":          "#!/bin/sh\nexec su-exec \"${PUID:-0}:${PGID:-0}\" \"$@\"\n",
		"setpriv to root":          "#!/bin/sh\nexec setpriv --reuid=0 --init-groups /app/run\n",
		"setpriv without reuid":    "#!/bin/sh\nexec setpriv --regid=1000 --init-groups /app/run\n",
		"chpst to root":            "#!/bin/sh\nexec chpst -u :0:0 /app/run\n",
		"runuser su style":         "#!/bin/sh\nexec runuser -l app -c /app/run\n",
		"drop with no command":     "#!/bin/sh\nexec su-exec app\n",
		"exec before the guard":    "#!/bin/sh\nexec \"$@\"\nif [ \"$(id -u)\" = 0 ]; then exec su-exec app \"$@\"; fi\n",
		"no exec":                  "#!/bin/sh\nsu-exec app /app/run\n",
		"falls off the end":        "#!/bin/sh\nchown app /data\n",
		"a daemon first":           "#!/bin/sh\nnginx\nexec su-exec app \"$@\"\n",
		"in the background":        "#!/bin/sh\ncrond &\nexec su-exec app \"$@\"\n",
		"a drop in the background": "#!/bin/sh\nsu-exec app /app/worker &\nexec su-exec app \"$@\"\n",
		"sources a script":         "#!/bin/sh\n. /docker-entrypoint.d/env.sh\nexec su-exec app \"$@\"\n",
		"calls a function":         "#!/bin/sh\nsetup() {\n  nginx\n}\nsetup\nexec su-exec app \"$@\"\n",
		"a command in a variable":  "#!/bin/sh\n$PREPARE\nexec su-exec app \"$@\"\n",
		"exec in a pipeline":       "#!/bin/sh\nexec su-exec app /app/run | tee /log\n",
		"a loop runs it":           "#!/bin/sh\nfor f in /init/*; do \"$f\"; done\nexec su-exec app \"$@\"\n",
		"no shebang":               "exec su-exec app \"$@\"\n",
		"another interpreter":      "#!/usr/bin/python3\nexec su-exec app \"$@\"\n",
		"unclosed quote":           "#!/bin/sh\necho \"oops\nexec su-exec app \"$@\n",
		"unclosed if":              "#!/bin/sh\nif [ \"$(id -u)\" = 0 ]; then\n  exec su-exec app \"$@\"\n",
		"unclosed heredoc":         "#!/bin/sh\ncat <<EOF\nexec su-exec app \"$@\"\n",
		"guard in an elif":         "#!/bin/sh\nif [ -n \"$X\" ]; then\n  exec \"$@\"\nelif [ \"$(id -u)\" = 0 ]; then\n  exec su-exec app \"$@\"\nfi\nexec \"$@\"\n",
		"a function keyword":       "#!/bin/bash\nfunction prep {\n  chown app /data\n}\nprep\nexec su-exec app \"$@\"\n",
		"a function with parens":   "#!/bin/bash\nfunction prep() { :; }\nprep\nexec su-exec app \"$@\"\n",
		"exit in a subshell":       "#!/bin/sh\n( exit 0 )\n",
		"a while loop condition":   "#!/bin/sh\nwhile pgrep db; do sleep 1; done\nexec su-exec app \"$@\"\n",
		"case without in":          "#!/bin/sh\ncase \"$1\"\n  x) ;;\nesac\nexec su-exec app \"$@\"\n",
		"case without esac":        "#!/bin/sh\ncase \"$1\" in\n  x) exec su-exec app \"$@\"\n",
		"case with a bad pattern":  "#!/bin/sh\ncase \"$1\" in\n  ;;\nesac\n",
		"while without do":         "#!/bin/sh\nwhile true; exec su-exec app \"$@\"; done\n",
		"for without do":           "#!/bin/sh\nfor x in a b; exec su-exec app \"$@\"; done\n",
		"for with a bad name":      "#!/bin/sh\nfor ; do :; done\n",
		"unclosed subshell":        "#!/bin/sh\n( chown app /data\nexec su-exec app \"$@\"\n",
		"unclosed group":           "#!/bin/sh\n{ chown app /data\nexec su-exec app \"$@\"\n",
		"unclosed backtick":        "#!/bin/sh\nX=`id -u\nexec su-exec app \"$@\"\n",
		"unclosed substitution":    "#!/bin/sh\nX=$(id -u\nexec su-exec app \"$@\"\n",
		"unclosed single quote":    "#!/bin/sh\necho 'oops\nexec su-exec app \"$@\"\n",
		"unclosed $( in quotes":    "#!/bin/sh\necho \"$(id -u\"\nexec su-exec app \"$@\"\n",
		"an operator first":        "#!/bin/sh\n| exec su-exec app \"$@\"\n",
		"empty shebang":            "#!\nexec su-exec app \"$@\"\n",
		"heredoc, no delimiter":    "#!/bin/sh\ncat <<\nexec su-exec app \"$@\"\n",
		"setpriv unknown option":   "#!/bin/sh\nexec setpriv --dump --reuid=1000 /app/run\n",
		"setpriv missing value":    "#!/bin/sh\nexec setpriv --reuid\n",
		"runuser unknown option":   "#!/bin/sh\nexec runuser -x -u app /app/run\n",
		"runuser missing value":    "#!/bin/sh\nexec runuser -u\n",
		"chpst unknown option":     "#!/bin/sh\nexec chpst -Z -u app /app/run\n",
		"chpst missing value":      "#!/bin/sh\nexec chpst -u\n",
		"find runs a daemon":       "#!/bin/sh\nfind /init -exec nginx \\;\nexec su-exec app \"$@\"\n",
		"command runs a program":   "#!/bin/sh\ncommand nginx\nexec su-exec app \"$@\"\n",
	} {
		t.Run(name, func(t *testing.T) {
			if got, ok := scriptDrop(script); ok {
				t.Errorf("drop %+v read from\n%s", got, script)
			}
		})
	}
}

// The other branch of a guard is never root, so whatever it runs leaves the evidence standing; the
// branches past a negated guard are read as root's.
func TestTheGuardDecidesWhichBranchIsRoot(t *testing.T) {
	nonRootRunsAnything := "#!/bin/sh\nif [ \"$(id -u)\" -ne 0 ]; then\n  nginx &\n  exec \"$@\"\nelif [ -n \"$X\" ]; then\n  exec su-exec app sh\nelse\n  exec su-exec app \"$@\"\nfi\n"
	if got, ok := scriptDrop(nonRootRunsAnything); !ok || got.line != 6 {
		t.Errorf("drop %+v (%v), want the elif's su-exec on line 6", got, ok)
	}
	rootElse := "#!/bin/sh\nif [ \"$(id -u)\" != 0 ]; then\n  exec \"$@\"\nelse\n  exec \"$@\"\nfi\n"
	if got, ok := scriptDrop(rootElse); ok {
		t.Errorf("drop %+v, want none: root's branch runs the command as root", got)
	}
}

// The parts of the shell an entrypoint uses beside the drop are read without losing the drop.
func TestShellShapesAroundTheDropAreRead(t *testing.T) {
	script := strings.Join([]string{
		"#!/bin/sh",
		"set -eu",
		"umask 022",
		`trap 'echo stopped' TERM`,
		"log() { echo \"$@\" >&2; }",
		"while read -r line; do echo \"$line\"; done < /etc/motd",
		"{ echo a; echo b; } > /tmp/x",
		"( cd /app && ls )",
		"for d in /data /cache; do mkdir -p \"$d\"; done",
		"until true; do sleep 1; done",
		"command -v su-exec >/dev/null || exit 1",
		`X="a;b|c" Y='d&e' Z=$(echo "$(id -u)")`,
		"echo \"${X:-$(date +%s)}\" `id -u` 2>/dev/null",
		"cat <<-'END' >/dev/null",
		"\texec bash",
		"\tEND",
		"[[ -d /data && -w /data ]] || mkdir /data",
		"exec su-exec app \\",
		"  \"$@\"",
	}, "\n") + "\n"
	got, ok := scriptDrop(script)
	if !ok || got.command != "su-exec" || got.line != 18 {
		t.Errorf("drop %+v (%v), want su-exec on line 18", got, ok)
	}
}
