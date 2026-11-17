package scanners

import (
	"context"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/git"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// rootUserSARIF is Trivy's SARIF with DS-0002 on each Dockerfile named, and DS-0026 on the first.
func rootUserSARIF(dockerfiles ...string) string {
	results := []string{trivySARIFAt("DS-0026", dockerfiles[0], 1)}
	for _, d := range dockerfiles {
		results = append(results, trivySARIFAt("DS-0002", d, 1))
	}
	return `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Trivy"}},"results":[` + strings.Join(results, ",") + `]}]}`
}

// dropsIn reads the privilegeDrop of each result of SARIF, keyed by rule and file.
func dropsIn(t *testing.T, out []byte) map[string]*sarif.PrivilegeDrop {
	t.Helper()
	rep, err := sarif.FromSARIF(out)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]*sarif.PrivilegeDrop{}
	for _, r := range rep.Results {
		got[r.RuleID+"@"+r.Location.URI] = r.PrivilegeDrop
	}
	return got
}

// entrypointDropFor is withEntrypointDrops over a checkout holding files, for DS-0002 on dockerfile.
func entrypointDropFor(t *testing.T, files map[string]string, dockerfile string) *sarif.PrivilegeDrop {
	t.Helper()
	out, err := withEntrypointDrops([]byte(rootUserSARIF(dockerfile)), writeTree(t, files))
	if err != nil {
		t.Fatal(err)
	}
	got := dropsIn(t, out)
	if got["DS-0026@"+dockerfile] != nil {
		t.Errorf("DS-0026 carries %+v, want evidence only on DS-0002", got["DS-0026@"+dockerfile])
	}
	return got["DS-0002@"+dockerfile]
}

// The DS-0002 finding of an image whose copied entrypoint drops root carries the line that drops it,
// in the script's place in the repository.
func TestARootImageWhoseEntrypointDropsRootCarriesTheLine(t *testing.T) {
	for name, tc := range map[string]struct {
		files      map[string]string
		dockerfile string
		want       sarif.PrivilegeDrop
	}{
		"into a directory": {map[string]string{
			"Dockerfile": "FROM golang:1.26 AS build\nRUN go build -o /out/app .\n\nFROM alpine:3.22\n" +
				"RUN apk add --no-cache su-exec\nCOPY --from=build /out/app /usr/local/bin/app\n" +
				"COPY entrypoint.sh /usr/local/bin/\nRUN chmod +x /usr/local/bin/entrypoint.sh\n" +
				"ENTRYPOINT [\"/usr/local/bin/entrypoint.sh\"]\nCMD [\"app\"]\n",
			"entrypoint.sh": guardedSuExec,
		}, "Dockerfile", sarif.PrivilegeDrop{Command: "su-exec", User: "$PUID:$PGID", File: "entrypoint.sh", Line: 11}},
		"to a file, shell form": {map[string]string{
			"Dockerfile":         "FROM debian:12\nCOPY --chmod=755 scripts/start.sh /start.sh\nENTRYPOINT /start.sh\n",
			"scripts/start.sh":   "#!/bin/sh\nexec setpriv --reuid=app --regid=app --init-groups \"$@\"\n",
			"scripts/unused.sh":  "#!/bin/sh\nexec \"$@\"\n",
			"docs/Dockerfile.md": "not read",
		}, "Dockerfile", sarif.PrivilegeDrop{Command: "setpriv", User: "app", File: "scripts/start.sh", Line: 2}},
		"the whole context, relative": {map[string]string{
			"Dockerfile":           "FROM node:24\nWORKDIR /app\nCOPY . .\nENTRYPOINT [\"./docker/entrypoint.sh\"]\n",
			"docker/entrypoint.sh": "#!/bin/bash\nchown -R node /app/data\nexec runuser -u node -- \"$@\"\n",
		}, "Dockerfile", sarif.PrivilegeDrop{Command: "runuser", User: "node", File: "docker/entrypoint.sh", Line: 3}},
		"CMD without ENTRYPOINT": {map[string]string{
			"Dockerfile": "FROM alpine\nCOPY run /etc/s6/app/run\nCMD [\"/etc/s6/app/run\"]\n",
			"run":        "#!/bin/sh\nexec s6-setuidgid app /app/server\n",
		}, "Dockerfile", sarif.PrivilegeDrop{Command: "s6-setuidgid", User: "app", File: "run", Line: 2}},
		"context is the Dockerfile's directory": {map[string]string{
			"deploy/Dockerfile.aio": "FROM node:24\n# syntax comment\nCOPY entrypoint.sh \\\n  /entrypoint.sh\nENTRYPOINT [\"/entrypoint.sh\"]\n",
			"deploy/entrypoint.sh":  "#!/bin/sh\nexec chpst -u node node /app/index.js\n",
		}, "deploy/Dockerfile.aio", sarif.PrivilegeDrop{Command: "chpst", User: "node", File: "deploy/entrypoint.sh", Line: 2}},
		"context is the repository root": {map[string]string{
			"build/Dockerfile":    "FROM node:24\nCOPY build/entrypoint.sh /entrypoint.sh\nENTRYPOINT [\"/entrypoint.sh\"]\n",
			"build/entrypoint.sh": "#!/bin/sh\nexec gosu node \"$@\"\n",
		}, "build/Dockerfile", sarif.PrivilegeDrop{Command: "gosu", User: "node", File: "build/entrypoint.sh", Line: 2}},
	} {
		t.Run(name, func(t *testing.T) {
			got := entrypointDropFor(t, tc.files, tc.dockerfile)
			if got == nil || *got != tc.want {
				t.Errorf("privilegeDrop %+v, want %+v", got, tc.want)
			}
		})
	}
}

// The evidence is only what the Dockerfile copies in and starts: a script it does not copy, one an
// earlier stage starts, or one something else may have replaced is no evidence.
func TestAnEntrypointTheImageMayNotRunIsNoEvidence(t *testing.T) {
	drops := "#!/bin/sh\nexec su-exec app \"$@\"\n"
	for name, files := range map[string]map[string]string{
		"not copied": {
			"Dockerfile":    "FROM alpine\nENTRYPOINT [\"/entrypoint.sh\"]\n",
			"entrypoint.sh": drops,
		},
		"an earlier stage's entrypoint": {
			"Dockerfile":    "FROM alpine AS base\nCOPY entrypoint.sh /entrypoint.sh\nENTRYPOINT [\"/entrypoint.sh\"]\n\nFROM base\nRUN apk add curl\n",
			"entrypoint.sh": drops,
		},
		"copied in an earlier stage": {
			"Dockerfile":    "FROM alpine AS base\nCOPY entrypoint.sh /entrypoint.sh\n\nFROM base\nENTRYPOINT [\"/entrypoint.sh\"]\n",
			"entrypoint.sh": drops,
		},
		"replaced from another stage": {
			"Dockerfile":    "FROM alpine AS gen\nRUN echo > /e.sh\nFROM alpine\nCOPY entrypoint.sh /entrypoint.sh\nCOPY --from=gen /e.sh /entrypoint.sh\nENTRYPOINT [\"/entrypoint.sh\"]\n",
			"entrypoint.sh": drops,
		},
		"edited after the copy": {
			"Dockerfile":    "FROM alpine\nCOPY entrypoint.sh /entrypoint.sh\nRUN sed -i 's/su-exec app//' /entrypoint.sh\nENTRYPOINT [\"/entrypoint.sh\"]\n",
			"entrypoint.sh": drops,
		},
		"a wildcard": {
			"Dockerfile":    "FROM alpine\nCOPY *.sh /\nENTRYPOINT [\"/entrypoint.sh\"]\n",
			"entrypoint.sh": drops,
		},
		"a variable in the path": {
			"Dockerfile":    "FROM alpine\nARG DIR=/\nCOPY entrypoint.sh $DIR\nENTRYPOINT [\"/entrypoint.sh\"]\n",
			"entrypoint.sh": drops,
		},
		"looked up on PATH": {
			"Dockerfile":    "FROM alpine\nCOPY entrypoint.sh /usr/local/bin/\nENTRYPOINT [\"entrypoint.sh\"]\n",
			"entrypoint.sh": drops,
		},
		"a shell form a shell expands": {
			"Dockerfile":    "FROM alpine\nCOPY entrypoint.sh /entrypoint.sh\nENTRYPOINT /entrypoint.sh $ARGS\n",
			"entrypoint.sh": drops,
		},
		"another shell": {
			"Dockerfile":    "FROM alpine\nSHELL [\"/bin/bash\", \"-c\"]\nCOPY entrypoint.sh /entrypoint.sh\nENTRYPOINT /entrypoint.sh\n",
			"entrypoint.sh": drops,
		},
		"a relative path under a variable WORKDIR": {
			"Dockerfile":    "FROM alpine\nWORKDIR $HOME\nCOPY entrypoint.sh .\nENTRYPOINT [\"./entrypoint.sh\"]\n",
			"entrypoint.sh": drops,
		},
		"a heredoc": {
			"Dockerfile":    "FROM alpine\nCOPY entrypoint.sh /entrypoint.sh\nRUN <<EOF\nENTRYPOINT [\"/entrypoint.sh\"]\nEOF\n",
			"entrypoint.sh": drops,
		},
		"another escape character": {
			"Dockerfile":    "# escape=`\nFROM alpine\nCOPY entrypoint.sh /entrypoint.sh\nENTRYPOINT [\"/entrypoint.sh\"]\n",
			"entrypoint.sh": drops,
		},
		"no entrypoint": {
			"Dockerfile":    "FROM alpine\nCOPY entrypoint.sh /entrypoint.sh\n",
			"entrypoint.sh": drops,
		},
		"no FROM": {
			"Dockerfile":    "COPY entrypoint.sh /entrypoint.sh\nENTRYPOINT [\"/entrypoint.sh\"]\n",
			"entrypoint.sh": drops,
		},
		"the script does not drop root": {
			"Dockerfile":    "FROM alpine\nCOPY entrypoint.sh /entrypoint.sh\nENTRYPOINT [\"/entrypoint.sh\"]\n",
			"entrypoint.sh": "#!/bin/sh\nexec \"$@\"\n",
		},
		"a directory at the path": {
			"Dockerfile":       "FROM alpine\nCOPY entrypoint.sh /entrypoint.sh/\nENTRYPOINT [\"/entrypoint.sh\"]\n",
			"entrypoint.sh/go": drops,
		},
		"two contexts that disagree": {
			"svc/Dockerfile":    "FROM alpine\nCOPY entrypoint.sh /entrypoint.sh\nENTRYPOINT [\"/entrypoint.sh\"]\n",
			"svc/entrypoint.sh": drops,
			"entrypoint.sh":     "#!/bin/sh\nexec \"$@\"\n",
		},
	} {
		t.Run(name, func(t *testing.T) {
			dockerfile := "Dockerfile"
			if _, ok := files["svc/Dockerfile"]; ok {
				dockerfile = "svc/Dockerfile"
			}
			if got := entrypointDropFor(t, files, dockerfile); got != nil {
				t.Errorf("privilegeDrop %+v, want none", got)
			}
		})
	}
}

// The older id Trivy wrote the check under is read too, and a path outside the checkout or a file
// that is not there leaves the SARIF as it was.
func TestEntrypointDropsReadOnlyTheCheckout(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"Dockerfile":    "FROM alpine\nCOPY entrypoint.sh /entrypoint.sh\nENTRYPOINT [\"/entrypoint.sh\"]\n",
		"entrypoint.sh": "#!/bin/sh\nexec su-exec app \"$@\"\n",
	})
	in := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Trivy"}},"results":[` +
		strings.Join([]string{trivySARIFAt("DS002", "Dockerfile", 1), trivySARIFAt("DS-0002", "../Dockerfile", 1),
			trivySARIFAt("DS-0002", dir+"/Dockerfile", 1), trivySARIFAt("DS-0002", "missing/Dockerfile", 1)}, ",") + `]}]}`
	out, err := withEntrypointDrops([]byte(in), dir)
	if err != nil {
		t.Fatal(err)
	}
	got := dropsIn(t, out)
	if got["DS002@Dockerfile"] == nil {
		t.Error("DS002 carries no privilegeDrop, want the older id read as DS-0002")
	}
	if got["DS-0002@"+dir+"/Dockerfile"] == nil {
		t.Error("an absolute path inside the checkout carries no privilegeDrop")
	}
	if got["DS-0002@../Dockerfile"] != nil || got["DS-0002@missing/Dockerfile"] != nil {
		t.Errorf("a Dockerfile outside the checkout or missing carries evidence: %+v", got)
	}

	for name, sarifIn := range map[string]string{
		"no DS-0002":   `{"runs":[{"results":[` + trivySARIFAt("DS-0026", "Dockerfile", 1) + `]}]}`,
		"no checkout":  rootUserSARIF("Dockerfile"),
		"no locations": `{"runs":[{"results":[{"ruleId":"DS-0002"}]}]}`,
	} {
		d := dir
		if name == "no checkout" {
			d = dir + "/absent"
		}
		out, err := withEntrypointDrops([]byte(sarifIn), d)
		if err != nil || string(out) != sarifIn {
			t.Errorf("%s: SARIF changed (%v)", name, err)
		}
	}
	if _, err := withEntrypointDrops([]byte(`{"runs": DS`), dir); err == nil {
		t.Error("unreadable SARIF read as nothing to add")
	}
}

// Each repository's finding carries its own script's evidence: the scanner reads the checkout it ran
// over, so of two repositories with the same Dockerfile path, only the one whose script drops root
// carries it.
func TestEachRepositoryCarriesItsOwnEntrypointEvidence(t *testing.T) {
	was := sharedTrivyVersion.val
	t.Cleanup(func() { sharedTrivyVersion.val = was })
	sharedTrivyVersion.val = "trivy@0.76.1;db@2026-11-16T00:00:00Z"

	dockerfile := "FROM alpine\nCOPY entrypoint.sh /entrypoint.sh\nENTRYPOINT [\"/entrypoint.sh\"]\n"
	dirs := map[string]string{
		"drops": writeTree(t, map[string]string{"Dockerfile": dockerfile, "entrypoint.sh": guardedSuExec}),
		"root":  writeTree(t, map[string]string{"Dockerfile": dockerfile, "entrypoint.sh": "#!/bin/sh\nexec \"$@\"\n"}),
	}
	for repo, dir := range dirs {
		s := NewTrivyConfig().(repoScanner)
		s.checkout = func(context.Context, string, string, git.Scope) (git.Tree, func(), error) {
			return git.Tree{Dir: dir}, func() {}, nil
		}
		s.runLogged = trivyConfigRun(func(_ context.Context, _ string, argv []string) ([]byte, []byte, error) {
			if argv[1] == "fs" {
				return []byte(`{"Results": []}`), nil, nil
			}
			return []byte(rootUserSARIF("Dockerfile")), nil, nil
		})
		rep, err := s.Scan(context.Background(), plugin.RepositoryTarget{URL: repo}, nil)
		if err != nil {
			t.Fatal(err)
		}
		var drop *sarif.PrivilegeDrop
		for _, r := range rep.Results {
			if r.RuleID == "DS-0002" {
				drop = r.PrivilegeDrop
			}
		}
		switch {
		case repo == "drops" && (drop == nil || drop.File != "entrypoint.sh" || drop.Line != 11):
			t.Errorf("%s: privilegeDrop %+v, want su-exec in entrypoint.sh:11", repo, drop)
		case repo == "root" && drop != nil:
			t.Errorf("%s: privilegeDrop %+v, want none", repo, drop)
		}
	}

	// An older Trivy writes SARIF itself, and the evidence is added to it the same way.
	sharedTrivyVersion.val = "trivy@0.52.0;db@2026-11-16T00:00:00Z"
	out, _, err := trivyConfigRun(func(context.Context, string, []string) ([]byte, []byte, error) {
		return []byte(rootUserSARIF("Dockerfile")), nil, nil
	})(context.Background(), dirs["drops"], trivyConfigArgs(dirs["drops"], nil))
	if err != nil {
		t.Fatal(err)
	}
	if got := dropsIn(t, out)["DS-0002@Dockerfile"]; got == nil {
		t.Error("an older Trivy's DS-0002 carries no privilegeDrop")
	}
}
