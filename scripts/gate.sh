#!/usr/bin/env bash
# Local quality gate — mirrors CI so failures are caught before pushing.
# Runs formatting, vet, lint, race tests + coverage, and vulnerability scan.
set -euo pipefail

cd "$(dirname "$0")/.."

echo "▶ gofmt"
unformatted="$(gofmt -l .)"
if [ -n "$unformatted" ]; then
	echo "  not gofmt-formatted:"
	echo "$unformatted"
	exit 1
fi

echo "▶ go mod tidy"
# CI fails the build when go.mod and go.sum are not what `go mod tidy` would write, and the
# usual way to get there is importing a package that was previously an indirect dependency —
# which builds and tests perfectly well right up until the pipeline says otherwise. Checked
# here so the gate covers what CI covers.
tidy_before=$(cat go.mod go.sum)
go mod tidy
if [ "$tidy_before" != "$(cat go.mod go.sum)" ]; then
	echo "  go.mod/go.sum were not tidy — updated in place. Review and commit:" >&2
	git --no-pager diff --stat -- go.mod go.sum >&2
	exit 1
fi

echo "▶ go vet"
go vet ./...

echo "▶ golangci-lint"
# Always use a fresh cache: the persistent golangci-lint cache can report false
# passes locally that then fail in CI (e.g. staticcheck SA4000/QF1001).
if command -v golangci-lint >/dev/null 2>&1; then
	GOLANGCI_LINT_CACHE="$(mktemp -d)" golangci-lint run ./...
else
	echo "  golangci-lint not installed — skipping (CI still enforces it)"
fi

echo "▶ go test (race + coverage)"
go test -race -covermode=atomic -coverprofile=coverage.out ./...

echo "▶ self-scan (sast)"
# Draugr on Draugr, before pushing. Scoped to `sast` because that is the control that reads the
# code you just changed — sca and licenses answer questions about go.mod, which CI can have.
#
# --working-tree, and it is the whole point: without it the scan reads the committed revision and
# says nothing about what you are about to commit, which is the one thing a pre-push check is for.
#
# Semgrep is the reason this earns its four seconds. gosec is already covered by golangci-lint
# above, faster and with no extra install; semgrep is covered nowhere else, so a finding it
# raises is currently first seen in CI.
#
# Skipped rather than fatal when the pieces are missing, and it says which piece: this is the one
# check here that needs tools beyond the Go toolchain, and a contributor should not have to
# install Semgrep to run the tests.
# bin/draugr, never one on PATH. A gate is a claim about the code in front of you, and an
# installed Draugr is whatever release somebody last downloaded — the one on this machine is nine
# versions behind and does not have the flag below. Checking HEAD with an old binary would answer
# a question nobody asked.
if [ -x bin/draugr ]; then
	if command -v semgrep >/dev/null 2>&1 || command -v gosec >/dev/null 2>&1; then
		bin/draugr scan .draugr/self.saga.yaml --controls sast --working-tree --no-tips
	else
		echo "  no sast scanner found — skipping (pipx install semgrep, or draugr tools install gosec)"
	fi
else
	echo "  bin/draugr not built — skipping (run: make build)"
fi

echo "▶ no-conflict-markers"
./scripts/check-no-conflict-markers.sh

echo "▶ doc-anchors"
./scripts/check-doc-anchors.py

echo "▶ public-scope"
./scripts/check-public-scope.sh

echo "▶ no-defect-recounts"
./scripts/check-no-defect-recounts.sh

echo "▶ changelog"
./scripts/changelog.sh check

echo "▶ govulncheck"
if command -v govulncheck >/dev/null 2>&1; then
	govulncheck ./...
else
	echo "  govulncheck not installed — skipping (CI still enforces it)"
fi

echo "✓ gate passed"
