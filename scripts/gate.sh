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

echo "▶ govulncheck"
if command -v govulncheck >/dev/null 2>&1; then
	govulncheck ./...
else
	echo "  govulncheck not installed — skipping (CI still enforces it)"
fi

echo "✓ gate passed"
