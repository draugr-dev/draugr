#!/usr/bin/env bash
# A Go service with a Dockerfile, under the descriptor `draugr init` writes for it: config.detect and
# no controls. A reader of the YAML alone sees no control enabled; the scan turns on sca, secrets and
# sast, gosec and govulncheck for the go.mod, and iac for the Dockerfile.
. "$(dirname "${BASH_SOURCE[0]}")/../fixture.sh"
printf 'module shop\n\ngo 1.22\n' >go.mod
printf 'package main\n\nfunc main() {}\n' >main.go
printf 'FROM alpine:3.20\nCOPY . /app\n' >Dockerfile
cat >draugr.saga.yaml <<'YAML'
project: shop
config:
  detect: true
components:
  - name: shop
    repositories:
      - url: .
YAML
git_ init -q -b main
git_ add go.mod main.go Dockerfile draugr.saga.yaml
git_ commit -q -m "A Go service"
