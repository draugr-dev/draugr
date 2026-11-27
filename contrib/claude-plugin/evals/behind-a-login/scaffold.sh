#!/usr/bin/env bash
# The web component is declared internal. The schema's exposure values are public (internet-facing,
# no authentication), authenticated (internet-facing, behind authentication), internal and
# restricted, so a service on the internet behind a sign-in is authenticated, and public, the word a
# guess reaches for, ranks its findings as though anyone could reach them.
. "$(dirname "${BASH_SOURCE[0]}")/../fixture.sh"
repo
descriptor
