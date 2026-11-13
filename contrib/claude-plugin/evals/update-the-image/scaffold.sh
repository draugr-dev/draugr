#!/usr/bin/env bash
. "$(dirname "${BASH_SOURCE[0]}")/../fixture.sh"
repo
# Three critical findings inside python:3.8-slim, an image the api service runs and somebody else
# builds, beside two npm upgrades in the api service. No report.json, so the image has to come from
# fix_list, whose first list is the image to update rather than a package to upgrade inside it.
dependencies
upstream_image
descriptor
sarif_only .
