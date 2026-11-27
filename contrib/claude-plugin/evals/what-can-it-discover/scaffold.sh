#!/usr/bin/env bash
# The question is what can be discovered, which list_surveyors answers without reaching anything. No
# GitLab token is set and the README's command points KUBECONFIG at a file that does not exist, so a
# survey the agent runs anyway reaches nothing.
. "$(dirname "${BASH_SOURCE[0]}")/../fixture.sh"
repo
descriptor
