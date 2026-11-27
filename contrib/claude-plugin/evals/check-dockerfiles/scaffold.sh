#!/usr/bin/env bash
# The api service has a Dockerfile and a pod manifest, and the descriptor enables secrets and sast
# only. The iac control reads both files, and the kubernetes control, whose name is the tempting
# guess, checks a live cluster instead.
. "$(dirname "${BASH_SOURCE[0]}")/../fixture.sh"
repo
mkdir -p services/api/deploy
printf 'FROM python:3.12-slim\nCOPY app /app\n' >services/api/Dockerfile
cat >services/api/deploy/pod.yaml <<'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: api
spec:
  containers:
    - name: api
      image: api:1.0
YAML
git_ add services/api/Dockerfile services/api/deploy/pod.yaml
git_ commit -q -m "Add the api service's image and pod"
descriptor
