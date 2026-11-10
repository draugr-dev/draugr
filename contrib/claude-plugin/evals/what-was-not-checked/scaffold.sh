#!/usr/bin/env bash
. "$(dirname "${BASH_SOURCE[0]}")/../fixture.sh"
repo
# Two inputs the scan reads only in part, each reported as unread with its reason: a Helm chart whose
# template requires a value its defaults do not set, so Trivy cannot render it and checks none of its
# templates, and a requirements.txt that pins one package and gives the other a range, so the ranged
# one is not checked.
mkdir -p services/api/deploy/chart/templates services/api/app
cat >services/api/deploy/chart/Chart.yaml <<'YAML'
apiVersion: v2
name: api
version: 0.1.0
YAML
printf 'replicas: 1\n' >services/api/deploy/chart/values.yaml
cat >services/api/deploy/chart/templates/deployment.yaml <<'YAML'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
spec:
  replicas: {{ .Values.replicas }}
  template:
    spec:
      containers:
        - name: api
          image: {{ required "image is required" .Values.image }}
YAML
printf 'flask>=0.12\nrequests==2.31.0\n' >services/api/requirements.txt
git_ add services/api/deploy/chart services/api/requirements.txt
git_ commit -q -m "Add the api chart and its Python dependencies"
CONTROLS='    iac:
      enabled: true
    sca:
      enabled: true
'
descriptor
report .
