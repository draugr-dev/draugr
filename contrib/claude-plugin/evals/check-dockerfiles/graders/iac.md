---
type: llm
focus: trace
---

PASS if the agent does all three:

1. Names `iac` as the control that checks the Dockerfile and the Kubernetes manifests.
2. Turns it on with `iac:` and `enabled: true` under `config.controls`, or under a component's
   `controls`, either by telling the user to or by editing draugr.saga.yaml.
3. Names trivy-config as the scanner the control runs. Naming kics as an optional extra scanner is
   correct too.

FAIL if the agent says the `kubernetes` control checks the manifests, names a control or scanner
for this that list_controls did not return, or writes a key under `iac` other than `enabled`,
`trivyConfig`, `kics` or `nonShippingPaths`, the four the descriptor accepts there.
