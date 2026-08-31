- The `licenses` control now scans a component's **images** as well as its repositories. A license
  obligation inside a deployed image used to be invisible — and silently so, because the control
  ran and reported covered — which landed hardest on third-party images, where the source
  repository is not declared because the team does not build it. Nothing to change in your
  descriptor: `licenses: enabled: true` covers both, with the same policy.
- `licenses` gained `trivyLicense.full: true`, which turns on Trivy's `--license-full` to read
  `LICENSE` files and source headers rather than only package metadata. It finds licenses no
  manifest declares, and walks every file to do it — so a pull-request gate probably wants the
  fast answer and a release probably wants this one.
