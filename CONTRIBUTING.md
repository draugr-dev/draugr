# Contributing to Draugr

Thanks for your interest in Draugr — a developer-first, descriptor-driven security scanning
orchestration engine. Contributions of all kinds are welcome: bug reports, feature ideas,
docs, new scanner/controller integrations, and code.

## Ways to contribute

- **Report a bug or request a feature** — open an [issue](https://github.com/draugr-dev/draugr/issues).
  For bugs, include your OS/arch, the Draugr version (`draugr version`), the command you ran,
  and what happened vs. what you expected.
- **Improve the docs** — docs live in [`docs/`](docs/) and alongside each integration
  (`internal/scanners/*.md`, `internal/controllers/*.md`). Docs are a first-class deliverable.
- **Add an integration** — new controls follow a repeatable shape (a controller + a scanner);
  see the existing ones (e.g. `sca`, `secrets`) and [`docs/contributing/plugin-api.md`](docs/contributing/plugin-api.md).
- **Fix or build something** — see the workflow below.

## Development

Requires **Go 1.26+** and the external scanners for whatever controls you touch (or run
`draugr tools install` to fetch pinned, verified copies).

```bash
make build   # build ./bin/draugr
make test    # run tests
make gate    # full local gate: fmt, vet, golangci-lint, race tests + coverage, govulncheck
```

Please run `make gate` before opening a pull request — CI runs the same checks.

### Editing the CHANGELOG

New entries go under `## [Unreleased]`. Released sections are a record of what shipped — once a
version is tagged, editing its notes rewrites history that release notes and the published site
already quote.

`make changelog-guard` (part of `make gate`, and a CI check) compares each released section
against its own tag and fails if one has moved. The failure it exists for is aim rather than
malice: an entry meant for `[Unreleased]` landing one section lower produces a perfectly valid
CHANGELOG describing a fix in a release that does not contain it. It reports how many sections it
checked, because a guard that silently checks nothing is worse than no guard.

#### On the file's size

It grows, and that is fine for now. Two things make it worth leaving alone:

- **The file ships inside every release archive**, next to the binary, and those archives are
  checksummed with the checksums file signed by cosign. Someone with only a verified tarball —
  air-gapped, or in a regulated environment — has the whole history offline and tamper-evident.
  GitHub's release notes are editable after publication through the API, leave no trace in git,
  and are covered by no signature. Splitting the file trades that away unless the archive ships
  too.
- There is no industry standard to follow. Rust keeps one ~10,000-line file; Kubernetes splits
  per minor version; esbuild splits per year; Go and TypeScript keep none at all and rely on
  release pages. [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), which this file
  follows, prescribes one file and is silent on archives.

Revisit at roughly **3,000 lines**, or the first year boundary. When splitting, put older entries
in `CHANGELOG-ARCHIVE.md` — the guard already looks for that name, so archived sections keep being
checked rather than quietly dropping out of the check as they age — and add the archive to the
release archive so the signed artifact still carries the whole record.

### Changing what `draugr scan` prints

The console layout is quoted in the README, in several documents under `docs/`, and re-recorded
in the demo GIF. None of those notice when it changes, so it is pinned by a golden test:

```bash
go test ./pkg/report -run TestConsoleGolden          # fails if the layout moved
go test ./pkg/report -update                         # accept the new layout
make examples                                        # real output from the demo sandbox
```

If the golden fails, the failure lists the documents to refresh; `make examples` prints a real
scan of [`draugr-demo`](https://github.com/draugr-dev/draugr-demo) to paste from (it clones the
sandbox and needs Trivy, Gitleaks and Semgrep on PATH). The GIF re-renders itself after every
release — you don't need to run vhs locally, though `gh workflow run 'Demo GIF'` will do it on
demand.

Two blog posts on the website quote console output as well. They live in a different repository,
so no test here can catch them; the golden's failure message names them so they don't get missed.

### Integration tests

Heavier tests that exercise real external dependencies — a real Trivy binary and an ephemeral
[kind](https://kind.sigs.k8s.io/) cluster — live in `test/integration/`, gated behind the
`integration` build tag so the default `go test ./...` stays fast and hermetic. Run them
locally (needs `trivy` on PATH, a reachable cluster for the k8s test, and a built binary):

```bash
make build
DRAUGR_BIN="$PWD/bin/draugr" go test -tags integration ./test/integration/...
```

In CI they run in the dedicated **Integration** workflow — on `main`, nightly, on demand, and
on a PR only when it carries the `ci-integration` label (add the label to run them against a
PR). The workflow is advisory: failures are visible but it is not a required check.

## Pull requests

1. **Branch** from `main` and keep PRs focused.
2. **Add tests** for new behavior; keep coverage healthy for the packages you change.
3. **Update docs** in the same PR when behavior changes (the colocated `.md` for an
   integration, plus `docs/` and the `CHANGELOG.md` `[Unreleased]` section where user-facing).
   Registering a controller, scanner or surveyor without its colocated `.md` and a linking row
   in [`docs/reference/catalog.md`](docs/reference/catalog.md) fails
   `TestEveryPluginHasColocatedDocs` — a doc nothing links to is a doc nobody finds.
4. **Green CI** — build, lint, tests, and the vulnerability scan must pass.
5. Write clear commit messages describing the *why*, not just the *what*.

## Conduct & security

- This project follows its [Code of Conduct](CODE_OF_CONDUCT.md).
- Please report security issues privately per [SECURITY.md](SECURITY.md) — do **not** open a
  public issue for a vulnerability.

## License

By contributing, you agree that your contributions are licensed under the project's
[Apache License 2.0](LICENSE).
