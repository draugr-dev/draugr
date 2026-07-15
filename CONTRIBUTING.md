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
  see the existing ones (e.g. `sca`, `secrets`) and [`docs/plugin-api.md`](docs/plugin-api.md).
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

## Pull requests

1. **Branch** from `main` and keep PRs focused.
2. **Add tests** for new behavior; keep coverage healthy for the packages you change.
3. **Update docs** in the same PR when behavior changes (the colocated `.md` for an
   integration, plus `docs/` and the `CHANGELOG.md` `[Unreleased]` section where user-facing).
4. **Green CI** — build, lint, tests, and the vulnerability scan must pass.
5. Write clear commit messages describing the *why*, not just the *what*.

## Conduct & security

- This project follows its [Code of Conduct](CODE_OF_CONDUCT.md).
- Please report security issues privately per [SECURITY.md](SECURITY.md) — do **not** open a
  public issue for a vulnerability.

## License

By contributing, you agree that your contributions are licensed under the project's
[Apache License 2.0](LICENSE).
