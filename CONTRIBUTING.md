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

You can edit the file by hand — it is Markdown, and nothing here is mandatory. There is a helper
for the parts that are easy to get quietly wrong:

```bash
make changelog                      # check it (also part of `make gate` and CI)
make changelog-show                 # print what a tag would publish
echo "- **What you can now do.**" | ./scripts/changelog.sh add fixed
```

`add` puts the entry under the right heading in `[Unreleased]`, creating the heading in
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) order and clearing `_Nothing yet._`. The
sections it accepts are Added, Changed, Deprecated, Removed, Fixed and Security; `### Fix` reads
fine and lands nowhere the release notes look.

**What `make changelog` catches** — it runs in `make gate` and in CI, so a heading nobody
recognises never reaches `main`. Every one of these produces a file that looks right:

- **Two `### Fixed` blocks under one version.** The published notes contain whichever the
  extractor reaches first, and there is no way to tell from the release page that half is missing.
- **A heading that is not one of the six.** Entries under it are simply not published.
- **A released version with no link reference**, which renders as a bare `[0.58.0]`.
- **A released section that has changed since its tag** — the original guard, still run as part of
  this. The failure it exists for is aim rather than malice: an entry meant for `[Unreleased]`
  landing one section lower produces a perfectly valid CHANGELOG describing a fix in a release
  that does not contain it. It reports how many sections it checked, because a guard that
  silently checks nothing is worse than no guard.

Heading checks apply to `[Unreleased]` only. Released sections are held to what their tag said,
and the earliest history predates this convention — a check that can never pass is a check nobody
reads.

**Releasing.** `./scripts/changelog.sh promote X.Y.Z` moves `[Unreleased]` into a dated section
and updates the compare links, then prints what the tag will publish. Read that output. It
**refuses to promote an empty `[Unreleased]`**, which is the case worth refusing: an entry that
was written but never landed produces a release nobody can describe, and the only moment that is
cheap to fix is before the tag exists.

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

### Cutting a release

Releases come from the CHANGELOG, and go out in two steps.

**Run the `Release prepare` workflow** (Actions → Release prepare → Run workflow). It derives the
version from what is under `[Unreleased]`, promotes that section to a dated one, and opens a pull
request whose body is the notes the release will publish:

| `[Unreleased]` contains | Bump |
|---|---|
| `Added`, `Changed`, `Deprecated` or `Removed` | minor |
| only `Fixed` and/or `Security` | patch |
| — | **major is never derived** |

Major takes the workflow's `version` input. Deciding an interface is now unsupportable is a
judgement about people, not one a heading should be able to reach.

**Merging that pull request tags the release.** A second workflow watches `main` and tags any
released section that has no tag yet — so the state is the file rather than a label or a commit
subject, and a hand-promoted CHANGELOG is tagged the same way. Running it twice is a no-op: the
second run finds the tag and stops.

The tag triggers the release workflow, which **refuses to publish** unless the self-scan and the
integration suite both pass on that exact tree.

Deliberately not on every merge. A version per trivial change is noise in the tag list and in
everyone's dependency updates — dispatch it when the accumulated notes are worth shipping. Check
what they say first:

```bash
make changelog-show      # exactly what a tag would publish
./scripts/changelog.sh next    # the version that implies
```

### Suppressing a gosec finding

Write **`#nosec`**, never `//nolint:gosec`:

```go
data, err := os.ReadFile(path) // #nosec G304 -- operator-provided config path
```

Both matter. gosec runs twice here — inside `golangci-lint` (fast, local, in `make gate`) and as
Draugr's own `sast` scanner (what a user would get). `#nosec` silences both; `//nolint:gosec`
silences only the first, so a codebase using it passes `make gate` and fails the self-scan on the
same line.

Name the rule, and give a reason after `--`. A bare `#nosec` silences every gosec rule on that
line, including one nobody has reviewed.

### Writing the comment that explains a guard

Everything here is world-readable — code comments, test rationale, workflow comments, config —
and a comment saying *why* a check exists is one of the most useful things in the repository.
Write it as **the risk the guard protects against**, not the occasion that prompted it.

- No: *"the licenses control shipped without its docs and the gap reached the published site."*
- Yes: *"a plugin with no documentation still compiles and still passes its own tests; nothing
  looks wrong until someone goes looking for the docs."*

The engineering value is in the second half, and the second half survives the rewrite intact. The
first adds nothing a reader can act on, and a file of them reads as a defect log rather than as a
design. It also stays true after the specific occasion is forgotten, which the other form does
not.

`scripts/check-no-defect-recounts.sh` (in `make gate` and in CI) catches the phrasings with no
innocent reading. It cannot catch all of them, so this is a habit rather than a rule the tooling
enforces for you.

The **CHANGELOG is the exception**, and only its `### Fixed` section: users need to know what
changed in a release, described as the fix rather than as the blunder.

### Changing what `draugr scan` prints

The console layout is quoted in several documents under `docs/`, and captured verbatim into the
demo screenshot the README shows and the terminal fragment the website's home page carries.
None of those notice when it changes, so it is pinned by a golden test:

```bash
go test ./pkg/report -run TestConsoleGolden          # fails if the layout moved
go test ./pkg/report -update                         # accept the new layout
make examples                                        # real output from the demo sandbox
```

If the golden fails, the failure lists the documents to refresh; `make examples` prints a real
scan of [`draugr-demo`](https://github.com/draugr-dev/draugr-demo) to paste from (it clones the
sandbox and needs Trivy, Gitleaks and Semgrep on PATH). The demo assets re-render themselves
after every release — you don't need to run vhs locally, though
`gh workflow run 'Demo assets'` will do it on demand.

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
