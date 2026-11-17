# npm-audit converter

Turns what `npm audit --json` writes into a Draugr converter file, for an import with `format:
draugr-converter`. npm audit writes no SARIF, and Draugr has no reader for its JSON, so this is how
its findings reach a scan.

Each advisory npm lists against a package becomes one finding, with:

- the advisory's GitHub id as the rule, such as `GHSA-xvch-5gv4-984h`, so it merges with another
  scanner's finding of the same advisory;
- npm's severity (`moderate` read as medium) and the advisory's CVSS score;
- the package, its installed version from `package-lock.json`, the version npm says fixes it, and
  its package URL, all under `package`;
- the CWE ids the advisory names, under `cwe`.

A package npm lists only because one of its dependencies is vulnerable gets no finding of its own;
the dependency's entry carries it.

Draugr runs no converter. Your pipeline runs this one, and Draugr reads the file it writes.

## In CI

```yaml
# GitHub Actions
- run: npm audit --json > npm-audit.json || true    # npm audit exits 1 when it finds something
- run: >
    go run github.com/draugr-dev/draugr/contrib/converters/npm-audit@latest
    -audit npm-audit.json -lock package-lock.json -commit "$GITHUB_SHA" -o npm-audit.draugr.json
- uses: draugr-dev/draugr@v0
```

| flag | meaning |
|---|---|
| `-audit` | the file `npm audit --json` wrote (required) |
| `-lock` | the lockfile npm audit read, relative to the repository's root (default `package-lock.json`). Every finding is located there |
| `-commit` | the commit npm audit ran on (required) |
| `-repository` | the repository, where the importing component has several |
| `-o` | the file to write, standard output when empty |

The converter reads its own output back as Draugr will before writing it, so a file it writes is
one the import accepts.

## In the descriptor

[`manifest.yaml`](manifest.yaml) is the import entry to copy under the component's `imports`:

```yaml
- control: sca
  file: npm-audit.draugr.json
  format: draugr-converter
  commit: ${{ GITHUB_SHA }}
  converter:
    name: npm-audit
    contract: 1
    sets: [package, cwe]
```

## Tests

`go test ./contrib/converters/npm-audit/` converts `testdata/npm-audit.json`, what npm 11.16.0's
`npm audit --json` wrote for a lockfile pinning lodash 4.17.20 and minimist 1.2.5, and compares the
result with `testdata/npm-audit.draugr.json`. `go test -update` rewrites that file after a change
meant to alter it.

[Write a converter](../../../docs/guides/writing-a-converter.md) says how to write one for another
tool, and the [converter contract](../../../docs/reference/converter-contract.md) lists every key.
