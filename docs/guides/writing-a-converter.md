---
title: Write a converter
description: Bring a tool Draugr has no reader for into a scan, with each finding's package, CWE ids or a priority raise, through a converter your pipeline runs and Draugr reads.
section: Guides
order: 28
---

# Write a converter

A converter turns another tool's output into a file in Draugr's [converter
contract](../reference/converter-contract.md), for a tool that writes no SARIF, or whose SARIF
leaves out what Draugr ranks a finding by, such as the package or the CWE ids. Your pipeline runs the
converter after the tool, and the descriptor imports the file it writes with `format:
draugr-converter`. Draugr runs no converter. It reads the file, holds it to the commit, and refuses
it unless the converter is the one the descriptor declares.

[`contrib/converters/npm-audit`](../../contrib/converters/npm-audit/) is a working converter for
`npm audit --json`, which writes no SARIF. The steps below use it; a converter for another tool has
the same shape.

## 1. Choose what the converter sets

Every converter writes the finding as the tool reported it: its rule id, message, severity and
location. Beyond that, it may set any of these of Draugr's own properties, and nothing else:

| property | use it for |
|---|---|
| `package` | a dependency finding: the package, installed and fixed versions, package URL |
| `cwe` | the CWE ids the tool names for a flaw |
| `labels` | your own labels on a finding, such as the team that triages it |
| `reachable` | a verdict that your code reaches the vulnerable code |
| `raise` | a band a finding is ranked at least at, with the reason |

A converter can never set a finding aside or lower one. A file that names `suppression`, `aside`,
`priority` or `reachable: false` is refused, naming the property ([What no converter may
set](../reference/converter-contract.md#what-no-converter-may-set)).

The npm audit converter sets `package` and `cwe`.

## 2. Write the converter

Read the tool's output and write one result per flaw. The npm audit converter reads each advisory npm
lists against a package, takes the installed version from `package-lock.json`, and writes:

```json
{
  "ruleId": "GHSA-xvch-5gv4-984h",
  "message": "Prototype Pollution in minimist",
  "severity": "critical",
  "score": 9.8,
  "location": {"path": "package-lock.json"},
  "package": {"name": "minimist", "version": "1.2.5", "fixedVersion": "1.2.8",
              "purl": "pkg:npm/minimist@1.2.5", "ecosystem": "npm"},
  "cwe": ["CWE-1321"]
}
```

- **Use the advisory id the tool reports as `ruleId`**, a GHSA or CVE id, so the finding merges with
  another scanner's copy of the same advisory instead of counting twice.
- **Write paths relative to the repository's root**, as the import reads them.
- **Take `commit` as an argument**, such as `$GITHUB_SHA`. The contract requires it, and Draugr
  refuses a file converted on another commit than the one it scans.
- **Check the file before writing it.** The npm audit converter reads its own output back with the
  reader the import runs, and writes nothing on an error. In another language, validate against
  [`draugr-converter.v1.schema.json`](../../pkg/converter/draugr-converter.v1.schema.json).
- **Test it on a recorded output of the tool**, as `convert_test.go` does with a real `npm audit
  --json`, so a change in the tool's output fails a test before it fails a scan.

## 3. Run it in the pipeline

After the tool, and before `draugr scan`:

```yaml
# GitHub Actions
- run: npm audit --json > npm-audit.json || true    # npm audit exits 1 when it finds something
- run: >
    go run github.com/draugr-dev/draugr/contrib/converters/npm-audit@latest
    -audit npm-audit.json -lock package-lock.json -commit "$GITHUB_SHA" -o npm-audit.draugr.json
- uses: draugr-dev/draugr@v0
```

## 4. Declare the import

Under the component the tool scanned, name the converter, the contract version it writes, and what
it may set. A converter's file is refused unless its `converter.name` matches, and any property it
sets beyond `sets` is refused too:

```yaml
components:
  - name: web
    imports:
      - control: sca
        file: npm-audit.draugr.json
        format: draugr-converter
        commit: ${{ GITHUB_SHA }}
        converter:
          name: npm-audit
          contract: 1
          sets: [package, cwe]
```

The descriptor grants the properties because it is the file your team reviews. The converter's file
is written fresh on every run, so nothing in it can grant itself more.

In a component with several repositories, the converter also writes `repository`, the one the tool
scanned.

## 5. Check it

`draugr doctor` reads the file as the scan will:

```console
TARGETS
Kind        Target                 Result
repository  .                      ✓ resolves to 7de995591d35
file        npm-audit.draugr.json  ✓ converter file, 5 findings
```

`draugr scan` ranks the findings with the rest. Each names the converter, and says what it set:

```console
  P1  critical  GHSA-xvch-5gv4-984h
      Prototype Pollution in minimist
      scanner npm audit · minimist 1.2.5 → 1.2.8
      package-lock.json · converter npm-audit set package, cwe · also found by trivy
```

`report.json` carries the stamp on each finding, with the SHA-256 of the file read:

```json
"cwe": ["CWE-1321"],
"converter": {"name": "npm-audit", "version": "1.0.0", "contract": 1,
              "sha256": "9b372fda5b1ebf4bdd5badd3452520623de27b49de1caedeff193f65d53fa539",
              "set": ["package", "cwe"]}
```

A file the contract refuses stops the run, and the **Errors** block names the file and the key at
fault. A converter's file edited to set `aside` on its first result reads `results[0] sets aside,
which no converter may set`, and `draugr doctor` fails the file with the same words.

## See also

- [Converter contract](../reference/converter-contract.md), every key of the file.
- [Import another scanner's SARIF](importing-sarif.md), for a tool that writes SARIF.
- [`components[].imports`](../reference/saga-schema.md#componentsimports), the import's fields.
