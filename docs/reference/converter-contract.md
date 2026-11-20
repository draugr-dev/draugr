---
title: Converter contract
description: Every key of the file a converter writes for an import with format draugr-converter, which of Draugr's properties a converter may set, and what Draugr refuses.
section: Reference
order: 37
---

# Converter contract

A converter file is the JSON a converter writes for Draugr to import with
[`format: draugr-converter`](saga-schema.md#componentsimports): the findings of a tool Draugr has no
reader for, with the result properties of Draugr's own the descriptor lets that converter set. A CI
step runs the converter. Draugr runs nothing and reads the file. [Write a
converter](../guides/writing-a-converter.md) walks through one.

This page describes contract version 1. The JSON Schema,
[`draugr-converter.v1.schema.json`](../../pkg/converter/draugr-converter.v1.schema.json), is what
Draugr reads a file against, and every object in it refuses a key it does not define.

## The file

```json
{
  "contract": "draugr-converter",
  "version": 1,
  "converter": {"name": "npm-audit", "version": "1.0.0"},
  "source": {"tool": "npm audit", "file": "npm-audit.json", "sha256": "755488ba…"},
  "commit": "7de995591d35d5cc0c7745d13cc00c948dea1672",
  "written": "2026-11-17T17:24:43Z",
  "results": [
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
  ]
}
```

| key | required | meaning |
|---|---|---|
| `contract` | yes | always `draugr-converter` |
| `version` | yes | the contract version, `1` |
| `converter.name` | yes | the converter's name, lowercase letters, digits and hyphens. It has to be the `converter.name` the import declares |
| `converter.version` | no | the converter's own version |
| `source.tool` | yes | the tool whose output the converter read, as each finding names it |
| `source.version` | no | that tool's version |
| `source.file` | no | the file the converter read |
| `source.sha256` | no | that file's SHA-256, in lowercase hexadecimal |
| `commit` | yes | the commit the tool scanned, 7 to 64 hexadecimal characters |
| `repository` | no | the repository the tool scanned, as a URL or a path. Required where the importing component has several repositories |
| `written` | no | when the converter wrote the file, RFC 3339 in UTC, such as `2026-11-17T17:24:43Z` |
| `results` | yes | the findings. An empty list is a clean scan |

## A result

The first five keys are the finding as the tool reported it, which any import reads. The rest are
Draugr's own properties, which the import's `converter.sets` has to list.

| key | required | meaning |
|---|---|---|
| `ruleId` | yes | the tool's id for the flaw, such as an advisory id. A GHSA or CVE id merges the finding with another scanner's copy of it |
| `message` | yes | what the tool said, in one line |
| `severity` | yes | `critical`, `high`, `medium` or `low`, the tool's rating in Draugr's words |
| `score` | no | a CVSS-style score from 0 to 10, which decides the severity where present |
| `location.path` | no | the file, relative to the repository's root |
| `location.line` | no | the line, from 1 |
| `package` | no | the dependency the finding is about: `name` (required), `version`, `fixedVersion`, `purl` and `ecosystem` |
| `cwe` | no | the CWE ids of the flaw, such as `CWE-79` |
| `labels` | no | labels on the finding, string keys to string values |
| `reachable` | no | `true`: the project's code reaches the vulnerable code. Needs `package` |
| `raise` | no | `priority`, `P1` to `P4`, and `reason`: a band the finding is ranked at least at |

A key written with an empty value, such as `"cwe": []`, still sets its property.

## What a converter may set

The list is fixed in Draugr. The import's `converter.sets` names which of them one converter may
set, and can leave any out and add none.

| property | what Draugr does with it |
|---|---|
| `package` | the finding's package, installed and fixed version, package URL and ecosystem, as a dependency scanner reports them. An upgrade in the fix list, and a merge with another scanner's finding of the same advisory in the same package |
| `cwe` | the finding's CWE ids, in `report.json` and `results.sarif` |
| `labels` | labels beside the component's own. A key the component's `labels` also sets keeps the component's value |
| `reachable` | a reachable verdict, credited to the converter and dated by `written` |
| `raise` | the finding is ranked at least at `priority`, and the report gives `reason`, as `raised to P1 by converter acme-deps, on the internal exploited list`. A band already higher stays where it is |

## What no converter may set

A finding moves down only on evidence Draugr can check, such as a call graph it reads or a decision
recorded in the descriptor. A converter's statement is neither. Each of these sets a finding aside,
says who accepted a risk, or ranks a finding lower, and a file setting one is refused with an error
naming it, whatever the descriptor declares:

- `suppression`, `suppressions`, `aside`, `nonShipping`, `acceptedBy`, `origin`;
- a `priority` on a result (use `raise`, whose own `priority` only raises), `priorityCap`,
  `rankedAs`, `unreachable`, and `reachable: false`.

A fragment may not declare a converter or import a converter's file. Declare it in the descriptor
itself.

## The stamp

Every finding read from the file carries the converter that wrote it, as `converter` in
`report.json` and `draugr/converter` in `results.sarif`:

| key | meaning |
|---|---|
| `name` | the converter's name |
| `version` | the converter's own version, where the file states one |
| `contract` | the contract version the file follows |
| `sha256` | the SHA-256 of the file Draugr read |
| `set` | the properties the converter set on this finding |
| `raise` | the raise it asked for, where it asked one |

The console names the converter beside the tool, as `imported npm audit (converter npm-audit)`, and
says under the finding which properties it set: `converter npm-audit: package, cwe`. **Measured
against** lists `converter: npm-audit 1.0.0, contract 1, may set package, cwe` beside the file's
SHA-256, and its `severity` field reads `converter score` or `converter rating`, whichever rated the
findings.

## Errors

A file Draugr cannot read under the contract stops the run as a scanner that could not run does,
naming the key at fault, and is never read as a clean scan. `draugr doctor` reads it the same way.

| the file | the error |
|---|---|
| is not a converter file | `not a converter file. A converter writes contract draugr-converter` |
| states an older version | `contract version 0 is older than Draugr reads, version 1. Update the converter` |
| states a newer version | `contract version 2 is newer than this Draugr reads, version 1. Update Draugr`, or have the converter write version 1 |
| states a version that is not a whole number | `contract version "one" is not a whole number. Draugr reads version 1` |
| sets a property no converter may set | `results[0] sets aside, which no converter may set` |
| says the code does not reach a flaw | `results[0] sets reachable false, a lowering no converter may make` |
| sets a property `converter.sets` leaves out | `results[0] sets labels, which converter.sets does not list` |
| has a key the contract does not define | `results[0] has level, a key contract version 1 does not define` |
| lacks a key the contract requires | `the file has no commit, which the contract requires` |
| holds a value the contract does not take | `results[0].severity is "urgent", not one of critical, high, medium, low` |
| was written by another converter | `written by converter acme-deps, and the import declares npm-audit` |
| names no repository, in a component of several | `names no repository, and component web has several. Set repository` |

The file's `commit` binds it as an import's `commit` does: a file converted on another commit stops
the run, and an import's `commit` that differs from the file's stops it too
([Commit](../../internal/scanners/sarif-import.md#commit)).
