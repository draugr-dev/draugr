# Adding a scanner

A **scanner** runs one tool and returns [SARIF](../../concepts/controls-and-scanners.md). It does
not decide whether anything is bad — that is the controller's job — and it does not decide whether
the build fails, which is the gate's.

Add one when a control that already exists could be answered by another tool. If the question
itself is new, you want [a control](control.md) instead.

## 1. Pick the shape

Three helpers cover almost everything. Use one rather than implementing `plugin.Scanner` by hand;
they carry the checkout, the path rewriting and the tool stamping that every scanner needs to get
right identically.

| Your tool… | Use | Example |
|---|---|---|
| scans a checked-out repository and speaks SARIF | `newRepoScanner(info, argsFn)` | `internal/scanners/semgrep.go` |
| scans a checked-out repository, speaks its own JSON | `newRepoScannerWithParser(info, argsFn, parse)` | `internal/scanners/retirejs.go` |
| scans a named artifact (an image, a host) | `tooladapter.New(tooladapter.Config{…})` | `internal/scanners/grype.go` |

`argsFn(dir, cfg) []string` returns the argv. Keep it a pure function of its inputs — it is the
piece worth testing exactly, because argv is where a wrong flag hides.

## 2. Write it

```go
// NewRetireJS returns a Scanner that runs retire.js over a checked-out repository.
func NewRetireJS() plugin.Scanner {
	return newRepoScannerWithParser(
		plugin.ScannerInfo{
			Name:        "retirejs",
			Origin:      "RetireJS",
			Binary:      "retire",
			Controls:     []string{"sca"},
			TargetKinds:  []plugin.TargetKind{plugin.TargetRepository},
			ConfigSchema: json.RawMessage(noScannerOptions),
		},
		retireJSArgs,
		parseRetireJS,
	)
}
```

The fields of `plugin.ScannerInfo` that decide behavior:

- **`Name`** — the identifier in reports, `draugr controls`, and rule output. Hyphenated names are
  fine, and cost you an entry in step 4.
- **`Binary`** — the executable, so `draugr doctor` can check for it. Empty for a scanner that
  needs no external tool.
- **`AlsoRequires`** — further executables the tool shells out to in turn. Declaring the whole
  requirement is what makes the preflight check worth running; otherwise a machine missing the
  second tool passes `doctor` and fails at scan time.
- **`Controls`** — which controls this scanner can serve.
- **`TargetKinds`** — what it accepts.
- **`Origin`** — who publishes the *tool*, not who wrote the scanner. Note that a scanner does not
  get to claim its own origin: the registry stamps built-ins, because “which of these is a third
  party executing on my machine” is a supply-chain question, and an answer supplied by the subject
  is not an answer.
- **`ConfigSchema`** — a JSON Schema for the options this scanner accepts under its own
  descriptor key. Use `noScannerOptions` when it takes none — a real declaration meaning “this
  scanner is configured by choosing it, and by nothing else”, not an omission. Without a schema a
  mistyped option is dropped between the YAML and the argv with no warning, and the only way to
  find out is to notice the setting had no effect. `TestEveryScannerDeclaresItsOptions` in
  `internal/builtins` keeps this true for scanners added later.
- **`Effects`** — see step 6. Empty is the common and correct case.

### Never fail on findings

Almost every security tool exits non-zero when it finds something. Draugr must tell it not to:
`--exit-code 0` for Trivy, `--exitwith 0` for retire.js, and so on for whatever yours uses.

A scanner that fails on findings makes the **exit code** the verdict, when severity is the
control's job and the gate's answer is the only verdict there should be. The failure is quiet in
the worst way: the run stops, and what the tool actually found never reaches the report.

Do check the exit code for the *other* meaning — the tool could not run — and return an error.

### Check whether the tool's SARIF carries a level

If it omits one, `pkg/sarif` defaults absent → `warning`. Decide deliberately whether that is
right for your control, and escalate in the controller if it is not.

## 3. Register it

```go
// internal/builtins/builtins.go
reg.RegisterScanner(scanners.NewRetireJS())
```

This makes the scanner **exist**. Four more things make it **reachable**, and each is invisible to
unit tests, because they construct `plugin.Config` directly and never go through descriptor
validation.

## 4. The four things unit tests cannot see

**`scannerConfigKey`** (`internal/controllers/config.go`) — for any hyphenated scanner name.
Descriptor fields are camelCase without exception, so `grype-fs` is configured as `grypeFs`.
Without the entry, a descriptor naming your scanner is rejected as naming a scanner the control
does not have.

**`resolveScanners`** (`internal/controllers/config.go`) — for any control more than one scanner
can serve. A controller that hardcodes one scanner will never select yours, whatever the
descriptor says, and nothing will report that it did not.

**`externalTools`** (`internal/cli/doctor.go`) — only for a tool Draugr does **not** distribute.
It makes `doctor` name the tool's source instead of suggesting `draugr tools install`, which will
never find it. Suggesting an install that runs, succeeds, and leaves the tool missing is worse
advice than none. If Draugr *can* provision the tool, see [tool.md](tool.md) instead.

**Regenerate the schemas:**

```bash
go generate ./pkg/saga/...
go test ./internal/schemagen/
```

Both the Saga and fragment schemas are built from the live registry. Drift shows up for a user as
an editor rejecting a descriptor that Draugr itself accepts.

## 5. Document it

A colocated `internal/scanners/<name>.md`, plus a row in
[`docs/reference/catalog.md`](../../reference/catalog.md). Copy the shape of an existing one; it
must cover what the scanner does, its control, the tool and links, **license and terms of use**,
and the integration notes worth knowing.

The license and terms section is enforced by `TestEveryToolDocStatesItsTerms`, and the rules for
establishing it are in [the shared section](README.md#read-the-license-the-terms-and-the-privacy-notice--all-three-from-the-source).
Keep it honest and short where there is little to say — “no terms of use beyond the license; it is
a command-line tool, not a service” is a complete answer, and a reader can act on it.

## 6. Effects and consent

Most scanners read and report, and declare no effects. Declare one when the scan does something
that outlives it or that the operator would not expect from the word “scan” — creating a project
in a vendor's account, uploading an inventory, writing to the target.

Effects are **static per scanner**, not per job or per target: the declaration is about what this
scanner can do, and the descriptor's `allowEffects` is how an operator consents to it. A scanner
declaring the `disclosure` effect must also carry a `## What is sent` section in its doc, which
`TestDisclosingScannersDocumentWhatTheySend` checks.

Configuration can itself be the consent where the configuration has no other purpose. A field
whose only function is to authorize the behavior — naming the environment variable holding a
token, for instance — is a deliberate act by the operator, and a second consent gate on top of it
adds ceremony rather than safety. Say so in the doc, so the reasoning is reviewable.

## 6b. Caching, if your answer depends on downloaded data

Two optional interfaces, and forgetting either is silent — the scanner works and only its cache
behavior is wrong:

- **`plugin.CacheVersioner`** contributes the version of whatever actually decides your answer — a
  vulnerability database, a template set — to the cache key. Without it a database refresh leaves
  every cached entry describing the old one.
- **`plugin.Prewarmer`** warms that data once before the run fans out, instead of every job
  discovering it missing at the same moment.

See [the cache architecture](../cache.md).

## 7. Test it

Cover, at minimum:

- `Info()` — name, controls, target kinds. Assert the values, not that the type implements the
  interface: a test that a type satisfies something it always satisfies passes for free.
- **The argv, exactly.** Including the flag that stops the tool failing on findings — that is the
  one whose absence is silent.
- **The parser, against real output.** Capture what the tool actually printed and use that. A
  fixture written by hand tests the parser against the shape its author imagined, which is the
  shape the parser already handles. Abridge real output rather than inventing it.
- **Two repositories**, wherever anything is derived per repository. See
  [the shared section](README.md#tests-take-two-of-whatever-there-can-be-two-of).
- Unparseable output → an error, never a clean report.
- Empty output → an empty report, which is a real answer and not a failure.

## 8. Prove it with a descriptor

Every failure in step 4 passes `make gate` and appears the moment a real descriptor is loaded.

```bash
draugr validate <your>.saga.yaml   # catches a missing scannerConfigKey
draugr doctor  --saga <your>.saga.yaml   # catches a missing tool, and bad advice about it
draugr scan    <your>.saga.yaml    # catches a controller that never selects your scanner
```

Watch for tools that allowlist example values — several secret scanners ignore the canonical
vendor example keys — so use realistic-but-fake fixtures, or your end-to-end proof is a scan that
found nothing for the wrong reason.

## 9. Finish

The [definition of done](README.md#definition-of-done): reference docs, the colocated doc and its
catalog row, a user-first `CHANGELOG.md` entry, tests at ≥90% on changed packages, and `make gate`
clean.

Two more that live outside this repository, and drift precisely because they do:

- **The website** — a new capability belongs in the homepage capability list, and in a `learn/`
  page if it is a concept rather than a flag.
- **The demo** — [`draugr-demo`](https://github.com/draugr-dev/draugr-demo) is what someone
  evaluating Draugr actually runs. A capability absent from its Saga is one they will not find,
  whatever the docs say. Its *descriptor* is authored and may be changed; its *findings* are the
  point and must not be fixed.

Both consume the latest **release**, so a change to either lands after a release containing your
scanner — two pull requests, either side of it.
