package scanners

// A scanner's config schema is the contract between a descriptor and the tool behind it, and
// every registered scanner declares one — including the scanners that accept nothing.
//
// The reason is what happens without one. `plugin.ValidateConfig` treats an absent schema as
// "accept anything", so a descriptor writing an option a scanner does not read produces no error,
// no warning, and a green run: the option is dropped between the YAML and the argv, and the only
// way to find out is to notice that the setting had no effect. That is precisely the silent
// failure this project refuses everywhere else — a flag either does something or says why it
// didn't.
//
// So `noScannerOptions` is a real declaration rather than an omission. It says "this scanner is
// configured by choosing it, and by nothing else", and it makes a descriptor that assumes
// otherwise fail before the scan runs, naming the option it could not honor.
//
// `TestEveryScannerDeclaresItsOptions` in internal/builtins keeps this true for scanners added
// later, because "remember to declare a schema" is not a rule anyone remembers.
const noScannerOptions = `{
  "type": "object",
  "additionalProperties": false,
  "properties": {}
}`

// licensePolicyProperties are the `deny` and `warn` lists, written once and used by every scanner
// that serves the licenses control.
//
// Shared rather than repeated, because these two are not the scanner's own options: they are the
// control's policy, and the controller hands the same resolved lists to whichever scanner runs.
// Two copies of the shape could disagree, and the descriptor a reader was told is valid would be
// the one the other scanner refuses.
//
// An entry is an SPDX identifier, or that identifier written with the reason somebody had for
// taking that position on it. The reason changes nothing about a scan — what it changes is that
// whoever meets the finding can read the argument for the rule that produced it.
//
// The entry is spelled out under both keys rather than shared with a $ref: plugin.ValidateConfig
// resolves no references, and a reference it does not resolve is a constraint that silently stops
// applying — an editor would still reject a bad entry, and the scan would not.
const licensePolicyProperties = `
    "deny": {
      "type": "array",
      "items": {
        "type": ["string", "object"],
        "additionalProperties": false,
        "required": ["id", "reason"],
        "properties": {
          "id": { "type": "string", "description": "The SPDX identifier." },
          "reason": { "type": "string", "description": "Why this project will not accept it." }
        }
      },
      "description": "SPDX identifiers that fail the gate, e.g. [\"AGPL-3.0-only\", \"SSPL-1.0\"]. An entry may instead be written {id, reason} to record why."
    },
    "warn": {
      "type": "array",
      "items": {
        "type": ["string", "object"],
        "additionalProperties": false,
        "required": ["id", "reason"],
        "properties": {
          "id": { "type": "string", "description": "The SPDX identifier." },
          "reason": { "type": "string", "description": "Why this project wants to be told about it." }
        }
      },
      "description": "SPDX identifiers reported as warnings rather than failures, e.g. [\"GPL-3.0-only\"]. An entry may instead be written {id, reason}."
    }`
