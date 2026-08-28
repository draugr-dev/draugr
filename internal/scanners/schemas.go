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
