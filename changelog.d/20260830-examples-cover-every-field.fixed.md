- `examples/` now writes every field a Saga descriptor has. `builtBy` on an image somebody else
  publishes, exclusions carrying `acceptedBy`, `expires` and a VEX status, exploitability feeds,
  fragments, SBOM scope, per-control gate thresholds, host authentication and OpenAPI-driven
  scans, and `operatedBy` on a managed cluster were all documented and in the schema without
  appearing in a single file anybody could copy. New examples: accepting a finding on the record,
  ranking on exploitability, and a root descriptor collecting fragments from the teams that own
  the code.
