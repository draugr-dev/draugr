package scanners

// mendConfigProperties are the Saga options both Mend scanners accept.
//
// `settings` is the one uncurated block in Draugr, and deliberately so. What the Unified Agent
// discovers depends entirely on how each ecosystem's package manager was told to run; curating a
// subset would mean tracking every ecosystem Mend supports and lagging behind it, and the people
// running this already know these keys from their own Mend setup. Everything Draugr can be
// responsible for is a named option above it.
//
// Credentials are absent on purpose. A user key authenticates everything and is read from the
// environment; a product token identifies a product and grants nothing, so it belongs in the
// descriptor where it can differ per component and be reviewed alongside it.
const mendConfigProperties = `
    "productToken": {
      "type": "string",
      "description": "The Mend product this component reports into. Required. It identifies a product and grants no access, so it belongs in the descriptor rather than the environment."
    },
    "project": {
      "type": "string",
      "description": "Mend project name to report into. Defaults to the component's name, which keeps one project per component rather than per repository."
    },
    "resultTimeout": {
      "type": "string",
      "description": "How long to wait for Mend to finish analyzing an upload, e.g. \"15m\". Raise it for large monorepos, where the agent's upload finishes long before the analysis does."
    },
    "settings": {
      "type": "object",
      "description": "Unified Agent configuration keys, passed through verbatim. Draugr writes the component's scope exclusions first, so anything here overrides them."
    }`

// mendSCAConfigSchema is the JSON Schema for controllers.sca.mendSca.
const mendSCAConfigSchema = `{
  "type": "object",
  "additionalProperties": false,
  "required": ["productToken"],
  "properties": {` + mendConfigProperties + `
  }
}`

// mendLicensesConfigSchema is the JSON Schema for controllers.licenses.mendLicenses: the shared
// Mend options plus the license policy the control gates on.
const mendLicensesConfigSchema = `{
  "type": "object",
  "additionalProperties": false,
  "required": ["productToken"],
  "properties": {` + mendConfigProperties + `,` + licensePolicyProperties + `
  }
}`
