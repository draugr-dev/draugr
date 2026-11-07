package controllers

import (
	"encoding/json"
	"fmt"

	"github.com/draugr-dev/draugr/pkg/saga"
)

// nonShippingKey decides whether the findings in files under documentation, examples or tests count.
// sast, iac and sca each take it, under the control, because each reports a location in the
// repository's own files. secrets does not: a credential committed beside a test is as live as one
// committed beside the code.
//
// One key per control rather than one for the project, as every setting that sets a kind of finding
// aside is: devDependencies, providedDependencies and cpeMatches sit under sca for the same reason.
// The answer differs by control. A team can set aside ten thousand Helm fixtures under iac and keep
// counting a SQL injection in a test helper under sast, and a component can answer for itself.
const nonShippingKey = "nonShippingPaths"

// nonShippingProperty describes nonShippingPaths where it sits, as a property of a control's schema.
const nonShippingProperty = `"nonShippingPaths": {
      "type": "string",
      "default": "report",
      "anyOf": [
        { "const": "report", "description": "Each finding in a file under a docs, examples or tests directory is counted, labeled with the kind of directory, and listed after the findings in shipped code. The default." },
        { "const": "suppress", "description": "Each finding in a file under a docs, examples or tests directory stays in the report, suppressed with the reason in docs, examples or tests, and out of the counts and the gate." }
      ],
      "description": "Whether findings in files under a docs, examples or tests directory count, such as docs/, examples/, tests/ and testdata/ at any depth. A component's setting replaces the project's."
    }`

// nonShippingOptionSchema is the schema of a control whose only setting is nonShippingPaths.
var nonShippingOptionSchema = json.RawMessage(`{
  "type": "object",
  "properties": {
    ` + nonShippingProperty + `
  }
}`)

// reportsNonShipping resolves nonShippingPaths for one component of one control, and names the key
// that decided it: the component's setting first, then the project's, and with neither written the
// default, report, named by the project's key.
func reportsNonShipping(model saga.Model, component, control string) (bool, string) {
	return controlSetting(model, component, control, nonShippingKey, true)
}

// ReportsNonShipping resolves sast's nonShippingPaths for one component.
func (SAST) ReportsNonShipping(model saga.Model, component string) (bool, string) {
	return reportsNonShipping(model, component, "sast")
}

// ReportsNonShipping resolves iac's nonShippingPaths for one component.
func (IAC) ReportsNonShipping(model saga.Model, component string) (bool, string) {
	return reportsNonShipping(model, component, "iac")
}

// ReportsNonShipping resolves sca's nonShippingPaths for one component. A dependency file under
// tests/, such as a go.mod for a module only the tests build, is the case it covers.
func (SCA) ReportsNonShipping(model saga.Model, component string) (bool, string) {
	return reportsNonShipping(model, component, scaControl)
}

// controlSetting resolves one of a control's suppress-or-report settings for one component, and
// names the key that decided it: the component's setting first, then the project's, and with neither
// written the default, report where def is true and suppress where it is false, named by the
// project's key, which is the one a reader writes to change it.
func controlSetting(model saga.Model, component, control, key string, def bool) (bool, string) {
	project := "config.controls." + control + "." + key
	if comp := componentNamed(model, component); comp != nil {
		if v, written := comp.Controls[control][key].(string); written {
			return v == devReport, fmt.Sprintf("components[%q].controls.%s.%s", comp.Name, control, key)
		}
	}
	if v, written := model.Config.Controls[control][key].(string); written {
		return v == devReport, project
	}
	return def, project
}
