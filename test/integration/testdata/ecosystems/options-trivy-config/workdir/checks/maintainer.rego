# METADATA
# title: Image names no maintainer
# description: A Dockerfile with no maintainer label names nobody to ask about the image.
# scope: package
# schemas:
#   - input: schema["dockerfile"]
# custom:
#   id: DRAUGR-0001
#   avd_id: DRAUGR-0001
#   severity: MEDIUM
#   short_code: no-maintainer-label
#   recommended_action: Add a maintainer label.
#   input:
#     selector:
#       - type: dockerfile
package user.draugr.maintainer

import rego.v1

labeled if {
	some cmd in input.Stages[_].Commands
	cmd.Cmd == "label"
	startswith(lower(cmd.Value[0]), "maintainer")
}

deny contains res if {
	not labeled
	some cmd in input.Stages[0].Commands
	cmd.Cmd == "from"
	res := result.new("The image has no maintainer label.", cmd)
}
