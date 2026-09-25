# METADATA
# title: Base image from an untrusted registry
# description: A base image named without a registry is pulled from Docker Hub.
# scope: package
# schemas:
#   - input: schema["dockerfile"]
# custom:
#   id: DRAUGR-0002
#   avd_id: DRAUGR-0002
#   severity: HIGH
#   short_code: untrusted-base-registry
#   recommended_action: Name the base image with the organization's registry.
#   input:
#     selector:
#       - type: dockerfile
package acme.draugr.registry

import rego.v1

deny contains res if {
	some cmd in input.Stages[_].Commands
	cmd.Cmd == "from"
	not startswith(cmd.Value[0], "registry.acme.example/")
	res := result.new(sprintf("The base image %s is not from registry.acme.example.", [cmd.Value[0]]), cmd)
}
