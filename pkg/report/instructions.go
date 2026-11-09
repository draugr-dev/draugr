package report

import (
	"slices"
	"strings"
)

// ruleInstruction is what to do about a line a rule flags, in Draugr's words, by the rule's short
// name. A scanner's own text usually names a flaw and leaves the change to the reader, and a reader
// with no security background cannot get from "Errors unhandled" to an edit.
//
// A rule sees one line and not what the line is for, so each sentence has to hold on every line the
// rule flags, however that line is written. Where a rule cannot tell whether the line is wrong, the
// sentence says what to check or carries an "if". Each reads the same over one line or many, because
// a row can stand for several. A rule with no entry keeps the scanner's own words as its title.
var ruleInstruction = map[string]string{ // #nosec G101 -- sentences for a reader, keyed by rule name; none is a credential
	// Conversions and errors.
	"G104": "Handle the returned error",
	"G115": "Check the value's range before converting it",

	// Reaching outside the program.
	"G103":                        "Check the unsafe call is needed",
	"G204":                        "Check who can set the command's arguments",
	"exec-use":                    "Check who can set the executed command",
	"non-literal-import":          "Check who can set the imported module's name",
	"dynamic-urllib-use-detected": "Check who can set the URL",
	"check-unscoped-find":         "Scope the find to the current user if records belong to users",

	// File paths and permissions.
	"G304":                        "Check who can set the file path",
	"G703":                        "Check who can set the file path",
	"path-join-resolve-traversal": "Check who can set the file path",
	"unlink-use":                  "Check who can set the file path",
	"G301":                        "Set directory permissions to 0750 or less",
	"G302":                        "Set file permissions to 0600 or less",
	"G306":                        "Set file permissions to 0600 or less",

	// Randomness and hashing.
	"G404":             "Use crypto/rand if the value must be unguessable",
	"math-random-used": "Use crypto/rand if the value must be unguessable",
	"G401":             "Use SHA-256, or bcrypt for passwords, if the hash protects data",
	"G501":             "Use SHA-256, or bcrypt for passwords, if the hash protects data",
	"use-of-md5":       "Use SHA-256, or bcrypt for passwords, if the hash protects data",

	// Connections.
	"G402":                      "Check the TLS settings: certificate verification, version, ciphers",
	"bypass-tls-verification":   "Check the TLS settings: certificate verification, version, ciphers",
	"missing-ssl-minversion":    "Check the TLS settings: certificate verification, version, ciphers",
	"G112":                      "Set ReadHeaderTimeout on the server",
	"detect-insecure-websocket": "Use wss:// for the WebSocket connection",
	"plaintext-http-link":       "Use an HTTPS link if the site supports it",

	// Cookies.
	"G124":                    "Check Secure, HttpOnly and SameSite on the cookie",
	"cookie-missing-httponly": "Check Secure, HttpOnly and SameSite on the cookie",
	"cookie-missing-secure":   "Check Secure, HttpOnly and SameSite on the cookie",

	// Output a browser or a log reads.
	"G203":                              "Check no user input reaches a value the template leaves unescaped",
	"G706":                              "Remove line breaks from the value before logging it",
	"avoid-content-tag":                 "Check no outside data reaches content_tag()",
	"avoid-html-safe":                   "Check no outside data reaches html_safe()",
	"template-explicit-unescape":        "Check no outside data reaches the unescaped value",
	"var-in-href":                       "Check no outside data reaches the link's href",
	"missing-integrity":                 "Add an integrity attribute to the tag",
	"unsafe-formatstring":               "Use a constant format string",
	"no-direct-write-to-responsewriter": "Use html/template if the response is HTML",

	// Queries and serialized data.
	"formatted-sql-query":          "Pass outside data as query parameters, not in the SQL text",
	"sqlalchemy-execute-raw-query": "Pass outside data as query parameters, not in the SQL text",
	"avoid-sqlalchemy-text":        "Check no outside data reaches sqlalchemy.text",
	"unserialize-use":              "Check who can set the input to unserialize()",
	"avoid-pickle":                 "Use JSON instead of pickle if the data can come from outside",
	"pickles-in-pytorch":           "Use safetensors or weights_only=True if the file can come from outside",
	"prototype-pollution-loop":     "Check the loop cannot write to an object's prototype",
	"detect-non-literal-regexp":    "Use a fixed regular expression, or check who can set it",

	// Credentials in code.
	"G101":                                "Check for a credential, and rotate any you find",
	"detected-private-key":                "Remove and rotate the private key if it is real",
	"python-logger-credential-disclosure": "Check the log call writes no secret",

	// GitHub Actions and Dependabot.
	"github-actions-mutable-action-tag": "Pin actions to a full commit SHA",
	"run-shell-injection":               "Pass github.* values through an environment variable, not ${{ }}",
	"secrets-inherit":                   "Pass only the secrets the called workflow needs",
	"gha-workflow-env-secret":           "Move the secret to the step that needs it",
	"dependabot-missing-cooldown":       "Add a cooldown to the Dependabot configuration",

	// A host's TLS, whose sentence only restates the instruction.
	"tls-no-tls13": "Turn on TLS 1.3",

	// Kubernetes.
	"allow-privilege-escalation":                    "Set allowPrivilegeEscalation to false",
	"allow-privilege-escalation-true":               "Set allowPrivilegeEscalation to false",
	"allow-privilege-escalation-no-securitycontext": "Set allowPrivilegeEscalation to false",
	"run-as-non-root":                               "Set runAsNonRoot to true",
	"hostnetwork-pod":                               "Remove hostNetwork from the pod unless it needs the node's network",
	"hostpid-pod":                                   "Remove hostPID from the pod unless it needs the node's processes",
	"privileged-container":                          "Remove privileged from the container unless it needs host access",

	// Rails, shell and source text.
	"model-attributes-attr-accessible":  "Allow only named attributes through mass assignment",
	"ifs-tampering":                     "Restore IFS after changing it, or set it for one command only",
	"contains-bidirectional-characters": "Check the bidirectional characters are intended",
	"numpy-in-pytorch-modules":          "Use PyTorch operations in the module instead of NumPy",
}

// instructionFor is the instruction for the findings at one line: the rule that titles the line, and
// otherwise the first of the others that has one, so two rules about one flaw read alike. also holds
// what another rule on the line asks for instead. One change does not clear a finding that asks for a
// different one, and a row naming only the first would say it did.
func instructionFor(fs []finding) (instruction, also string) {
	if len(fs) == 0 {
		return "", ""
	}
	var others []string
	add := func(f finding) {
		i := instructionOf(f.ruleID)
		switch {
		case i == "" || i == instruction || slices.Contains(others, i):
		case instruction == "":
			instruction = i
		default:
			others = append(others, i)
		}
	}
	add(titleFinding(fs))
	for _, f := range fs {
		add(f)
	}
	if len(others) > 0 {
		also = "Also: " + strings.Join(others, " · ")
	}
	return instruction, also
}

// findingInstruction is the instruction for one finding, where it flags a line of code.
func findingInstruction(f finding) string {
	if !onALine(f) {
		return ""
	}
	return instructionOf(f.ruleID)
}
