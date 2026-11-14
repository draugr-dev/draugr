package report

// reasonedInstruction is ruleInstruction for rules whose scanner writes a sentence worth keeping: the
// row takes the instruction as its title and the scanner's sentence beneath it, as the reason. A rule
// whose sentence only repeats the instruction, or says nothing about the line, belongs in
// ruleInstruction. So does one whose title is short enough to carry the whole of what it says.
//
// A rule with no entry here or there keeps its name as its title and its sentence beneath. Each
// sentence holds wherever the rule fires, under the same terms as ruleInstruction. A rule matching a
// pattern on one line can flag a line that is fine, so a change it cannot be sure of carries an "if".
// Check an instruction that loosens something for the direction of the risk: 0644 is more access than
// the 0660 it would replace.
var reasonedInstruction = map[string]string{ // #nosec G101 -- sentences for a reader, keyed by rule name; none is a credential
	// Headers a server sends. These are Draugr's own rules.
	"csp-missing":                       "Add a Content-Security-Policy header",
	"hsts-missing":                      "Add a Strict-Transport-Security header",
	"permissions-policy-missing":        "Add a Permissions-Policy header",
	"referrer-policy-missing":           "Add a Referrer-Policy header",
	"x-content-type-options-missing":    "Set X-Content-Type-Options to nosniff",
	"x-content-type-options-invalid":    "Set X-Content-Type-Options to nosniff",
	"x-frame-options-missing":           "Add X-Frame-Options, or frame-ancestors in the CSP",
	"server-disclosure":                 "Remove or shorten the Server header",
	"x-powered-by-disclosure":           "Remove the X-Powered-By header",
	"cache-control-missing":             "Add Cache-Control: no-store if responses hold sensitive data",
	"cors-wildcard":                     "Name the allowed origins unless the API is meant to be public",
	"cors-wildcard-with-credentials":    "Name the allowed origins in Access-Control-Allow-Origin",
	"csp-no-reporting":                  "Add a reporting directive to the Content-Security-Policy",
	"csp-base-uri-missing":              "Add base-uri to the Content-Security-Policy",
	"csp-default-src-missing":           "Add default-src to the Content-Security-Policy",
	"csp-script-src-missing":            "Add script-src to the Content-Security-Policy",
	"csp-object-src-broad":              "Set object-src to 'none' in the Content-Security-Policy",
	"csp-object-src-not-none":           "Set object-src to 'none' in the Content-Security-Policy",
	"csp-script-src-broad":              "Name the script origins in the Content-Security-Policy",
	"csp-unsafe-eval":                   "Remove 'unsafe-eval' from the Content-Security-Policy",
	"csp-unsafe-inline":                 "Remove 'unsafe-inline' from the Content-Security-Policy",
	"csp-unsafe-inline-legacy-fallback": "Remove 'unsafe-inline' from the Content-Security-Policy",
	"csp-blocks-inline-handler":         "Move the inline handlers to a script file",

	// TLS and certificates. Also Draugr's own, and a sentence can hold the date or the name.
	"tls-deprecated-protocol":    "Turn off TLS versions older than 1.2",
	"tls-modern-unsupported":     "Turn on TLS 1.2 or newer",
	"tls-legacy-cipher-only":     "Turn on ECDHE suites with AES-GCM or ChaCha20, and turn off the old ones",
	"tls-no-shared-cipher":       "Turn on ECDHE suites with AES-GCM or ChaCha20, and turn off the old ones",
	"tls-cipher-rc4":             "Turn off the RC4 suites",
	"tls-cipher-3des":            "Turn off the 3DES suites",
	"tls-cipher-static-rsa":      "Turn off the suites with RSA key exchange",
	"tls-cipher-cbc":             "Turn off the CBC suites, keeping AES-GCM and ChaCha20",
	"tls-cert-expired":           "Renew the certificate, or check its start date",
	"tls-cert-expiring":          "Renew the certificate",
	"tls-cert-untrusted":         "Serve the full certificate chain from a trusted authority",
	"tls-cert-hostname-mismatch": "Reissue the certificate to cover the host's name",
	"tls-cert-invalid":           "Replace the certificate",
	"tls-cert-no-san":            "Reissue the certificate with the host's name as a SAN",
	"tls-cert-chain-order":       "Serve the leaf first, then each issuer in turn",
	"tls-weak-cert-signature":    "Reissue the certificate with a SHA-256 or stronger signature",
	"tls-weak-key":               "Reissue the certificate with a stronger key",

	// Credentials. A rule matching a shape can flag a placeholder or a test value, and the most
	// general of them can flag anything long enough, so these leave room for that.
	"generic-api-key":     "Check for a credential, and rotate any you find",
	"private-key":         "Remove and rotate the private key if it is real",
	"jwt":                 "Remove and rotate the token if it is a live one",
	"curl-auth-header":    "Remove and rotate the token in the curl command if it is real",
	"curl-auth-user":      "Remove and rotate the password in the curl command if it is real",
	"gcp-api-key":         "Restrict or rotate the Google Cloud API key if it is real",
	"aws-access-token":    "Remove and rotate the AWS access key if it is real",
	"github-pat":          "Remove and rotate the GitHub token if it is real",
	"stripe-access-token": "Remove and rotate the Stripe token if it is real",
	"pkcs12-file":         "Remove and rotate the keys in the PKCS #12 file if they are real",

	// Containers and Kubernetes.
	"missing-user":            "Set a non-root USER in the Dockerfile",
	"missing-user-entrypoint": "Set a non-root USER in the Dockerfile",

	// Commands and code run from data.
	"dangerous-system-call":             "Run the command as an argument list, without a shell",
	"subprocess-injection":              "Run the command as an argument list, without a shell",
	"dangerous-subprocess-use":          "Run the command as an argument list, without a shell",
	"subprocess-shell-true":             "Run the command as an argument list, without a shell",
	"B602":                              "Run the command as an argument list, without a shell",
	"B605":                              "Run the command as an argument list, without a shell",
	"command-injection-process-builder": "Check who can set the ProcessBuilder command and arguments",
	"detect-child-process":              "Check who can set the command and its arguments",
	"user-eval":                         "Remove eval(), or check no outside data reaches it",
	"eval-injection":                    "Remove eval(), or check no outside data reaches it",
	"eval-detected":                     "Remove eval(), or check no outside data reaches it",
	"B307":                              "Remove eval(), or check no outside data reaches it",
	"unsafe-reflection":                 "Check who can set the name used for reflection",
	"unsafe-reflect-by-name":            "Check who can set the name used for reflection",
	"remote-property-injection":         "Check no outside data selects the object's property",
	"dangerous-annotations-usage":       "Check no outside data reaches get_type_hints",

	// Output a browser reads.
	"raw-html-format":                     "Use a template that escapes HTML, not a built string",
	"import-text-template":                "Use html/template if the output is HTML",
	"no-fprintf-to-responsewriter":        "Use html/template if the response is HTML",
	"no-io-writestring-to-responsewriter": "Use html/template if the response is HTML",
	"direct-response-write":               "Escape outside data before writing it to the response",
	"avoid-v-html":                        "Check no outside data reaches v-html",
	"unknown-value-with-script-tag":       "Check no outside data reaches the script tag",
	"incomplete-sanitization":             "If it escapes data, replace every occurrence, not only the first",
	"detect-replaceall-sanitization":      "If replaceAll escapes HTML, use an escaping library instead",
	"avoid-redirect":                      "Check who can set the redirect URL",
	"cors-misconfiguration":               "Check who can set the CORS header",
	"insecure-object-assign":              "Check no outside data reaches Object.assign",
	"express-data-exfiltration":           "Check no outside data reaches Object.assign",

	// Requests a server accepts.
	"django-no-csrf-token":           "Add {% csrf_token %} to forms that post to your own site",
	"missing-csrf-protection":        "Add protect_from_forgery to the controller if it serves browser forms",
	"unrestricted-request-mapping":   "Name the HTTP method on the RequestMapping",
	"websocket-missing-origin-check": "Check the Origin header in the WebSocket handshake",
	"model-attr-accessible":          "Stop permitting attributes like admin and role from request data",
	"mass-assignment-vuln":           "Remove without_protection from the mass assignment",
	"detailed-exceptions":            "Turn off detailed exception reports outside development",
	"ajv-allerrors-true":             "Set allErrors to false in Ajv",

	// Servers and connections.
	"debug-enabled":                   "Turn off debug mode outside development",
	"B201":                            "Turn off debug mode outside development",
	"avoid_app_run_with_bad_host":     "Bind a specific host unless the server must be reachable from outside",
	"avoid-bind-to-all-interfaces":    "Bind a specific host unless the server must be reachable from outside",
	"B104":                            "Bind a specific host unless the server must be reachable from outside",
	"use-tls":                         "Serve over TLS, or behind a proxy that terminates TLS",
	"grpc-server-insecure-connection": "Add TLS credentials to the gRPC server",
	"httpsconnection-detected":        "Check the HTTPS connection verifies certificates",
	"G114":                            "Use an http.Server with timeouts",
	"G123":                            "Set VerifyConnection on the TLS configuration",

	// Files, deserialized data and expressions.
	"unsafe-path-combine":                 "Check who can set the file path",
	"insecure-file-permissions":           "Grant only the access needed, such as 0600 for a private file",
	"tarfile-extractall-traversal":        "Check the archive cannot come from outside, or use filter='data'",
	"G122":                                "Use os.Root inside the walk if the tree can hold untrusted symlinks",
	"use-defused-xml-parse":               "Use defusedxml if the XML can come from outside",
	"go-unsafe-deserialization-interface": "Decode into a concrete struct, not interface{}, where the shape is known",
	"check-regex-dos":                     "Use a fixed regular expression, or check who can set it",
	"regular-expression-dos":              "Pass a timeout to the regular expression",

	// Randomness, hashing and encryption.
	"weak-random":           "Use a secure random generator if the value must be unguessable",
	"insecure-uuid-version": "Use a random UUID (version 4) if it must be unguessable",
	"sha224-hash":           "Use a stronger hash if the hash protects data",
	"gcm-no-tag-length":     "Set authTagLength in createDecipheriv",
	"G407":                  "Generate a random IV or nonce for each encryption",

	// Values, locks and goroutines.
	"string-to-int-signedness-cast": "Check the value's range before converting it",
	"missing-unlock-before-return":  "Unlock the mutex on every return path",
	"missing-runlock-on-rwmutex":    "Unlock the mutex on every return path",
	"G117":                          "Check the secret field is meant to be serialized",
	"G118":                          "Pass the request's context if the goroutine should stop with it",

	// CI and package managers.
	"gha-curl-pipe-shell":               "Download a pinned version and check its hash before running it",
	"github-script-injection":           "Pass github.* values through an environment variable, not ${{ }}",
	"pull-request-target-code-checkout": "Do not run pull request code under pull_request_target",
	"uv-missing-dependency-cooldown":    "Add exclude-newer to the uv configuration",
	"pnpm-minimum-release-age":          "Add minimumReleaseAge to the pnpm workspace",
	"yarn-missing-minimal-age-gate":     "Set npmMinimalAgeGate in .yarnrc.yml",

	// Image signatures. Draugr's own; the sentence names the signer found and the one expected.
	// An unexpected signer is either a build that moved or an image that is not what it claims,
	// and nothing in the code tells the two apart, so the first step is finding out which.
	"provenance-unexpected-identity": "Find out what signed the image before running it",
	"provenance-unsigned":            "Sign the image in the build that publishes it, or ask its publisher to",
	"provenance-not-covered":         "Declare a signer that covers the image, or accept it uncovered",
}

// instructionOf is the instruction for a rule, from whichever table holds it.
func instructionOf(rule string) string {
	if i := ruleInstruction[shortRuleName(rule)]; i != "" {
		return i
	}
	if i := reasonedInstruction[shortRuleName(rule)]; i != "" {
		return i
	}
	return cloudInstruction[shortRuleName(rule)]
}

// instructionsKeepTheirReason reports whether a row titled with instruction keeps the scanner's
// sentence beneath it: whether a rule on its lines holds the instruction in reasonedInstruction or
// cloudInstruction.
func instructionsKeepTheirReason(fs []finding, instruction string) bool {
	for _, f := range fs {
		if name := shortRuleName(f.ruleID); reasonedInstruction[name] == instruction || cloudInstruction[name] == instruction {
			return true
		}
	}
	return false
}

// titleHidesRule reports whether an action grouped on a rule is titled by an instruction, so the rule's
// name appears nowhere in its title and needs a line of its own.
func (a action) titleHidesRule() bool {
	if !a.byRule || len(a.findings) == 0 || a.findings[0].ruleID == "" {
		return false
	}
	return instructionOf(a.findings[0].ruleID) == a.title
}
