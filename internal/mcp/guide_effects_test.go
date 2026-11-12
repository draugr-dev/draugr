package mcp

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/builtins"
)

// effectLine is how the approval prompt prints one effect, `<scanner> (<kind>): <detail>`, as the
// guide quotes it inside an example.
var effectLine = regexp.MustCompile(`^\s+([a-z0-9-]+) \(([a-z-]+)\): (.+)$`)

// The MCP guide quotes the approval prompt word for word, and each scanner's line in it is that
// scanner's declared effect. A detail can change in the scanner without anything else noticing:
// `draugr controls` has goldens and the guide has none, so its copy would keep describing what the
// scanner used to do.
func TestTheMCPGuideQuotesEachEffectAsDeclared(t *testing.T) {
	doc, err := os.ReadFile("../../docs/guides/ai-agents-mcp.md")
	if err != nil {
		t.Fatal(err)
	}
	reg := builtins.Registry()
	quoted := 0
	inFence := false
	for i, line := range strings.Split(string(doc), "\n") {
		if strings.HasPrefix(line, "```") {
			inFence = !inFence
			continue
		}
		m := effectLine.FindStringSubmatch(line)
		if !inFence || m == nil {
			continue
		}
		quoted++
		name, kind, detail := m[1], m[2], m[3]
		sc, ok := reg.Scanner(name)
		if !ok {
			t.Errorf("ai-agents-mcp.md:%d quotes an effect of %s, which is not a registered scanner", i+1, name)
			continue
		}
		var declared []string
		for _, e := range sc.Info().Effects {
			got := fmt.Sprintf("%s (%s): %s", name, e.Kind, e.Detail)
			if got == strings.TrimSpace(line) {
				declared = nil
				break
			}
			declared = append(declared, got)
		}
		if declared != nil || len(sc.Info().Effects) == 0 {
			t.Errorf("ai-agents-mcp.md:%d quotes %s (%s): %q,\nwhich %s does not declare. It declares:\n  %s",
				i+1, name, kind, detail, name, strings.Join(declared, "\n  "))
		}
	}
	if quoted == 0 {
		t.Fatal("found no quoted effect line in ai-agents-mcp.md; the guide or the pattern has moved")
	}
}
