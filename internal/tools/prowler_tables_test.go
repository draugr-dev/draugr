package tools

import (
	"os"
	"regexp"
	"testing"
)

// scripts/prowler-tables.sh, which tool-bump's scheduled run calls, finds ProwlerTablesVersion with
// sed, so the constant stays a quoted release on a line of its own. Reformatted, the scheduled run
// fails rather than comparing nothing, and this fails first.
func TestProwlerTablesVersionIsALineTheScheduledRunReads(t *testing.T) {
	src, err := os.ReadFile("tools.go")
	if err != nil {
		t.Fatal(err)
	}
	line := regexp.MustCompile(`(?m)^const ProwlerTablesVersion = "([0-9][0-9.]*)"$`).FindSubmatch(src)
	if line == nil || string(line[1]) != ProwlerTablesVersion {
		t.Errorf("tools.go has no `const ProwlerTablesVersion = \"%s\"` line for the scheduled run to read", ProwlerTablesVersion)
	}
	if !regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`).MatchString(ProwlerTablesVersion) {
		t.Errorf("ProwlerTablesVersion = %q, want a release such as 5.44.0", ProwlerTablesVersion)
	}
}
