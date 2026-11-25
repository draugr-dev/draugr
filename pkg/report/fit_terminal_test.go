package report

import (
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// sectionLines are the lines of the block under a heading, up to the blank line that ends it.
func sectionLines(out, heading string) []string {
	_, block, ok := strings.Cut(out, "\n"+heading)
	if !ok {
		return nil
	}
	block, _, _ = strings.Cut(block, "\n\n")
	return strings.Split(block, "\n")[1:]
}

// On a terminal of a known width, no FOUND or TRY row is wider than it: FOUND's file lists are cut
// to fewer paths with the rest counted, and a TRY command too long to sit beside the others gets
// its description on the next line, whole. Off a terminal, every row keeps its whole text.
func TestFoundAndTryFitTheTerminal(t *testing.T) {
	deep := ".config/mise/locks/mise.dev/pypi-docker-hosts/0.2.1/"
	out := "/home/someone/projects/the-service/goos.out"
	data := func() Data {
		d := withReports(goldenFullData(), out, "json", "sarif")
		d.Found = []Found{
			{Kind: "python", Files: deep + "pyproject.toml · " + deep + "uv.lock", Paths: []string{deep + "pyproject.toml", deep + "uv.lock"}, Did: "sca · trivy-fs"},
			{Kind: "Terraform", Files: "infra/azure", Paths: []string{"infra/azure"}, Did: "iac"},
		}
		return d
	}

	t.Setenv("COLUMNS", "120")
	got := renderConsole(t, data())
	found, try := sectionLines(got, "FOUND"), sectionLines(got, "TRY")
	if len(found) != 2 || len(try) == 0 {
		t.Fatalf("want two FOUND rows and a TRY block, got FOUND %q TRY %q:\n%s", found, try, got)
	}
	for _, l := range append(found, try...) {
		if n := len([]rune(l)); n > 120 {
			t.Errorf("a %d-cell line on a 120-column terminal: %q", n, l)
		}
	}
	for _, want := range []string{deep + "pyproject.toml · +1", "  Terraform  infra/azure "} {
		if !strings.Contains(strings.Join(found, "\n"), want) {
			t.Errorf("FOUND missing %q:\n%s", want, strings.Join(found, "\n"))
		}
	}
	if !strings.Contains(got, "draugr explain <rule> -r "+out+"/results.sarif\n") ||
		!strings.Contains(got, " what a rule means and how to fix it\n") {
		t.Errorf("the long explain row should end its line, its description whole on the next:\n%s", strings.Join(try, "\n"))
	}

	t.Setenv("COLUMNS", "0")
	whole := renderConsole(t, data())
	if !strings.Contains(whole, deep+"pyproject.toml · "+deep+"uv.lock") {
		t.Errorf("off a terminal the file list should be whole:\n%s", strings.Join(sectionLines(whole, "FOUND"), "\n"))
	}
	if !strings.Contains(whole, "results.sarif  what a rule means and how to fix it\n") {
		t.Errorf("off a terminal TRY rows should stay on one line:\n%s", strings.Join(sectionLines(whole, "TRY"), "\n"))
	}
}

// REPORTS fits the terminal as TRY does: with a long -o path, no row is wider than the terminal,
// each path is whole so it can be copied, and a description that does not fit beside its path is on
// the next line, whole. Off a terminal every row keeps its line.
func TestReportsFitTheTerminal(t *testing.T) {
	out := "/home/someone/projects/a-service-with-a-long-name/build/security/reports/goos"
	data := func() Data { return withReports(goldenFullData(), out, "json", "sarif", "html") }
	for _, width := range []string{"80", "120"} {
		t.Run(width, func(t *testing.T) {
			t.Setenv("COLUMNS", width)
			reports := sectionLines(renderConsole(t, data()), "REPORTS")
			if len(reports) < 3 {
				t.Fatalf("want a REPORTS row per file, got %q", reports)
			}
			block := strings.Join(reports, "\n")
			cols, _ := strconv.Atoi(width)
			for _, l := range reports {
				// Only a path alone may run past the edge, because cutting it would leave nothing to copy.
				line := strings.TrimSpace(l)
				alone := strings.HasPrefix(line, out) && !strings.Contains(line, " ")
				if n := len([]rune(l)); n > cols && !alone {
					t.Errorf("a %d-cell line on a %s-column terminal: %q", n, width, l)
				}
			}
			for _, f := range []string{"report.html", "results.sarif", "report.json"} {
				if !strings.Contains(block, out+"/"+f+"\n") {
					t.Errorf("%s is not whole at the end of its line:\n%s", f, block)
				}
			}
			for _, purpose := range reportPurpose {
				if !strings.Contains(block, purpose) {
					t.Errorf("REPORTS lost %q:\n%s", purpose, block)
				}
			}
		})
	}

	t.Setenv("COLUMNS", "0")
	whole := strings.Join(sectionLines(renderConsole(t, data()), "REPORTS"), "\n")
	if !regexp.MustCompile(regexp.QuoteMeta(out+"/report.html") + ` +` + regexp.QuoteMeta(reportPurpose["html"])).MatchString(whole) {
		t.Errorf("off a terminal a REPORTS row should stay on one line:\n%s", whole)
	}
}
