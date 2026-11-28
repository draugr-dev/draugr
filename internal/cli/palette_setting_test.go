package cli

import (
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/tui"
)

// output.palette in the user's file holds for every command the process runs, and a project's file
// beside it outranks it, as every output setting does.
func TestThePaletteSettingReachesEveryPainter(t *testing.T) {
	configHome(t, "output:\n  palette: light-background\n")
	if _, _, err := runRoot(t, t.TempDir(), "version"); err != nil {
		t.Fatal(err)
	}
	if got := tui.ActivePalette(); got != tui.PaletteLightBackground {
		t.Errorf("after the user's file: palette %q, want %q", got, tui.PaletteLightBackground)
	}
	if _, _, err := runRoot(t, projectBeside(t, "output:\n  palette: standard\n"), "version"); err != nil {
		t.Fatal(err)
	}
	if got := tui.ActivePalette(); got != tui.PaletteStandard {
		t.Errorf("under a project's standard: palette %q, want %q", got, tui.PaletteStandard)
	}
}

// A misspelled palette cannot stop a command, the one that mends it included, and draws in the
// standard colors meanwhile; the commands that read the file name it.
func TestAMisspelledPaletteIsNamedAndNotDrawn(t *testing.T) {
	configHome(t, "")
	dir := projectBeside(t, "output:\n  palette: high-contrast\n")
	if _, _, err := runRoot(t, dir, "version"); err != nil {
		t.Fatalf("a misspelled palette stopped `version`: %v", err)
	}
	if got := tui.ActivePalette(); got != tui.PaletteStandard {
		t.Errorf("palette %q, want the standard one in place of a name that does not exist", got)
	}
	out, _, err := runRoot(t, dir, "config", "validate")
	if err == nil || !strings.Contains(out, `output.palette: "high-contrast" is not standard or light-background`) {
		t.Errorf("validate did not name the palette: %v\n%s", err, out)
	}
	if out, _, err = runRoot(t, dir, "config", "unset", "output.palette"); err != nil {
		t.Fatalf("unset could not mend the file: %v\n%s", err, out)
	}
	if out, _, err = runRoot(t, dir, "config", "validate"); err != nil {
		t.Errorf("the mended file does not validate: %v\n%s", err, out)
	}
}

// `draugr config show` names the palette in force, so somebody wondering why the colors moved can
// find the file that moved them.
func TestConfigShowNamesThePalette(t *testing.T) {
	configHome(t, "output:\n  palette: light-background\n")
	out, _, err := runRoot(t, t.TempDir(), "config", "show")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "output.palette") || !strings.Contains(out, "light-background") {
		t.Errorf("config show does not name the palette:\n%s", out)
	}
}
