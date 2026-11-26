package tools

import (
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// pinBlock is one requirement in a generated pins file: the package and version it pins, the
// Python minors its marker limits it to (nil when it applies to every one), the digests pip will
// accept for it, and the wheel generate.py recorded as chosen for each minor.
type pinBlock struct {
	name, version string
	minors        []int
	hashes        map[string]bool
	chosen        map[int]chosenWheel
}

type chosenWheel struct{ file, sha string }

var (
	pinnedForLine   = regexp.MustCompile(`^# pinned-for: (.+)$`)
	chosenLine      = regexp.MustCompile(`^# ((?:3\.\d+ ?)+): (\S+\.whl) sha256:([0-9a-f]{64})$`)
	requirementLine = regexp.MustCompile(`^([A-Za-z0-9._-]+)==(\S+?)(?: ; (.+?))? \\$`)
	hashLine        = regexp.MustCompile(`^--hash=sha256:([0-9a-f]{64})(?: \\)?$`)
	markerMinor     = regexp.MustCompile(`^python_version == "3\.(\d+)"$`)
)

// parsePins reads a pins file as generate.py writes it, failing the test on any line it does not
// recognize, so a hand edit or a change to the generator's output shows here rather than passing
// unread.
func parsePins(t *testing.T, text string) (claimed []int, blocks []pinBlock) {
	t.Helper()
	var pending map[int]chosenWheel
	var current *pinBlock
	for n, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case line == "":
			current = nil
		case pinnedForLine.MatchString(line):
			for v := range strings.FieldsSeq(pinnedForLine.FindStringSubmatch(line)[1]) {
				claimed = append(claimed, minorOf(t, v))
			}
		case chosenLine.MatchString(line):
			m := chosenLine.FindStringSubmatch(line)
			if pending == nil {
				pending = map[int]chosenWheel{}
			}
			for v := range strings.FieldsSeq(m[1]) {
				pending[minorOf(t, v)] = chosenWheel{file: m[2], sha: m[3]}
			}
		case strings.HasPrefix(line, "#"):
			// the header's prose
		case requirementLine.MatchString(line):
			m := requirementLine.FindStringSubmatch(line)
			blocks = append(blocks, pinBlock{name: m[1], version: m[2], hashes: map[string]bool{},
				chosen: pending})
			pending = nil
			current = &blocks[len(blocks)-1]
			if m[3] != "" {
				for clause := range strings.SplitSeq(m[3], " or ") {
					mm := markerMinor.FindStringSubmatch(clause)
					if mm == nil {
						t.Fatalf("line %d: a marker clause the test does not read: %q", n+1, clause)
					}
					minor, _ := strconv.Atoi(mm[1])
					current.minors = append(current.minors, minor)
				}
			}
		case hashLine.MatchString(line) && current != nil:
			current.hashes[hashLine.FindStringSubmatch(line)[1]] = true
		default:
			t.Fatalf("line %d is not one generate.py writes: %q", n+1, raw)
		}
	}
	return claimed, blocks
}

func minorOf(t *testing.T, version string) int {
	t.Helper()
	rest, ok := strings.CutPrefix(version, "3.")
	n, err := strconv.Atoi(rest)
	if !ok || err != nil {
		t.Fatalf("%q is not a Python 3 minor", version)
	}
	return n
}

// wheelProject is how a wheel's filename spells a project: lowercase, with runs of -, _ and .
// folded to one underscore (the wheel filename rules, PEP 427 and the binary distribution format).
func wheelProject(name string) string {
	return strings.ToLower(regexp.MustCompile(`[-_.]+`).ReplaceAllString(name, "_"))
}

// The pins hold a wheel for every Python the installer may build a venv with.
//
// findPython picks the newest interpreter from newestPythonMinor down to the tool's minimum, so each
// of those is one a user's install may run on. A set resolved for fewer leaves the rest to the
// unpinned fallback; the install still works and says so, which is why nothing else would notice.
// The generator records the wheel it chose for each minor, and this holds the file to it: every
// requirement that applies on a minor names its chosen wheel, pip will accept that wheel's digest,
// and no minor gets two versions of one package or none of the tool itself.
func TestThePinsCoverEveryPythonTheInstallerUses(t *testing.T) {
	for name, spec := range pythonInstallable {
		data, err := pythonPins.ReadFile("pythonpins/" + spec.Pins + ".txt")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		claimed, blocks := parsePins(t, string(data))

		var want []int
		for minor := spec.MinPythonMinor; minor <= newestPythonMinor; minor++ {
			want = append(want, minor)
		}
		if !slices.Equal(claimed, want) {
			t.Errorf("%s: the pins are resolved for the Python 3 minors %v and the installer uses %v; "+
				"set OLDEST and NEWEST in generate.py to match and regenerate", name, claimed, want)
		}

		for _, minor := range claimed {
			seen := map[string]string{}
			for _, b := range blocks {
				if b.minors != nil && !slices.Contains(b.minors, minor) {
					continue
				}
				project := wheelProject(b.name)
				if other, dup := seen[project]; dup {
					t.Errorf("%s on 3.%d: %s is pinned at both %s and %s", name, minor, b.name, other,
						b.version)
				}
				seen[project] = b.version
				wheel, ok := b.chosen[minor]
				if !ok {
					t.Errorf("%s on 3.%d: %s==%s applies but no wheel is recorded for it", name, minor,
						b.name, b.version)
					continue
				}
				if !strings.HasPrefix(strings.ToLower(wheel.file), project+"-"+b.version+"-") {
					t.Errorf("%s on 3.%d: %s==%s records %s, a wheel of something else", name, minor,
						b.name, b.version, wheel.file)
				}
				if !b.hashes[wheel.sha] {
					t.Errorf("%s on 3.%d: %s==%s would refuse %s, the wheel recorded for it", name,
						minor, b.name, b.version, wheel.file)
				}
			}
			if _, ok := seen[wheelProject(spec.Package)]; !ok {
				t.Errorf("%s on 3.%d: the set holds no %s", name, minor, spec.Package)
			}
		}
		// A recorded wheel for a minor the requirement's marker excludes is a set that says one thing
		// in its comments and another to pip.
		for _, b := range blocks {
			for minor := range b.chosen {
				if b.minors != nil && !slices.Contains(b.minors, minor) {
					t.Errorf("%s: %s==%s records a wheel for 3.%d and its marker excludes it", name,
						b.name, b.version, minor)
				}
			}
		}
	}
}

// The test reads what the generator writes, and refuses what it does not, so a format change on
// either side fails here instead of leaving the check above reading nothing.
func TestParsePinsReadsTheGeneratorsFormat(t *testing.T) {
	sha := func(c string) string { return strings.Repeat(c, 64) }
	text := "# Generated by internal/tools/pythonpins/generate.py, do not edit.\n" +
		"#\n# pinned-for: 3.10 3.11\n\n" +
		"# 3.10: foo_bar-1.0-cp310-cp310-manylinux_2_17_x86_64.whl sha256:" + sha("a") + "\n" +
		"Foo.Bar==1.0 ; python_version == \"3.10\" \\\n" +
		"    --hash=sha256:" + sha("a") + " \\\n" +
		"    --hash=sha256:" + sha("b") + "\n\n" +
		"# 3.10 3.11: baz-2.0-py3-none-any.whl sha256:" + sha("c") + "\n" +
		"baz==2.0 \\\n    --hash=sha256:" + sha("c") + "\n"

	claimed, blocks := parsePins(t, text)
	if !slices.Equal(claimed, []int{10, 11}) {
		t.Errorf("claimed = %v", claimed)
	}
	if len(blocks) != 2 {
		t.Fatalf("blocks = %+v", blocks)
	}
	foo, baz := blocks[0], blocks[1]
	if foo.name != "Foo.Bar" || foo.version != "1.0" || !slices.Equal(foo.minors, []int{10}) ||
		len(foo.hashes) != 2 || foo.chosen[10].sha != sha("a") {
		t.Errorf("foo = %+v", foo)
	}
	if baz.minors != nil || len(baz.chosen) != 2 || !baz.hashes[sha("c")] {
		t.Errorf("baz = %+v", baz)
	}
	if got := wheelProject("Foo.Bar"); got != "foo_bar" {
		t.Errorf("wheelProject = %q", got)
	}
}
