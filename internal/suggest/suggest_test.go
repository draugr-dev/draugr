package suggest

import "testing"

func TestNearestSuggestsATypoAndNothingWild(t *testing.T) {
	known := map[string]bool{"sast": true, "sca": true, "iac": true, "secrets": true}
	for name, want := range map[string]string{
		"sats": "sast", "iaac": "iac", "SCAA": "sca", "secretz": "secrets",
		"kubernetes-posture": "", "zzzzzzzz": "", "": "",
	} {
		if got := Nearest(name, known); got != want {
			t.Errorf("Nearest(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestNearestBreaksATieAlphabetically(t *testing.T) {
	// Equally close candidates must give the same answer on every run, or one error message reads
	// differently each time it is printed.
	if got := Nearest("ab", map[string]bool{"ac": true, "aa": true}); got != "aa" {
		t.Errorf("Nearest(ab) = %q, want aa", got)
	}
}

func TestDistance(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"", "", 0}, {"trivy", "trivy", 0}, {"trivvy", "trivy", 1}, {"", "abc", 3}, {"kitten", "sitting", 3},
	} {
		if got := Distance(c.a, c.b); got != c.want {
			t.Errorf("Distance(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}
