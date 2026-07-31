package saga

import (
	"testing"
	"time"
)

// An exclusion accepted "until the upstream fix lands" has nothing that brings the finding back,
// so temporary ones become permanent by default — which is how a suppression mechanism decays
// into a way of never seeing something again.
func TestExcludeRuleExpiredOn(t *testing.T) {
	t.Parallel()

	day := func(s string) time.Time {
		d, err := time.Parse("2006-01-02", s)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}

	for _, tc := range []struct {
		name    string
		expires string
		now     string
		want    bool
	}{
		{"no expiry never lapses", "", "2030-01-01", false},
		{"before the date", "2026-08-14", "2026-08-01", false},
		// A date with no time on it means the whole day: an exclusion expiring on the 14th
		// applies throughout the 14th, which is what a reader of the descriptor expects.
		{"on the date it still applies", "2026-08-14", "2026-08-14", false},
		{"the day after", "2026-08-14", "2026-08-15", true},
		{"long past", "2026-08-14", "2027-01-01", true},
		// Validate rejects an unparseable date; if one reaches here, dropping the suppression
		// silently would be worse than keeping it.
		{"unparseable keeps suppressing", "next tuesday", "2030-01-01", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			e := ExcludeRule{Rules: []string{"x"}, Reason: "r", Expires: tc.expires}
			if got := e.ExpiredOn(day(tc.now)); got != tc.want {
				t.Errorf("ExpiredOn = %v, want %v", got, tc.want)
			}
		})
	}
}

// A date that does not parse is worse than no date: the exclusion would keep suppressing forever
// while the descriptor claims it lapses.
func TestValidateRejectsAnUnreadableExpiry(t *testing.T) {
	t.Parallel()

	m := &Model{
		Release: Release{Version: "1.0"},
		Config: Config{Exclude: []ExcludeRule{
			{Rules: []string{"CVE-1"}, Reason: "waiting on upstream", Expires: "August"},
		}},
	}
	err := m.Validate()
	if err == nil {
		t.Fatal("want an error")
	}
	if !contains(err.Error(), "YYYY-MM-DD") {
		t.Errorf("the error should say the format, got: %v", err)
	}

	ok := &Model{
		Release: Release{Version: "1.0"},
		Config: Config{Exclude: []ExcludeRule{
			{Rules: []string{"CVE-1"}, Reason: "waiting on upstream",
				AcceptedBy: "Wilson Santos", Expires: "2026-08-14"},
		}},
	}
	if err := ok.Validate(); err != nil {
		t.Errorf("a well-formed exclusion should validate, got: %v", err)
	}
}

func contains(s, sub string) bool { return len(s) >= len(sub) && (s == sub || indexOf(s, sub) >= 0) }

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
