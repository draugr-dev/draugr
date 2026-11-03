package manifests

import "testing"

// Every reason LicensesNotRead writes reads back to what wrote it, and a reason it would not write
// reads back to nothing, so a report folding these rows never folds another reason in with them.
func TestLicensesNotReadReadsBack(t *testing.T) {
	for _, tc := range []struct {
		packages int
		command  string
		want     string
	}{
		{3, "", "records no licenses for 3 packages"},
		{1, "", "records no license for 1 package"},
		{2, "dotnet restore", "licenses of 2 packages not read, run dotnet restore"},
		{1, "go mod download", "license of 1 package not read, run go mod download"},
	} {
		reason := LicensesNotRead(tc.packages, tc.command)
		if reason != tc.want {
			t.Errorf("LicensesNotRead(%d, %q) = %q, want %q", tc.packages, tc.command, reason, tc.want)
		}
		n, command, ok := ParseLicensesNotRead(reason)
		if !ok || n != tc.packages || command != tc.command {
			t.Errorf("ParseLicensesNotRead(%q) = %d, %q, %v", reason, n, command, ok)
		}
	}
	for _, reason := range []string{
		"licenses of 1 package not read, run go mod download", // not the singular LicensesNotRead writes
		"transitive dependencies not resolved, run mvn dependency:resolve",
		"2 dependency versions not resolved, run mvn dependency:resolve",
		"records no licenses for many packages",
		"no packages read",
		"",
	} {
		if n, command, ok := ParseLicensesNotRead(reason); ok {
			t.Errorf("ParseLicensesNotRead(%q) = %d, %q, true; want false", reason, n, command)
		}
	}
}
