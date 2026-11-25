package sealed

import (
	"encoding/json"
	"fmt"
	"strings"
)

// BaseFile is where a scenario keeps the base report an earlier release wrote, under its directory.
const BaseFile = "base/results.sarif"

// StoreBase is a results.sarif as a scenario keeps it for a later run: the run's work directory as
// <work>, and each of the fixture's commits as <commit:N>, its place in commits as Commits lists
// them. Both differ on every run, and the comparison needs the real values back, since it reads the
// file at the base's commit from the fixture's checkout.
func StoreBase(raw []byte, work string, commits []string) []byte {
	s := strings.ReplaceAll(string(raw), work, "<work>")
	for i, c := range commits {
		s = strings.ReplaceAll(s, c, fmt.Sprintf("<commit:%d>", i))
	}
	return []byte(s)
}

// RestoreBase is StoreBase undone for this run's work directory and commits.
func RestoreBase(stored []byte, work string, commits []string) []byte {
	s := strings.ReplaceAll(string(stored), "<work>", work)
	for i, c := range commits {
		s = strings.ReplaceAll(s, fmt.Sprintf("<commit:%d>", i), c)
	}
	return []byte(s)
}

// UnreadBase is a stored base with each commit placeholder replaced by a commit id no repository
// holds, so the comparison cannot read anything at the base's commit.
func UnreadBase(stored []byte, work string, commits []string) []byte {
	missing := make([]string, len(commits))
	for i := range commits {
		missing[i] = fmt.Sprintf("%040x", i+1)
	}
	return RestoreBase(stored, work, missing)
}

// BaseRelease is the release a results.sarif's first run names as its tool driver's version.
func BaseRelease(raw []byte) (string, error) {
	var log struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Version string `json:"version"`
				} `json:"driver"`
			} `json:"tool"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(raw, &log); err != nil {
		return "", err
	}
	if len(log.Runs) == 0 || log.Runs[0].Tool.Driver.Version == "" {
		return "", fmt.Errorf("names no release")
	}
	return log.Runs[0].Tool.Driver.Version, nil
}
