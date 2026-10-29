package publish

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/ci"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// skipRecord is one "publishers skipped" record as --log-format json writes it.
type skipRecord struct {
	Kinds  map[string]int `json:"kinds"`
	Reason string         `json:"reason"`
	// order is the kinds in the order the record lists them, which a map cannot keep.
	order []string
}

// jsonLogs sends the default logger to a JSON handler for the test, and returns what it wrote.
func jsonLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

// skipRecords reads the "publishers skipped" records out of a JSON log, in order.
func skipRecords(t *testing.T, logs *bytes.Buffer) []skipRecord {
	t.Helper()
	var out []skipRecord
	sc := bufio.NewScanner(bytes.NewReader(logs.Bytes()))
	for sc.Scan() {
		var head struct {
			Msg   string          `json:"msg"`
			Kinds json.RawMessage `json:"kinds"`
		}
		if err := json.Unmarshal(sc.Bytes(), &head); err != nil {
			t.Fatalf("not a JSON record: %s", sc.Bytes())
		}
		if head.Msg == "publisher skipped" {
			t.Fatalf("a skip was logged on its own: %s", sc.Bytes())
		}
		if head.Msg != "publishers skipped" {
			continue
		}
		var r skipRecord
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			t.Fatal(err)
		}
		dec := json.NewDecoder(bytes.NewReader(head.Kinds))
		for {
			tok, err := dec.Token()
			if err != nil {
				break
			}
			if k, ok := tok.(string); ok {
				r.order = append(r.order, k)
			}
		}
		out = append(out, r)
	}
	return out
}

// outsideCI is a developer's machine: no CI system and no forge credential.
func outsideCI(t *testing.T) {
	t.Helper()
	for _, v := range []string{
		"GITHUB_ACTIONS", "GITHUB_REPOSITORY", "GITHUB_SHA", "GITHUB_REF", "GITHUB_TOKEN", "GH_TOKEN",
		"GITLAB_CI", "GITLAB_TOKEN", "CI_PROJECT_ID", "CI_MERGE_REQUEST_IID",
	} {
		t.Setenv(v, "")
	}
}

func TestPublishersSkippedForOneReasonAreOneRecord(t *testing.T) {
	outsideCI(t)
	logs := jsonLogs(t)
	dir := t.TempDir()

	err := Run(context.Background(), []saga.PublisherConfig{
		{Kind: "github"},
		{Kind: "gitlab-issue"},
		{Kind: "github-issue", Select: &saga.PublisherSelect{Controls: []string{"sca"}}},
		{Kind: "file", Dir: dir, Reports: []saga.ReportConfig{{Format: "json"}}},
		{Kind: "github-issue", Select: &saga.PublisherSelect{Controls: []string{"secrets"}}},
		{Kind: "github-pr-comment"},
		{Kind: "gitlab-issue", Split: saga.SplitControl},
		{Kind: "github-issue", Split: saga.SplitComponent},
	}, sampleData())
	if err != nil {
		t.Fatal(err)
	}

	got := skipRecords(t, logs)
	want := []skipRecord{
		{
			Reason: "not a GitHub Actions environment",
			Kinds:  map[string]int{"github": 1, "github-issue": 3, "github-pr-comment": 1},
			order:  []string{"github", "github-issue", "github-pr-comment"},
		},
		{
			Reason: "not a GitLab CI environment",
			Kinds:  map[string]int{"gitlab-issue": 2},
			order:  []string{"gitlab-issue"},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("records = %+v\nwant %+v\nlog:\n%s", got, want, logs)
	}
}

func TestIssueEntriesThatStandAsideAreCountedWithTheRest(t *testing.T) {
	gh, srv := newFakeGitHub(t)
	issueEnv(t, srv.URL)
	t.Setenv("GITHUB_REF", "refs/heads/dev")
	logs := jsonLogs(t)

	data := onMain(nil)
	data.CI = &ci.Context{Branch: "dev", DefaultBranch: "main"}
	err := Run(context.Background(), []saga.PublisherConfig{
		{Kind: "github-issue"},
		{Kind: "github-pr-comment"},
		{Kind: "github-issue", Branches: []string{"release/*"}, Split: saga.SplitControl},
		{Kind: "github-issue", Split: saga.SplitComponent},
		{Kind: "github-issue", Branches: []string{"release/*"}, Split: saga.SplitComponent},
	}, data)
	if err != nil {
		t.Fatal(err)
	}
	if len(gh.requests) != 0 {
		t.Errorf("an entry standing aside sent %q", gh.requests)
	}

	got := skipRecords(t, logs)
	want := []skipRecord{
		{
			Reason: "branch dev is not the default branch, main",
			Kinds:  map[string]int{"github-issue": 2},
			order:  []string{"github-issue"},
		},
		{
			Reason: "no pull request in context",
			Kinds:  map[string]int{"github-pr-comment": 1},
			order:  []string{"github-pr-comment"},
		},
		{
			Reason: "branch dev is not in branches",
			Kinds:  map[string]int{"github-issue": 2},
			order:  []string{"github-issue"},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("records = %+v\nwant %+v\nlog:\n%s", got, want, logs)
	}
}

func TestAPublisherThatFailsIsNotReportedAsSkipped(t *testing.T) {
	outsideCI(t)
	logs := jsonLogs(t)

	// A repository named with no token is publishing intended and not possible: an error, never a
	// skip, and the entries beside it still report theirs.
	err := Run(context.Background(), []saga.PublisherConfig{
		{Kind: "github-issue", Repo: "acme/app"},
		{Kind: "github-issue"},
		{Kind: "github"},
	}, sampleData())
	if err == nil || !strings.Contains(err.Error(), "github-issue publisher missing") {
		t.Fatalf("err = %v", err)
	}

	got := skipRecords(t, logs)
	want := []skipRecord{{
		Reason: "not a GitHub Actions environment",
		Kinds:  map[string]int{"github-issue": 1, "github": 1},
		order:  []string{"github-issue", "github"},
	}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("records = %+v\nwant %+v\nlog:\n%s", got, want, logs)
	}
}

func TestASkipOutsideARunIsLoggedAtOnceInTheSameShape(t *testing.T) {
	logs := jsonLogs(t)
	// A caller driving one publisher itself, as `draugr diff --publish` does, has no run to gather
	// skips over.
	if err := (skipPublisher{kind: "github-pr-comment", reason: "no pull request in context"}).
		Publish(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	got := skipRecords(t, logs)
	want := []skipRecord{{
		Reason: "no pull request in context",
		Kinds:  map[string]int{"github-pr-comment": 1},
		order:  []string{"github-pr-comment"},
	}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("records = %+v\nwant %+v", got, want)
	}
}

func TestTheConsoleRecordNamesEachKindWithItsCount(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	ctx, s := collectSkips(context.Background())
	reportSkip(ctx, "github", "not a GitHub Actions environment")
	reportSkip(ctx, "github-issue", "not a GitHub Actions environment")
	reportSkip(ctx, "github-issue", "not a GitHub Actions environment")
	s.log()

	want := `msg="publishers skipped" kinds.github=1 kinds.github-issue=2 reason="not a GitHub Actions environment"`
	if !strings.Contains(buf.String(), want) {
		t.Errorf("log = %s\nwant %s", buf.String(), want)
	}
}
