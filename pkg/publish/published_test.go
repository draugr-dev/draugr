package publish

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/draugr-dev/draugr/pkg/report"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// judgeRuns publishes to the servers given, each named by its URL, and returns the runs Judge says
// they recorded.
func judgeRuns(t *testing.T, servers ...*server) ([]report.PublishedRun, []string, error) {
	t.Helper()
	var urls []string
	var cfgs []saga.PublisherConfig
	for _, p := range servers {
		srv := p.server(t)
		urls = append(urls, srv.URL)
		cfgs = append(cfgs, saga.PublisherConfig{Kind: "draugr-api", URL: srv.URL})
	}
	t.Setenv(apiURLEnv, urls[0])
	t.Setenv(apiTokenEnv, "drgr_ci_test")
	if len(urls) > 1 {
		t.Setenv(apiOriginsEnv, urls[1])
	}
	got, err := Judge(context.Background(), cfgs, sampleData(), time.Minute)
	return got.Runs, urls, err
}

// A server that judges no policy still recorded the run, and the run is named, with its page where
// the server gives one.
func TestJudgeNamesEveryRunAServerRecorded(t *testing.T) {
	runs, urls, err := judgeRuns(t,
		&server{runURL: "https://console.example/#/projects/payments/runs/run-1"},
		&server{duplicate: true})
	if err != nil {
		t.Fatal(err)
	}
	want := []report.PublishedRun{
		{Server: urls[0], Project: "payments", Run: "run-1", URL: "https://console.example/#/projects/payments/runs/run-1"},
		{Server: urls[1], Project: "payments", Run: "run-1", Duplicate: true},
	}
	if !reflect.DeepEqual(runs, want) {
		t.Errorf("runs:\n got %+v\nwant %+v", runs, want)
	}
}

// A run the server would not take is no published run: the error says what happened to it.
func TestARunNotRecordedIsNotNamed(t *testing.T) {
	runs, _, err := judgeRuns(t, &server{evidenceError: "no storage"})
	if err == nil || len(runs) != 0 {
		t.Errorf("runs %+v, err %v", runs, err)
	}
}

// What the server says is printed to a terminal and opened in a browser, so only plain text and a
// plain web address are kept.
func TestTheServersWordsAreKeptOnlyWhenPlain(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"https://console.example/#/projects/p/runs/r", "https://console.example/#/projects/p/runs/r"},
		{"http://localhost:8080/#/runs/r", "http://localhost:8080/#/runs/r"},
		{"", ""},
		{"javascript:alert(1)", ""},
		{"/#/projects/p/runs/r", ""},
		{"https://console.example/\x1b]8;;evil\a", ""},
		{"https://console.example/a b", ""},
		{"https://console.example/a b", ""},
		{"ftp://console.example/r", ""},
		{"https://%zz", ""},
	} {
		if got := webAddress(tc.in); got != tc.want {
			t.Errorf("webAddress(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	if got := printable("run-1\x1b[2J"); got != "" {
		t.Errorf("a control character is kept: %q", got)
	}
	if got := printable("run-1"); got != "run-1" {
		t.Errorf("plain text dropped: %q", got)
	}
}
