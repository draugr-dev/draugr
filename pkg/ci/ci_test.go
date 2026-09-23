package ci

import (
	"errors"
	"reflect"
	"testing"
)

func envOf(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func noFile(string) ([]byte, error) { return nil, errors.New("no file") }

func detectEnv(env func(string) string) Context { return detect(env, noFile, false) }

// Each platform spells the same six facts differently, and a field read from the wrong variable is
// invisible: it produces a report that is populated and wrong.
func TestEveryPlatformIsRead(t *testing.T) {
	for name, tc := range map[string]struct {
		env  map[string]string
		want Context
	}{
		"github actions": {
			map[string]string{
				"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": "acme/payments",
				"GITHUB_REF": "refs/heads/main", "GITHUB_WORKFLOW": "security",
				"GITHUB_JOB": "scan", "GITHUB_RUN_ID": "77", "GITHUB_RUN_ATTEMPT": "2",
				"GITHUB_SERVER_URL": "https://github.com",
			},
			Context{
				System: "github-actions", Repository: "acme/payments", Ref: "refs/heads/main",
				Workflow: "security", Job: "scan", RunID: "77", Attempt: "2",
				URL: "https://github.com/acme/payments/actions/runs/77",
			},
		},
		"gitlab": {
			map[string]string{
				"GITLAB_CI": "true", "CI_PROJECT_PATH": "acme/payments",
				"CI_COMMIT_REF_NAME": "main", "CI_PIPELINE_ID": "5", "CI_JOB_NAME": "scan",
				"CI_JOB_ID": "88", "CI_JOB_URL": "https://gitlab.com/acme/payments/-/jobs/88",
			},
			Context{
				System: "gitlab-ci", Repository: "acme/payments", Ref: "main", Workflow: "5",
				Job: "scan", RunID: "88", URL: "https://gitlab.com/acme/payments/-/jobs/88",
			},
		},
		"azure": {
			map[string]string{
				"TF_BUILD": "True", "BUILD_REPOSITORY_NAME": "acme/payments",
				"BUILD_SOURCEBRANCH": "refs/heads/main", "BUILD_DEFINITIONNAME": "security",
				"AGENT_JOBNAME": "scan", "BUILD_BUILDID": "99",
			},
			Context{
				System: "azure-pipelines", Repository: "acme/payments", Ref: "refs/heads/main",
				Workflow: "security", Job: "scan", RunID: "99",
			},
		},
		"circleci": {
			map[string]string{
				"CIRCLECI": "true", "CIRCLE_PROJECT_USERNAME": "acme",
				"CIRCLE_PROJECT_REPONAME": "payments", "CIRCLE_BRANCH": "main",
				"CIRCLE_WORKFLOW_ID": "wf-1", "CIRCLE_JOB": "scan",
				"CIRCLE_BUILD_URL": "https://circleci.com/gh/acme/payments/4",
			},
			Context{
				System: "circleci", Repository: "acme/payments", Ref: "main", Workflow: "wf-1",
				Job: "scan", RunID: "wf-1", URL: "https://circleci.com/gh/acme/payments/4",
			},
		},
		"buildkite": {
			map[string]string{
				"BUILDKITE": "true", "BUILDKITE_PIPELINE_SLUG": "payments",
				"BUILDKITE_BRANCH": "main", "BUILDKITE_LABEL": "scan",
				"BUILDKITE_BUILD_ID":  "bk-1",
				"BUILDKITE_BUILD_URL": "https://buildkite.com/acme/payments/builds/4",
			},
			Context{
				System: "buildkite", Repository: "payments", Ref: "main", Workflow: "payments",
				Job: "scan", RunID: "bk-1",
				URL: "https://buildkite.com/acme/payments/builds/4",
			},
		},
		"nothing": {map[string]string{}, Context{}},
	} {
		t.Run(name, func(t *testing.T) {
			if got := detectEnv(envOf(tc.env)); got != tc.want {
				t.Errorf("detect()\n got %+v\nwant %+v", got, tc.want)
			}
		})
	}
}

// The run key is an idempotency key, so a change in how it is derived silently turns retries into
// duplicate runs on somebody's platform. Only GitHub reuses a run id across attempts.
func TestJobIDQualifiesOnlyWhereTheIDIsReused(t *testing.T) {
	for name, tc := range map[string]struct {
		ctx  Context
		want string
	}{
		"github first attempt":   {Context{RunID: "77", Attempt: "1"}, "77-1"},
		"github retried":         {Context{RunID: "77", Attempt: "2"}, "77-2"},
		"a platform without one": {Context{RunID: "88"}, "88"},
		"not in CI":              {Context{}, ""},
	} {
		t.Run(name, func(t *testing.T) {
			if got := tc.ctx.JobID(); got != tc.want {
				t.Errorf("JobID() = %q, want %q", got, tc.want)
			}
		})
	}
	if detectEnv(envOf(map[string]string{"BUILDKITE": "true", "BUILDKITE_RETRY_COUNT": "3"})).Attempt != "" {
		t.Error("a platform whose retries get their own id must not be attempt-qualified")
	}
}

// A platform marker without its run id, and a run id without its marker, both occur: the first in
// a job that has not started, the second where a pipeline exports only what it needs.
func TestEitherMarkerOrRunIDIsEnough(t *testing.T) {
	if got := detectEnv(envOf(map[string]string{"GITHUB_RUN_ID": "77"})); got.System != "github-actions" || got.RunID != "77" {
		t.Errorf("a bare run id was not recognized: %+v", got)
	}
	if got := detectEnv(envOf(map[string]string{"GITHUB_ACTIONS": "true"})); !got.Detected() || got.JobID() != "" {
		t.Errorf("a marker without a run id: %+v", got)
	}
}

// Half a repository is not a repository, and a field that is sometimes "acme/payments" and
// sometimes "acme" is one nothing downstream can parse.
func TestPartialRepositoryIsNoRepository(t *testing.T) {
	got := detectEnv(envOf(map[string]string{"CIRCLECI": "true", "CIRCLE_PROJECT_USERNAME": "acme"}))
	if got.Repository != "" {
		t.Errorf("Repository = %q, want empty", got.Repository)
	}
}

// The URL is built from parts, so it must be absent rather than truncated when a part is missing.
func TestNoURLWithoutEveryPart(t *testing.T) {
	got := detectEnv(envOf(map[string]string{
		"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": "acme/payments", "GITHUB_RUN_ID": "77",
	}))
	if got.URL != "" {
		t.Errorf("URL = %q, want empty without GITHUB_SERVER_URL", got.URL)
	}
}

// Detect is the exported path and reads the real environment; it must agree with detect.
func TestDetectReadsTheEnvironment(t *testing.T) {
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("GITHUB_RUN_ID", "12345")
	if got := Detect(); got.System != "github-actions" || got.RunID != "12345" {
		t.Errorf("Detect() = %+v", got)
	}
}

// Who ran the pipeline and who wrote the commit, per platform, and never one filled in from the
// other. Every platform in one table, because a person read from the wrong variable produces a
// report that is populated and wrong.
func TestEveryPlatformNamesItsActors(t *testing.T) {
	event := []byte(`{"head_commit":{"author":{"name":"Ana Lima","email":"ana@example.com","username":"ana"}}}`)
	readFile := func(path string) ([]byte, error) {
		if path == "/ev.json" {
			return event, nil
		}
		return nil, errors.New("no file")
	}
	for name, tc := range map[string]struct {
		env             map[string]string
		runBy, author   *Actor
		runByE, authorE *Actor // with recordEmail
	}{
		"github push": {
			env: map[string]string{"GITHUB_ACTIONS": "true", "GITHUB_ACTOR": "bo", "GITHUB_ACTOR_ID": "42",
				"GITHUB_EVENT_NAME": "push", "GITHUB_EVENT_PATH": "/ev.json"},
			runBy: &Actor{Handle: "bo", ID: "42"}, author: &Actor{Handle: "ana", Name: "Ana Lima"},
			runByE: &Actor{Handle: "bo", ID: "42"}, authorE: &Actor{Handle: "ana", Name: "Ana Lima", Email: "ana@example.com"},
		},
		"github pull request": {
			env: map[string]string{"GITHUB_ACTIONS": "true", "GITHUB_ACTOR": "bo",
				"GITHUB_EVENT_NAME": "pull_request", "GITHUB_EVENT_PATH": "/ev.json"},
			runBy: &Actor{Handle: "bo"}, runByE: &Actor{Handle: "bo"},
		},
		"gitlab": {
			env: map[string]string{"GITLAB_CI": "true", "GITLAB_USER_LOGIN": "bo", "GITLAB_USER_NAME": "Bo Chen",
				"GITLAB_USER_ID": "7", "GITLAB_USER_EMAIL": "bo@example.com", "CI_COMMIT_AUTHOR": "Ana Lima <ana@example.com>"},
			runBy: &Actor{Handle: "bo", Name: "Bo Chen", ID: "7"}, author: &Actor{Name: "Ana Lima"},
			runByE:  &Actor{Handle: "bo", Name: "Bo Chen", ID: "7", Email: "bo@example.com"},
			authorE: &Actor{Name: "Ana Lima", Email: "ana@example.com"},
		},
		"azure": {
			env: map[string]string{"TF_BUILD": "True", "BUILD_REQUESTEDFOR": "Bo Chen", "BUILD_REQUESTEDFORID": "a1-b2",
				"BUILD_REQUESTEDFOREMAIL": "bo@example.com", "BUILD_SOURCEVERSIONAUTHOR": "Ana Lima"},
			runBy: &Actor{Name: "Bo Chen", ID: "a1-b2"}, author: &Actor{Name: "Ana Lima"},
			runByE: &Actor{Name: "Bo Chen", ID: "a1-b2", Email: "bo@example.com"}, authorE: &Actor{Name: "Ana Lima"},
		},
		"circleci": {
			env:   map[string]string{"CIRCLECI": "true", "CIRCLE_USERNAME": "bo"},
			runBy: &Actor{Handle: "bo"}, runByE: &Actor{Handle: "bo"},
		},
		"buildkite": {
			env: map[string]string{"BUILDKITE": "true", "BUILDKITE_BUILD_CREATOR": "Bo Chen",
				"BUILDKITE_BUILD_CREATOR_EMAIL": "bo@example.com", "BUILDKITE_BUILD_AUTHOR": "Ana Lima",
				"BUILDKITE_BUILD_AUTHOR_EMAIL": "ana@example.com"},
			runBy: &Actor{Name: "Bo Chen"}, author: &Actor{Name: "Ana Lima"},
			runByE: &Actor{Name: "Bo Chen", Email: "bo@example.com"}, authorE: &Actor{Name: "Ana Lima", Email: "ana@example.com"},
		},
		"nobody named": {
			env: map[string]string{"GITLAB_CI": "true"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			got := detect(envOf(tc.env), readFile, false)
			if !reflect.DeepEqual(got.RunBy, tc.runBy) || !reflect.DeepEqual(got.CommitAuthor, tc.author) {
				t.Errorf("without email: runBy %+v author %+v; want %+v %+v", got.RunBy, got.CommitAuthor, tc.runBy, tc.author)
			}
			got = detect(envOf(tc.env), readFile, true)
			if !reflect.DeepEqual(got.RunBy, tc.runByE) || !reflect.DeepEqual(got.CommitAuthor, tc.authorE) {
				t.Errorf("with email: runBy %+v author %+v; want %+v %+v", got.RunBy, got.CommitAuthor, tc.runByE, tc.authorE)
			}
		})
	}
}

// A re-run by somebody else keeps the first actor in GITHUB_ACTOR; the person who pressed re-run is
// recorded beside them, and only when they differ.
func TestARerunBySomebodyElseIsRecorded(t *testing.T) {
	got := detectEnv(envOf(map[string]string{"GITHUB_ACTIONS": "true", "GITHUB_ACTOR": "bo", "GITHUB_TRIGGERING_ACTOR": "cy"}))
	if got.TriggeredBy == nil || got.TriggeredBy.Handle != "cy" {
		t.Errorf("triggeredBy = %+v", got.TriggeredBy)
	}
	if got := detectEnv(envOf(map[string]string{"GITHUB_ACTIONS": "true", "GITHUB_ACTOR": "bo", "GITHUB_TRIGGERING_ACTOR": "bo"})); got.TriggeredBy != nil {
		t.Errorf("triggeredBy = %+v; the same person is not a second actor", got.TriggeredBy)
	}
}

// An event file that is missing or is not the shape expected names nobody rather than failing the
// scan: the author is a hint, and a broken hint is no hint.
func TestAnUnreadableEventNamesNobody(t *testing.T) {
	env := map[string]string{"GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "push", "GITHUB_EVENT_PATH": "/ev.json"}
	if got := detect(envOf(env), noFile, true); got.CommitAuthor != nil {
		t.Errorf("missing file: author %+v", got.CommitAuthor)
	}
	garbage := func(string) ([]byte, error) { return []byte("not json"), nil }
	if got := detect(envOf(env), garbage, true); got.CommitAuthor != nil {
		t.Errorf("bad json: author %+v", got.CommitAuthor)
	}
}

// Detect and DetectWithEmail read the real environment; outside CI both find nothing.
func TestDetectOutsideCI(t *testing.T) {
	for _, k := range []string{"GITHUB_ACTIONS", "GITHUB_RUN_ID", "GITLAB_CI", "CI_JOB_ID", "TF_BUILD", "BUILD_BUILDID",
		"CIRCLECI", "CIRCLE_WORKFLOW_ID", "BUILDKITE", "BUILDKITE_BUILD_ID"} {
		t.Setenv(k, "")
	}
	if Detect().Detected() || DetectWithEmail().Detected() {
		t.Error("detected a CI system in an environment with none")
	}
}
