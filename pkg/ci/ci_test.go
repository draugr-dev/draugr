package ci

import "testing"

func envOf(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

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
			if got := detect(envOf(tc.env)); got != tc.want {
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
	if detect(envOf(map[string]string{"BUILDKITE": "true", "BUILDKITE_RETRY_COUNT": "3"})).Attempt != "" {
		t.Error("a platform whose retries get their own id must not be attempt-qualified")
	}
}

// A platform marker without its run id, and a run id without its marker, both occur: the first in
// a job that has not started, the second where a pipeline exports only what it needs.
func TestEitherMarkerOrRunIDIsEnough(t *testing.T) {
	if got := detect(envOf(map[string]string{"GITHUB_RUN_ID": "77"})); got.System != "github-actions" || got.RunID != "77" {
		t.Errorf("a bare run id was not recognized: %+v", got)
	}
	if got := detect(envOf(map[string]string{"GITHUB_ACTIONS": "true"})); !got.Detected() || got.JobID() != "" {
		t.Errorf("a marker without a run id: %+v", got)
	}
}

// Half a repository is not a repository, and a field that is sometimes "acme/payments" and
// sometimes "acme" is one nothing downstream can parse.
func TestPartialRepositoryIsNoRepository(t *testing.T) {
	got := detect(envOf(map[string]string{"CIRCLECI": "true", "CIRCLE_PROJECT_USERNAME": "acme"}))
	if got.Repository != "" {
		t.Errorf("Repository = %q, want empty", got.Repository)
	}
}

// The URL is built from parts, so it must be absent rather than truncated when a part is missing.
func TestNoURLWithoutEveryPart(t *testing.T) {
	got := detect(envOf(map[string]string{
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
