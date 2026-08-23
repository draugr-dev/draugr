// Package ci reports the continuous-integration job a scan is running in.
//
// The facts here exist once, in the process doing the work, and are gone when it exits. Nothing
// downstream can recover them: a report names a repository and cannot say which workflow produced
// the scan, so "which pipeline published this, and can I go and look at it" is unanswerable from
// the artifact alone.
//
// Every value is read from a named variable on a named platform. Nothing scans the environment,
// which is what keeps a token that happens to be exported out of a document that gets published.
package ci

import "os"

// Context is the job a scan ran in, or the zero value when it did not run in one.
type Context struct {
	// System names the platform: "github-actions", "gitlab-ci", "azure-pipelines", "circleci",
	// "buildkite".
	System string `json:"system" yaml:"system"`
	// Repository is the repository the pipeline is for, in the platform's own spelling.
	Repository string `json:"repository,omitempty" yaml:"repository,omitempty"`
	// Ref is the branch or tag being built.
	Ref string `json:"ref,omitempty" yaml:"ref,omitempty"`
	// Workflow and Job locate the scan within the pipeline. A repository usually has several
	// pipelines and a pipeline several jobs, so neither identifies it alone.
	Workflow string `json:"workflow,omitempty" yaml:"workflow,omitempty"`
	Job      string `json:"job,omitempty" yaml:"job,omitempty"`
	// RunID is the platform's identifier for this run, and Attempt distinguishes a retry of a
	// failed run from a fresh one. Together they are what a run key is derived from.
	//
	// Attempt is set only where the platform reuses the run id across attempts, which today is
	// GitHub Actions. Elsewhere a retry already has an id of its own and qualifying it further
	// would make every first attempt look like a retry.
	RunID   string `json:"runId,omitempty" yaml:"runId,omitempty"`
	Attempt string `json:"attempt,omitempty" yaml:"attempt,omitempty"`
	// URL is where a person can go and read the job's own logs. Absent where the platform does
	// not publish enough to build one — a guessed URL is worse than none.
	URL string `json:"url,omitempty" yaml:"url,omitempty"`
}

// Detected reports whether a scan is running in a recognized CI system.
func (c Context) Detected() bool { return c.System != "" }

// JobID identifies this job to a platform, or "" outside CI.
//
// Attempt-qualified where the platform distinguishes attempts, because a re-run of a failed job is
// a different event from the attempt that failed, and a key that could not tell them apart would
// have the retry refused as a duplicate.
func (c Context) JobID() string {
	switch {
	case c.RunID == "":
		return ""
	case c.Attempt != "":
		return c.RunID + "-" + c.Attempt
	default:
		return c.RunID
	}
}

// Detect reads the environment and returns what it recognizes.
func Detect() Context { return detect(os.Getenv) }

// detect takes its lookup so the platforms can be tested without setting process environment,
// which no test can do concurrently.
//
// Each platform is recognized by its marker variable or by the variable holding its run id. Both
// are always set by the real thing; accepting either means a run id on its own still identifies
// the job, which is what a report is keyed on.
func detect(env func(string) string) Context {
	switch {
	case env("GITHUB_ACTIONS") != "" || env("GITHUB_RUN_ID") != "":
		c := Context{
			System:     "github-actions",
			Repository: env("GITHUB_REPOSITORY"),
			Ref:        env("GITHUB_REF"),
			Workflow:   env("GITHUB_WORKFLOW"),
			Job:        env("GITHUB_JOB"),
			RunID:      env("GITHUB_RUN_ID"),
			Attempt:    env("GITHUB_RUN_ATTEMPT"),
		}
		if server, repo := env("GITHUB_SERVER_URL"), c.Repository; server != "" && repo != "" && c.RunID != "" {
			c.URL = server + "/" + repo + "/actions/runs/" + c.RunID
		}
		return c
	case env("GITLAB_CI") != "" || env("CI_JOB_ID") != "":
		return Context{
			System:     "gitlab-ci",
			Repository: env("CI_PROJECT_PATH"),
			Ref:        env("CI_COMMIT_REF_NAME"),
			Workflow:   env("CI_PIPELINE_ID"),
			Job:        env("CI_JOB_NAME"),
			RunID:      env("CI_JOB_ID"),
			URL:        env("CI_JOB_URL"),
		}
	case env("TF_BUILD") != "" || env("BUILD_BUILDID") != "":
		return Context{
			System:     "azure-pipelines",
			Repository: env("BUILD_REPOSITORY_NAME"),
			Ref:        env("BUILD_SOURCEBRANCH"),
			Workflow:   env("BUILD_DEFINITIONNAME"),
			Job:        env("AGENT_JOBNAME"),
			RunID:      env("BUILD_BUILDID"),
		}
	case env("CIRCLECI") != "" || env("CIRCLE_WORKFLOW_ID") != "":
		return Context{
			System:     "circleci",
			Repository: repoOf(env("CIRCLE_PROJECT_USERNAME"), env("CIRCLE_PROJECT_REPONAME")),
			Ref:        env("CIRCLE_BRANCH"),
			Workflow:   env("CIRCLE_WORKFLOW_ID"),
			Job:        env("CIRCLE_JOB"),
			RunID:      env("CIRCLE_WORKFLOW_ID"),
			URL:        env("CIRCLE_BUILD_URL"),
		}
	case env("BUILDKITE") != "" || env("BUILDKITE_BUILD_ID") != "":
		return Context{
			System:     "buildkite",
			Repository: env("BUILDKITE_PIPELINE_SLUG"),
			Ref:        env("BUILDKITE_BRANCH"),
			Workflow:   env("BUILDKITE_PIPELINE_SLUG"),
			Job:        env("BUILDKITE_LABEL"),
			RunID:      env("BUILDKITE_BUILD_ID"),
			URL:        env("BUILDKITE_BUILD_URL"),
		}
	}
	return Context{}
}

// repoOf joins an owner and a repository, and returns neither half on its own — "acme" is not a
// repository, and a field that is sometimes a path and sometimes an owner is one nothing can read.
func repoOf(owner, name string) string {
	if owner == "" || name == "" {
		return ""
	}
	return owner + "/" + name
}
