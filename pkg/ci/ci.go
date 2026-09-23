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

import (
	"encoding/json"
	"os"
	"strings"
)

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
	// URL is where a person can go and read the job's own logs. Absent where the platform does not
	// publish enough to build one. A guessed URL is worse than none.
	URL string `json:"url,omitempty" yaml:"url,omitempty"`

	// RunBy is who the platform reports as having started the pipeline, and CommitAuthor who it
	// reports as having written the commit being built. Two fields because they are usually two
	// people: for a suppression, one wrote the line and the other pressed a button, and a trail
	// that folds them together cannot say which it is showing.
	//
	// Both are what the CI system reported, not an identity anybody verified. A pipeline controls
	// its own environment, so these are a lead to follow and never evidence of who acted. Absent
	// where the platform does not say; neither is ever filled in from the other.
	RunBy        *Actor `json:"runBy,omitempty" yaml:"runBy,omitempty"`
	CommitAuthor *Actor `json:"commitAuthor,omitempty" yaml:"commitAuthor,omitempty"`
	// TriggeredBy is set only when a re-run was started by somebody other than RunBy, which on
	// GitHub keeps the original actor in GITHUB_ACTOR. A re-run by somebody else is the case an
	// auditor asks about.
	TriggeredBy *Actor `json:"triggeredBy,omitempty" yaml:"triggeredBy,omitempty"`
}

// Actor is a person as a CI system reports them.
type Actor struct {
	// Handle is the platform login, where the platform reports one.
	Handle string `json:"handle,omitempty" yaml:"handle,omitempty"`
	// Name is a display name, which is not unique: two people can share one.
	Name string `json:"name,omitempty" yaml:"name,omitempty"`
	// ID is the platform's stable identifier for the account, which is what makes the record
	// unambiguous where a handle is missing or a name is shared.
	ID string `json:"id,omitempty" yaml:"id,omitempty"`
	// Email is set only when the descriptor asked for it (`config.ci.recordEmail`). It is
	// personal data, so the default is not to read it at all.
	Email string `json:"email,omitempty" yaml:"email,omitempty"`
}

// actor returns nil for an actor with nothing in it, so an absent person is absent rather than an
// empty object a consumer has to tell apart from somebody the platform named.
func actor(a Actor) *Actor {
	if a == (Actor{}) {
		return nil
	}
	return &a
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

// Detect reads the environment and returns what it recognizes. No email address is read.
func Detect() Context { return detect(os.Getenv, os.ReadFile, false) }

// DetectWithEmail is Detect, also reading the email addresses the platform reports for its actors.
// For a descriptor that set `config.ci.recordEmail`.
func DetectWithEmail() Context { return detect(os.Getenv, os.ReadFile, true) }

// detect takes its lookup so the platforms can be tested without setting process environment,
// which no test can do concurrently.
//
// Each platform is recognized by its marker variable or by the variable holding its run id. Both
// are always set by the real thing; accepting either means a run id on its own still identifies
// the job, which is what a report is keyed on.
func detect(env func(string) string, readFile func(string) ([]byte, error), withEmail bool) Context {
	email := func(name string) string {
		if !withEmail {
			return ""
		}
		return env(name)
	}
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
		// GitHub puts no email for the actor anywhere a job can read it.
		c.RunBy = actor(Actor{Handle: env("GITHUB_ACTOR"), ID: env("GITHUB_ACTOR_ID")})
		if t := env("GITHUB_TRIGGERING_ACTOR"); t != "" && t != env("GITHUB_ACTOR") {
			c.TriggeredBy = &Actor{Handle: t}
		}
		c.CommitAuthor = githubCommitAuthor(env, readFile, withEmail)
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
			RunBy: actor(Actor{Handle: env("GITLAB_USER_LOGIN"), Name: env("GITLAB_USER_NAME"),
				ID: env("GITLAB_USER_ID"), Email: email("GITLAB_USER_EMAIL")}),
			CommitAuthor: nameAndEmail(env("CI_COMMIT_AUTHOR"), withEmail),
		}
	case env("TF_BUILD") != "" || env("BUILD_BUILDID") != "":
		return Context{
			System:     "azure-pipelines",
			Repository: env("BUILD_REPOSITORY_NAME"),
			Ref:        env("BUILD_SOURCEBRANCH"),
			Workflow:   env("BUILD_DEFINITIONNAME"),
			Job:        env("AGENT_JOBNAME"),
			RunID:      env("BUILD_BUILDID"),
			// A display name, not a login: Azure reports no handle for the person.
			RunBy: actor(Actor{Name: env("BUILD_REQUESTEDFOR"), ID: env("BUILD_REQUESTEDFORID"),
				Email: email("BUILD_REQUESTEDFOREMAIL")}),
			CommitAuthor: actor(Actor{Name: env("BUILD_SOURCEVERSIONAUTHOR")}),
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
			RunBy:      actor(Actor{Handle: env("CIRCLE_USERNAME")}),
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
			RunBy: actor(Actor{Name: env("BUILDKITE_BUILD_CREATOR"),
				Email: email("BUILDKITE_BUILD_CREATOR_EMAIL")}),
			CommitAuthor: actor(Actor{Name: env("BUILDKITE_BUILD_AUTHOR"),
				Email: email("BUILDKITE_BUILD_AUTHOR_EMAIL")}),
		}
	}
	return Context{}
}

// repoOf joins an owner and a repository, and returns neither half on its own. "acme" is not a
// repository, and a field that is sometimes a path and sometimes an owner is one nothing can read.
func repoOf(owner, name string) string {
	if owner == "" || name == "" {
		return ""
	}
	return owner + "/" + name
}

// nameAndEmail reads a "Name <email>" author, as GitLab reports one. Without withEmail the address
// is dropped rather than kept inside the name.
func nameAndEmail(v string, withEmail bool) *Actor {
	name, addr, found := strings.Cut(v, "<")
	a := Actor{Name: strings.TrimSpace(name)}
	if found && withEmail {
		a.Email = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(addr), ">"))
	}
	return actor(a)
}

// githubCommitAuthor reads the author of the pushed commit from the event GitHub describes the run
// with. Only a push carries one; a pull request, a schedule or a manual dispatch names who acted,
// which is RunBy, and says nothing about who wrote the commit.
//
// The file is the one GITHUB_EVENT_PATH names, read and never searched for, like every other value
// here.
func githubCommitAuthor(env func(string) string, readFile func(string) ([]byte, error), withEmail bool) *Actor {
	path := env("GITHUB_EVENT_PATH")
	if env("GITHUB_EVENT_NAME") != "push" || path == "" {
		return nil
	}
	body, err := readFile(path)
	if err != nil {
		return nil
	}
	var event struct {
		HeadCommit struct {
			Author struct {
				Name     string `json:"name"`
				Email    string `json:"email"`
				Username string `json:"username"`
			} `json:"author"`
		} `json:"head_commit"`
	}
	if json.Unmarshal(body, &event) != nil {
		return nil
	}
	a := event.HeadCommit.Author
	out := Actor{Handle: a.Username, Name: a.Name}
	if withEmail {
		out.Email = a.Email
	}
	return actor(out)
}
