package ciguard

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

// appKey is how a workflow reads the release App's private key.
const appKey = "secrets.RELEASE_APP_PRIVATE_KEY"

// tokenJob names a job that mints an App token, by workflow file and job key.
type tokenJob struct{ workflow, job string }

func (j tokenJob) String() string { return j.workflow + ": " + j.job }

// workflowsGrantAllowed lists each job whose App token may ask for `workflows`, with the reason it
// needs it. Every other token is refused that permission.
var workflowsGrantAllowed = map[tokenJob]string{
	{postPublish, "major-tag"}: "it moves the major tag onto the release's commit, and GitHub refuses " +
		"that move from an App without workflows whenever no branch holds the commit's version of a " +
		"workflow file",
}

// TestEveryAppTokenNamesItsPermissions holds every token minted with create-github-app-token to
// the permissions it names.
//
// A step that names no `permission-*` input receives everything the App's installation holds,
// including anything granted later for an unrelated job. `workflows` is the grant that matters
// most, because a token holding it can rewrite a file under .github/workflows/, and the workflow it
// rewrites then runs with every secret and permission the repository gives that workflow. So each
// token names what its job uses, and `workflows` is refused to every job not listed in
// workflowsGrantAllowed.
//
// The App's key may reach only these steps. A job reading it any other way mints a token this
// guard does not see.
func TestEveryAppTokenNamesItsPermissions(t *testing.T) {
	t.Parallel()
	minted := 0
	askedForWorkflows := map[tokenJob]bool{}
	for name, w := range readAllWorkflows(t) {
		code := jobCode(t, name)
		for job, spec := range w.Jobs {
			at := tokenJob{name, job}
			keyed := 0
			for _, s := range spec.Steps {
				if !strings.HasPrefix(s.Uses, "actions/create-github-app-token@") {
					continue
				}
				minted++
				if key, _ := s.With["private-key"].(string); strings.Contains(key, appKey) {
					keyed++
				}
				named := namedPermissions(s.With)
				if len(named) == 0 {
					t.Errorf("%s: step %q names no permission-* input at read or write, so its token "+
						"holds everything the App is granted", at, s.Name)
				}
				if slices.Contains(named, "permission-workflows") {
					if _, ok := workflowsGrantAllowed[at]; !ok {
						t.Errorf("%s: step %q asks for permission-workflows, and the job is not in "+
							"workflowsGrantAllowed. A token with workflows can rewrite what every later "+
							"run executes; list the job there, with its reason, only if it writes under "+
							".github/workflows/ or moves a ref GitHub refuses without it", at, s.Name)
					}
					askedForWorkflows[at] = true
				}
			}
			// A job calling another workflow passes the key on by name; the called workflow's jobs
			// are read in their own file.
			if spec.Uses != "" {
				continue
			}
			if n := strings.Count(code[job], appKey); n != keyed {
				t.Errorf("%s reads %s in %d places, of which %d are a create-github-app-token step's "+
					"private-key, so something else mints a token from the App with permissions this "+
					"guard does not see", at, appKey, n, keyed)
			}
		}
	}
	if minted == 0 {
		t.Fatal("no step mints an App token, so this guard is reading the wrong files")
	}
	for at, why := range workflowsGrantAllowed {
		if !askedForWorkflows[at] {
			t.Errorf("workflowsGrantAllowed lists %s (%s), and no token there asks for "+
				"permission-workflows; remove the entry, so a job given that name later is not "+
				"allowed it unexamined", at, why)
		}
	}
}

// namedPermissions returns the permission-* inputs a create-github-app-token step sets to read or
// write. The action skips an input left empty, so a step whose every input is empty still mints a
// token holding everything.
func namedPermissions(with map[string]any) []string {
	var out []string
	for k, v := range with {
		if !strings.HasPrefix(k, "permission-") {
			continue
		}
		if level := fmt.Sprint(v); level == "read" || level == "write" {
			out = append(out, k)
		}
	}
	slices.Sort(out)
	return out
}
