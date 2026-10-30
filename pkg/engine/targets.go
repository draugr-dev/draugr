package engine

import (
	"context"
	"errors"
	"log/slog"
	"os/exec"
	"slices"

	"github.com/draugr-dev/draugr/internal/registry"
	"github.com/draugr-dev/draugr/pkg/plugin"
)

// TargetStatus is what became of a target a run planned.
type TargetStatus string

// The outcomes a planned target can have.
const (
	// TargetReached is a target at least one job read.
	TargetReached TargetStatus = "reached"
	// TargetFailed is a target every job for it tried and failed to read.
	TargetFailed TargetStatus = "failed"
	// TargetSkipped is a target no job was run for, for a reason the run states: the scanner could
	// not honor its scope, or the tool was not installed.
	TargetSkipped TargetStatus = "skipped"
)

// TargetOutcome is what became of one distinct target the run planned.
//
// Identified the way `draugr doctor` identifies targets, so a target doctor checked and the same
// target in a run's report match: a repository by its source and revision, an image by its pinned
// reference, a host by its URL and a cluster by its name.
type TargetOutcome struct {
	Kind   string       `json:"kind"`
	Target string       `json:"target"`
	Status TargetStatus `json:"status"`
	// Detail is why the target was not reached: the first failure in the scanner's words, or the
	// reason it was skipped. Empty when it was reached.
	Detail string `json:"detail,omitempty"`
	// Components are the components that declared it, so a target that was not reached can be
	// read as the components it leaves unscanned.
	Components []string `json:"components,omitempty"`
	// Refusal is the registry's answer when the target is an image its registry declined to serve,
	// and nil otherwise.
	Refusal *Refusal `json:"refusal,omitempty"`
}

// Refusal is a container registry declining to serve an image to the machine that ran the scan.
type Refusal struct {
	// Registry is the image's registry, as `docker login` names it: `docker.io` for Docker Hub.
	Registry string `json:"registry"`
	// Status is the HTTP status the refusal amounts to: 401 when the registry asked for a
	// credential, 403 when it declined the request it was given.
	Status int `json:"status"`
	// Credential is whether the machine held a credential for Registry where the scanners read one,
	// asked after the scans. Absent when the run did not ask, or the configuration could not be read.
	Credential *bool `json:"credential,omitempty"`
}

// refusalOf reads a failed pull of an image for its registry declining to serve it: from everything
// the tool printed where the scanner ran one, and from the error alone otherwise. A tool's output is
// read in full because the error is shortened to a line, and the registry's answer can be the part
// shortened away.
func refusalOf(t plugin.Target, err error) *Refusal {
	img, ok := t.(plugin.ImageTarget)
	if !ok || err == nil {
		return nil
	}
	ref, perr := registry.Parse(img.PinnedRef())
	if perr != nil {
		return nil
	}
	text := err.Error()
	if exit, ok := errors.AsType[*exec.ExitError](err); ok {
		text = string(exit.Stderr) + "\n" + text
	}
	status := registry.RefusalStatus(text, ref.Host)
	if status == 0 {
		return nil
	}
	return &Refusal{Registry: registry.LoginHost(ref.Host), Status: status}
}

// noteCredentials says, for each image a registry refused, whether this machine holds a credential
// for that registry, asking once per registry. Nothing is said when nothing can answer, or the
// answer could not be read: a refusal reported without the fact is still true.
func noteCredentials(ctx context.Context, targets []TargetOutcome, held func(context.Context, string) (bool, error)) {
	if held == nil {
		return
	}
	known := map[string]*bool{}
	for i := range targets {
		r := targets[i].Refusal
		if r == nil {
			continue
		}
		answer, asked := known[r.Registry]
		if !asked {
			if ok, err := held(ctx, r.Registry); err == nil {
				answer = &ok
			} else {
				slog.DebugContext(ctx, "could not read the credential for a registry that refused an image",
					"registry", r.Registry, "error", err.Error())
			}
			known[r.Registry] = answer
		}
		r.Credential = answer
	}
}

// targetOutcomes accounts for each distinct target in the plan, in the order first planned.
//
// Reached beats everything: a target one scanner read and another failed on was examined. A target
// that was never reached failed if any job for it ran and failed, and was skipped if every job for
// it was skipped or could not start its tool; a failure says more than a skip about why nothing was
// read. A missing tool is a fact about the machine rather than the target, and its control's error
// says it once.
func targetOutcomes(planned []PlannedJob, skipped []SkippedJob, failures []Unscanned, reached map[string]bool) []TargetOutcome {
	var order []string
	at := map[string]*TargetOutcome{}
	note := func(t plugin.Target, component string) *TargetOutcome {
		key := outcomeKey(t)
		o, ok := at[key]
		if !ok {
			kind, id := outcomeIdentity(t)
			o = &TargetOutcome{Kind: kind, Target: id}
			at[key] = o
			order = append(order, key)
		}
		if component != "" && !slices.Contains(o.Components, component) {
			o.Components = append(o.Components, component)
		}
		return o
	}
	for _, pj := range planned {
		if pj.Job.Target != nil {
			note(pj.Job.Target, pj.Component)
		}
	}
	for _, f := range failures {
		if f.target == nil {
			continue
		}
		o := note(f.target, f.Component)
		switch {
		case f.toolMissing && o.Status == "":
			o.Status, o.Detail = TargetSkipped, f.Detail
		case !f.toolMissing && o.Status != TargetFailed:
			o.Status, o.Detail, o.Refusal = TargetFailed, f.Detail, f.refusal
		}
	}
	for _, sk := range skipped {
		if sk.target == nil {
			continue
		}
		o := note(sk.target, sk.Component)
		if o.Status == "" {
			o.Status, o.Detail = TargetSkipped, sk.Reason
		}
	}
	out := make([]TargetOutcome, 0, len(order))
	for _, key := range order {
		o := at[key]
		switch {
		case reached[key]:
			o.Status, o.Detail, o.Refusal = TargetReached, "", nil
		case o.Status == "":
			// Planned, never read and never reported as failing: a job the run was canceled
			// before it could start.
			o.Status = TargetFailed
		}
		slices.Sort(o.Components)
		out = append(out, *o)
	}
	return out
}

// outcomeKey identifies a target at the grain a run's account of its targets uses.
func outcomeKey(t plugin.Target) string {
	kind, id := outcomeIdentity(t)
	return kind + "\x00" + id
}

// outcomeIdentity names a target the way doctor does: a repository by source and revision whatever
// paths a job read, an image by its pinned reference, a host by its URL without credentials, a
// cluster by its name whatever namespaces, an account by its provider and ID whatever regions.
func outcomeIdentity(t plugin.Target) (kind, id string) {
	switch t := t.(type) {
	case plugin.RepositoryTarget:
		id = t.Source()
		if t.Revision != "" {
			id += "@" + t.Revision
		}
		return "repository", id
	case plugin.ImageTarget:
		return "image", t.PinnedRef()
	case plugin.HostTarget:
		return "host", plugin.SourceURL(t.URL)
	case plugin.AccountTarget:
		return "account", t.Provider + "/" + t.ID
	case plugin.KubernetesTarget:
		if t.Cluster == "" {
			return "cluster", "kubernetes"
		}
		return "cluster", "kubernetes/" + t.Cluster
	}
	return string(t.Kind()), t.Identity()
}
