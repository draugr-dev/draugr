package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/draugr-dev/draugr/pkg/publish"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/skald"
)

// policyChecker is the server call, swapped in tests.
var policyChecker = func(ctx context.Context, dest publish.APIDestination, effective string) (skald.PolicyOutcome, error) {
	return publish.NewPolicyClient().Check(ctx, dest, effective)
}

// checkOrgPolicy asks each draugr-api server the descriptor publishes to what the organization's
// policy makes of it, before any tool runs.
//
// Nil where the descriptor publishes to no draugr-api server. A check that could not be asked, with
// no endpoint or token, offline, or a server that judges no policy, is recorded as not checked with
// the reason, never as a pass. Draugr holds no rule logic: the server judges and words each verdict,
// and this only gathers what it says.
func checkOrgPolicy(ctx context.Context, model *saga.Model, effective string, offline bool) (*skald.PolicyCheck, error) {
	dests := publish.APIPublishers(model.Config.Publishers)
	if len(dests) == 0 {
		return nil, nil
	}
	out := &skald.PolicyCheck{Outcome: skald.PolicyNone}
	var servers, reasons []string
	for _, cfg := range dests {
		dest, skip, err := publish.ResolveAPI(cfg)
		if err != nil {
			return nil, err
		}
		switch {
		case skip != "":
			reasons = append(reasons, skip)
			continue
		case offline:
			reasons = append(reasons, "offline")
			continue
		}
		outcome, err := policyChecker(ctx, dest, effective)
		if errors.Is(err, publish.ErrNoPolicyCheck) {
			reasons = append(reasons, dest.Endpoint+" checks no organization policy")
			continue
		}
		if err != nil {
			reasons = append(reasons, err.Error())
			continue
		}
		out.Checked = true
		servers = append(servers, dest.Endpoint)
		out.Version = max(out.Version, outcome.PolicyVersion)
		out.Outcome = skald.Strongest(out.Outcome, outcome.Outcome)
		out.Verdicts = append(out.Verdicts, outcome.Verdicts...)
	}
	out.Server = strings.Join(servers, ", ")
	if !out.Checked {
		out.Outcome = ""
		out.Reason = strings.Join(reasons, "; ")
	}
	return out, nil
}

// requirePolicy is --policy: the check has to have run, so a missing token, an unreachable server
// or a descriptor publishing nowhere is an error rather than a quiet "not checked".
func requirePolicy(p *skald.PolicyCheck) error {
	switch {
	case p == nil:
		return fmt.Errorf("--policy: the descriptor publishes to no draugr-api server, so there is no organization policy to check")
	case !p.Checked:
		return fmt.Errorf("--policy: the organization's policy was not checked: %s", p.Reason)
	}
	return nil
}

// refusedRules names each rule that refuses the run, and its profile, for the command's error.
func refusedRules(p *skald.PolicyCheck) string {
	var out []string
	for _, v := range p.Verdicts {
		if v.Acts == skald.PolicyRefuse {
			out = append(out, v.Rule+" ("+v.Profile+")")
		}
	}
	return strings.Join(out, ", ")
}

// failingRules names each rule whose setting fails the gate for this descriptor, and its profile.
func failingRules(p *skald.PolicyCheck) string {
	var out []string
	for _, v := range p.Verdicts {
		if v.Acts == skald.PolicyFail {
			out = append(out, v.Rule+" ("+v.Profile+")")
		}
	}
	return strings.Join(out, ", ")
}
