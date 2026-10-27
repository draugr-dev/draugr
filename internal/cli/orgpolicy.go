package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/draugr-dev/draugr/internal/login"
	"github.com/draugr-dev/draugr/pkg/ci"
	"github.com/draugr-dev/draugr/pkg/publish"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/skald"
)

// policyChecker is the server call, swapped in tests.
var policyChecker = func(ctx context.Context, dest publish.APIDestination, effective string) (skald.PolicyOutcome, error) {
	return publish.NewPolicyClient().Check(ctx, dest, effective)
}

// loginStore is where `draugr login` keeps a person's token, swapped in tests.
var loginStore = func() login.Store { return login.Keychain{} }

// inPipeline reports whether this run is a CI job, swapped in tests.
var inPipeline = func() bool { return ci.Detect().Detected() }

// policyLogins is the store a policy check reads a person's login from, nil in a pipeline.
//
// A pipeline has its own token and no person's keychain, and on a runner with no keychain service
// even looking for one can start a session bus. So a CI job never reads it.
func policyLogins() login.Store {
	if inPipeline() {
		return nil
	}
	return loginStore()
}

// Reasons a policy check records in place of asking the server.
const (
	policyOffline = "offline"
	// policyNotAsked is doctor without --policy, which sends no credential anywhere.
	policyNotAsked = "run with --policy to ask the server"
	// policyNoPublisher is an environment naming a server the descriptor does not publish to.
	policyNoPublisher = "the descriptor publishes to no draugr-api server"
)

// checkOrgPolicy asks each draugr-api server the descriptor publishes to what the organization's
// policy makes of it, before any tool runs.
//
// held, when set, is the reason no server is asked: offline, or doctor without --policy. Every
// destination is still resolved, which needs no network, so a refused url or a missing token is
// reported the same way either way.
//
// Nil where the descriptor publishes to no draugr-api server and the environment names none. Where
// the environment names one, a descriptor with no draugr-api publisher is recorded as not checked,
// because removing the publisher is a change to the descriptor and must not remove the check
// without a word. A check that could not be asked, with no endpoint or token, a url the environment
// does not allow, offline, or a server that judges no policy, is recorded as not checked with the
// reason, never as a pass. Draugr holds no rule logic: the server judges and words each verdict, and
// this only gathers what it says.
func checkOrgPolicy(ctx context.Context, model *saga.Model, effective, held string) (*skald.PolicyCheck, error) {
	p, _, err := checkOrgPolicyAs(ctx, model, effective, held)
	return p, err
}

// checkOrgPolicyAs is checkOrgPolicy, also returning each person's login a check was sent with.
//
// Where no token is set in the environment, a person's login from `draugr login` stands in for it.
// The logins are returned beside the check rather than in it, because the check is recorded in
// report.json and whose login asked is not part of the run.
func checkOrgPolicyAs(ctx context.Context, model *saga.Model, effective, held string) (*skald.PolicyCheck, []login.Login, error) {
	dests := publish.APIPublishers(model.Config.Publishers)
	if len(dests) == 0 {
		if publish.APIURLSet() {
			return &skald.PolicyCheck{Reason: policyNoPublisher}, nil, nil
		}
		return nil, nil, nil
	}
	logins := policyLogins()
	var used []login.Login
	out := &skald.PolicyCheck{Outcome: skald.PolicyNone}
	var servers, reasons []string
	for _, cfg := range dests {
		dest, skip, err := publish.ResolvePolicyAPI(cfg, logins, time.Now())
		var refused *publish.OriginRefusedError
		if errors.As(err, &refused) {
			reasons = append(reasons, refused.Reason())
			continue
		}
		if err != nil {
			return nil, nil, err
		}
		switch {
		case skip != "":
			reasons = append(reasons, skip)
			continue
		case held != "":
			reasons = append(reasons, held)
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
		if dest.Login != nil {
			used = append(used, *dest.Login)
		}
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
	return out, used, nil
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

// requireRunPolicy is --policy after publishing: a server that could not say what it made of the
// run, or had not decided by the time the wait ended, is an error rather than a line in the report.
// A run published to no server that judges policy has nothing to require.
func requireRunPolicy(p *skald.PolicyCheck, wait time.Duration) error {
	switch {
	case p == nil || p.Run == nil:
		return nil
	case !p.Run.Checked:
		return fmt.Errorf("--policy: the server gave no policy verdict on the published run: %s", p.Run.Reason)
	case p.Run.Pending && wait <= 0:
		return fmt.Errorf("--policy: the server decides part of the policy after the run is published, and " +
			"--policy-wait 0 does not wait for it. Set --policy-wait above 0")
	case p.Run.Pending:
		return fmt.Errorf("--policy: the server had not decided the policy on the published run after %s. "+
			"Raise --policy-wait", wait)
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
