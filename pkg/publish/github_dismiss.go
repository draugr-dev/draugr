package publish

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Code scanning does not read SARIF `suppressions`. The SARIF support reference lists the result
// properties it uses and suppressions is not among them, so a finding Draugr accepted arrives as an
// open alert with nothing saying it was accepted, and the Security tab cannot tell a decision from a
// finding nobody has looked at.
//
// The publisher therefore finishes the job itself once GitHub has processed the upload: an open
// alert whose result is suppressed is dismissed with the reason, and an alert Draugr dismissed
// earlier whose result is no longer suppressed, an exclusion that expired, say, is reopened. An
// alert a person dismissed is theirs and is left alone.

// dismissedBy opens every dismissal comment the publisher writes. It is how a later run tells its
// own dismissals from a person's, which it must never reopen.
const dismissedBy = "Accepted in Draugr: "

// dismissalCommentLimit is the most GitHub keeps of a dismissal comment.
const dismissalCommentLimit = 280

// alertKey is what an alert and a SARIF result have in common: GitHub's alert listing carries no
// fingerprint, so a result is matched on its rule and where it is.
type alertKey struct {
	rule, path string
	line       int
}

// suppressedResult is a result as the follow-up needs it: whether it is suppressed, and why.
type suppressedResult struct {
	suppressed bool
	comment    string
}

// uploadedResults reads the results of the SARIF the publisher just uploaded, keyed as alerts are,
// and the tool name GitHub files them under.
func uploadedResults(sarif []byte) (tool string, results map[alertKey]suppressedResult, err error) {
	var doc struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Name string `json:"name"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string `json:"ruleId"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
						Region struct {
							StartLine int `json:"startLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
				Suppressions []struct {
					Justification string `json:"justification"`
					Properties    struct {
						AcceptedBy string `json:"acceptedBy"`
					} `json:"properties"`
				} `json:"suppressions"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(sarif, &doc); err != nil {
		return "", nil, fmt.Errorf("github code scanning: could not read the report to find accepted findings: %w", err)
	}
	results = map[alertKey]suppressedResult{}
	for _, run := range doc.Runs {
		if tool == "" {
			tool = run.Tool.Driver.Name
		}
		for _, r := range run.Results {
			if len(r.Locations) == 0 {
				continue
			}
			loc := r.Locations[0].PhysicalLocation
			key := alertKey{rule: r.RuleID, path: loc.ArtifactLocation.URI, line: loc.Region.StartLine}
			if len(r.Suppressions) == 0 {
				// One result unsuppressed at a place is enough to keep its alert open, whatever
				// another result at the same rule and line says.
				results[key] = suppressedResult{}
				continue
			}
			if prev, seen := results[key]; seen && !prev.suppressed {
				continue
			}
			s := r.Suppressions[0]
			results[key] = suppressedResult{suppressed: true, comment: dismissalComment(s.Justification, s.Properties.AcceptedBy)}
		}
	}
	return tool, results, nil
}

// dismissalComment is the reason as GitHub will show it, cut to what GitHub keeps. The reason is
// what gives way: who accepted the finding is the half of the comment an auditor reads it for.
func dismissalComment(justification, acceptedBy string) string {
	reason := strings.Join(strings.Fields(justification), " ")
	if reason == "" {
		reason = "no reason recorded"
	}
	suffix := ""
	if acceptedBy != "" {
		suffix = " (accepted by " + acceptedBy + ")"
	}
	room := dismissalCommentLimit - len([]rune(dismissedBy)) - len([]rune(suffix))
	if r := []rune(reason); len(r) > room {
		reason = string(r[:max(room-1, 0)]) + "…"
	}
	return dismissedBy + reason + suffix
}

// codeScanningAlert is the part of an alert the follow-up reads.
type codeScanningAlert struct {
	Number int    `json:"number"`
	State  string `json:"state"`
	Rule   struct {
		ID string `json:"id"`
	} `json:"rule"`
	DismissedComment string `json:"dismissed_comment"`
	Instance         struct {
		Location struct {
			Path      string `json:"path"`
			StartLine int    `json:"start_line"`
		} `json:"location"`
	} `json:"most_recent_instance"`
}

func (a codeScanningAlert) key() alertKey {
	return alertKey{rule: a.Rule.ID, path: a.Instance.Location.Path, line: a.Instance.Location.StartLine}
}

// syncSuppressions brings the alerts of one upload into line with the suppressions in it.
func (g githubPublisher) syncSuppressions(ctx context.Context, uploadID string, sarif []byte) error {
	tool, results, err := uploadedResults(sarif)
	if err != nil {
		return err
	}
	if err := g.awaitProcessing(ctx, uploadID); err != nil {
		return err
	}
	var failed []string
	for _, state := range []string{"open", "dismissed"} {
		alerts, err := g.alerts(ctx, tool, state)
		if err != nil {
			return err
		}
		for _, a := range alerts {
			r, ok := results[a.key()]
			if !ok {
				continue
			}
			var change map[string]string
			switch {
			case a.State == "open" && r.suppressed:
				change = map[string]string{"state": "dismissed", "dismissed_reason": "won't fix", "dismissed_comment": r.comment}
			case a.State == "dismissed" && !r.suppressed && strings.HasPrefix(a.DismissedComment, dismissedBy):
				change = map[string]string{"state": "open"}
			default:
				continue
			}
			if err := g.call(ctx, http.MethodPatch, fmt.Sprintf("code-scanning/alerts/%d", a.Number), change, nil); err != nil {
				failed = append(failed, fmt.Sprintf("alert %d (%s): %v", a.Number, a.Rule.ID, err))
			}
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("github code scanning: the upload succeeded, and these alerts could not be updated to match "+
			"the accepted findings: %s. Check that the token has security-events: write, then re-run",
			strings.Join(failed, "; "))
	}
	return nil
}

// awaitProcessing waits for GitHub to finish processing an upload, because the alerts it creates do
// not exist until then.
func (g githubPublisher) awaitProcessing(ctx context.Context, uploadID string) error {
	deadline := time.Now().Add(g.processingWait)
	for {
		var status struct {
			ProcessingStatus string   `json:"processing_status"`
			Errors           []string `json:"errors"`
		}
		if err := g.call(ctx, http.MethodGet, "code-scanning/sarifs/"+url.PathEscape(uploadID), nil, &status); err != nil {
			return err
		}
		switch status.ProcessingStatus {
		case "complete":
			return nil
		case "failed":
			return fmt.Errorf("github code scanning could not process the upload: %s", strings.Join(status.Errors, "; "))
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("github code scanning had not processed the upload after %s, so no accepted finding's "+
				"alert was dismissed. Re-run once GitHub has processed it", g.processingWait)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(g.processingPoll):
		}
	}
}

// alerts lists this tool's alerts on the ref in one state.
func (g githubPublisher) alerts(ctx context.Context, tool, state string) ([]codeScanningAlert, error) {
	q := url.Values{"ref": {g.ref}, "state": {state}, "per_page": {"100"}}
	if tool != "" {
		q.Set("tool_name", tool)
	}
	next := fmt.Sprintf("%s/repos/%s/code-scanning/alerts?%s", g.apiURL, g.repo, q.Encode())
	var out []codeScanningAlert
	for next != "" {
		var page []codeScanningAlert
		h, err := g.request(ctx, http.MethodGet, next, nil, &page)
		if err != nil {
			return nil, err
		}
		out = append(out, page...)
		next = nextPageURL(h.Get("Link"))
	}
	return out, nil
}

// call sends one request to a path under the repository.
func (g githubPublisher) call(ctx context.Context, method, path string, body, into any) error {
	_, err := g.request(ctx, method, fmt.Sprintf("%s/repos/%s/%s", g.apiURL, g.repo, path), body, into)
	return err
}

// request sends one request and decodes a successful answer into into.
func (g githubPublisher) request(ctx context.Context, method, target string, body, into any) (http.Header, error) {
	var payload io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		payload = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, payload)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+g.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := g.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, errors.New(resp.Status + ": " + strings.TrimSpace(string(msg)))
	}
	if into != nil {
		if err := json.NewDecoder(resp.Body).Decode(into); err != nil {
			return nil, fmt.Errorf("read %s %s: %w", method, req.URL.Path, err)
		}
	}
	return resp.Header, nil
}
