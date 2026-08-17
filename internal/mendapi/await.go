package mendapi

import (
	"context"
	"fmt"
	"time"
)

// AwaitOpts configures the wait for an upload to be processed.
type AwaitOpts struct {
	ProductToken string
	ProjectName  string
	// RequestToken is what the agent reported for this upload, when it reported one.
	RequestToken string
	// ExpectLibraries is how many dependencies the agent said it resolved. Used when there is no
	// request token: the inventory holding at least that many is evidence the upload was applied,
	// and it compares what arrived against what was sent rather than trusting a clock.
	ExpectLibraries int
	// Timeout bounds the whole wait. Minutes rather than seconds: a large component is exactly
	// when Mend is slowest to process, and also when giving up early does most damage.
	Timeout time.Duration
	// Interval is the first gap between polls; it backs off from there.
	Interval time.Duration
	// Sleep is injectable so tests need not wait. Nil uses a real timer.
	Sleep func(context.Context, time.Duration) error
}

const (
	defaultAwaitTimeout  = 10 * time.Minute
	defaultAwaitInterval = 5 * time.Second
	maxAwaitInterval     = 30 * time.Second
)

// Await blocks until the upload identified by RequestToken has been processed, then returns the
// project's alerts.
//
// The reason this exists: Mend accepts an upload and processes it afterwards, so a query made too
// early is answered — honestly — with nothing. Nothing is indistinguishable from a clean project,
// so without this an eager poll turns "has not finished reading your code" into "no
// vulnerabilities", and does it most reliably on the largest components, because those take
// longest.
//
// The check is a correlation, not a guess about timing. Where the agent reports an update-request
// token, the project's vitals carry it once the upload has been applied, which answers "has *my*
// scan landed" rather than "has *something* happened recently". Where it does not — and the CLI's
// agent does not print one — the fallback compares the inventory against the number of
// dependencies the agent said it resolved, which is still evidence about *this* upload rather
// than about the clock.
//
// **A timeout is an error, never an empty result.** Returning no alerts here would report a pass
// for a scan nobody has read, which is the failure the whole function exists to prevent.
func (c *Client) Await(ctx context.Context, opts AwaitOpts) ([]Alert, error) {
	timeout, interval := opts.Timeout, opts.Interval
	if timeout <= 0 {
		timeout = defaultAwaitTimeout
	}
	if interval <= 0 {
		interval = defaultAwaitInterval
	}
	sleep := opts.Sleep
	if sleep == nil {
		sleep = sleepCtx
	}

	deadline := time.Now().Add(timeout)
	var lastErr error

	for attempt := 0; ; attempt++ {
		project, err := c.ProjectByName(ctx, opts.ProductToken, opts.ProjectName)
		if err == nil {
			var landed bool
			landed, lastErr = c.landed(ctx, project.Token, opts)
			if lastErr == nil && landed {
				return c.Alerts(ctx, project.Token)
			}
		} else {
			// The project not existing yet is the ordinary early state, not a failure: the upload
			// creates it, and creation is itself part of what we are waiting for.
			lastErr = err
		}

		if time.Now().After(deadline) {
			return nil, fmt.Errorf(
				"mend: results for project %q were not ready within %s — the scan uploaded but "+
					"Mend had not finished processing it, so there is nothing to report yet "+
					"rather than nothing to find. Raise resultTimeout for a component this large. "+
					"(last state: %v)", opts.ProjectName, timeout, lastErr)
		}
		if err := sleep(ctx, interval); err != nil {
			return nil, err
		}
		if interval < maxAwaitInterval {
			interval *= 2
			if interval > maxAwaitInterval {
				interval = maxAwaitInterval
			}
		}
	}
}

// landed reports whether the upload has been applied to the project.
//
// With a request token this is exact. Without one — an agent version that did not report it — the
// weaker fallback is that the project exists and has been updated at all, which cannot tell our
// upload from somebody else's. The caller is told which of the two it got by the token being
// empty, and the scanner passes one whenever the agent gives it.
func (c *Client) landed(ctx context.Context, projectToken string, opts AwaitOpts) (bool, error) {
	if opts.RequestToken != "" {
		vitals, err := c.Vitals(ctx, projectToken)
		if err != nil {
			return false, err
		}
		return vitals.RequestToken == opts.RequestToken, nil
	}
	if opts.ExpectLibraries > 0 {
		n, err := c.LibraryCount(ctx, projectToken)
		if err != nil {
			return false, err
		}
		if n < opts.ExpectLibraries {
			return false, fmt.Errorf("inventory holds %d of the %d libraries the scan sent", n, opts.ExpectLibraries)
		}
		return true, nil
	}
	// Nothing to correlate against. The project existing and having been updated is all that can
	// be said, and it cannot tell this upload from anybody else's.
	vitals, err := c.Vitals(ctx, projectToken)
	if err != nil {
		return false, err
	}
	return vitals.LastUpdatedDate != "", nil
}

// sleepCtx waits, or returns early if the run is canceled.
func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
