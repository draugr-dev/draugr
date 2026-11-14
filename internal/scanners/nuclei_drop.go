package scanners

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"

	"github.com/draugr-dev/draugr/internal/toolexec"
)

// nucleiSkip is a host Nuclei stopped scanning partway, as its log says so, in one of two forms:
//
//	[INF] Skipped probe-web.internal:8080 from target list as found unresponsive permanently: cause="no address found for host" chain="got err while executing https://login.microsoftonline.com:443/…"
//	[INF] Skipped probe-web.internal:8080 from target list as found unresponsive 31 times
//
// Nuclei counts errors per host and, past a limit (30 by default, `-mhe`), drops the host from the
// scan and runs none of the templates it has not reached. The run then finishes and exits 0, and its
// output holds the findings made before the drop and nothing to mark it. The log line is the only
// record, and `-silent` hides it.
type nucleiSkip struct {
	// host is the host and port Nuclei names, such as "probe-web.internal:8080".
	host string
	// cause is Nuclei's reason, such as "no address found for host", and request the URL whose
	// failure it was, where the line names one. That URL is not always the host's: a template that
	// requests another host can fail and be counted against the one being scanned.
	cause, request string
}

// nucleiSkipRE reads a Skipped line. The text after the colon is Nuclei's error, which carries
// cause="…" and names the failed request either in chain="… executing <url>…" or as a leading
// `Get "<url>":`.
var (
	nucleiSkipRE    = regexp.MustCompile(`^\[INF\] Skipped (\S+) from target list as found unresponsive(?: permanently: (.*)| (\d+) times)$`)
	nucleiCauseRE   = regexp.MustCompile(`cause="([^"]*)"`)
	nucleiRequestRE = regexp.MustCompile(`executing ([^"\s;\\]+)`)
	nucleiMethodRE  = regexp.MustCompile(`^[A-Z][a-z]* "([^"]+)"`)
)

// nucleiSkips reads every Skipped line in Nuclei's log, in order.
func nucleiSkips(log []byte) []nucleiSkip {
	var out []nucleiSkip
	for line := range strings.SplitSeq(string(log), "\n") {
		m := nucleiSkipRE.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		s := nucleiSkip{host: m[1]}
		if m[3] != "" {
			s.cause = m[3] + " errors"
		}
		if c := nucleiCauseRE.FindStringSubmatch(m[2]); c != nil {
			s.cause = c[1]
		}
		if r := nucleiRequestRE.FindStringSubmatch(m[2]); r != nil {
			s.request = r[1]
		} else if r := nucleiMethodRE.FindStringSubmatch(m[2]); r != nil {
			s.request = r[1]
		}
		out = append(out, s)
	}
	return out
}

// nucleiSkipped is a run that finished after Nuclei stopped scanning one or more hosts. The run's
// output is complete as far as it went, so it is returned beside this error, and the scan decides
// whether a skipped host is the one it was testing.
type nucleiSkipped struct{ skips []nucleiSkip }

func (e *nucleiSkipped) Error() string {
	hosts := make([]string, 0, len(e.skips))
	for _, s := range e.skips {
		hosts = append(hosts, s.host)
	}
	return "nuclei stopped scanning " + strings.Join(hosts, ", ")
}

// of is the skip for the endpoint at rawURL, nil when Nuclei did not drop it. A drop of another
// port, which a template probing past the URL can cause, does not shorten the endpoint's scan.
func (e *nucleiSkipped) of(rawURL string) *nucleiSkip {
	want := nucleiHostPort(rawURL)
	for i, s := range e.skips {
		if want != "" && strings.EqualFold(s.host, want) {
			return &e.skips[i]
		}
	}
	return nil
}

// nucleiHostPort is a URL's host and port as Nuclei names a host in its log, with the scheme's port
// where the URL gives none.
func nucleiHostPort(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Hostname() == "" {
		return ""
	}
	port := u.Port()
	if port == "" {
		port = "80"
		if strings.EqualFold(u.Scheme, "https") {
			port = "443"
		}
	}
	return net.JoinHostPort(u.Hostname(), port)
}

// nucleiDropError is the scan's error for an endpoint Nuclei stopped testing: why, what was lost, and
// what to do before the next run.
func nucleiDropError(endpoint string, s nucleiSkip) error {
	var msg string
	switch {
	case s.cause == "":
		msg = fmt.Sprintf("nuclei stopped testing %s partway, after too many failed requests", endpoint)
	case strings.HasSuffix(s.cause, " errors"):
		msg = fmt.Sprintf("nuclei stopped testing %s partway, after %s requests to it failed", endpoint,
			strings.TrimSuffix(s.cause, " errors"))
	default:
		msg = fmt.Sprintf("nuclei stopped testing %s partway: %s", endpoint, s.cause)
	}
	if s.request != "" {
		msg += " at " + s.request
	}
	msg += ". Its findings until then are kept, and its remaining templates did not run."
	other := false
	if u, err := url.Parse(s.request); err == nil && u.Hostname() != "" {
		other = !strings.EqualFold(nucleiHostPort(s.request), nucleiHostPort(endpoint))
	}
	if other {
		msg += " That request was to another host, and Nuclei counted its failure against the endpoint. " +
			"Check that this network can reach that host, then rerun"
	} else {
		msg += " Check that the endpoint stayed up and rerun; if it was slow, lower `rateLimit` or raise `timeout`"
	}
	return errors.New(msg)
}

// nucleiLogKept reports whether a line of Nuclei's log is one the run holds: a fatal, error or
// warning line, which nucleiLogShown relays, or a Skipped line, which nucleiSkips reads. Nuclei logs
// at info level as it works, and nothing reads the rest.
func nucleiLogKept(line []byte) bool {
	line = bytes.TrimSpace(line)
	for _, tag := range []string{"[FTL]", "[ERR]", "[WRN]"} {
		if bytes.HasPrefix(line, []byte(tag)) {
			return true
		}
	}
	return bytes.HasPrefix(line, []byte("[INF] Skipped "))
}

// nucleiLogShown is the part of Nuclei's log Draugr relays to its own log and quotes in an error:
// the fatal, error and warning lines, fatal first, so the first line of a failed run's error is the
// reason it failed. The banner and the info lines are left out, as `-silent` left them out before
// the scanner needed to read the Skipped line among them.
func nucleiLogShown(log []byte) []byte {
	var levels [3][][]byte
	for line := range bytes.SplitSeq(log, []byte("\n")) {
		line = bytes.TrimSpace(line)
		for i, tag := range []string{"[FTL]", "[ERR]", "[WRN]"} {
			if bytes.HasPrefix(line, []byte(tag)) {
				levels[i] = append(levels[i], line)
				break
			}
		}
	}
	return bytes.Join(append(append(levels[0], levels[1]...), levels[2]...), []byte("\n"))
}

// execNuclei runs Nuclei and returns its output. A run that finished after dropping a host returns
// its output with a *nucleiSkipped.
func execNuclei(ctx context.Context, argv []string) ([]byte, error) {
	out, log, err := toolexec.RunWithLog(ctx, "", argv, nil, toolexec.Log{Keep: nucleiLogKept, Shown: nucleiLogShown})
	if err != nil {
		return out, err
	}
	if skips := nucleiSkips(log); len(skips) > 0 {
		return out, &nucleiSkipped{skips: skips}
	}
	return out, nil
}
