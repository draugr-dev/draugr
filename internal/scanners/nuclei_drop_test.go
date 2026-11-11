package scanners

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
)

// nucleiSkipLog is Nuclei 3.11.1's log from a scan of probe-web.internal:8080 on a network with no
// outside DNS, as it printed it with -nc: the banner, info lines, and four Skipped lines, two for the
// endpoint and two for ports templates probed past it.
const nucleiSkipLog = `                     __     _
   ____  __  _______/ /__  (_)
/_/ /_/\__,_/\___/_/\___/_/   v3.11.1
[ERR] Could not read nuclei-ignore file: open /home/u/.config/nuclei/.nuclei-ignore: no such file or directory
[INF] Templates loaded for current scan: 10625
[INF] Skipped probe-web.internal:8080 from target list as found unresponsive permanently: cause="no address found for host" chain="got err while executing https://login.microsoftonline.com:443/probe-web.internal/v2.0/.well-known/openid-configuration"
[INF] Skipped probe-web.internal:8080 from target list as found unresponsive permanently: cause="no address found for host" chain="got err while executing https://www.rdap.net/domain/probe-web.internal"
[INF] Skipped probe-web.internal:5814 from target list as found unresponsive permanently: Get "https://probe-web.internal:5814/autopass": cause="port closed or filtered" address=probe-web.internal:5814 chain="connection refused"
[INF] Skipped probe-web.internal:4040 from target list as found unresponsive permanently: cause="port closed or filtered" address=probe-web.internal:4040 chain="connection refused; got err while executing https://probe-web.internal:4040/jobs/?\"'><script>alert(document.domain)</script>"
[INF] Scan completed in 2m. 65 matches found.
`

func TestNucleiSkipsReadsEachForm(t *testing.T) {
	t.Parallel()
	got := nucleiSkips([]byte(nucleiSkipLog))
	want := []nucleiSkip{
		{"probe-web.internal:8080", "no address found for host",
			"https://login.microsoftonline.com:443/probe-web.internal/v2.0/.well-known/openid-configuration"},
		{"probe-web.internal:8080", "no address found for host", "https://www.rdap.net/domain/probe-web.internal"},
		{"probe-web.internal:5814", "port closed or filtered", "https://probe-web.internal:5814/autopass"},
		{"probe-web.internal:4040", "port closed or filtered", "https://probe-web.internal:4040/jobs/?"},
	}
	if len(got) != len(want) {
		t.Fatalf("skips = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("skip %d = %+v, want %+v", i, got[i], want[i])
		}
	}
	// A line with no cause and no request still names the host.
	bare := nucleiSkips([]byte("[INF] Skipped h:1 from target list as found unresponsive permanently: too many errors"))
	if len(bare) != 1 || bare[0] != (nucleiSkip{host: "h:1"}) {
		t.Errorf("bare skip = %+v", bare)
	}
	// The form Nuclei 3.11.1 printed for an endpoint that stopped answering partway through a scan.
	counted := nucleiSkips([]byte("[INF] Skipped probe-web.internal:8080 from target list as found unresponsive 31 times"))
	if len(counted) != 1 || counted[0] != (nucleiSkip{host: "probe-web.internal:8080", cause: "31 errors"}) {
		t.Errorf("counted skip = %+v", counted)
	}
}

func TestNucleiSkippedOfMatchesTheEndpointOnly(t *testing.T) {
	t.Parallel()
	skipped := &nucleiSkipped{skips: nucleiSkips([]byte(nucleiSkipLog))}
	for _, c := range []struct {
		url  string
		want bool
	}{
		{"http://probe-web.internal:8080/", true},
		{"http://PROBE-WEB.internal:8080/app", true},
		// Ports a template probed past the URL do not shorten the endpoint's scan.
		{"http://probe-web.internal/", false},
		{"https://probe-web.internal/", false},
		{"not a url", false},
	} {
		if got := skipped.of(c.url) != nil; got != c.want {
			t.Errorf("of(%q) = %v, want %v", c.url, got, c.want)
		}
	}
	if got := nucleiHostPort("https://app.example.com"); got != "app.example.com:443" {
		t.Errorf("https default port: %q", got)
	}
	if got := nucleiHostPort("http://[::1]/"); got != "[::1]:80" {
		t.Errorf("IPv6: %q", got)
	}
	if !strings.Contains(skipped.Error(), "probe-web.internal:4040") {
		t.Errorf("Error() = %q, want the hosts it names", skipped.Error())
	}
}

func TestNucleiDropErrorSaysWhoseRequestFailed(t *testing.T) {
	t.Parallel()
	const endpoint = "http://probe-web.internal:8080/"
	other := nucleiDropError(endpoint, nucleiSkip{"probe-web.internal:8080", "no address found for host",
		"https://login.microsoftonline.com:443/probe-web.internal/v2.0/.well-known/openid-configuration"}).Error()
	for _, want := range []string{"stopped testing http://probe-web.internal:8080/ partway", "no address found for host",
		"login.microsoftonline.com", "another host", "remaining templates did not run", "can reach that host"} {
		if !strings.Contains(other, want) {
			t.Errorf("error should say %q:\n%s", want, other)
		}
	}
	if strings.Contains(other, "rateLimit") {
		t.Errorf("a rate limit does not stop a lookup of another host failing:\n%s", other)
	}

	own := nucleiDropError(endpoint, nucleiSkip{"probe-web.internal:8080", "port closed or filtered",
		"http://probe-web.internal:8080/admin"}).Error()
	if !strings.Contains(own, "`rateLimit`") || strings.Contains(own, "another host") {
		t.Errorf("the endpoint stopped answering, so the advice is about the scan's pace:\n%s", own)
	}
	bare := nucleiDropError(endpoint, nucleiSkip{host: "probe-web.internal:8080"}).Error()
	if !strings.Contains(bare, "after too many failed requests") || !strings.Contains(bare, "`timeout`") {
		t.Errorf("a line with no cause:\n%s", bare)
	}
	counted := nucleiDropError(endpoint, nucleiSkip{host: "probe-web.internal:8080", cause: "31 errors"}).Error()
	if !strings.Contains(counted, "after 31 requests to it failed") || !strings.Contains(counted, "stayed up") {
		t.Errorf("the counted form:\n%s", counted)
	}
}

// The fatal line is the reason a run failed, so it leads what the error quotes, and the banner and
// the info lines are left out of it.
func TestNucleiLogShownLeadsWithTheFatalLine(t *testing.T) {
	t.Parallel()
	log := nucleiSkipLog + "[WRN] something to warn about\n[FTL] Could not run nuclei: no templates provided for scan\n"
	got := string(nucleiLogShown([]byte(log)))
	want := "[FTL] Could not run nuclei: no templates provided for scan\n" +
		"[ERR] Could not read nuclei-ignore file: open /home/u/.config/nuclei/.nuclei-ignore: no such file or directory\n" +
		"[WRN] something to warn about"
	if got != want {
		t.Errorf("shown =\n%s\nwant\n%s", got, want)
	}
}

// A scan whose endpoint Nuclei dropped keeps its findings and is partial. A drop of another port
// changes nothing.
func TestNucleiScanReportsADroppedEndpointAsPartial(t *testing.T) {
	t.Parallel()
	const finding = `{"template-id":"t","matched-at":"http://probe-web.internal:8080/a","info":{"name":"T","severity":"high"}}`
	scan := func(skips string) (int, error) {
		s := nucleiScanner{info: NewNuclei().Info(), run: func(context.Context, []string) ([]byte, error) {
			return []byte(finding), &nucleiSkipped{skips: nucleiSkips([]byte(skips))}
		}}
		rep, err := s.Scan(context.Background(), plugin.HostTarget{URL: "http://probe-web.internal:8080/"}, nil)
		return len(rep.Results), err
	}

	n, err := scan(nucleiSkipLog)
	partial, ok := errors.AsType[*plugin.PartialScanError](err)
	if !ok {
		t.Fatalf("err = %v, want a partial scan", err)
	}
	if n != 1 || len(partial.Report.Results) != 1 {
		t.Errorf("findings = %d, partial report %d, want the one finding kept in both", n, len(partial.Report.Results))
	}
	if !strings.Contains(err.Error(), "login.microsoftonline.com") {
		t.Errorf("the first drop of the endpoint is the one quoted: %v", err)
	}

	other := strings.Join(strings.Split(nucleiSkipLog, "\n")[7:9], "\n")
	if n, err := scan(other); err != nil || n != 1 {
		t.Errorf("drops of other ports: %d findings, err %v; want the scan complete", n, err)
	}
}

// execNuclei against a stand-in that writes a finding to stdout and the log to stderr, as Nuclei
// does: the output comes back with the skips, and a failed run's error quotes the fatal line.
func TestExecNucleiReadsTheLog(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	logFile := filepath.Join(dir, "log")
	if err := os.WriteFile(logFile, []byte(nucleiSkipLog), 0o600); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(dir, "nuclei")
	body := "#!/bin/sh\necho '{\"template-id\":\"t\"}'\ncat " + logFile + " >&2\n" +
		"[ \"$1\" = fail ] && { echo '[FTL] Could not run nuclei: no templates provided for scan' >&2; exit 1; }\nexit 0\n"
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil { // #nosec G306 -- an executable stand-in in t.TempDir()
		t.Fatal(err)
	}

	out, err := execNuclei(context.Background(), []string{script})
	skipped, ok := errors.AsType[*nucleiSkipped](err)
	if !ok || len(skipped.skips) != 4 || !strings.Contains(string(out), "template-id") {
		t.Errorf("out %q, err %v; want the finding and four skips", out, err)
	}

	_, err = execNuclei(context.Background(), []string{script, "fail"})
	if err == nil || !nucleiHadNoTemplates(err) || strings.Contains(err.Error(), "____") {
		t.Errorf("a failed run's error should quote the fatal line and not the banner: %v", err)
	}

	clean := filepath.Join(dir, "clean")
	if err := os.WriteFile(clean, []byte("#!/bin/sh\necho '[INF] Scan completed' >&2\n"), 0o700); err != nil { // #nosec G306 -- an executable stand-in in t.TempDir()
		t.Fatal(err)
	}
	if _, err := execNuclei(context.Background(), []string{clean}); err != nil {
		t.Errorf("a run with no skips: %v", err)
	}
}
