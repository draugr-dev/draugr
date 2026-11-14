package engine

import (
	"testing"

	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/saga"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// hostController plans one job per host a component declares, as tls and headers do.
type hostController struct {
	name     string
	verifies bool
}

func (c hostController) Info() plugin.ControllerInfo {
	return plugin.ControllerInfo{Name: c.name, Scope: plugin.ScopeComponent, VerifiesCertificates: c.verifies}
}

func (c hostController) Plan(_ saga.Model, comp *saga.Component) ([]plugin.ScanJob, error) {
	var jobs []plugin.ScanJob
	for _, h := range comp.Hosts {
		jobs = append(jobs, plugin.ScanJob{Scanner: c.name, Target: plugin.HostTarget{Name: h.Name, URL: h.URL}})
	}
	return jobs, nil
}

func (c hostController) Aggregate(reports []sarif.Report) (plugin.ControlResult, error) {
	return plugin.ControlResult{Control: c.name, Report: sarif.Merge(reports...)}, nil
}

// certificateModel has two components with two hosts each, one host shared by both, and the
// certificate control enabled on the first component only.
func certificateModel() saga.Model {
	return saga.Model{
		Config: saga.Config{Controls: map[string]saga.ControllerSettings{"headers": {"enabled": true}}},
		Components: []saga.Component{{
			Name:     "api",
			Hosts:    []saga.Host{{Name: "public", URL: "https://api.example.com/"}, {Name: "shared", URL: "https://shared.example.com/"}},
			Controls: map[string]saga.ControllerSettings{"tls": {"enabled": true}},
		}, {
			Name:  "web",
			Hosts: []saga.Host{{Name: "site", URL: "https://www.example.com/"}, {Name: "shared", URL: "https://shared.example.com/"}},
		}},
	}
}

// certificateMarks is each planned host job's control, component, URL and mark.
func certificateMarks(t *testing.T, planned []PlannedJob) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, pj := range planned {
		host, ok := pj.Job.Target.(plugin.HostTarget)
		if !ok {
			t.Fatalf("planned %T, want a host", pj.Job.Target)
		}
		out[pj.Control+" "+pj.Component+" "+host.URL] = host.CertificateReported
	}
	return out
}

// A job on an endpoint whose certificate another control in the run verifies is marked, in that
// component only. The verifying control's own jobs are not, and neither is a host it has no job on,
// the same URL under another component included.
func TestAJobOnAnEndpointTheRunVerifiesIsMarked(t *testing.T) {
	reg := NewRegistry()
	reg.RegisterController(hostController{name: "tls", verifies: true})
	reg.RegisterController(hostController{name: "headers"})

	planned, err := New(reg).Plan(certificateModel())
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"headers api https://api.example.com/":    true,
		"headers api https://shared.example.com/": true,
		"headers web https://www.example.com/":    false,
		"headers web https://shared.example.com/": false,
		"tls api https://api.example.com/":        false,
		"tls api https://shared.example.com/":     false,
	}
	got := certificateMarks(t, planned)
	if len(got) != len(want) {
		t.Fatalf("planned %v, want %v", got, want)
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%s marked %v, want %v", k, got[k], w)
		}
	}
	// The mark is part of the identity, so a result read past a certificate is never the cached
	// answer for a job that may not.
	for _, pj := range planned {
		host, _ := pj.Job.Target.(plugin.HostTarget)
		if host.CertificateReported != (host.Identity() != plugin.SourceURL(host.URL)) {
			t.Errorf("%s %s identity %q, want the mark exactly where it is set", pj.Control, host.URL, host.Identity())
		}
	}
}

// A run narrowed to leave the verifying control out marks nothing, since nothing in it would
// report the certificate.
func TestARunWithoutTheVerifyingControlMarksNothing(t *testing.T) {
	reg := NewRegistry()
	reg.RegisterController(hostController{name: "tls", verifies: true})
	reg.RegisterController(hostController{name: "headers"})

	planned, err := New(reg, WithScope(Scope{Controls: []string{"headers"}})).Plan(certificateModel())
	if err != nil {
		t.Fatal(err)
	}
	if len(planned) != 4 {
		t.Fatalf("planned %d jobs, want the four headers jobs", len(planned))
	}
	for k, marked := range certificateMarks(t, planned) {
		if marked {
			t.Errorf("%s marked in a run without tls", k)
		}
	}
}
