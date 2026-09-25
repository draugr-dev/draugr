package mcp

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/draugr-dev/draugr/internal/builtins"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// The failure this guards against is a prompt that reads identically whatever it is asking about.
// A reader approving five read-only controls over a checkout learns nothing about having approved
// probing traffic at a live host, and the person answering is usually not the one who wrote the
// descriptor.
func TestDescribeScanNamesWhatThisDescriptorDoes(t *testing.T) {
	model := &saga.Model{
		Config: saga.Config{Controls: map[string]saga.ControllerSettings{
			"secrets": {"enabled": true},
			"sca":     {"enabled": true},
		}},
		Components: []saga.Component{
			{Name: "api", Repositories: []saga.Repository{{URL: "https://example.com/a.git"}}},
			{Name: "web", Repositories: []saga.Repository{{URL: "https://example.com/b.git"}}},
		},
	}
	got := describeScan(mustPlan(t, model), "app.saga.yaml")
	for _, want := range []string{"app.saga.yaml", "sca", "secrets", "2 components"} {
		if !strings.Contains(got, want) {
			t.Errorf("prompt should contain %q:\n%s", want, got)
		}
	}
	// Nothing here touches a live service, so nothing should claim to.
	if strings.Contains(got, "live service") {
		t.Errorf("a repository scan should not warn about live traffic:\n%s", got)
	}
}

func TestDescribeScanSaysWhenItWillProbeALiveHost(t *testing.T) {
	model := &saga.Model{
		Config: saga.Config{
			Controls:     map[string]saga.ControllerSettings{"dast": {"enabled": true}},
			AllowEffects: saga.EffectPermissions{"network"},
		},
		Components: []saga.Component{
			{Name: "api", Hosts: []saga.Host{{URL: "https://api.example.com"}}},
		},
	}
	got := describeScan(mustPlan(t, model), "app.saga.yaml")
	if !strings.Contains(got, "live service") {
		t.Errorf("a dast scan must say it sends traffic:\n%s", got)
	}
	if !strings.Contains(got, "nuclei") {
		t.Errorf("the prompt should name the scanner doing it:\n%s", got)
	}
	if !strings.Contains(got, "authorized") {
		t.Errorf("probing a host you do not own is unlawful in many places; say so:\n%s", got)
	}
}

// Delivery is an effect on the user's machine and on third parties. Approving a scan is not
// approving an upload, so the prompt has to name what will be delivered and where.
func TestDescribeScanNamesWhereResultsGo(t *testing.T) {
	model := &saga.Model{
		Config: saga.Config{
			Controls: map[string]saga.ControllerSettings{"secrets": {"enabled": true}},
			Publishers: []saga.PublisherConfig{
				{Kind: "file", Dir: "out/reports"},
				{Kind: "github", Repo: "acme/app"},
			},
		},
		Components: []saga.Component{
			{Name: "api", Repositories: []saga.Repository{{URL: "https://example.com/a.git"}}},
		},
	}
	got := describeScan(mustPlan(t, model), "app.saga.yaml")
	for _, want := range []string{"delivered to", "file: out/reports", "github: acme/app"} {
		if !strings.Contains(got, want) {
			t.Errorf("prompt should contain %q:\n%s", want, got)
		}
	}
}

// A descriptor that would examine nothing says so, rather than describing a scan that is not
// going to happen.
func TestDescribeScanSaysWhenNothingIsEnabled(t *testing.T) {
	model := &saga.Model{Components: []saga.Component{{Name: "api"}}}
	got := describeScan(mustPlan(t, model), "app.saga.yaml")
	if !strings.Contains(got, "examine nothing") {
		t.Errorf("an empty plan should say so:\n%s", got)
	}
}

// The point of the delivered list: a caller that knows a file exists can read it back with
// summarize_report instead of paying for another scan.
func TestScanDeliversTheDescriptorsPublishers(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "reports")
	path := filepath.Join(dir, "published.saga.yaml")
	// No control enabled, so this needs no scanner binary and no network. The publisher still has a
	// complete run to render, which is the part under test.
	if err := os.WriteFile(path, []byte(
		"project: app\nrelease:\n  version: \"1.0\"\n"+
			"config:\n  publishers:\n    - kind: file\n      dir: "+out+"\n      reports:\n        - format: sarif\n"+
			"components:\n  - name: api\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, res, err := scanTool(builtins.Registry(), ScanAlways)(context.Background(), nil, ScanInput{Path: path})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(res.Delivered) != 1 || !strings.Contains(res.Delivered[0], out) {
		t.Errorf("delivered = %v, want the file publisher's directory", res.Delivered)
	}
	entries, err := os.ReadDir(out)
	if err != nil {
		t.Fatalf("the publisher wrote nothing: %v", err)
	}
	if len(entries) == 0 {
		t.Error("the publisher's directory is empty")
	}
}

// A descriptor with no publishers must not invent a destination.
func TestScanReportsNoDeliveryWhenNoneIsConfigured(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "plain.saga.yaml")
	if err := os.WriteFile(path, []byte(
		"project: app\nrelease:\n  version: \"1.0\"\ncomponents:\n  - name: api\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, res, err := scanTool(builtins.Registry(), ScanAlways)(context.Background(), nil, ScanInput{Path: path})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(res.Delivered) != 0 {
		t.Errorf("delivered = %v, want none", res.Delivered)
	}
}

func mustPlan(t *testing.T, m *saga.Model) scanPlan {
	t.Helper()
	p, err := planScan(builtins.Registry(), m)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	return p
}

// The decision is a function of the mode and the plan alone, so every combination is written down
// here rather than inferred from the handler's behavior.
func TestNeedsApprovalReadsTheModeAndThePlan(t *testing.T) {
	var (
		local    = scanPlan{controls: []string{"secrets"}}
		effect   = scanPlan{controls: []string{"dast"}, effects: []string{"nuclei (network): …"}}
		offsite  = scanPlan{controls: []string{"secrets"}, offMachine: []string{"github: acme/app"}}
		nothing  = scanPlan{}
		allPlans = []scanPlan{local, effect, offsite, nothing}
	)
	for _, p := range allPlans {
		if needsApproval(ScanAlways, p) {
			t.Errorf("always asks for %+v", p)
		}
		if !needsApproval(ScanAsk, p) {
			t.Errorf("ask does not ask for %+v", p)
		}
		// Off never reaches this point, because the tool is not registered; if it did, asking is the
		// safe answer.
		if !needsApproval(ScanOff, p) {
			t.Errorf("off does not ask for %+v", p)
		}
	}
	for p, want := range map[*scanPlan]bool{&local: false, &nothing: false, &effect: true, &offsite: true} {
		if got := needsApproval(ScanEffects, *p); got != want {
			t.Errorf("effects: needsApproval(%+v) = %v, want %v", *p, got, want)
		}
	}
}

// One component planning an effect-bearing scanner is enough to ask for the whole scan, and the
// prompt names that component's scanner rather than describing the other as if it did the same.
func TestEffectsModeAsksWhenAnyComponentPlansAnEffect(t *testing.T) {
	model := &saga.Model{
		Config: saga.Config{
			Controls:     map[string]saga.ControllerSettings{"secrets": {"enabled": true}, "dast": {"enabled": true}},
			AllowEffects: saga.EffectPermissions{"network"},
		},
		Components: []saga.Component{
			{Name: "api", Hosts: []saga.Host{{URL: "https://api.example.com"}}},
			{Name: "web", Repositories: []saga.Repository{{URL: "https://example.com/web.git"}}},
		},
	}
	p := mustPlan(t, model)
	if !needsApproval(ScanEffects, p) {
		t.Fatalf("a plan with dast against a host should ask: %+v", p)
	}
	if len(p.effects) != 1 || !strings.HasPrefix(p.effects[0], "nuclei (network)") {
		t.Errorf("effects = %v, want the one nuclei declares", p.effects)
	}
	if p.components != 2 {
		t.Errorf("components = %d, want 2", p.components)
	}

	// Without the host, the same descriptor plans nothing that leaves the checkout.
	model.Components[0].Hosts = nil
	model.Components[0].Repositories = []saga.Repository{{URL: "https://example.com/api.git"}}
	if p := mustPlan(t, model); needsApproval(ScanEffects, p) {
		t.Errorf("a repository-only plan should not ask: %+v", p.effects)
	}
}

// Two repositories under one component plan two jobs, and a scanner that uploads applies to both.
// The answer must come from the scanners planned, not from how many repositories carry them.
func TestEffectsModeAcrossTwoRepositoriesOfOneComponent(t *testing.T) {
	repos := []saga.Repository{{URL: "https://example.com/a.git"}, {URL: "https://example.com/b.git"}}
	readOnly := &saga.Model{
		Config:     saga.Config{Controls: map[string]saga.ControllerSettings{"secrets": {"enabled": true}, "sca": {"enabled": true}}},
		Components: []saga.Component{{Name: "api", Repositories: repos}},
	}
	if p := mustPlan(t, readOnly); needsApproval(ScanEffects, p) {
		t.Errorf("read-only controls over two repositories should not ask: %v", p.effects)
	}

	uploading := &saga.Model{
		Config: saga.Config{
			Controls: map[string]saga.ControllerSettings{"sca": {
				"mendSca": map[string]any{"enabled": true, "productToken": "token"},
			}},
			AllowEffects: saga.EffectPermissions{"disclosure", "mutate"},
		},
		Components: []saga.Component{{Name: "api", Repositories: repos}},
	}
	p := mustPlan(t, uploading)
	if !needsApproval(ScanEffects, p) {
		t.Fatalf("mend-sca uploads to a third party and should ask: %+v", p)
	}
	// Effects are listed per scanner, so two repositories do not repeat each line.
	seen := map[string]bool{}
	for _, e := range p.effects {
		if seen[e] {
			t.Errorf("effect listed twice: %q", e)
		}
		seen[e] = true
		if !strings.HasPrefix(e, "mend-sca ") {
			t.Errorf("effect %q, want only mend-sca's", e)
		}
	}
}

// A report sent to somebody else's service is an effect of the scan, whatever the scanners do.
func TestEffectsModeAsksBeforeDeliveringOffTheMachine(t *testing.T) {
	model := &saga.Model{
		Config: saga.Config{
			Controls:   map[string]saga.ControllerSettings{"secrets": {"enabled": true}},
			Publishers: []saga.PublisherConfig{{Kind: "file", Dir: "out"}},
		},
		Components: []saga.Component{{Name: "api", Repositories: []saga.Repository{{URL: "https://example.com/a.git"}}}},
	}
	if p := mustPlan(t, model); needsApproval(ScanEffects, p) {
		t.Errorf("a file publisher writes to this machine and should not ask: %v", p.offMachine)
	}
	model.Config.Publishers = append(model.Config.Publishers, saga.PublisherConfig{Kind: "github", Repo: "acme/app"})
	p := mustPlan(t, model)
	if !needsApproval(ScanEffects, p) {
		t.Fatal("a github publisher should ask")
	}
	if got := p.reasons(); len(got) != 1 || got[0] != "delivers results to github: acme/app" {
		t.Errorf("reasons = %v, want the github destination alone", got)
	}
}

// Without a way to ask, the refusal is the only thing the user sees, so it carries what the prompt
// would have said and a command that runs the same scan.
func TestEffectsRefusalNamesTheEffectsAndTheCommand(t *testing.T) {
	p := scanPlan{effects: []string{"nuclei (network): sends requests"}, offMachine: []string{"github: acme/app"}}
	got := refusal(ScanEffects, p, "app.saga.yaml")
	for _, want := range []string{"nuclei (network)", "delivers results to github: acme/app", "`draugr scan app.saga.yaml`"} {
		if !strings.Contains(got, want) {
			t.Errorf("refusal should contain %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "--scan=always") {
		t.Errorf("effects mode should not suggest dropping the question for every scan:\n%s", got)
	}
	if ask := refusal(ScanAsk, p, "app.saga.yaml"); !strings.Contains(ask, "--scan=always") {
		t.Errorf("ask mode names the flag that removes the question:\n%s", ask)
	}
}

// Driven through a client session, because the claim is about what a user sees: a scan that only
// reads runs without a prompt, and one that probes a host stops at the prompt and runs nothing when
// declined.
func TestEffectsModeThroughAClient(t *testing.T) {
	dir := t.TempDir()
	plain := filepath.Join(dir, "plain.saga.yaml")
	probing := filepath.Join(dir, "probing.saga.yaml")
	for path, body := range map[string]string{
		plain: "project: app\nrelease:\n  version: \"1.0\"\ncomponents:\n  - name: api\n",
		probing: "project: app\nrelease:\n  version: \"1.0\"\n" +
			"config:\n  allowEffects: [network]\n  controls:\n    dast:\n      enabled: true\n" +
			"components:\n  - name: api\n    hosts:\n      - url: https://api.example.com\n" +
			"  - name: web\n",
	} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	var asked []string
	sess := connectWith(t,
		Options{Registry: builtins.Registry(), Scan: ScanEffects, Root: dir},
		&mcp.ClientOptions{
			ElicitationHandler: func(_ context.Context, req *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
				asked = append(asked, req.Params.Message)
				return &mcp.ElicitResult{Action: "decline"}, nil
			},
		})
	call := func(path string) *mcp.CallToolResult {
		t.Helper()
		res, err := sess.CallTool(context.Background(), &mcp.CallToolParams{
			Name: "scan", Arguments: map[string]any{"path": path},
		})
		if err != nil {
			t.Fatalf("CallTool: %v", err)
		}
		return res
	}

	if res := call(plain); res.IsError {
		t.Errorf("a scan that only reads should run: %+v", res.Content)
	}
	if len(asked) != 0 {
		t.Fatalf("a scan that only reads should not ask, asked %q", asked)
	}

	if res := call(probing); !res.IsError {
		t.Error("a declined dast scan should not run")
	}
	if len(asked) != 1 {
		t.Fatalf("want one prompt for the dast scan, got %d", len(asked))
	}
	for _, want := range []string{"nuclei (network)", "authorized"} {
		if !strings.Contains(asked[0], want) {
			t.Errorf("prompt should contain %q:\n%s", want, asked[0])
		}
	}
}

// A client that cannot prompt is refused, and the refusal is what reaches the user.
func TestEffectsModeRefusesAClientThatCannotAsk(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "published.saga.yaml")
	if err := os.WriteFile(path, []byte(
		"project: app\nrelease:\n  version: \"1.0\"\n"+
			"config:\n  publishers:\n    - kind: github\n      repo: acme/app\n"+
			"components:\n  - name: api\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sess := connectWith(t, Options{Registry: builtins.Registry(), Scan: ScanEffects, Root: dir}, nil)
	res, err := sess.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "scan", Arguments: map[string]any{"path": path},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !res.IsError {
		t.Fatal("want a refusal from a client without elicitation")
	}
	var text strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			text.WriteString(tc.Text)
		}
	}
	for _, want := range []string{"delivers results to github: acme/app", "draugr scan " + path} {
		if !strings.Contains(text.String(), want) {
			t.Errorf("refusal should contain %q:\n%s", want, text.String())
		}
	}
}
