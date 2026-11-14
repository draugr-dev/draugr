//go:build integration

package integration

import (
	"context"
	"crypto/md5" // #nosec G501 -- the digest Trivy names a cached module's directory by, not a security use
	"encoding/hex"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/netpolicy"
	"github.com/draugr-dev/draugr/internal/scanners"
	"github.com/draugr-dev/draugr/pkg/plugin"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// plantedModule is a registry module the repository below calls and nothing can fetch offline.
const (
	plantedSource  = "example-org/planted/aws"
	plantedVersion = "1.0.0"
)

// plantedModuleBody is what the module would declare: SSH open to the internet, which Trivy reports
// as AWS-0107 wherever it evaluates the module.
const plantedModuleBody = `resource "aws_security_group_rule" "ssh" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = "sg-123"
  description       = "ssh"
}
`

// Trivy keeps the registry modules it downloads in .aqua/cache under the temporary directory and
// reads that cache before it tries to fetch, so a module another program left there would be
// checked by an offline scan that cannot fetch it. The scan of a commit has to come out the same
// whatever the machine's temporary directory holds: here, with the module a repository calls
// planted where Trivy looks for it, and with that directory empty.
func TestTrivyConfigReadsNoModuleAnotherProgramCached(t *testing.T) {
	requireTool(t, "trivy", "trivy-config runs it")
	requireTool(t, "git", "the scan checks the repository out before scanning it")
	t.Setenv("HOME", t.TempDir())
	netpolicy.SetOffline(true)
	t.Cleanup(func() { netpolicy.SetOffline(false) })

	repo := newRepo(t, map[string]string{
		"main.tf": "module \"planted\" {\n  source  = \"" + plantedSource + "\"\n  version = \"" + plantedVersion + "\"\n}\n",
	})

	scan := func(tmp string) sarif.Report {
		t.Helper()
		t.Setenv("TMPDIR", tmp)
		report, err := scanners.NewTrivyConfig().Scan(context.Background(), plugin.RepositoryTarget{URL: repo}, plugin.Config{})
		if err != nil {
			t.Fatal(err)
		}
		return report
	}

	planted := t.TempDir()
	key := md5.Sum([]byte(plantedSource + ":" + plantedVersion)) // #nosec G401 -- Trivy's cache key, see the import
	cached := filepath.Join(planted, ".aqua", "cache", hex.EncodeToString(key[:]))
	if err := os.MkdirAll(cached, 0o750); err != nil {
		t.Fatal(err)
	}
	writeFile(t, cached, "main.tf", plantedModuleBody)

	withCache, empty := scan(planted), scan(t.TempDir())
	describe := func(r sarif.Report) string {
		var out []string
		for _, res := range r.Results {
			out = append(out, res.RuleID+" "+res.Location.URI)
		}
		for _, in := range r.Inputs {
			out = append(out, "unread "+in.Path+": "+in.Unread)
		}
		slices.Sort(out)
		return strings.Join(out, "\n")
	}
	if a, b := describe(withCache), describe(empty); a != b {
		t.Errorf("with a module cached under TMPDIR the scan found\n%s\n\nand with none\n%s", a, b)
	}
	if got := describe(empty); !strings.Contains(got, `unread main.tf: module "planted" not loaded`) {
		t.Errorf("the module the scan could not fetch is not reported unread:\n%s", got)
	}
	if _, err := os.Stat(filepath.Join(cached, "main.tf")); err != nil {
		t.Errorf("the cache other programs read was changed: %v", err)
	}
}
