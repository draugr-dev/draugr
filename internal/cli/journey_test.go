package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/draugr-dev/draugr/internal/builtins"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// What one command writes, the next has to accept.
//
// Every test in this package drives one command and asks whether its own output is right. The
// failure that gets through is the seam: `init` wrote a project name taken from the directory, the
// validator rejected it, and the scaffold failed on the very next command `init` itself printed as
// the thing to run next. Both commands were individually correct and the sequence was broken.
//
// So this walks the sequence a person actually walks, in a directory named the way real
// directories are named.
func TestTheFirstFiveMinutesWork(t *testing.T) {
	for _, dirName := range []string{"My.Service", "payments_api", "Team Alpha", "acme"} {
		t.Run(dirName, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), dirName)
			if err := os.MkdirAll(filepath.Join(dir, "app"), 0o750); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "app", "requirements.txt"),
				[]byte("flask==1.0\n"), 0o600); err != nil {
				t.Fatal(err)
			}

			// 1. init writes the scaffold, and says what to run next.
			var out bytes.Buffer
			path := filepath.Join(dir, "draugr.saga.yaml")
			if err := runInit(dir, initOptions{output: path}, &out); err != nil {
				t.Fatalf("init: %v", err)
			}
			next := out.String()
			if !strings.Contains(next, "draugr doctor") || !strings.Contains(next, "draugr scan") {
				t.Fatalf("init stopped naming what to run next:\n%s", next)
			}

			// 2. The thing it wrote loads. This is the seam that broke.
			model, err := saga.LoadFile(path)
			if err != nil {
				t.Fatalf("init wrote a descriptor Draugr cannot load: %v", err)
			}

			// 3. And validate, which is one of the two commands init tells you to run, agrees.
			if err := loadAndCheck(path); err != nil {
				t.Fatalf("init wrote a descriptor `draugr validate` rejects: %v", err)
			}

			// 4. And doctor, which is the other one, gets far enough to talk about tools rather
			// than refusing the file.
			stubDetect(t, allToolsPresent())
			var doc bytes.Buffer
			_ = runDoctor(context.Background(), &doc, builtins.Registry(), path, doctorRun{},
				detectTool, func(context.Context) (string, error) { return "v9.9.9", nil })
			if strings.Contains(doc.String(), "✗ invalid") {
				t.Errorf("doctor refuses what init wrote:\n%s", doc.String())
			}
			if !strings.Contains(doc.String(), "TOOLS") {
				t.Errorf("doctor never reached the tools it needs:\n%s", doc.String())
			}

			// 5. The project name is the directory's, recognizably, because somebody reads it back.
			if model.Project == "" {
				t.Error("no project name")
			}
		})
	}
}
