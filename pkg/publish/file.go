package publish

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/draugr-dev/draugr/pkg/report"
	"github.com/draugr-dev/draugr/pkg/saga"
)

// filePublisher writes each rendered report to a file in a directory, named by the report's
// default filename (e.g. results.sarif, report.md).
type filePublisher struct {
	dir string
}

func newFilePublisher(cfg saga.PublisherConfig) (Publisher, error) {
	if cfg.Dir == "" {
		return nil, fmt.Errorf("file publisher requires a 'dir'")
	}
	return filePublisher{dir: cfg.Dir}, nil
}

func (filePublisher) Kind() string { return "file" }

func (p filePublisher) Publish(_ context.Context, artifacts []report.Artifact) error {
	if err := os.MkdirAll(p.dir, 0o750); err != nil {
		return err
	}
	for _, a := range artifacts {
		path := filepath.Join(p.dir, a.Filename)
		if err := os.WriteFile(path, a.Bytes, 0o600); err != nil {
			return fmt.Errorf("write %s: %w", path, err)
		}
	}
	return nil
}
