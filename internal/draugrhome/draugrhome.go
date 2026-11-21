// Package draugrhome answers where Draugr keeps what it downloads: the tools `draugr tools install`
// provisions, the data they need, and the feeds a scan reads without the network.
//
// One answer, read by every caller, because the install, the PATH a scan runs under, `doctor` and
// `tools uninstall` have to agree on it. A tool installed into one directory and looked for in
// another is a tool that is missing, and the scan that cannot find it says so only after it has
// started.
//
// The settings file is not here. ~/.draugr/config.yaml is a person's configuration, found by its own
// discovery and moved with DRAUGR_CONFIG, and a directory shared between people, such as a CI
// runner's tool cache, should not carry one person's settings to the others.
package draugrhome

import (
	"fmt"
	"os"
	"path/filepath"
)

// EnvVar names the variable that moves Draugr's directory away from ~/.draugr.
const EnvVar = "DRAUGR_HOME"

// Dir is Draugr's own directory: $DRAUGR_HOME when it is set, and ~/.draugr otherwise.
//
// A relative DRAUGR_HOME is refused rather than resolved. Resolved against the working directory,
// it would name a different directory from every directory a command is run in, so tools installed
// from one checkout would be missing from the next, with nothing to say why.
func Dir() (string, error) {
	if v := os.Getenv(EnvVar); v != "" {
		if !filepath.IsAbs(v) {
			return "", fmt.Errorf("%s must be an absolute path, and %q is relative. "+
				"Set it to the full path of the directory Draugr should install tools into, such as %s",
				EnvVar, v, filepath.Join(string(filepath.Separator), "opt", "draugr"))
		}
		return filepath.Clean(v), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locate home directory: %w", err)
	}
	return filepath.Join(home, ".draugr"), nil
}

// FromEnv reports whether DRAUGR_HOME is what set Dir, so output naming the directory can say why
// it is not the default.
func FromEnv() bool { return os.Getenv(EnvVar) != "" }

// Check returns the error Dir would give for DRAUGR_HOME, or nil when the variable is unset or
// usable. Unlike Dir, it does not fail where there is no home directory: that is a machine Draugr
// can still run on, with nowhere to install tools, and the command that needs one says so.
func Check() error {
	if !FromEnv() {
		return nil
	}
	_, err := Dir()
	return err
}
