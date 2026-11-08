package scanners

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync"

	"github.com/draugr-dev/draugr/internal/english"
	"github.com/draugr-dev/draugr/internal/netpolicy"
	"github.com/draugr-dev/draugr/internal/tools"
	"github.com/draugr-dev/draugr/pkg/sarif"
)

// A dast scan tests the URL a host declares and nothing else on the machine or beyond it. Nuclei's
// community set reaches further in four ways, and each is closed here rather than documented, because
// a reader entitled to test one web application is not thereby entitled to try SSH logins on its host
// or to tell a third party its name.
//
//   - JavaScript and tcp templates choose their own ports, whatever the URL's: nucleiExcludedTypes.
//   - Some HTTP templates name a fixed other port, or a fixed outside host, some of them carrying the
//     target's name or a credential found on it, and some hold a JavaScript or tcp block beside their
//     HTTP one, which the exclusion by type passes: nucleiTemplateReaches.
//   - Every lookup goes to Nuclei's built-in public resolvers, so any scan of a named host tells them
//     the name: nucleiResolverFile.

// nucleiExcludedTypes are the template protocols Nuclei is told to skip unless the descriptor names
// its own templates. A template of either kind connects to a port it chooses, which the URL cannot
// narrow, and whether it does so can depend on the URL's port.
const nucleiExcludedTypes = "javascript,tcp"

var (
	// nucleiOtherPortRE is a fixed port on the target's host, which is a different service from the URL.
	nucleiOtherPortRE = regexp.MustCompile(`\{\{(?:Host|Hostname|RootURL|BaseURL)\}\}:[0-9]+`)
	// nucleiAtHostRE is the host a raw request is sent to.
	nucleiAtHostRE = regexp.MustCompile(`^\s*@Host:\s*(\S+)`)
	// nucleiOutsideURLRE is a path entry naming its own scheme and host instead of the target's.
	nucleiOutsideURLRE = regexp.MustCompile(`^https?://`)
	// nucleiOwnPortProtoRE is a protocol block whose template chooses its own port, and
	// nucleiOtherProtoRE any other. A template holding both is multi-protocol to Nuclei, so -ept passes
	// it for the type it does not list, and the block that dials runs anyway.
	nucleiOwnPortProtoRE = regexp.MustCompile(`(?m)^(?:javascript|tcp|network):`)
	nucleiOtherProtoRE   = regexp.MustCompile(`(?m)^(?:http|requests|dns|ssl|headless|websocket|whois|file|code):`)
)

// nucleiTemplateReaches reports whether a template sends a request anywhere but the URL it was given.
//
// It reads the lines rather than the YAML, because the set is thirteen thousand files read on every
// run. A match it should not have made costs one template; the shapes it looks for are the ones the
// community set uses, and a template hiding its host in a variable passes.
//
// A self-contained template runs no matter what the target is and reads as though it reaches
// everywhere, but Nuclei loads none without -esc, which the scan does not pass.
func nucleiTemplateReaches(text []byte) bool {
	reaches, selfContained, inPath := nucleiOwnPortProtoRE.Match(text) && nucleiOtherProtoRE.Match(text), false, false
	pathIndent := 0
	for line := range bytes.Lines(text) {
		s := strings.TrimRight(string(line), " \r\n")
		trimmed := strings.TrimLeft(s, " ")
		indent := len(s) - len(trimmed)
		if strings.HasPrefix(s, "self-contained:") && strings.Contains(s, "true") {
			selfContained = true
		}
		if nucleiOtherPortRE.MatchString(s) {
			reaches = true
		}
		if m := nucleiAtHostRE.FindStringSubmatch(s); m != nil && !strings.Contains(m[1], "{{") {
			reaches = true
		}
		switch {
		case trimmed == "path:" || trimmed == "- path:":
			inPath, pathIndent = true, indent
		case inPath && strings.HasPrefix(trimmed, "- ") && indent >= pathIndent:
			if nucleiOutsideURLRE.MatchString(strings.Trim(trimmed[2:], `"' `)) {
				reaches = true
			}
		case trimmed != "":
			inPath = false
		}
	}
	return reaches && !selfContained
}

var nucleiTemplateIDRE = regexp.MustCompile(`(?m)^id:\s*(\S+)`)

// nucleiReachingTemplates lists the IDs of the templates under dir that reach past the URL, sorted, so
// the same set gives the same command line.
func nucleiReachingTemplates(dir string) ([]string, error) {
	var ids []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		switch {
		case err != nil:
			return err
		case d.IsDir() && strings.HasPrefix(d.Name(), ".") && path != dir:
			return filepath.SkipDir
		case d.IsDir() || filepath.Ext(path) != ".yaml":
			return nil
		}
		text, err := os.ReadFile(path) // #nosec G304,G122 -- a template in the directory Nuclei itself loads from
		if err != nil {
			return err
		}
		if nucleiTemplateReaches(text) {
			if m := nucleiTemplateIDRE.FindSubmatch(text); m != nil {
				ids = append(ids, string(m[1]))
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	slices.Sort(ids)
	return slices.Compact(ids), nil
}

// nucleiReachScan is the answer for one process: the set does not change once it has been warmed.
type nucleiReachScan struct {
	once sync.Once
	ids  []string
	err  error
}

// reaching lists the templates of the installed set to leave out. The set is republished daily, so a
// list written down here would be out of date the day a new template lands, and the scan would go on
// reaching further with nothing to say so.
func (w *nucleiTemplateWarmer) reaching(ctx context.Context) ([]string, error) {
	w.reach.once.Do(func() {
		out, err := w.run(ctx, []string{"nuclei", "-templates-version"})
		if err != nil {
			w.reach.err = err
			return
		}
		set := tools.NucleiTemplates(out)
		if set.Dir == "" {
			w.reach.err = errors.New("nuclei named no template directory")
			return
		}
		w.reach.ids, w.reach.err = nucleiReachingTemplates(set.Dir)
	})
	return w.reach.ids, w.reach.err
}

// nucleiResolvConf is where the machine lists the resolvers it already uses.
const nucleiResolvConf = "/etc/resolv.conf"

// nucleiResolvers reads the nameserver lines of a resolv.conf, as Nuclei's -r wants them. Nothing is
// an answer: an unreadable file and one naming no server leave the same choice to the caller.
func nucleiResolvers(path string) []string {
	f, err := os.Open(path) // #nosec G304 -- a fixed system path, or a test's own file
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 2 && fields[0] == "nameserver" {
			out = append(out, net.JoinHostPort(fields[1], "53"))
		}
	}
	return out
}

// nucleiResolverFile writes the machine's resolvers to a file for -r and returns its flags. Nuclei
// otherwise asks 1.1.1.1, 1.0.0.1, 8.8.8.8 and 8.8.4.4 for every name, -sr only adding the system as a
// fallback, so any scan of an internal name tells them the name exists.
//
// With no resolvers to name, the scan cannot keep the name local. An offline run refuses, because it
// promises to contact nothing besides its targets; any other run goes on and the report says so.
func nucleiResolverFile(ctx context.Context, path string) (args []string, field *sarif.Field, cleanup func(), err error) {
	cleanup = func() {}
	servers := nucleiResolvers(path)
	if len(servers) == 0 {
		if netpolicy.Offline() {
			return nil, nil, cleanup, fmt.Errorf("nuclei: %s names no DNS resolver, and an offline scan must not "+
				"send the target's name to Nuclei's public resolvers; add a nameserver line to it, or run "+
				"without --offline", path)
		}
		// Windows has no such file, so a warning there would repeat on every run with nothing to act on.
		level := slog.LevelWarn
		if runtime.GOOS == "windows" {
			level = slog.LevelInfo
		}
		slog.Log(ctx, level, "Nuclei asks its public resolvers for the target's name",
			"hint", "add a nameserver line to "+path+" to keep lookups on this machine")
		return nil, &sarif.Field{Key: "resolvers", Value: "Nuclei's built-in public servers"}, cleanup, nil
	}
	f, err := os.CreateTemp("", "draugr-nuclei-resolvers-*.txt")
	if err != nil {
		return nil, nil, cleanup, fmt.Errorf("nuclei: prepare resolvers: %w", err)
	}
	cleanup = func() { _ = os.Remove(f.Name()) } // #nosec G703 -- the file this function just made
	_, werr := f.WriteString(strings.Join(servers, "\n") + "\n")
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		cleanup()
		return nil, nil, func() {}, fmt.Errorf("nuclei: prepare resolvers: %w", werr)
	}
	return []string{"-r", f.Name()}, nil, cleanup, nil
}

// nucleiLeftOut says what the scan was kept from running, in the report, because a smaller scan that
// says nothing reads exactly like a complete one.
func nucleiLeftOut(ids []string) sarif.Field {
	value := strings.ReplaceAll(nucleiExcludedTypes, ",", " and ") + " templates"
	if len(ids) > 0 {
		value += "; " + english.Count(len(ids), "template") + " naming another host or port"
	}
	return sarif.Field{Key: "left out", Value: value}
}
