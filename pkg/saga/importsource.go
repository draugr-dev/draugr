package saga

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// importKey is what names one import in a list: its control and its file, or its control, source and
// repository.
type importKey struct {
	control, file, source, repository string
}

// key is the import's importKey. The repository is compared as GitHub compares one, without regard to
// case.
func (i Import) key() importKey {
	return importKey{control: i.Control, file: i.File, source: i.Source, repository: strings.ToLower(i.Repository)}
}

// githubRepository is an owner/name as GitHub spells one: letters, digits, hyphens, underscores and
// dots, with no path beyond the name.
var githubRepository = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)

// validateFileOnly refuses the keys only a source reads on an import that reads a file, where they
// would do nothing.
func validateFileOnly(imp Import, at string) []error {
	var errs []error
	for _, k := range []struct{ key, value string }{{"tokenEnv", imp.TokenEnv}, {"repository", imp.Repository}} {
		if k.value != "" {
			errs = append(errs, fmt.Errorf("%s.%s is read only with source, and this import reads a file. Remove %s", at, k.key, k.key))
		}
	}
	return errs
}

// validateImportSource refuses a source Draugr does not read, the keys only a file reads, a
// repository not written as owner/name, and a source left to choose among several repositories.
//
// The repository is required where the component declares more than one, because the alerts belong
// to one repository and nothing in them says which of the component's it is. Whether the repository
// named is one of the component's is asked when the scan runs, where a local checkout's remote is
// known.
func validateImportSource(imp Import, repositories []Repository, at string) []error {
	var errs []error
	switch {
	case slices.Contains(ImportSources, imp.Source):
	case slices.Contains(ImportSources, strings.ToLower(imp.Source)):
		errs = append(errs, lowercaseOnly(at+".source", imp.Source))
	default:
		errs = append(errs, fmt.Errorf("%s.source %q is not one of %s", at, imp.Source, strings.Join(ImportSources, ", ")))
	}
	for _, k := range []struct {
		key string
		set bool
	}{{"format", imp.Format != ""}, {"severity", imp.Severity != nil}, {"commit", imp.Commit != ""}, {"converter", imp.Converter != nil}} {
		if k.set {
			errs = append(errs, fmt.Errorf("%s.%s is read only with file, and this import reads %s. Remove %s",
				at, k.key, imp.Source, k.key))
		}
	}
	if imp.Repository != "" && !githubRepository.MatchString(imp.Repository) {
		errs = append(errs, fmt.Errorf("%s.repository %q is not owner/name, such as draugr-dev/draugr", at, imp.Repository))
	}
	if imp.Repository == "" && distinctRepositories(repositories) > 1 {
		errs = append(errs, fmt.Errorf("%s: the component declares %d repositories. Name the one whose alerts to read "+
			"with repository: owner/name, one import per repository", at, distinctRepositories(repositories)))
	}
	return errs
}

// distinctRepositories counts the repositories a component declares, an address listed twice for two
// subtrees being one repository.
func distinctRepositories(repositories []Repository) int {
	var urls []string
	for _, r := range repositories {
		if !slices.Contains(urls, r.URL) {
			urls = append(urls, r.URL)
		}
	}
	return len(urls)
}
