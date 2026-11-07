package manifests

import (
	"encoding/xml"
	"regexp"
	"slices"
	"strings"
)

// Scope is where a pom.xml puts a dependency on the classpath, folded into the three answers a
// finding needs: it ships with the application, it is supplied by the runtime the application is
// deployed into, or it is used only to build and test.
type Scope int

const (
	// ScopeRuntime is Maven's compile and runtime scopes, a dependency written with no scope, and an
	// optional one: each is on the application's own runtime classpath.
	ScopeRuntime Scope = iota
	// ScopeProvided is Maven's provided and system scopes: the dependency is compiled against and
	// left out of what is packaged, because the server or platform the application runs in supplies
	// its own copy.
	ScopeProvided
	// ScopeTest is Maven's test scope: a development dependency.
	ScopeTest
)

// pomDependency is one <dependency> element, in <dependencies> or in <dependencyManagement>.
type pomDependency struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Scope      string `xml:"scope"`
}

// pomProject is the part of a pom.xml that decides a dependency's scope and version.
type pomProject struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Parent     struct {
		GroupID string `xml:"groupId"`
		Version string `xml:"version"`
	} `xml:"parent"`
	Properties struct {
		Entries []struct {
			XMLName xml.Name
			Value   string `xml:",chardata"`
		} `xml:",any"`
	} `xml:"properties"`
	Dependencies []pomDependency `xml:"dependencies>dependency"`
	Managed      []pomDependency `xml:"dependencyManagement>dependencies>dependency"`
}

// pomProperty is a ${name} reference in a pom value.
var pomProperty = regexp.MustCompile(`\$\{([^}]+)\}`)

// PomScopes reads the scope a pom.xml declares for each of its direct dependencies, keyed by
// groupId:artifactId.
//
// A dependency with no scope of its own takes the one the same pom's dependencyManagement gives it,
// and a groupId written as a property is resolved from the pom's own properties and its project and
// parent coordinates. What this file cannot answer is left out rather than guessed: a scope managed
// by a parent POM or an imported BOM, a groupId held in a property only a parent defines, and a
// dependency declared in a profile. A dependency left out is read by the caller as runtime, the
// answer that keeps its findings counted.
//
// A dependency declared more than once, with a classifier or a type apart, takes the scope that
// reaches furthest into production: runtime over provided, provided over test. One copy that ships
// is enough for its flaws to ship.
func PomScopes(data []byte) (map[string]Scope, error) {
	p, props, err := parsePom(data)
	if err != nil {
		return nil, err
	}
	key := func(d pomDependency) (string, bool) { return pomKey(d, props) }
	managed := map[string]string{}
	for _, d := range p.Managed {
		if k, ok := key(d); ok && d.Scope != "" {
			managed[k] = expandPom(d.Scope, props)
		}
	}
	scopes := map[string]Scope{}
	for _, d := range p.Dependencies {
		k, ok := key(d)
		if !ok {
			continue
		}
		scope := expandPom(d.Scope, props)
		if scope == "" {
			scope = managed[k]
		}
		s := scopeOf(scope)
		if prior, seen := scopes[k]; seen && prior < s {
			continue
		}
		scopes[k] = s
	}
	return scopes, nil
}

// PomVersions reads the versions a pom.xml declares for its direct dependencies, keyed by
// groupId:artifactId, each with every version declared for it.
//
// A version written as a property is resolved from the pom's own properties and its project and
// parent coordinates, and a dependency written with no version takes the one the same pom's
// dependencyManagement gives it. A version this file cannot answer, one a parent POM or an imported
// BOM manages or a property only a parent defines, is left out rather than guessed.
func PomVersions(data []byte) (map[string][]string, error) {
	p, props, err := parsePom(data)
	if err != nil {
		return nil, err
	}
	managed := map[string]string{}
	for _, d := range p.Managed {
		if k, ok := pomKey(d, props); ok {
			if v := expandPom(d.Version, props); v != "" && !strings.Contains(v, "${") {
				managed[k] = v
			}
		}
	}
	versions := map[string][]string{}
	for _, d := range p.Dependencies {
		k, ok := pomKey(d, props)
		if !ok {
			continue
		}
		v := expandPom(d.Version, props)
		if v == "" {
			v = managed[k]
		}
		if v == "" || strings.Contains(v, "${") || slices.Contains(versions[k], v) {
			continue
		}
		versions[k] = append(versions[k], v)
	}
	return versions, nil
}

// parsePom decodes a pom.xml and the properties a value in it may refer to: its own, and its
// project and parent coordinates.
func parsePom(data []byte) (pomProject, map[string]string, error) {
	var p pomProject
	if err := xml.Unmarshal(data, &p); err != nil {
		return pomProject{}, nil, err
	}
	group := firstOf(p.GroupID, p.Parent.GroupID)
	version := firstOf(p.Version, p.Parent.Version)
	props := map[string]string{
		"project.groupId":        group,
		"pom.groupId":            group,
		"project.parent.groupId": strings.TrimSpace(p.Parent.GroupID),
		"project.artifactId":     strings.TrimSpace(p.ArtifactID),
		"project.version":        version,
		"pom.version":            version,
		"project.parent.version": strings.TrimSpace(p.Parent.Version),
	}
	for _, e := range p.Properties.Entries {
		props[e.XMLName.Local] = strings.TrimSpace(e.Value)
	}
	return p, props, nil
}

// pomKey is a dependency's groupId:artifactId with its properties resolved, or false where either
// is empty or names a property this pom does not define.
func pomKey(d pomDependency, props map[string]string) (string, bool) {
	g, a := expandPom(d.GroupID, props), expandPom(d.ArtifactID, props)
	if g == "" || a == "" || strings.Contains(g+a, "${") {
		return "", false
	}
	return g + ":" + a, true
}

// scopeOf folds a Maven scope into a Scope. An unknown word is runtime, as Maven itself treats a
// scope it does not recognize as compile.
func scopeOf(scope string) Scope {
	switch scope {
	case "provided", "system":
		return ScopeProvided
	case "test":
		return ScopeTest
	}
	return ScopeRuntime
}

// expandPom trims a pom value and replaces each ${name} the properties define. A reference they do
// not define is left in place, for the caller to recognize as unresolved.
func expandPom(v string, props map[string]string) string {
	v = strings.TrimSpace(v)
	if !strings.Contains(v, "${") {
		return v
	}
	return pomProperty.ReplaceAllStringFunc(v, func(ref string) string {
		if val, ok := props[ref[2:len(ref)-1]]; ok && val != "" && !strings.Contains(val, "${") {
			return val
		}
		return ref
	})
}

// firstOf is the first value that is not empty.
func firstOf(values ...string) string {
	for _, v := range values {
		if v = strings.TrimSpace(v); v != "" {
			return v
		}
	}
	return ""
}
