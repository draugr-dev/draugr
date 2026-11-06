package manifests

import (
	"encoding/xml"
	"regexp"
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
	Scope      string `xml:"scope"`
}

// pomProject is the part of a pom.xml that decides a dependency's scope.
type pomProject struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Parent     struct {
		GroupID string `xml:"groupId"`
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
	var p pomProject
	if err := xml.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	group := firstOf(p.GroupID, p.Parent.GroupID)
	props := map[string]string{
		"project.groupId":        group,
		"pom.groupId":            group,
		"project.parent.groupId": strings.TrimSpace(p.Parent.GroupID),
		"project.artifactId":     strings.TrimSpace(p.ArtifactID),
	}
	for _, e := range p.Properties.Entries {
		props[e.XMLName.Local] = strings.TrimSpace(e.Value)
	}
	key := func(d pomDependency) (string, bool) {
		g, a := expandPom(d.GroupID, props), expandPom(d.ArtifactID, props)
		if g == "" || a == "" || strings.Contains(g+a, "${") {
			return "", false
		}
		return g + ":" + a, true
	}
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
