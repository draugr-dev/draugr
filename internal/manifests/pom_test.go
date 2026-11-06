package manifests

import (
	"maps"
	"testing"
)

// pomWith is a pom.xml with the given body inside <project>.
func pomWith(body string) []byte {
	return []byte(`<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
` + body + `
</project>
`)
}

func TestPomScopes(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want map[string]Scope
	}{
		{"each scope", `
  <dependencies>
    <dependency><groupId>g</groupId><artifactId>none</artifactId><version>1</version></dependency>
    <dependency><groupId>g</groupId><artifactId>compile</artifactId><scope>compile</scope></dependency>
    <dependency><groupId>g</groupId><artifactId>runtime</artifactId><scope>runtime</scope></dependency>
    <dependency><groupId>g</groupId><artifactId>provided</artifactId><scope> provided </scope></dependency>
    <dependency><groupId>g</groupId><artifactId>system</artifactId><scope>system</scope><systemPath>/x.jar</systemPath></dependency>
    <dependency><groupId>g</groupId><artifactId>test</artifactId><scope>test</scope></dependency>
    <dependency><groupId>g</groupId><artifactId>optional</artifactId><optional>true</optional></dependency>
    <dependency><groupId>g</groupId><artifactId>unknown</artifactId><scope>bundled</scope></dependency>
  </dependencies>`, map[string]Scope{
			"g:none": ScopeRuntime, "g:compile": ScopeRuntime, "g:runtime": ScopeRuntime,
			"g:provided": ScopeProvided, "g:system": ScopeProvided, "g:test": ScopeTest,
			"g:optional": ScopeRuntime, "g:unknown": ScopeRuntime,
		}},
		{"a scope from dependencyManagement, and one written over it", `
  <dependencyManagement>
    <dependencies>
      <dependency><groupId>g</groupId><artifactId>a</artifactId><scope>test</scope></dependency>
      <dependency><groupId>g</groupId><artifactId>b</artifactId><scope>provided</scope></dependency>
      <dependency><groupId>g</groupId><artifactId>unused</artifactId><scope>test</scope></dependency>
    </dependencies>
  </dependencyManagement>
  <dependencies>
    <dependency><groupId>g</groupId><artifactId>a</artifactId></dependency>
    <dependency><groupId>g</groupId><artifactId>b</artifactId><scope>compile</scope></dependency>
  </dependencies>`, map[string]Scope{"g:a": ScopeTest, "g:b": ScopeRuntime}},
		{"properties and the project's coordinates", `
  <parent><groupId>org.parent</groupId><artifactId>p</artifactId><version>1</version></parent>
  <artifactId>self</artifactId>
  <properties>
    <lib.group>org.lib</lib.group>
    <lib.scope>provided</lib.scope>
    <nested>${lib.group}</nested>
  </properties>
  <dependencies>
    <dependency><groupId>${lib.group}</groupId><artifactId>lib</artifactId><scope>${lib.scope}</scope></dependency>
    <dependency><groupId>${project.groupId}</groupId><artifactId>${project.artifactId}-tests</artifactId><scope>test</scope></dependency>
    <dependency><groupId>${project.parent.groupId}</groupId><artifactId>sibling</artifactId><scope>provided</scope></dependency>
    <dependency><groupId>${undefined}</groupId><artifactId>gone</artifactId><scope>provided</scope></dependency>
    <dependency><groupId>${nested}</groupId><artifactId>gone</artifactId><scope>provided</scope></dependency>
    <dependency><groupId></groupId><artifactId>gone</artifactId><scope>provided</scope></dependency>
  </dependencies>`, map[string]Scope{
			"org.lib:lib": ScopeProvided, "org.parent:self-tests": ScopeTest, "org.parent:sibling": ScopeProvided,
		}},
		{"a dependency declared twice takes the scope that ships", `
  <dependencies>
    <dependency><groupId>g</groupId><artifactId>a</artifactId><type>test-jar</type><scope>test</scope></dependency>
    <dependency><groupId>g</groupId><artifactId>a</artifactId></dependency>
    <dependency><groupId>g</groupId><artifactId>b</artifactId><scope>provided</scope></dependency>
    <dependency><groupId>g</groupId><artifactId>b</artifactId><classifier>tests</classifier><scope>test</scope></dependency>
  </dependencies>`, map[string]Scope{"g:a": ScopeRuntime, "g:b": ScopeProvided}},
		{"profiles and plugins are not the project's dependencies", `
  <profiles><profile><dependencies>
    <dependency><groupId>g</groupId><artifactId>profiled</artifactId><scope>provided</scope></dependency>
  </dependencies></profile></profiles>
  <build><plugins><plugin><dependencies>
    <dependency><groupId>g</groupId><artifactId>plugin</artifactId><scope>provided</scope></dependency>
  </dependencies></plugin></plugins></build>`, map[string]Scope{}},
	} {
		got, err := PomScopes(pomWith(tc.body))
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if !maps.Equal(got, tc.want) {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestPomScopesRefusesWhatIsNotXML(t *testing.T) {
	if _, err := PomScopes([]byte("<project><dependencies>")); err == nil {
		t.Error("a truncated pom parsed")
	}
}
