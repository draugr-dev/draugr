package saga

import (
	"strings"
	"testing"
)

const clusterHeader = "project: acme\nrelease: { version: \"1.0.0\" }\n"

// A component refers to a cluster declared under clusters:. A name nothing declares is refused,
// naming the ones that are; so is the same cluster twice in one component, and a reference with
// no name. Two components may share a cluster, whole and by namespaces, which is the point.
func TestComponentsReferToDeclaredClusters(t *testing.T) {
	ok := clusterHeader + `
clusters:
  prod: {context: prod-admin, operatedBy: provider}
components:
  - name: platform
    kubernetes: [{cluster: prod}]
  - name: payments
    kubernetes: [{cluster: prod, namespaces: [payments]}]
`
	m, err := Load([]byte(ok))
	if err != nil {
		t.Fatalf("two components sharing a cluster: %v", err)
	}
	if got := m.Clusters["prod"]; got.Context != "prod-admin" || got.OperatedBy != OperatedByProvider {
		t.Errorf("cluster = %+v", got)
	}

	for name, tc := range map[string]struct{ body, want string }{
		"an undeclared name": {`
clusters:
  prod: {}
  staging: {}
components:
  - name: c
    kubernetes: [{cluster: prdo}]
`, `kubernetes[0].cluster "prdo" is not declared in clusters (it has prod, staging)`},
		"no clusters at all": {`
components:
  - name: c
    kubernetes: [{cluster: prod}]
`, `kubernetes[0].cluster "prod" is not declared in clusters`},
		"one cluster twice": {`
clusters:
  prod: {}
components:
  - name: c
    kubernetes: [{cluster: prod}, {cluster: prod, namespaces: [a]}]
`, `kubernetes[1] names cluster "prod" again, after kubernetes[0]`},
		"no name": {`
clusters:
  prod: {}
components:
  - name: c
    kubernetes: [{namespaces: [a]}]
`, `kubernetes[0].cluster is required`},
		"an operator that is not one": {`
clusters:
  prod: {operatedBy: managed}
components:
  - name: c
    kubernetes: [{cluster: prod}]
`, `clusters.prod.operatedBy "managed" is not self or provider`},
	} {
		_, err := Load([]byte(clusterHeader + tc.body))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error %v, want %q", name, err, tc.want)
		}
	}
}

// A descriptor written for the previous shape is refused, and each error says where the value
// went: the context and the operator to the cluster's entry, the benchmark settings too.
func TestTheOldClusterFieldsNameTheirNewHome(t *testing.T) {
	for body, want := range map[string]string{
		"components:\n  - name: c\n    kubernetes: [{ref: prod}]\n":                  "`clusters: {prod: {context: prod-eu-west-1}}`",
		"components:\n  - name: c\n    kubernetes: [{operatedBy: provider}]\n":       "moved to the cluster's entry under the top-level `clusters:`",
		"config:\n  controls:\n    kubernetes: {enabled: true, context: prod}\n":     "config.controls.kubernetes.context was removed. Use `context` on the cluster's entry",
		"config:\n  controls:\n    kubernetes: {enabled: true, benchmark: x}\n":      "config.controls.kubernetes.benchmark was removed",
		"config:\n  controls:\n    kubernetes: {enabled: true, version: \"1.30\"}\n": "config.controls.kubernetes.version was removed",
	} {
		_, err := Load([]byte(clusterHeader + body))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: error %v, want %q", body, err, want)
		}
	}
}

// Fragments may declare the clusters their components run on. The same facts in two documents are
// one cluster; different facts leave no single answer to which applied, and are refused naming the
// fragment.
func TestAClusterIsDeclaredOnceAcrossFragments(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "draugr.saga.yaml", clusterHeader+`
fragments:
  - path: "teams/*.saga-fragment.yaml"
clusters:
  prod: {context: prod-admin}
`)
	write(t, dir, "teams/a.saga-fragment.yaml", `
clusters:
  prod: {context: prod-admin}
components:
  - name: a
    kubernetes: [{cluster: prod}]
`)
	res, err := resolveIn(t, dir)
	if err != nil {
		t.Fatalf("ResolveFile: %v", err)
	}
	if err := res.Model.Validate(); err != nil {
		t.Errorf("the same facts twice: %v", err)
	}

	write(t, dir, "teams/b.saga-fragment.yaml", `
clusters:
  prod: {context: somebody-elses-prod}
components:
  - name: b
    kubernetes: [{cluster: prod, namespaces: [b]}]
`)
	res, err = resolveIn(t, dir)
	if err == nil {
		err = res.Model.Validate()
	}
	if err == nil || !strings.Contains(err.Error(), "clusters.prod:") ||
		!strings.Contains(err.Error(), "b.saga-fragment.yaml") || !strings.Contains(err.Error(), "declared once") {
		t.Errorf("two definitions of one cluster: %v", err)
	}
}

// A surveyor's fragment has no file behind it, and its disagreement is named as a fragment's.
func TestAConflictingSurveyedClusterIsRefused(t *testing.T) {
	m := &Model{Release: Release{Version: "1"}, Clusters: map[string]Cluster{"prod": {Context: "a"}}}
	Merge(m, Fragment{Clusters: map[string]Cluster{"prod": {Context: "b"}, "dev": {Context: "dev"}}})
	if m.Clusters["dev"].Context != "dev" {
		t.Error("a new cluster from a fragment was not added")
	}
	err := m.Validate()
	if err == nil || !strings.Contains(err.Error(), "a fragment defines it differently") {
		t.Errorf("error %v, want the conflict named", err)
	}
}

// A declared cluster nobody runs on is a warning: it changes no result, and the likelier story is a
// component that was removed and left it behind.
func TestAnUnusedClusterIsWarnedAbout(t *testing.T) {
	m := &Model{
		Clusters:   map[string]Cluster{"prod": {}, "spare": {}},
		Components: []Component{{Name: "c", Kubernetes: []ClusterRef{{Cluster: "prod"}}}},
	}
	got := m.ClusterWarnings()
	if len(got) != 1 || !strings.Contains(got[0], "clusters.spare is declared") {
		t.Errorf("warnings = %v, want spare alone", got)
	}
}
