package ciguard

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"gopkg.in/yaml.v3"
)

// triggerFilters are the keys that narrow an event to some refs or some files.
var triggerFilters = []string{"branches", "branches-ignore", "tags", "tags-ignore", "paths", "paths-ignore"}

// emptyFilters names each filter in a workflow's `on:` that is present and lists nothing, as
// "event.filter".
//
// GitHub reads `paths:` with no entries as no filter at all, so the event fires on everything while
// the file still reads as narrowed. Left behind when the last entry is deleted, it turns a trigger
// meant for a few files into one for every push.
func emptyFilters(on any) []string {
	events, ok := on.(map[string]any)
	if !ok {
		return nil // `on: push` or `on: [push, pull_request]`, which carry no filters
	}
	var empty []string
	for event, config := range events {
		filters, ok := config.(map[string]any)
		if !ok {
			continue
		}
		for _, key := range triggerFilters {
			value, present := filters[key]
			if !present {
				continue
			}
			if list, ok := value.([]any); !ok || len(list) == 0 {
				empty = append(empty, event+"."+key)
			}
		}
	}
	slices.Sort(empty)
	return empty
}

// TestEveryTriggerFilterNamesSomething holds every workflow's branch, tag and path filters to
// listing at least one entry.
func TestEveryTriggerFilterNamesSomething(t *testing.T) {
	t.Parallel()

	paths, err := filepath.Glob("../../.github/workflows/*.yml")
	if err != nil || len(paths) == 0 {
		t.Fatalf("no workflows found: %v", err)
	}
	for _, path := range paths {
		raw, err := os.ReadFile(path) // #nosec G304 -- a checked-in workflow
		if err != nil {
			t.Fatal(err)
		}
		var workflow struct {
			On any `yaml:"on"`
		}
		if err := yaml.Unmarshal(raw, &workflow); err != nil {
			t.Fatalf("parse %s: %v", filepath.Base(path), err)
		}
		for _, filter := range emptyFilters(workflow.On) {
			t.Errorf("%s: %s lists nothing, so the event fires unfiltered; list what it is for or "+
				"remove the key", filepath.Base(path), filter)
		}
	}
}

// The guard reads every shape `on:` takes, and finds the empty filter in each place it can sit.
func TestEmptyFiltersFindsAFilterThatListsNothing(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		on   string
		want []string
	}{
		"one event":                 {on: "push", want: nil},
		"a list of events":          {on: "[push, pull_request]", want: nil},
		"an event with no settings": {on: "\n  pull_request:\n", want: nil},
		"filters with entries": {
			on:   "\n  push:\n    branches: [main]\n    paths:\n      - docs/**\n",
			want: nil,
		},
		"a paths key with no entries": {
			on:   "\n  push:\n    branches: [main]\n    paths:\n  workflow_dispatch:\n",
			want: []string{"push.paths"},
		},
		"an empty list on two events": {
			on:   "\n  push:\n    tags: []\n  pull_request:\n    paths-ignore: []\n",
			want: []string{"pull_request.paths-ignore", "push.tags"},
		},
	} {
		var workflow struct {
			On any `yaml:"on"`
		}
		if err := yaml.Unmarshal([]byte("on: "+tc.on), &workflow); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := emptyFilters(workflow.On); !slices.Equal(got, tc.want) {
			t.Errorf("%s: emptyFilters = %v, want %v", name, got, tc.want)
		}
	}
}
