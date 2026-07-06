package main

import "testing"

func TestRun(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want int
	}{
		{"no args prints usage", nil, 0},
		{"version", []string{"version"}, 0},
		{"help", []string{"help"}, 0},
		{"unknown command", []string{"bogus"}, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := run(tc.args); got != tc.want {
				t.Fatalf("run(%v) = %d, want %d", tc.args, got, tc.want)
			}
		})
	}
}
