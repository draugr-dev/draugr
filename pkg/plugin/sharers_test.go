package plugin

import (
	"context"
	"testing"
)

// Outside a run, and for a value of one or less, a job shares the machine with nobody.
func TestSharers(t *testing.T) {
	for _, tc := range []struct {
		ctx  context.Context
		want int
	}{
		{context.Background(), 1},
		{WithSharers(context.Background(), 0), 1},
		{WithSharers(context.Background(), 1), 1},
		{WithSharers(context.Background(), 4), 4},
	} {
		if got := Sharers(tc.ctx); got != tc.want {
			t.Errorf("Sharers = %d, want %d", got, tc.want)
		}
	}
}
