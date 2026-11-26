package fieldprobe

import (
	"slices"
	"testing"
)

type inner struct {
	Name  string
	Count int
}

type sample struct {
	Text    string
	On      bool
	N       int64
	U       uint8
	F       float64
	Ptr     *inner
	List    []inner
	Tags    map[string]string
	Nested  inner
	private string
}

func TestFillSetsEveryExportedField(t *testing.T) {
	var s sample
	Fill(&s, nil)
	if got := Unset(s); len(got) != 0 {
		t.Errorf("Unset after Fill = %v, want none", got)
	}
	if s.private != "" {
		t.Errorf("an unexported field was filled: %q", s.private)
	}
	if s.Ptr.Name != "Ptr.Name" || s.List[0].Name != "List[0].Name" || s.Tags["Tags.key"] != "Tags[Tags.key]" {
		t.Errorf("a string does not name its path: %+v %+v %v", s.Ptr, s.List, s.Tags)
	}
	if s.N == int64(s.Nested.Count) {
		t.Errorf("two numbers share a value: %d", s.N)
	}
}

func TestFillTakesAnOverrideAtItsPath(t *testing.T) {
	var s sample
	Fill(&s, map[string]any{"Nested.Name": "set", "U": 9})
	if s.Nested.Name != "set" || s.U != 9 {
		t.Errorf("overrides not applied: %+v", s)
	}
}

func TestFillRefusesWhatItCannotFill(t *testing.T) {
	for name, v := range map[string]any{"a value": sample{}, "a nil pointer": (*sample)(nil), "a channel": &struct{ C chan int }{}} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Error("no panic")
				}
			}()
			Fill(v, nil)
		})
	}
}

func TestLostNamesEachFieldACopyDropped(t *testing.T) {
	var want sample
	Fill(&want, nil)
	got := want
	got.Text = ""
	got.Ptr = &inner{Name: want.Ptr.Name}
	got.List = []inner{{Name: "other", Count: want.List[0].Count}}
	got.Tags = map[string]string{"Tags.key": "other"}
	got.Nested.Count = 0
	wantLost := []string{"List[0].Name", "Nested.Count", "Ptr.Count", "Tags[Tags.key]", "Text"}
	if lost := Lost(want, got); !slices.Equal(lost, wantLost) {
		t.Errorf("Lost = %v, want %v", lost, wantLost)
	}
	if lost := Lost(want, want); len(lost) != 0 {
		t.Errorf("Lost of a value against itself = %v", lost)
	}
}

func TestLostNamesAWholeValueThatChangedShape(t *testing.T) {
	var want sample
	Fill(&want, nil)
	got := want
	got.Ptr = nil
	got.List = nil
	got.Tags = map[string]string{"other": "x"}
	wantLost := []string{"List", "Ptr", "Tags"}
	if lost := Lost(want, got); !slices.Equal(lost, wantLost) {
		t.Errorf("Lost = %v, want %v", lost, wantLost)
	}
	got.Tags = nil
	if lost := Lost(want, got); !slices.Contains(lost, "Tags") {
		t.Errorf("Lost = %v, want Tags named", lost)
	}
	var none sample
	if lost := Lost(none, none); len(lost) != 0 {
		t.Errorf("Lost of two empty values = %v", lost)
	}
}

func TestUnsetNamesEveryEmptyField(t *testing.T) {
	want := []string{"F", "List", "N", "Nested.Count", "Nested.Name", "On", "Ptr", "Tags", "Text", "U"}
	if got := Unset(sample{}); !slices.Equal(got, want) {
		t.Errorf("Unset = %v, want %v", got, want)
	}
	if got := Unset(&sample{Ptr: &inner{}}); !slices.Contains(got, "Ptr.Name") {
		t.Errorf("Unset = %v, want the fields under a set pointer named", got)
	}
}
