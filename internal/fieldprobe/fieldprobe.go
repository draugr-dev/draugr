// Package fieldprobe fills every exported field of a value and names the fields a copy of it lost.
//
// It is for round-trip tests of a type whose fields are written and read back by hand, field by
// field, in more than one place: results.sarif's property bag, report.json and the disk cache all
// carry a finding that way. A test that names the fields it checks passes for a field added after
// it was written, so a writer or reader that never learned the new field drops it with every test
// green. Filling by reflection instead means a new field is checked the day it is added.
package fieldprobe

import (
	"fmt"
	"reflect"
	"sort"
	"strconv"
)

// Fill sets every exported field reachable from ptr, which must be a non-nil pointer, to a non-zero
// value, following pointers, slices and maps into the types they hold. A string is set to its
// field's path, such as "Package.Name", so a value that lands in the wrong field names where it came
// from; numbers count up from 1, so no two fields share one; a bool is true; a slice and a map get
// one element each.
//
// Overrides sets the field at a path to a value of its own, for a field whose writer validates or
// rewrites what it is given, such as a level that must be one SARIF names. The value must be
// assignable to the field. A path names a field the way Lost does: "Escalation.From",
// "Reachability.Paths[0].Frames[0].Line".
func Fill(ptr any, overrides map[string]any) {
	v := reflect.ValueOf(ptr)
	if v.Kind() != reflect.Pointer || v.IsNil() {
		panic("fieldprobe: Fill needs a non-nil pointer")
	}
	f := filler{overrides: overrides}
	f.fill(v.Elem(), "")
}

type filler struct {
	overrides map[string]any
	n         int
}

func (f *filler) next() int {
	f.n++
	return f.n
}

func (f *filler) fill(v reflect.Value, path string) {
	if o, ok := f.overrides[path]; ok && path != "" {
		v.Set(reflect.ValueOf(o).Convert(v.Type()))
		return
	}
	switch v.Kind() {
	case reflect.String:
		v.SetString(path)
	case reflect.Bool:
		v.SetBool(true)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v.SetInt(int64(f.next()))
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		v.SetUint(uint64(f.next())) // #nosec G115 -- counts the fields of one value, never negative
	case reflect.Float32, reflect.Float64:
		v.SetFloat(float64(f.next()) + 0.5)
	case reflect.Pointer:
		p := reflect.New(v.Type().Elem())
		f.fill(p.Elem(), path)
		v.Set(p)
	case reflect.Slice:
		s := reflect.MakeSlice(v.Type(), 1, 1)
		f.fill(s.Index(0), path+"[0]")
		v.Set(s)
	case reflect.Map:
		m := reflect.MakeMapWithSize(v.Type(), 1)
		k := reflect.New(v.Type().Key()).Elem()
		f.fill(k, path+".key")
		e := reflect.New(v.Type().Elem()).Elem()
		f.fill(e, path+"["+fmt.Sprint(k.Interface())+"]")
		m.SetMapIndex(k, e)
		v.Set(m)
	case reflect.Struct:
		t := v.Type()
		for i := range t.NumField() {
			if !t.Field(i).IsExported() {
				continue
			}
			f.fill(v.Field(i), join(path, t.Field(i).Name))
		}
	default:
		panic("fieldprobe: no value to fill a " + v.Kind().String() + " at " + path)
	}
}

// Lost names, in order, every field of want whose value got does not hold, by its path from the
// top: "Package.Affected", "Correlation.AlsoFoundBy[0].Location". It descends into structs, pointers,
// slices and maps, so a field lost inside a nested value is named rather than its parent. A slice or
// map of a different length is named whole.
func Lost(want, got any) []string {
	var lost []string
	lose(reflect.ValueOf(want), reflect.ValueOf(got), "", &lost)
	sort.Strings(lost)
	return lost
}

func lose(want, got reflect.Value, path string, lost *[]string) {
	switch want.Kind() {
	case reflect.Pointer:
		if want.IsNil() || got.IsNil() {
			if want.IsNil() != got.IsNil() {
				*lost = append(*lost, path)
			}
			return
		}
		lose(want.Elem(), got.Elem(), path, lost)
	case reflect.Struct:
		t := want.Type()
		for i := range t.NumField() {
			if t.Field(i).IsExported() {
				lose(want.Field(i), got.Field(i), join(path, t.Field(i).Name), lost)
			}
		}
	case reflect.Slice:
		if want.Len() != got.Len() {
			*lost = append(*lost, path)
			return
		}
		for i := range want.Len() {
			lose(want.Index(i), got.Index(i), path+"["+strconv.Itoa(i)+"]", lost)
		}
	case reflect.Map:
		if want.Len() != got.Len() {
			*lost = append(*lost, path)
			return
		}
		for _, k := range want.MapKeys() {
			g := got.MapIndex(k)
			if !g.IsValid() {
				*lost = append(*lost, path)
				return
			}
			lose(want.MapIndex(k), g, path+"["+fmt.Sprint(k.Interface())+"]", lost)
		}
	default:
		if !reflect.DeepEqual(want.Interface(), got.Interface()) {
			*lost = append(*lost, path)
		}
	}
}

// Unset names, in order, every exported field reachable from v that holds its zero value, by its
// path from the top, following pointers, slices and maps the way Lost does. A nil pointer, an empty
// slice and an empty map are named whole.
func Unset(v any) []string {
	var out []string
	unset(reflect.ValueOf(v), "", &out)
	sort.Strings(out)
	return out
}

func unset(v reflect.Value, path string, out *[]string) {
	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() {
			*out = append(*out, path)
			return
		}
		unset(v.Elem(), path, out)
	case reflect.Struct:
		t := v.Type()
		for i := range t.NumField() {
			if t.Field(i).IsExported() {
				unset(v.Field(i), join(path, t.Field(i).Name), out)
			}
		}
	case reflect.Slice:
		if v.Len() == 0 {
			*out = append(*out, path)
			return
		}
		for i := range v.Len() {
			unset(v.Index(i), path+"["+strconv.Itoa(i)+"]", out)
		}
	case reflect.Map:
		if v.Len() == 0 {
			*out = append(*out, path)
			return
		}
		for _, k := range v.MapKeys() {
			unset(v.MapIndex(k), path+"["+fmt.Sprint(k.Interface())+"]", out)
		}
	default:
		if v.IsZero() {
			*out = append(*out, path)
		}
	}
}

func join(path, name string) string {
	if path == "" {
		return name
	}
	return path + "." + name
}
