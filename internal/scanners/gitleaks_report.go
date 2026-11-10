package scanners

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
)

// A Gitleaks report over a long history runs to gigabytes, nearly all of it results, and a decoded
// report takes several times its size. So the reports of a pass are read a result at a time: the
// comparison of the runs keeps a key per result, and the merged report is written from the reported
// one on disk. What is held beyond that is the reports' other members, which do not grow with the
// history.
//
// The merged report is what decoding the whole document and encoding it again with encoding/json
// writes: each object's members in key order, no space between tokens, numbers as written, strings
// escaped as encoding/json escapes them. Each member and each result is decoded and encoded on its
// own, and written in that order.

// gitleaksVisitor is told what a walk of a Gitleaks report finds. Each func may be nil.
type gitleaksVisitor struct {
	// member is a member of the report other than a list of runs.
	member func(key string, value json.RawMessage) error
	// runs starts the list of runs.
	runs func() error
	// run starts run i; null says it is null rather than an object.
	run func(i int, null bool) error
	// runMember is a member of run i other than a list of results.
	runMember func(i int, key string, value json.RawMessage) error
	// results starts run i's list of results, and resultsEnd ends it.
	results, resultsEnd func(i int) error
	// result is one result of run i.
	result func(i int, raw json.RawMessage) error
}

// jsonNull is the value a member given as null is passed as.
var jsonNull = json.RawMessage("null")

// walkGitleaksReport reads a Gitleaks SARIF report a member and a result at a time, telling v what
// it finds in the order the report holds it, and reports whether the report is null.
//
// A report or a run that is not an object, and runs or results that are not a list, are an error,
// as they are to decoding the report into its runs and their results. So is a report that names
// its runs twice, or a run its results. Nothing after the report is read.
func walkGitleaksReport(r io.Reader, v gitleaksVisitor) (bool, error) {
	dec := json.NewDecoder(r)
	dec.UseNumber()
	open, err := dec.Token()
	if err != nil {
		return false, err
	}
	if open == nil {
		return true, nil
	}
	if open != json.Delim('{') {
		return false, errors.New("the report is not an object")
	}
	runs := false
	for dec.More() {
		key, err := jsonMemberKey(dec)
		if err != nil {
			return false, err
		}
		if key != "runs" {
			if err := visitJSONMember(dec, func(value json.RawMessage) error { return call2(v.member, key, value) }); err != nil {
				return false, err
			}
			continue
		}
		if runs {
			return false, errors.New("the report names its runs twice")
		}
		runs = true
		list, err := dec.Token()
		if err != nil {
			return false, err
		}
		switch list {
		case nil:
			err = call2(v.member, key, jsonNull)
		case json.Delim('['):
			err = walkGitleaksRuns(dec, v)
		default:
			err = errors.New("the report's runs are not a list")
		}
		if err != nil {
			return false, err
		}
	}
	_, err = dec.Token() // the report's closing brace
	return false, err
}

// walkGitleaksRuns reads a list of runs, its opening bracket already read.
func walkGitleaksRuns(dec *json.Decoder, v gitleaksVisitor) error {
	if v.runs != nil {
		if err := v.runs(); err != nil {
			return err
		}
	}
	for i := 0; dec.More(); i++ {
		open, err := dec.Token()
		if err != nil {
			return err
		}
		if open != nil && open != json.Delim('{') {
			return errors.New("a run is not an object")
		}
		if v.run != nil {
			if err := v.run(i, open == nil); err != nil {
				return err
			}
		}
		if open == nil {
			continue
		}
		if err := walkGitleaksRun(dec, i, v); err != nil {
			return err
		}
	}
	_, err := dec.Token() // the list's closing bracket
	return err
}

// walkGitleaksRun reads the members of run i, its opening brace already read.
func walkGitleaksRun(dec *json.Decoder, i int, v gitleaksVisitor) error {
	results := false
	for dec.More() {
		key, err := jsonMemberKey(dec)
		if err != nil {
			return err
		}
		if key != "results" {
			err := visitJSONMember(dec, func(value json.RawMessage) error {
				if v.runMember == nil {
					return nil
				}
				return v.runMember(i, key, value)
			})
			if err != nil {
				return err
			}
			continue
		}
		if results {
			return errors.New("a run names its results twice")
		}
		results = true
		list, err := dec.Token()
		if err != nil {
			return err
		}
		switch list {
		case nil:
			if v.runMember != nil {
				err = v.runMember(i, key, jsonNull)
			}
		case json.Delim('['):
			err = walkGitleaksResults(dec, i, v)
		default:
			err = errors.New("a run's results are not a list")
		}
		if err != nil {
			return err
		}
	}
	_, err := dec.Token() // the run's closing brace
	return err
}

// walkGitleaksResults reads run i's list of results, its opening bracket already read, one result
// at a time.
func walkGitleaksResults(dec *json.Decoder, i int, v gitleaksVisitor) error {
	if err := call1(v.results, i); err != nil {
		return err
	}
	for dec.More() {
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return err
		}
		if v.result != nil {
			if err := v.result(i, raw); err != nil {
				return err
			}
		}
	}
	if _, err := dec.Token(); err != nil { // the list's closing bracket
		return err
	}
	return call1(v.resultsEnd, i)
}

// jsonMemberKey reads the name of an object's next member.
func jsonMemberKey(dec *json.Decoder) (string, error) {
	tok, err := dec.Token()
	if err != nil {
		return "", err
	}
	key, ok := tok.(string)
	if !ok {
		return "", errors.New("a member has no name")
	}
	return key, nil
}

// visitJSONMember reads the value of the member whose name was just read and hands it to visit.
func visitJSONMember(dec *json.Decoder, visit func(json.RawMessage) error) error {
	var value json.RawMessage
	if err := dec.Decode(&value); err != nil {
		return err
	}
	return visit(value)
}

func call1(f func(int) error, i int) error {
	if f == nil {
		return nil
	}
	return f(i)
}

func call2(f func(string, json.RawMessage) error, key string, value json.RawMessage) error {
	if f == nil {
		return nil
	}
	return f(key, value)
}

// decodeJSON decodes one JSON value, keeping each number as it was written.
func decodeJSON(raw []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return v, nil
}

// canonicalJSON is raw as encoding/json writes it once decoded.
func canonicalJSON(raw []byte) (json.RawMessage, error) {
	v, err := decodeJSON(raw)
	if err != nil {
		return nil, err
	}
	return json.Marshal(v)
}

// gitleaksSkeleton is a Gitleaks report less its results: its other members, and each run's, as
// encoding/json writes them.
type gitleaksSkeleton struct {
	null    bool
	members map[string]json.RawMessage
	// listed says the report holds a list of runs. Runs given as null are a member.
	listed bool
	// runs holds nil for a run that is null.
	runs []*gitleaksRunSkeleton
}

// gitleaksRunSkeleton is one run of a gitleaksSkeleton.
type gitleaksRunSkeleton struct {
	members map[string]json.RawMessage
	// listed says the run holds a list of results. Results given as null are a member.
	listed bool
	// added are results written after the run's own.
	added []json.RawMessage
}

// hasResults says whether the run is written with a list of results.
func (r *gitleaksRunSkeleton) hasResults() bool { return r.listed || len(r.added) > 0 }

// readGitleaksSkeleton reads a Gitleaks report less its results.
func readGitleaksSkeleton(r io.Reader) (*gitleaksSkeleton, error) {
	s := &gitleaksSkeleton{members: map[string]json.RawMessage{}}
	put := func(members map[string]json.RawMessage, key string, value json.RawMessage) error {
		c, err := canonicalJSON(value)
		members[key] = c
		return err
	}
	null, err := walkGitleaksReport(r, gitleaksVisitor{
		member: func(key string, value json.RawMessage) error { return put(s.members, key, value) },
		runs:   func() error { s.listed = true; return nil },
		run: func(_ int, null bool) error {
			var run *gitleaksRunSkeleton
			if !null {
				run = &gitleaksRunSkeleton{members: map[string]json.RawMessage{}}
			}
			s.runs = append(s.runs, run)
			return nil
		},
		runMember: func(i int, key string, value json.RawMessage) error { return put(s.runs[i].members, key, value) },
		results:   func(i int) error { s.runs[i].listed = true; return nil },
	})
	s.null = null
	return s, err
}

// add puts results after the first run's own, as appendSARIFResults does: a report with no run
// gains one, the run's tool its driver where it has none, and the driver its rules.
func (s *gitleaksSkeleton) add(results []json.RawMessage) error {
	if len(results) == 0 {
		return nil
	}
	if s.null {
		return errors.New("read its SARIF: the report is null")
	}
	if len(s.runs) == 0 {
		delete(s.members, "runs")
		s.listed = true
		s.runs = []*gitleaksRunSkeleton{{members: map[string]json.RawMessage{}}}
	}
	run := s.runs[0]
	if run == nil {
		return errors.New("read its SARIF: a run is not an object")
	}
	if !run.listed {
		delete(run.members, "results")
	}
	run.added = results
	var tool map[string]any
	if raw, ok := run.members["tool"]; ok {
		v, err := decodeJSON(raw)
		if err != nil {
			return err
		}
		tool, _ = v.(map[string]any)
	}
	if tool == nil {
		tool = map[string]any{}
	}
	driver, _ := tool["driver"].(map[string]any)
	if driver == nil {
		driver = map[string]any{"name": "gitleaks"}
		tool["driver"] = driver
	}
	rules, _ := driver["rules"].([]any)
	driver["rules"] = rules
	out, err := json.Marshal(tool)
	run.members["tool"] = out
	return err
}

// writeGitleaksMergedFile writes added into the Gitleaks report at path, with each location's path
// relative to dir, through a file beside it.
func writeGitleaksMergedFile(path, dir string, added []json.RawMessage) error {
	f, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".merged-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }()
	open := func() (io.ReadCloser, error) {
		return os.Open(path) // #nosec G304 -- the report path this run was given
	}
	err = writeGitleaksMerged(f, open, dir, added)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp, path) // #nosec G703 -- the report path this run was given
}

// writeGitleaksMerged writes to w the Gitleaks report open reads, with each location's path
// relative to dir and added after the first run's results. It reads the report twice: once for
// what is not a result, and once to copy the results across in order.
func writeGitleaksMerged(w io.Writer, open func() (io.ReadCloser, error), dir string, added []json.RawMessage) error {
	src, err := open()
	if err != nil {
		return err
	}
	s, err := readGitleaksSkeleton(src)
	_ = src.Close()
	if err != nil {
		return fmt.Errorf("read its report: %w", err)
	}
	if err := s.add(added); err != nil {
		return err
	}
	bw := bufio.NewWriter(w)
	m := &gitleaksMergeWriter{w: bw, s: s, dir: dir}
	if err := m.write(open); err != nil {
		return err
	}
	return bw.Flush()
}

// gitleaksMergeWriter writes a gitleaksSkeleton with the results read from its report a second
// time. A run is written when its results are reached, or at the end for a run with none listed.
type gitleaksMergeWriter struct {
	w   *bufio.Writer
	s   *gitleaksSkeleton
	dir string
	err error
	// next is the first run not yet started.
	next int
	// first says nothing has been written yet in the list of results open.
	first bool
	// written counts the members written in the run open.
	written int
}

func (m *gitleaksMergeWriter) put(b []byte) {
	if m.err == nil {
		_, m.err = m.w.Write(b)
	}
}

func (m *gitleaksMergeWriter) putString(s string) { m.put([]byte(s)) }

func (m *gitleaksMergeWriter) putKey(key string) {
	k, _ := json.Marshal(key) // a string always encodes
	m.put(k)
	m.putString(":")
}

func (m *gitleaksMergeWriter) write(open func() (io.ReadCloser, error)) error {
	s := m.s
	if s.null {
		m.putString("null")
		return m.err
	}
	keys := slices.Collect(maps.Keys(s.members))
	if s.listed {
		keys = append(keys, "runs")
	}
	slices.Sort(keys)
	m.putString("{")
	for i, key := range keys {
		if i > 0 {
			m.putString(",")
		}
		m.putKey(key)
		if key != "runs" || !s.listed {
			m.put(s.members[key])
			continue
		}
		m.putString("[")
		src, err := open()
		if err != nil {
			return err
		}
		_, err = walkGitleaksReport(src, gitleaksVisitor{results: m.openResults, result: m.result, resultsEnd: m.closeResults})
		_ = src.Close()
		if err != nil {
			return fmt.Errorf("read its report: %w", err)
		}
		m.runsBefore(len(s.runs))
		m.putString("]")
	}
	m.putString("}")
	return m.err
}

// runsBefore writes whole each run not yet started before run n.
func (m *gitleaksMergeWriter) runsBefore(n int) {
	for m.next < n {
		i := m.next
		m.startRun(i)
		r := m.s.runs[i]
		if r == nil {
			continue
		}
		m.closeRun(r)
	}
}

// startRun writes run i up to its first result, or whole where it is null.
func (m *gitleaksMergeWriter) startRun(i int) {
	if i > 0 {
		m.putString(",")
	}
	m.next = i + 1
	r := m.s.runs[i]
	if r == nil {
		m.putString("null")
		return
	}
	m.putString("{")
	m.written = 0
	for _, key := range slices.Sorted(maps.Keys(r.members)) {
		if key >= "results" {
			continue
		}
		m.member(key, r.members[key])
	}
	if r.hasResults() {
		if m.written > 0 {
			m.putString(",")
		}
		m.putKey("results")
		m.putString("[")
		m.written++
		m.first = true
	}
}

// closeRun writes what run r has after its own results: the results added, and its members after
// them.
func (m *gitleaksMergeWriter) closeRun(r *gitleaksRunSkeleton) {
	if r.hasResults() {
		for _, a := range r.added {
			m.resultBytes(a)
		}
		m.putString("]")
	}
	for _, key := range slices.Sorted(maps.Keys(r.members)) {
		if key < "results" {
			continue
		}
		m.member(key, r.members[key])
	}
	m.putString("}")
}

func (m *gitleaksMergeWriter) member(key string, value json.RawMessage) {
	if m.written > 0 {
		m.putString(",")
	}
	m.putKey(key)
	m.put(value)
	m.written++
}

func (m *gitleaksMergeWriter) openResults(i int) error {
	m.runsBefore(i)
	m.startRun(i)
	return m.err
}

func (m *gitleaksMergeWriter) result(_ int, raw json.RawMessage) error {
	v, err := decodeJSON(raw)
	if err != nil {
		return err
	}
	gitleaksRelative(v, m.dir)
	out, err := json.Marshal(v)
	if err != nil {
		return err
	}
	m.resultBytes(out)
	return m.err
}

func (m *gitleaksMergeWriter) resultBytes(b []byte) {
	if !m.first {
		m.putString(",")
	}
	m.first = false
	m.put(b)
}

func (m *gitleaksMergeWriter) closeResults(i int) error {
	m.closeRun(m.s.runs[i])
	return m.err
}
