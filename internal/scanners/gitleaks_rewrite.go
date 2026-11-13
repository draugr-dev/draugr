package scanners

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// rewriteGitleaksReport rewrites the Gitleaks SARIF report at path in place, one result at a time:
// each location's path made relative to dir, and added appended to the first run's results.
//
// A history pass's report runs to gigabytes, nearly all of it results, and decoding it whole into
// a tree of values takes several times its size again. What this holds at once is one result,
// and the members around the results, such as the tool and its rules, which do not grow with the
// history. Every member other than the results is copied as Gitleaks wrote it.
func rewriteGitleaksReport(path, dir string, added []json.RawMessage) (err error) {
	in, err := os.Open(path) // #nosec G304 -- a report path a Gitleaks run of this scan wrote
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = out.Close()
			_ = os.Remove(out.Name())
		}
	}()
	w := bufio.NewWriter(out)
	rw := &gitleaksRewriter{dec: json.NewDecoder(bufio.NewReader(in)), w: w, dir: dir, added: added}
	if err := rw.report(); err != nil {
		return fmt.Errorf("read its report: %w", err)
	}
	if err := w.Flush(); err != nil {
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Rename(out.Name(), path)
}

// gitleaksRewriter copies a Gitleaks SARIF report from dec to w, member by member.
type gitleaksRewriter struct {
	dec   *json.Decoder
	w     io.Writer
	dir   string
	added []json.RawMessage
	err   error
}

// write writes s, keeping the first write error for the caller.
func (rw *gitleaksRewriter) write(b []byte) {
	if rw.err == nil {
		_, rw.err = rw.w.Write(b)
	}
}

// copyValue copies the next value whole. Used for every member that is not the runs or results,
// none of which grows with the history.
func (rw *gitleaksRewriter) copyValue() error {
	var raw json.RawMessage
	if err := rw.dec.Decode(&raw); err != nil {
		return err
	}
	rw.write(raw)
	return rw.err
}

// key writes a member's name, after a comma unless it is the object's first.
func (rw *gitleaksRewriter) key(name string, first bool) {
	if !first {
		rw.write([]byte(","))
	}
	k, _ := json.Marshal(name) // a string always marshals
	rw.write(k)
	rw.write([]byte(":"))
}

// open reads the next token and reports whether it opens delim. A null is not an error, and false.
func (rw *gitleaksRewriter) open(delim json.Delim, what string) (bool, error) {
	tok, err := rw.dec.Token()
	if err != nil {
		return false, err
	}
	switch tok {
	case nil:
		return false, nil
	case delim:
		return true, nil
	}
	if delim == '{' {
		return false, errors.New(what + " is not an object")
	}
	return false, errors.New(what + " are not a list")
}

// report copies the whole document.
func (rw *gitleaksRewriter) report() error {
	ok, err := rw.open('{', "the report")
	if err != nil {
		return err
	}
	if !ok {
		if len(rw.added) > 0 {
			return errors.New("the document is null")
		}
		rw.write([]byte("null"))
		return rw.err
	}
	rw.write([]byte("{"))
	first, sawRuns := true, false
	for rw.dec.More() {
		tok, err := rw.dec.Token()
		if err != nil {
			return err
		}
		name, _ := tok.(string) // a member's name is always a string
		rw.key(name, first)
		first = false
		if name == "runs" && !sawRuns {
			sawRuns = true
			err = rw.runs()
		} else {
			err = rw.copyValue()
		}
		if err != nil {
			return err
		}
	}
	if _, err := rw.dec.Token(); err != nil { // the closing brace
		return err
	}
	if !sawRuns && len(rw.added) > 0 {
		rw.key("runs", first)
		rw.write([]byte("["))
		rw.newRun()
		rw.write([]byte("]"))
	}
	rw.write([]byte("}"))
	return rw.err
}

// runs copies the list of runs, the first taking what is added.
func (rw *gitleaksRewriter) runs() error {
	ok, err := rw.open('[', "the report's runs")
	if err != nil {
		return err
	}
	if !ok && len(rw.added) == 0 {
		rw.write([]byte("null"))
		return rw.err
	}
	rw.write([]byte("["))
	n := 0
	for ok && rw.dec.More() {
		if n > 0 {
			rw.write([]byte(","))
		}
		if err := rw.run(n == 0); err != nil {
			return err
		}
		n++
	}
	if ok {
		if _, err := rw.dec.Token(); err != nil { // the closing bracket
			return err
		}
	}
	if n == 0 && len(rw.added) > 0 {
		rw.newRun()
	}
	rw.write([]byte("]"))
	return rw.err
}

// newRun writes a run of Gitleaks holding only what is added, for a report that had none.
func (rw *gitleaksRewriter) newRun() {
	rw.write([]byte(`{"tool":{"driver":{"name":"gitleaks"}},"results":[`))
	rw.writeAdded(true)
	rw.write([]byte("]}"))
}

// run copies one run, its results one at a time. The first run also takes what is added.
func (rw *gitleaksRewriter) run(takesAdded bool) error {
	ok, err := rw.open('{', "a run")
	if err != nil {
		return err
	}
	if !ok {
		if takesAdded && len(rw.added) > 0 {
			return errors.New("a run is not an object")
		}
		rw.write([]byte("null"))
		return rw.err
	}
	rw.write([]byte("{"))
	first, sawResults := true, false
	for rw.dec.More() {
		tok, err := rw.dec.Token()
		if err != nil {
			return err
		}
		name, _ := tok.(string)
		rw.key(name, first)
		first = false
		if name == "results" && !sawResults {
			sawResults = true
			err = rw.results(takesAdded)
		} else {
			err = rw.copyValue()
		}
		if err != nil {
			return err
		}
	}
	if _, err := rw.dec.Token(); err != nil { // the closing brace
		return err
	}
	if takesAdded && !sawResults && len(rw.added) > 0 {
		rw.key("results", first)
		rw.write([]byte("["))
		rw.writeAdded(true)
		rw.write([]byte("]"))
	}
	rw.write([]byte("}"))
	return rw.err
}

// results copies a run's results one at a time, each made relative to dir, then what is added.
func (rw *gitleaksRewriter) results(takesAdded bool) error {
	ok, err := rw.open('[', "a run's results")
	if err != nil {
		return err
	}
	if !ok && (!takesAdded || len(rw.added) == 0) {
		rw.write([]byte("null"))
		return rw.err
	}
	rw.write([]byte("["))
	n := 0
	for ok && rw.dec.More() {
		var raw json.RawMessage
		if err := rw.dec.Decode(&raw); err != nil {
			return err
		}
		res, err := relativeGitleaksResult(raw, rw.dir)
		if err != nil {
			return err
		}
		if n > 0 {
			rw.write([]byte(","))
		}
		rw.write(res)
		n++
	}
	if ok {
		if _, err := rw.dec.Token(); err != nil { // the closing bracket
			return err
		}
	}
	if takesAdded {
		rw.writeAdded(n == 0)
	}
	rw.write([]byte("]"))
	return rw.err
}

// writeAdded writes what is added, as list items, the first after a comma unless first.
func (rw *gitleaksRewriter) writeAdded(first bool) {
	for _, r := range rw.added {
		if !first {
			rw.write([]byte(","))
		}
		rw.write(r)
		first = false
	}
}

// relativeGitleaksResult is one result with each location's path made relative to dir. A result
// whose locations hold no path to change is returned as it was.
func relativeGitleaksResult(raw json.RawMessage, dir string) ([]byte, error) {
	if dir == "" {
		return raw, nil
	}
	v, err := decodeJSON(raw)
	if err != nil {
		return nil, err
	}
	gitleaksRelative(v, dir)
	return json.Marshal(v)
}
